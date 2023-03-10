type G1 = pasta_curves::pallas::Point;
type G2 = pasta_curves::vesta::Point;
use std::time::Instant;

use clap::{Command, Arg};
use nova_sha256::sha256_step::circuit::SHA256CompressionCircuit;
use nova_sha256::sha256_step::util::{sha256_initial_digest_scalars, scalars_to_digest, DIGEST_LENGTH_BYTES};
use nova_snark::{traits::{circuit::TrivialTestCircuit, Group}, PublicParams, RecursiveSNARK, CompressedSNARK};
use flate2::{write::ZlibEncoder, Compression};
use sha2::{Sha256, Digest};

fn main() {
    let cmd = Command::new("Nova-based SHA256 circuit proof generation and verification")
    .bin_name("sha256")
    .arg(
        Arg::new("input_len_log")
            .value_name("Log2 of the test input length")
            .default_value("6")
            .value_parser(clap::value_parser!(usize))
            .long_help("Base 2 log of the test input length. For example, the value of 8 corresponds to 256 bytes of input. ")   
    )
    .after_help("This command generates a proof that the hash of 2^(input_log_len) zero bytes");

    let m = cmd.get_matches();
    let log_input_len = *m.get_one::<usize>("input_len_log").unwrap();
    let input_len = 1 << log_input_len;

    println!("Nova-based SHA256 compression function iterations");
    println!("=========================================================");

    type C1 = SHA256CompressionCircuit<<G1 as Group>::Scalar>;
    type C2 = TrivialTestCircuit<<G2 as Group>::Scalar>;
    let circuit_primary: C1 = SHA256CompressionCircuit::default();
    let circuit_secondary: C2 = TrivialTestCircuit::default();

    let param_gen_timer = Instant::now();
    println!("Producing public parameters...");
    let pp = PublicParams::<G1, G2, C1, C2>::setup(
        circuit_primary,
        circuit_secondary.clone()
    );

    let param_gen_time = param_gen_timer.elapsed();
    println!("PublicParams::setup, took {:?} ", param_gen_time);

    println!("Number of constraints per step (primary circuit): {}", pp.num_constraints().0);
    println!("Number of constraints per step (secondary circuit): {}", pp.num_constraints().1);
    println!("Number of variables per step (primary circuit): {}", pp.num_variables().0);
    println!("Number of variables per step (secondary circuit): {}", pp.num_variables().1);

    let input: Vec<u8> = vec![0u8; input_len]; // All the input bytes are zero
    let primary_circuit_sequence = C1::new_state_sequence(input.clone());

    let z0_primary = sha256_initial_digest_scalars::<<G1 as Group>::Scalar>();
    let z0_secondary = vec![<G2 as Group>::Scalar::zero()];

    let proof_gen_timer = Instant::now();
    // produce a recursive SNARK
    println!("Generating a RecursiveSNARK...");
    let mut recursive_snark: Option<RecursiveSNARK<G1, G2, C1, C2>> = None;

    let start = Instant::now();
    for (i, circuit_primary) in primary_circuit_sequence.iter().enumerate() {
        let step_start = Instant::now();
        let res = RecursiveSNARK::prove_step(
            &pp,
            recursive_snark,
            circuit_primary.clone(),
            circuit_secondary.clone(),
            z0_primary.clone(),
            z0_secondary.clone(),
        );
        assert!(res.is_ok());
        println!(
          "RecursiveSNARK::prove_step {}: {:?}, took {:?} ",
          i,
          res.is_ok(),
          step_start.elapsed()
        );
        recursive_snark = Some(res.unwrap());
    }
    println!("Total time taken by RecursiveSNARK::prove_steps: {:?}", start.elapsed());

    assert!(recursive_snark.is_some());
    let recursive_snark = recursive_snark.unwrap();

    // verify the recursive SNARK
    println!("Verifying a RecursiveSNARK...");
    let start = Instant::now();
    let num_steps = primary_circuit_sequence.len();
    let res = recursive_snark.verify(&pp, num_steps, z0_primary.clone(), z0_secondary.clone());
    println!(
      "RecursiveSNARK::verify: {:?}, took {:?}",
      res.is_ok(),
      start.elapsed()
    );
    assert!(res.is_ok());

    // produce a compressed SNARK
    println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
    let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp);

    let start = Instant::now();
    type EE1 = nova_snark::provider::ipa_pc::EvaluationEngine<G1>;
    type EE2 = nova_snark::provider::ipa_pc::EvaluationEngine<G2>;
    type S1 = nova_snark::spartan::RelaxedR1CSSNARK<G1, EE1>;
    type S2 = nova_snark::spartan::RelaxedR1CSSNARK<G2, EE2>;

    let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &pk, &recursive_snark);
    println!(
    "CompressedSNARK::prove: {:?}, took {:?}",
    res.is_ok(),
    start.elapsed()
    );
    assert!(res.is_ok());
    let proving_time = proof_gen_timer.elapsed();
    println!("Total proving time is {:?}", proving_time);

    let compressed_snark = res.unwrap();
  
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    bincode::serialize_into(&mut encoder, &compressed_snark).unwrap();
    let compressed_snark_encoded = encoder.finish().unwrap();
    println!(
      "CompressedSNARK::len {:?} bytes",
      compressed_snark_encoded.len()
    );

    // verify the compressed SNARK
    println!("Verifying a CompressedSNARK...");
    let start = Instant::now();
    let res = compressed_snark.verify(&vk, num_steps, z0_primary, z0_secondary);
    let verification_time = start.elapsed();
    println!(
      "CompressedSNARK::verify: {:?}, took {:?}",
      res.is_ok(),
      verification_time,
    );
    assert!(res.is_ok());
    println!("=========================================================");
    println!("Public parameters generation time: {:?} ", param_gen_time);
    println!("Total proving time (excl pp generation): {:?}", proving_time);
    println!("Total verification time: {:?}", verification_time);

    println!("=========================================================");

    let actual_hash_bytes = scalars_to_digest(res.unwrap().0.as_slice().try_into().unwrap());
    let mut hasher = Sha256::new();
    hasher.update(input);
    let expected_hash_bytes: [u8; DIGEST_LENGTH_BYTES] = hasher.finalize().try_into().unwrap();
    println!("Expected value of final hash = {:x?}", hex::encode(expected_hash_bytes));
    println!("Actual value of final hash   = {:x?}", hex::encode(actual_hash_bytes));
}