use std::marker::PhantomData;

use super::util::{sha256_msg_block_sequence, BLOCK_LENGTH_BYTES, DIGEST_LENGTH_BYTES};
use bellpepper::gadgets::{
    multipack::{bytes_to_bits, pack_bits},
    sha256::sha256_compression_function,
    uint32::UInt32,
};
use bellpepper_core::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
    ConstraintSystem, SynthesisError,
};
use ff::{PrimeField, PrimeFieldBits};
use nova_snark::traits::circuit::StepCircuit;

#[derive(Clone, Debug)]
pub struct SHA256CompressionCircuit<F>
where
    F: PrimeField,
{
    input: [u8; BLOCK_LENGTH_BYTES],
    marker: PhantomData<F>,
}

impl<F> Default for SHA256CompressionCircuit<F>
where
    F: PrimeField + PrimeFieldBits,
{
    fn default() -> Self {
        Self {
            input: [0u8; BLOCK_LENGTH_BYTES],
            marker: Default::default(),
        }
    }
}

impl<F> SHA256CompressionCircuit<F>
where
    F: PrimeField + PrimeFieldBits,
{
    // Produces the intermediate SHA256 digests when a message is hashed
    pub fn new_state_sequence(input: Vec<u8>) -> Vec<Self> {
        let block_seq = sha256_msg_block_sequence(input);
        block_seq
            .into_iter()
            .map(|b| SHA256CompressionCircuit {
                input: b,
                marker: PhantomData,
            })
            .collect()
    }

    pub fn compress<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        msg_block: [u8; BLOCK_LENGTH_BYTES],
        current_digest: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        assert!((F::CAPACITY * 2) as usize >= DIGEST_LENGTH_BYTES * 8);
        assert_eq!(current_digest.len(), 2);
        let initial_curr_digest_bits = current_digest[0]
            .to_bits_le(cs.namespace(|| "initial current digest bits"))
            .unwrap();
        let remaining_curr_digest_bits = current_digest[1]
            .to_bits_le(cs.namespace(|| "remaining current digest bits"))
            .unwrap();

        let mut current_digest_bits: Vec<Boolean> = initial_curr_digest_bits
            .into_iter()
            .take(F::CAPACITY as usize)
            .collect();
        let num_bits_remaining = DIGEST_LENGTH_BYTES * 8 - (F::CAPACITY as usize);
        current_digest_bits.append(
            &mut remaining_curr_digest_bits
                .into_iter()
                .take(num_bits_remaining)
                .collect(),
        );

        let mut current_state: Vec<UInt32> = vec![];
        for c in current_digest_bits.chunks(32) {
            current_state.push(UInt32::from_bits_be(c));
        }
        assert_eq!(current_state.len(), 8);

        let input_bit_values = bytes_to_bits(&msg_block);
        assert_eq!(input_bit_values.len(), BLOCK_LENGTH_BYTES * 8);
        let input_bits: Vec<Boolean> = input_bit_values
            .iter()
            .enumerate()
            .map(|(i, b)| {
                Boolean::from(
                    AllocatedBit::alloc(cs.namespace(|| format!("input bit {i}")), Some(*b))
                        .unwrap(),
                )
            })
            .collect();

        // SHA256 compression function application
        let next_state: Vec<UInt32> =
            sha256_compression_function(&mut *cs, &input_bits, &current_state)?;
        assert_eq!(next_state.len(), 8);

        let next_digest_bits: Vec<Boolean> = next_state
            .into_iter()
            .flat_map(|u| u.into_bits_be())
            .collect();
        assert_eq!(next_digest_bits.len(), DIGEST_LENGTH_BYTES * 8);

        let mut z_out: Vec<AllocatedNum<F>> = vec![];
        let (initial_next_digest_bits, remaining_next_digest_bits) =
            next_digest_bits.split_at(F::CAPACITY as usize);
        z_out.push(
            pack_bits(
                cs.namespace(|| "Packing initial next digest bits into scalar"),
                initial_next_digest_bits,
            )
            .unwrap(),
        );
        z_out.push(
            pack_bits(
                cs.namespace(|| "Packing remaining next digest bits into scalar"),
                remaining_next_digest_bits,
            )
            .unwrap(),
        );

        Ok(z_out)
    }
}

impl<F> StepCircuit<F> for SHA256CompressionCircuit<F>
where
    F: PrimeField + PrimeFieldBits,
{
    fn arity(&self) -> usize {
        2
    }

    fn synthesize<CS: ConstraintSystem<F>>(
        &self,
        cs: &mut CS,
        z: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        Self::compress(cs, self.input, z)
    }
}

#[cfg(test)]
mod tests {
    use crate::sha256_step::util::{digest_to_scalars, sha256_initial_digest_scalars};

    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use pasta_curves::Fp;

    #[test]
    fn test_sha256_compression_constraints() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let empty_input: Vec<u8> = vec![];
        let mut sha256_state_sequence = SHA256CompressionCircuit::new_state_sequence(empty_input);
        assert_eq!(sha256_state_sequence.len(), 1);

        let sha256_iteration = sha256_state_sequence.pop().unwrap();
        let mut z_in: Vec<AllocatedNum<Fp>> = vec![];

        for (i, s) in sha256_initial_digest_scalars().iter().enumerate() {
            z_in.push(
                AllocatedNum::alloc(cs.namespace(|| format!("z_in[{i}]")), || Ok(*s)).unwrap(),
            );
        }
        let z_out = sha256_iteration.synthesize(&mut cs, &z_in).unwrap();
        assert!(cs.is_satisfied());

        assert_eq!(z_out.len(), 2);
        let z_out_values = [
            z_out[0].get_value().unwrap_or_default(),
            z_out[1].get_value().unwrap_or_default(),
        ];

        let expected_digest: [u8; 32] =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .expect("Failed to parse digest string")
                .try_into()
                .unwrap();

        let expected_zout: [Fp; 2] = digest_to_scalars(&expected_digest);

        assert_eq!(expected_zout[0], z_out_values[0]);
        assert_eq!(expected_zout[1], z_out_values[1]);

        println!("Num constraints = {:?}", cs.num_constraints());
        println!("Num inputs = {:?}", cs.num_inputs());
    }
}
