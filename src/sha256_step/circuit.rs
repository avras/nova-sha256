use std::marker::PhantomData;

use crate::sha256_step::util::{sha256_msg_block_sequence, BLOCK_LENGTH, DIGEST_LENGTH};
use ff::{PrimeField, PrimeFieldBits};
use nova_snark::frontend::gadgets::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
};
use nova_snark::frontend::gadgets::{sha256::sha256_compression_function, uint32::UInt32};
use nova_snark::frontend::num::Num;
use nova_snark::frontend::{ConstraintSystem, SynthesisError};
use nova_snark::traits::circuit::StepCircuit;

// From bellpepper/src/gadgets/multipack.rs
/// Takes a sequence of booleans and exposes them as a single compact Num.
pub fn pack_bits<Scalar, CS>(
    mut cs: CS,
    bits: &[Boolean],
) -> Result<AllocatedNum<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let mut num = Num::<Scalar>::zero();
    let mut coeff = Scalar::ONE;
    for bit in bits.iter().take(Scalar::CAPACITY as usize) {
        num = num.add_bool_with_coeff(CS::one(), bit, coeff);

        coeff = coeff.double();
    }

    let alloc_num = AllocatedNum::alloc(cs.namespace(|| "input"), || {
        num.get_value().ok_or(SynthesisError::AssignmentMissing)
    })?;

    // num * 0 = input
    cs.enforce(
        || "packing constraint",
        |_| num.lc(Scalar::ONE),
        |lc| lc + CS::one(),
        |lc| lc + alloc_num.get_variable(),
    );

    Ok(alloc_num)
}

#[derive(Clone, Debug)]
pub struct SHA256CompressionCircuit<F>
where
    F: PrimeField,
{
    msg_block: [bool; BLOCK_LENGTH],
    marker: PhantomData<F>,
}

impl<F> Default for SHA256CompressionCircuit<F>
where
    F: PrimeField + PrimeFieldBits,
{
    fn default() -> Self {
        Self {
            msg_block: [false; BLOCK_LENGTH],
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
                msg_block: b,
                marker: PhantomData,
            })
            .collect()
    }

    pub fn compress<CS: ConstraintSystem<F>>(
        cs: &mut CS,
        msg_block: &[Boolean],
        current_digest: &[AllocatedNum<F>],
    ) -> Result<Vec<AllocatedNum<F>>, SynthesisError> {
        assert!((F::CAPACITY * 2) as usize >= DIGEST_LENGTH);
        assert_eq!(msg_block.len(), BLOCK_LENGTH);

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
        let num_bits_remaining = DIGEST_LENGTH - (F::CAPACITY as usize);
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

        // SHA256 compression function application
        let next_state: Vec<UInt32> =
            sha256_compression_function(&mut *cs, msg_block, &current_state)?;
        assert_eq!(next_state.len(), 8);

        let next_digest_bits: Vec<Boolean> = next_state
            .into_iter()
            .flat_map(|u| u.into_bits_be())
            .collect();
        assert_eq!(next_digest_bits.len(), DIGEST_LENGTH);

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
        let msg_block_bits: Vec<Boolean> = self
            .msg_block
            .iter()
            .enumerate()
            .map(|(i, b)| {
                Boolean::from(
                    AllocatedBit::alloc(cs.namespace(|| format!("input bit {i}")), Some(*b))
                        .unwrap(),
                )
            })
            .collect();

        Self::compress(cs, &msg_block_bits, z)
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

        assert_eq!(cs.num_constraints(), 27218);
    }
}
