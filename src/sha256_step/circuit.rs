use super::util::{
    digest_to_scalars, sha256_state_sequence, BLOCK_LENGTH_BYTES, DIGEST_LENGTH_BYTES,
};
use bellperson::{
    gadgets::{
        boolean::AllocatedBit, multipack::pack_bits, num::AllocatedNum,
        sha256::sha256_compression_function, uint32::UInt32,
    },
    gadgets::{boolean::Boolean, multipack::bytes_to_bits},
    ConstraintSystem, SynthesisError,
};
use ff::{PrimeField, PrimeFieldBits};
use nova_snark::traits::circuit::StepCircuit;

#[derive(Clone, Debug)]
pub struct SHA256CompressionCircuit<F: PrimeField> {
    input: [u8; BLOCK_LENGTH_BYTES],
    current_digest: [F; 2],
    next_digest: [F; 2],
}

impl<F> Default for SHA256CompressionCircuit<F>
where
    F: PrimeField + PrimeFieldBits,
{
    fn default() -> Self {
        Self {
            input: [0u8; BLOCK_LENGTH_BYTES],
            current_digest: [F::ZERO; 2],
            next_digest: [F::ZERO; 2],
        }
    }
}

impl<F: PrimeField + PrimeFieldBits> SHA256CompressionCircuit<F> {
    // Produces the intermediate SHA256 digests when a message is hashed
    pub fn new_state_sequence(input: Vec<u8>) -> Vec<Self> {
        let (block_seq, digest_seq) = sha256_state_sequence(input);
        let mut iteration_vec: Vec<SHA256CompressionCircuit<F>> = vec![];

        for i in 0..block_seq.len() {
            iteration_vec.push(SHA256CompressionCircuit {
                input: block_seq[i],
                current_digest: digest_to_scalars(&digest_seq[i]),
                next_digest: digest_to_scalars(&digest_seq[i + 1]),
            });
        }

        iteration_vec
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
        assert_eq!(z.len(), 2);
        let initial_curr_digest_bits = z[0]
            .to_bits_le(cs.namespace(|| "initial current digest bits"))
            .unwrap();
        let remaining_curr_digest_bits = z[1]
            .to_bits_le(cs.namespace(|| "remaining current digest bits"))
            .unwrap();

        let mut current_digest_bits = vec![];
        for i in 0..F::CAPACITY as usize {
            current_digest_bits.push(initial_curr_digest_bits[i].clone());
        }
        let num_bits_remaining = DIGEST_LENGTH_BYTES * 8 - (F::CAPACITY as usize);
        for i in 0..num_bits_remaining {
            current_digest_bits.push(remaining_curr_digest_bits[i].clone());
        }

        let mut current_state: Vec<UInt32> = vec![];
        for c in current_digest_bits.chunks(32) {
            current_state.push(UInt32::from_bits_be(c));
        }
        assert_eq!(current_state.len(), 8);

        let input_bit_values = bytes_to_bits(&self.input);
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
            .map(|u| u.into_bits_be())
            .flatten()
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

    fn output(&self, z: &[F]) -> Vec<F> {
        assert_eq!(z.len(), 2);
        assert_eq!(z[0], self.current_digest[0]);
        assert_eq!(z[1], self.current_digest[1]);

        // Compute output using non-deteriministic advice
        self.next_digest.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellperson::gadgets::test::TestConstraintSystem;
    use pasta_curves::Fp;

    #[test]
    fn test_sha256_compression_constraints() {
        let mut cs = TestConstraintSystem::<Fp>::new();
        let empty_input: Vec<u8> = vec![];
        let mut sha256_state_sequence = SHA256CompressionCircuit::new_state_sequence(empty_input);
        assert_eq!(sha256_state_sequence.len(), 1);

        let sha256_iteration = sha256_state_sequence.pop().unwrap();
        let mut z_in: Vec<AllocatedNum<Fp>> = vec![];

        for (i, s) in sha256_iteration.current_digest.iter().enumerate() {
            z_in.push(
                AllocatedNum::alloc(cs.namespace(|| format!("z_in[{i}]")), || Ok(*s)).unwrap(),
            );
        }
        let z_out = sha256_iteration.synthesize(&mut cs, &z_in).unwrap();
        assert!(cs.is_satisfied());

        assert_eq!(z_out.len(), sha256_iteration.next_digest.len());
        for (i, s) in sha256_iteration.next_digest.iter().enumerate() {
            assert_eq!(z_out[i].get_value().unwrap(), *s);
        }
        println!("Num constraints = {:?}", cs.num_constraints());
        println!("Num inputs = {:?}", cs.num_inputs());
    }
}
