use ff::{PrimeField, PrimeFieldBits};
use generic_array::{typenum::U64, GenericArray};

pub const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
pub const BLOCK_LENGTH_BYTES: usize = 64;
pub const BLOCK_LENGTH: usize = 512;
pub const DIGEST_LENGTH_BYTES: usize = 32;
pub const DIGEST_LENGTH: usize = 256;

// From bellpepper/src/gadgets/multipack.rs
fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|&v| (0..8).rev().map(move |i| (v >> i) & 1 == 1))
        .collect()
}

// From bellpepper/src/gadgets/multipack.rs
fn compute_multipacking<Scalar: PrimeField>(bits: &[bool]) -> Vec<Scalar> {
    let mut result = vec![];

    for bits in bits.chunks(Scalar::CAPACITY as usize) {
        let mut cur = Scalar::ZERO;
        let mut coeff = Scalar::ONE;

        for bit in bits {
            if *bit {
                cur.add_assign(&coeff);
            }

            coeff = coeff.double();
        }

        result.push(cur);
    }

    result
}

pub fn sha256_state_to_bytes(state: [u32; 8]) -> Vec<u8> {
    state.into_iter().flat_map(|x| x.to_be_bytes()).collect()
}

fn padded_input_to_blocks(input: Vec<u8>) -> Vec<GenericArray<u8, U64>> {
    assert!(input.len() % BLOCK_LENGTH_BYTES == 0);
    let mut input_clone = input.clone();
    let mut blocks: Vec<Vec<u8>> = vec![];

    let num_blocks = input.len() / BLOCK_LENGTH_BYTES;

    for i in (0..num_blocks).rev() {
        let block: Vec<u8> = input_clone.drain(i * BLOCK_LENGTH_BYTES..).collect();
        blocks.push(block);
    }

    // Reverse the order of the blocks as they were pushed in reverse order
    blocks.reverse();

    let blocks_ga_vec: Vec<GenericArray<u8, U64>> = blocks
        .iter()
        .map(|a| GenericArray::<u8, U64>::clone_from_slice(a))
        .collect();
    blocks_ga_vec
}

fn add_sha256_padding(input: Vec<u8>) -> Vec<u8> {
    let length_in_bits = (input.len() * 8) as u64;
    let mut padded_input = input;

    // appending a single '1' bit followed by 7 '0' bits
    // This is because the input is a byte vector
    padded_input.push(128u8);

    // Append zeros until the padded input (including 64-byte length)
    // is a multiple of 64 bytes. Note that input is always a byte vector.
    while (padded_input.len() + 8) % BLOCK_LENGTH_BYTES != 0 {
        padded_input.push(0u8);
    }
    padded_input.append(&mut length_in_bits.to_be_bytes().to_vec());
    padded_input
}

pub fn sha256_msg_block_sequence(input: Vec<u8>) -> Vec<[bool; BLOCK_LENGTH]> {
    let padded_input = add_sha256_padding(input);
    let blocks_vec: Vec<GenericArray<u8, U64>> = padded_input_to_blocks(padded_input);
    let blocks_vec_bytes: Vec<[u8; BLOCK_LENGTH_BYTES]> = blocks_vec
        .into_iter()
        .map(|b| b.try_into().unwrap())
        .collect();
    blocks_vec_bytes
        .iter()
        .map(|b| bytes_to_bits(b).try_into().unwrap())
        .collect()
}

pub fn digest_to_scalars<F>(digest: &[u8; DIGEST_LENGTH_BYTES]) -> [F; 2]
where
    F: PrimeField + PrimeFieldBits,
{
    compute_multipacking(&bytes_to_bits(digest))
        .try_into()
        .unwrap()
}

pub fn sha256_initial_digest_scalars<F>() -> Vec<F>
where
    F: PrimeField + PrimeFieldBits,
{
    let initial_vector: [u8; DIGEST_LENGTH_BYTES] =
        sha256_state_to_bytes(IV).as_slice().try_into().unwrap();
    digest_to_scalars(&initial_vector).to_vec()
}

pub fn scalars_to_digest<F>(scalars: [F; 2]) -> [u8; DIGEST_LENGTH_BYTES]
where
    F: PrimeField + PrimeFieldBits,
{
    let mut digest_bits: Vec<bool> = vec![];
    let initial_bits = scalars[0].to_le_bits();
    digest_bits.append(
        &mut initial_bits
            .into_iter()
            .take(F::CAPACITY as usize)
            .collect(),
    );

    let remaining_bits = scalars[1].to_le_bits();
    let num_bits_remaining = DIGEST_LENGTH - (F::CAPACITY as usize);
    digest_bits.append(
        &mut remaining_bits
            .into_iter()
            .take(num_bits_remaining)
            .collect(),
    );

    assert_eq!(digest_bits.len() % 8, 0);
    assert_eq!(digest_bits.len(), DIGEST_LENGTH);

    let mut digest: Vec<u8> = vec![];
    for i in 0..DIGEST_LENGTH_BYTES {
        let mut byte_val = 0u8;
        let mut coeff = 1u8;
        for j in 0..8usize {
            // The digest bits are interpreted as big-endian bytes
            if digest_bits[8 * i + 7 - j] {
                byte_val += coeff
            }
            coeff <<= 1;
        }
        digest.push(byte_val);
    }
    digest.as_slice().try_into().unwrap()
}

#[cfg(test)]
mod test {
    use super::*;
    use pasta_curves::Fp;
    use sha2::compress256;

    #[test]
    fn test_one_compression_iteration() {
        let mut state = IV;
        let input: Vec<u8> = vec![];
        let padded_input = add_sha256_padding(input);
        let blocks_vec = padded_input_to_blocks(padded_input);

        compress256(&mut state, blocks_vec.as_slice());

        let hash_bytes: Vec<u8> = sha256_state_to_bytes(state);
        let empty_bytes_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(empty_bytes_hash, hex::encode(hash_bytes));
    }

    #[test]
    fn test_two_compression_iterations() {
        let mut state = IV;
        let input: Vec<u8> = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(); // 56 bytes
        let padded_input = add_sha256_padding(input);
        let blocks_vec = padded_input_to_blocks(padded_input);
        assert_eq!(blocks_vec.len(), 2usize);

        compress256(&mut state, &[blocks_vec[0]]);
        compress256(&mut state, &[blocks_vec[1]]);

        let hash_bytes: Vec<u8> = sha256_state_to_bytes(state);
        let expected_hash = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
        assert_eq!(expected_hash, hex::encode(hash_bytes));
    }

    #[test]
    fn test_scalar_digest_roundtrip() {
        let initial_scalars: Vec<Fp> = sha256_initial_digest_scalars();
        let computed_bytes = scalars_to_digest(initial_scalars.clone().try_into().unwrap());
        let expected_bytes = sha256_state_to_bytes(IV);
        assert_eq!(expected_bytes.len(), computed_bytes.len());
        for i in 0..computed_bytes.len() {
            assert_eq!(expected_bytes[i], computed_bytes[i]);
        }
    }
}
