use bellperson::gadgets::multipack::{bytes_to_bits, compute_multipacking};
use ff::{PrimeField, PrimeFieldBits};
use generic_array::{typenum::U64, GenericArray};
use sha2::compress256;

pub const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
pub const BLOCK_LENGTH_BYTES: usize = 64;
pub const DIGEST_LENGTH_BYTES: usize = 32;

pub fn sha256_state_to_bytes(state: [u32; 8]) -> Vec<u8> {
    state
        .into_iter()
        .map(|x| x.to_be_bytes())
        .flatten()
        .collect()
}

fn padded_input_to_blocks(input: Vec<u8>) -> Vec<GenericArray<u8, U64>> {
    assert!(input.len() % BLOCK_LENGTH_BYTES == 0);

    let (blocks, remainder) = input.as_chunks::<BLOCK_LENGTH_BYTES>();
    assert_eq!(remainder, []);

    let blocks_vec: Vec<GenericArray<u8, U64>> = blocks
        .iter()
        .map(|a| GenericArray::<u8, U64>::clone_from_slice(a))
        .collect();
    blocks_vec
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

pub fn sha256_state_sequence(
    input: Vec<u8>,
) -> (
    Vec<[u8; BLOCK_LENGTH_BYTES]>,
    Vec<[u8; DIGEST_LENGTH_BYTES]>,
) {
    let padded_input = add_sha256_padding(input);

    let mut state = IV;
    let mut digest_sequence: Vec<[u8; DIGEST_LENGTH_BYTES]> = vec![];
    let mut block_sequence: Vec<[u8; BLOCK_LENGTH_BYTES]> = vec![];
    let state_bytes = sha256_state_to_bytes(state);
    assert_eq!(state_bytes.len(), DIGEST_LENGTH_BYTES);
    digest_sequence.push(state_bytes.as_slice().try_into().unwrap());

    let blocks_vec: Vec<GenericArray<u8, U64>> = padded_input_to_blocks(padded_input);
    for block in blocks_vec {
        compress256(&mut state, &[block]);
        let state_bytes = sha256_state_to_bytes(state);
        assert_eq!(state_bytes.len(), DIGEST_LENGTH_BYTES);
        digest_sequence.push(state_bytes.as_slice().try_into().unwrap());
        block_sequence.push(block.try_into().unwrap());
    }
    (block_sequence, digest_sequence)
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
    let num_bits_remaining = DIGEST_LENGTH_BYTES * 8 - (F::CAPACITY as usize);
    digest_bits.append(
        &mut remaining_bits
            .into_iter()
            .take(num_bits_remaining)
            .collect(),
    );

    assert_eq!(digest_bits.len() % 8, 0);
    assert_eq!(digest_bits.len() / 8, DIGEST_LENGTH_BYTES);

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
    fn test_digest_sequence_generation() {
        let input: Vec<u8> = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(); // 56 bytes
        let (_, digest_sequence) = sha256_state_sequence(input);
        assert_eq!(digest_sequence.len(), 3usize);

        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
        let expected_digest_sequence = [
            "6a09e667bb67ae853c6ef372a54ff53a510e527f9b05688c1f83d9ab5be0cd19",
            "85e655d6417a17953363376a624cde5c76e09589cac5f811cc4b32c1f20e533a",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ];

        for (i, hash_bytes) in digest_sequence.into_iter().enumerate() {
            assert_eq!(expected_digest_sequence[i], hex::encode(hash_bytes));
        }
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
