use crate::types::{
    Key,
    Keccak256Hash,
};

use std::result;
use rand::thread_rng;
use crate::error::AppError;
use curve25519_dalek::scalar::Scalar;
use crate::keccak::keccak256_hash_bytes;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use crate::key_cryptography::convert_hex_string_to_32_byte_array;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};

type Result<T> = result::Result<T, AppError>;

pub fn multiply_scalar_by_basepoint(scalar: Scalar) -> Result<CompressedEdwardsY> {
    Ok(compress_edwards_point(&scalar * &ED25519_BASEPOINT_TABLE)?)
}

pub fn convert_compressed_edwards_y_to_bytes(x: CompressedEdwardsY) -> Result<Key> {
    Ok(x.to_bytes())
}

fn generate_random_scalar() -> Result<Scalar> {
    Ok(Scalar::random(&mut thread_rng()))
}

fn convert_key_to_scalar_mod_order(key: Key) -> Result<Scalar> {
    Ok(Scalar::from_bytes_mod_order(key))
}

fn compress_edwards_point(e_point: EdwardsPoint) -> Result<CompressedEdwardsY> {
    Ok(e_point.compress())
}

pub fn generate_random_scalar_mod_order() -> Result<Scalar> {
    generate_random_scalar()
        .and_then(reduce_scalar_mod_l)
}

pub fn convert_keccak256_hash_to_scalar_mod_order(hash: Keccak256Hash) -> Result<Scalar> {
    convert_key_to_scalar_mod_order(hash)
}

pub fn convert_scalar_to_bytes(x: Scalar) -> Result<Key> {
    Ok(x.to_bytes())
}

pub fn reduce_scalar_mod_l(scalar: Scalar) -> Result<Scalar> {
    Ok(scalar.reduce())
}

pub fn convert_32_byte_array_to_scalar(byte_arr: Key) -> Result<Scalar> {
    match Scalar::from_canonical_bytes(byte_arr) {
        Some(canonical_scalar) => Ok(canonical_scalar),
        None => Err(
            AppError::Custom("✘ Not a point on the edwards curve!".to_string())
        )
    }
}

pub fn convert_hex_string_to_scalar(priv_sk: String) -> Result<Scalar> {
    convert_hex_string_to_32_byte_array(priv_sk)
        .and_then(convert_32_byte_array_to_scalar)
}

#[cfg(test)]
#[allow(unused_doc_comments)]
mod tests {
    use super::*;

    #[test]
    fn should_multiply_scalar_by_basepoint() {
        generate_random_scalar()
            .and_then(reduce_scalar_mod_l)
            .and_then(multiply_scalar_by_basepoint)
            .unwrap();
    }

    #[test]
    fn should_convert_edwards_point_to_bytes() {
        let scalar = generate_random_scalar_mod_order()
            .unwrap();
        let expected_bytes = convert_scalar_to_bytes(scalar.clone())
            .unwrap();
        let compressed_point = CompressedEdwardsY::from_slice(&expected_bytes);
        let result = convert_compressed_edwards_y_to_bytes(compressed_point)
            .unwrap();
        assert!(result == expected_bytes);
    }

    #[test]
    fn should_generate_random_scalar() {
        let result = generate_random_scalar().unwrap();
        assert!(result.to_bytes().len() == 32);
        assert!(result.is_canonical());
    }

    #[test]
    fn should_convert_32_byte_arr_to_scalar_mod_order() {
        let scalar = generate_random_scalar().unwrap();
        let result = convert_key_to_scalar_mod_order(scalar.to_bytes()).unwrap();
        assert!(result.to_bytes().len() == 32);
        assert!(result.is_canonical() == true);
    }

    #[test]
    fn should_compress_edwards_point_correctly() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        let result = compress_edwards_point(ED25519_BASEPOINT_POINT).unwrap();
        assert!(result.to_bytes().len() == 32);
    }

    #[test]
    fn should_generate_random_scalar_mod_order() {
        let result = generate_random_scalar_mod_order().unwrap();
        assert!(result.is_canonical());
    }

    #[test]
    fn should_convert_keccak256_hash_to_scalar_mod_order() {
        let bytes = [0x01, 0x02];
        let result = keccak256_hash_bytes(&bytes)
            .and_then(convert_keccak256_hash_to_scalar_mod_order)
            .unwrap();
        assert!(result.to_bytes().len() == 32);
        assert!(result.is_canonical() == true)
    }

    #[test]
    fn should_convert_scalar_to_bytes() {
        let scalar = generate_random_scalar_mod_order()
            .unwrap();
        let bytes = convert_scalar_to_bytes(scalar)
            .unwrap();
        let scalar_from_bytes = Scalar::from_canonical_bytes(bytes)
            .unwrap();
        assert!(scalar == scalar_from_bytes);
        assert!(scalar.is_canonical());
    }

    #[test]
    fn should_reduce_scalar_mod_l() {
        let non_canonical_scalar = Scalar::from_bits([0xff; 32]);
        assert!(!non_canonical_scalar.is_canonical());
        let canonical_scalar = reduce_scalar_mod_l(non_canonical_scalar)
            .unwrap();
        assert!(canonical_scalar.is_canonical());
    }

    #[test]
    fn should_convert_32_byte_array_to_scalar() {
        let scalar = generate_random_scalar()
            .unwrap();
        let bytes = convert_scalar_to_bytes(scalar)
            .unwrap();
        assert!(bytes.len() == 32);
        let scalar_from_bytes = convert_32_byte_array_to_scalar(bytes)
            .unwrap();
        assert!(scalar_from_bytes == scalar);
    }
}
