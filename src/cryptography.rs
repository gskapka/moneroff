use crate::error::AppError;
use crate::types::{HexKey, Keccak256Hash};

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use hex;
use rand::thread_rng;
use std::result;
use tiny_keccak::Keccak;

type Result<T> = result::Result<T, AppError>;

fn convert_hex_key_to_32_byte_arr(hex_key: HexKey) -> Result<[u8; 32]> {
    let decoded_hex = hex::decode(hex_key)?;
    match decoded_hex.len() {
        32 => {
            let mut array = [0; 32];
            let bytes = &decoded_hex[..array.len()];
            array.copy_from_slice(&bytes);
            Ok(array)
        }
        _ => Err(AppError::Custom("✘ Key length invalid!".to_string()))
    }
}

fn convert_32_byte_arr_to_scalar_mod_order(bytes: [u8; 32]) -> Result<Scalar> {
    Ok(Scalar::from_bytes_mod_order(bytes))
}

pub fn generate_random_scalar() -> Result<Scalar> {
    Ok(Scalar::random(&mut thread_rng()))
}

pub fn generate_random_scalar_mod_order() -> Result<Scalar> {
    generate_random_scalar().and_then(reduce_scalar_mod_l)
}

pub fn convert_keccak256_hash_to_scalar_mod_order(hash: Keccak256Hash) -> Result<Scalar> {
    convert_32_byte_arr_to_scalar_mod_order(hash)
}

pub fn convert_scalar_to_hex_key(scalar: Scalar) -> Result<HexKey> {
    Ok(hex::encode(scalar.to_bytes()))
}

pub fn keccak256_hash_bytes(bytes: &[u8]) -> Result<Keccak256Hash> {
    let mut res: Keccak256Hash = [0; 32];
    let mut keccak256 = Keccak::new_keccak256();
    keccak256.update(bytes);
    keccak256.finalize(&mut res);
    Ok(res)
}

pub fn keccak256_hash_hex_key(hex_key: HexKey) -> Result<Keccak256Hash> {
    keccak256_hash_bytes(&hex::decode(hex_key)?[..])
}

fn hash_scalar(scalar: Scalar) -> Result<Keccak256Hash> {
    keccak256_hash_bytes(&scalar.to_bytes())
}

fn convert_canonical_32_byte_arr_to_scalar(byte_arr: [u8; 32]) -> Result<Scalar> {
    Ok(Scalar::from_canonical_bytes(byte_arr)?)
}

fn convert_any_32_byte_arr_to_scalar(byte_arr: [u8; 32]) -> Result<Scalar> {
    Ok(Scalar::from_bits(byte_arr))
}

pub fn convert_hex_key_to_scalar(hex_key: HexKey) -> Result<Scalar> {
    convert_hex_key_to_32_byte_arr(hex_key).and_then(convert_canonical_32_byte_arr_to_scalar)
}

fn convert_scalar_to_compressed_edwards_y(scalar: Scalar) -> Result<CompressedEdwardsY> {
    Ok(CompressedEdwardsY::from_slice(scalar.as_bytes()))
}

fn convert_compressed_edwards_y_to_scalar(cey: CompressedEdwardsY) -> Result<Scalar> {
    convert_any_32_byte_arr_to_scalar(cey.to_bytes())
}

fn compress_edwards_point(e_point: EdwardsPoint) -> Result<CompressedEdwardsY> {
    Ok(e_point.compress())
}

pub fn multiply_scalar_by_basepoint(scalar: Scalar) -> Result<Scalar> {
    compress_edwards_point(scalar * ED25519_BASEPOINT_POINT)
        .and_then(|x| Ok(convert_compressed_edwards_y_to_scalar(x)?))
}

pub fn reduce_scalar_mod_l(scalar: Scalar) -> Result<Scalar> {
    Ok(scalar.reduce())
}

#[cfg(test)]
#[allow(unused_doc_comments)]
mod tests {
    use super::*;

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
    fn should_generate_random_scalar_mod_order() {
        let result = generate_random_scalar_mod_order().unwrap();
        assert!(result.is_canonical());
    }

    #[test]
    fn should_keccak256_hash_bytes() {
        let bytes = [0x01, 0x02];
        let result = keccak256_hash_bytes(&bytes)
            .unwrap();
        assert!(result.len() == 32);
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
    fn should_compress_edwards_point_correctly() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        let result = compress_edwards_point(ED25519_BASEPOINT_POINT).unwrap();
        assert!(result.to_bytes().len() == 32);
    }

    #[test]
    fn should_multiply_scalar_by_basepoint() {
        generate_random_scalar()
            .and_then(reduce_scalar_mod_l)
            .and_then(multiply_scalar_by_basepoint)
            .unwrap();
    }

    #[test]
    fn should_reduce_scalar_mod_l() {
        let non_canonical_scalar = Scalar::from_bits([0xff; 32]);
        assert!(!non_canonical_scalar.is_canonical());
        let canonical_scalar = reduce_scalar_mod_l(non_canonical_scalar)
            .unwrap();
        assert!(canonical_scalar.is_canonical());
    }

}
