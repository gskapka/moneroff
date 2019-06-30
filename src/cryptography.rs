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
    let mut array = [0; 32];
    let bytes = &decoded_hex[..array.len()];
    array.copy_from_slice(&bytes);
    Ok(array)
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

fn convert_keccak256_hash_to_scalar_mod_order(hash: Keccak256Hash) -> Result<Scalar> {
    convert_32_byte_arr_to_scalar_mod_order(hash)
}

pub fn convert_scalar_to_hex_key(scalar: Scalar) -> Result<HexKey> {
    Ok(hex::encode(scalar.to_bytes()))
}

fn keccak256_hash_bytes(bytes: &[u8]) -> Result<Keccak256Hash> {
    let mut res: Keccak256Hash = [0; 32];
    let mut keccak256 = Keccak::new_keccak256();
    keccak256.update(bytes);
    keccak256.finalize(&mut res);
    Ok(res)
}

fn keccak256_hash_hex_key(hex_key: HexKey) -> Result<Keccak256Hash> {
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

fn convert_hex_key_to_scalar(hex_key: HexKey) -> Result<Scalar> {
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

fn multiply_scalar_by_base_point(scalar: Scalar) -> Result<Scalar> {
    compress_edwards_point(scalar * ED25519_BASEPOINT_POINT)
        .and_then(|x| Ok(convert_compressed_edwards_y_to_scalar(x)?))
}

fn reduce_scalar_mod_l(scalar: Scalar) -> Result<Scalar> {
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
    }

    #[test]
    fn should_generate_random_scalar_mod_order() {
        let result = generate_random_scalar_mod_order().unwrap();
        assert!(result.is_canonical());
    }

    #[test]
    fn should_convert_32_byte_arr_to_scalar_mod_order() {
        let scalar = generate_random_scalar().unwrap();
        let result = convert_32_byte_arr_to_scalar_mod_order(scalar.to_bytes()).unwrap();
        assert!(result.to_bytes().len() == 32);
        assert!(result.is_canonical() == true);
    }

    #[test]
    fn should_convert_keccak256_hash_to_scalar_mod_order() {
        let result = generate_random_scalar()
            .and_then(hash_scalar)
            .and_then(convert_keccak256_hash_to_scalar_mod_order)
            .unwrap();
        assert!(result.to_bytes().len() == 32);
        assert!(result.is_canonical() == true)
    }

    #[test]
    fn should_convert_scalar_to_hex() {
        let result = generate_random_scalar()
            .and_then(convert_scalar_to_hex_key)
            .unwrap();
        assert!(result.chars().count() == 64);
    }

    #[test]
    fn should_hash_bytes_correctly() {
        /**
         * NOTE:
         * expected_hash = web3.utils.keccak26(web3.utils.toBN(hex_key_string))
         */
        let hex_key_string: HexKey =
            "faae50e630355f536a35f931b941e1578227e30c2cdfaa69c59c264484d40ed8".to_string();
        let expected_hash =
            "532bc0ce4f17550956943d3b883866c623be7f59cf07a0ec890ea037a10ab792".to_string();
        let hex_key_bytes = &hex::decode(hex_key_string).unwrap()[..];
        let hashed_bytes = keccak256_hash_bytes(&hex_key_bytes).unwrap();
        let result = hex::encode(hashed_bytes);
        assert!(result == expected_hash);
    }

    #[test]
    fn should_hash_a_hex_key_correctly() {
        /**
         * NOTE:
         * const str = web3.utils.toBN(hex_key_string).toString()
         * expected_hash = web3.utils.keccak26(str)
         */
        let hex_key_string: HexKey =
            "faae50e630355f536a35f931b941e1578227e30c2cdfaa69c59c264484d40ed8".to_string();
        let expected_hash =
            "532bc0ce4f17550956943d3b883866c623be7f59cf07a0ec890ea037a10ab792".to_string();
        let hashed_hex_key = keccak256_hash_hex_key(hex_key_string).unwrap();
        let result = hex::encode(hashed_hex_key);
        assert!(result == expected_hash)
    }

    #[test]
    fn should_hash_a_scalar_correctly() {
        let scalar = Scalar::one();
        /**
         * NOTE:
         * expected_hash = web3.utils.keccak256(`0x${scalar_hex}`)
         */
        let expected_hash =
            "48078cfed56339ea54962e72c37c7f588fc4f8e5bc173827ba75cb10a63a96a5".to_string();
        let hashed_scalar = hash_scalar(scalar).unwrap();
        let result = hex::encode(hashed_scalar);
        assert!(result == expected_hash)
    }

    #[test]
    fn should_convert_any_32_byte_arr_to_scalar() {
        let non_canonical_scalar = Scalar::from_bits([0xff; 32]);
        assert!(!non_canonical_scalar.is_canonical());
        let result = convert_any_32_byte_arr_to_scalar(non_canonical_scalar.to_bytes()).unwrap();
        assert!(result == non_canonical_scalar);
        let canonical_scalar = non_canonical_scalar.reduce();
        assert!(canonical_scalar.is_canonical());
        let result = convert_any_32_byte_arr_to_scalar(canonical_scalar.to_bytes()).unwrap();
        assert!(result == canonical_scalar);
    }

    #[test]
    fn should_convert_canonical_32_bytes_to_scalar() {
        let scalar = generate_random_scalar().unwrap();
        assert!(scalar.is_canonical());
        let result = convert_canonical_32_byte_arr_to_scalar(scalar.to_bytes()).unwrap();
        assert!(result == scalar);
    }

    #[test]
    fn should_fail_to_convert_non_canonical_32_bytes_to_scalar() {
        let non_canonical_scalar = Scalar::from_bits([0xff; 32]);
        assert!(!non_canonical_scalar.is_canonical());
        let _result = std::panic::catch_unwind(|| {
            convert_canonical_32_byte_arr_to_scalar(non_canonical_scalar.to_bytes()).unwrap()
        });
    }

    #[test]
    fn should_convert_hex_key_to_byte_arr() {
        let result = generate_random_scalar()
            .and_then(convert_scalar_to_hex_key)
            .and_then(convert_hex_key_to_32_byte_arr)
            .unwrap();
        assert!(result.len() == 32)
    }

    #[test]
    fn should_convert_scalar_to_hex_and_back_again() {
        let scalar = generate_random_scalar().unwrap();
        let result = convert_scalar_to_hex_key(scalar)
            .and_then(convert_hex_key_to_scalar)
            .unwrap();
        assert!(scalar == result)
    }

    #[test]
    fn should_convert_scalar_to_compressed_edwards_y() {
        let result = generate_random_scalar()
            .and_then(reduce_scalar_mod_l)
            .and_then(convert_scalar_to_compressed_edwards_y)
            .unwrap();
        assert!(result.as_bytes().len() == 32)
    }

    #[test]
    fn should_convert_compressed_edwards_y_to_scalar() {
        let scalar = generate_random_scalar().unwrap();
        let result = convert_scalar_to_compressed_edwards_y(scalar)
            .and_then(convert_compressed_edwards_y_to_scalar)
            .unwrap();
        assert!(result.as_bytes().len() == 32);
        assert!(scalar == result);
    }

    #[test]
    fn should_compress_edwards_point_correctly() {
        let result = compress_edwards_point(ED25519_BASEPOINT_POINT).unwrap();
        assert!(result.to_bytes().len() == 32);
    }

    #[test]
    fn should_reduce_scalar_mod_l() {
        let non_canonical_scalar = Scalar::from_bits([0xff; 32]);
        assert!(!non_canonical_scalar.is_canonical());
        let canonical_scalar = reduce_scalar_mod_l(non_canonical_scalar).unwrap();
        assert!(canonical_scalar.is_canonical());
    }

    #[test]
    fn should_multiply_scalar_by_base_point() {
        generate_random_scalar()
            .and_then(reduce_scalar_mod_l)
            .and_then(multiply_scalar_by_base_point)
            .unwrap();
    }
}
