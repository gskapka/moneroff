use crate::types::{
    Key,
    Address,
    Keccak256Hash,
};

use hex;
use std::result;
use rand::thread_rng;
use tiny_keccak::Keccak;
use crate::error::AppError;
use crate::monero_keys::MoneroKeys;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};

type Result<T> = result::Result<T, AppError>;

pub fn generate_random_scalar() -> Result<Scalar> {
    Ok(Scalar::random(&mut thread_rng()))
}

fn convert_key_to_scalar_mod_order(key: Key) -> Result<Scalar> {
    Ok(Scalar::from_bytes_mod_order(key))
}

pub fn generate_random_scalar_mod_order() -> Result<Scalar> {
    generate_random_scalar().and_then(reduce_scalar_mod_l)
}

pub fn convert_keccak256_hash_to_scalar_mod_order(hash: Keccak256Hash) -> Result<Scalar> {
    convert_key_to_scalar_mod_order(hash)
}

pub fn keccak256_hash_bytes(bytes: &[u8]) -> Result<Keccak256Hash> {
    let mut res: Keccak256Hash = [0; 32];
    let mut keccak256 = Keccak::new_keccak256();
    keccak256.update(bytes);
    keccak256.finalize(&mut res);
    Ok(res)
}

pub fn convert_edwards_point_to_bytes(x: CompressedEdwardsY) -> Result<Key> {
    Ok(x.to_bytes())
}

pub fn convert_scalar_to_bytes(x: Scalar) -> Result<Key> {
    Ok(x.to_bytes())
}

fn compress_edwards_point(e_point: EdwardsPoint) -> Result<CompressedEdwardsY> {
    Ok(e_point.compress())
}

pub fn multiply_scalar_by_basepoint(scalar: Scalar) -> Result<CompressedEdwardsY> {
    Ok(compress_edwards_point(&scalar * &ED25519_BASEPOINT_TABLE)?)
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

pub fn generate_priv_vk_from_priv_sk(priv_sk: Scalar) -> Result<Scalar> {
    keccak256_hash_bytes(&priv_sk.to_bytes())
        .and_then(convert_keccak256_hash_to_scalar_mod_order)
}

pub fn concatenate_address(
    keys: MoneroKeys,
    prefix_byte: [u8; 1],
    suffix_bytes: [u8; 4]
) -> Result<Address> {
    let pub_sk: Key = keys.get_pub_sk()?;
    let pub_vk: Key = keys.get_pub_vk()?;
    let mut address_bytes = [0; 69];
    address_bytes[..1].copy_from_slice(&prefix_byte);
    address_bytes[1..33].copy_from_slice(&pub_sk);
    address_bytes[33..65].copy_from_slice(&pub_vk);
    address_bytes[65..69].copy_from_slice(&suffix_bytes[..4]);
    Ok(address_bytes)
}

pub fn hash_pub_keys_with_prefix(
    keys: MoneroKeys,
    prefix: [u8; 1]
) -> Result<Keccak256Hash> {
    let pub_sk: Key = keys.get_pub_sk()?;
    let pub_vk: Key = keys.get_pub_vk()?;
    let mut bytes_to_hash = vec![0; 65];
    bytes_to_hash[..1].copy_from_slice(&prefix);
    bytes_to_hash[1..33].copy_from_slice(&pub_sk);
    bytes_to_hash[33..65].copy_from_slice(&pub_vk);
    keccak256_hash_bytes(&bytes_to_hash)
}

pub fn get_address_suffix_from_hash(hash: Keccak256Hash) -> Result<[u8; 4]> {
    let mut x = [0; 4];
    x.copy_from_slice(&hash[..4]);
    Ok(x)
}

pub fn convert_hex_string_to_32_byte_array(hex: String) -> Result<Key> {
    let decoded_hex = hex::decode(hex)?;
    match decoded_hex.len() {
        32 => {
            let mut array = [0; 32];
            array[..].copy_from_slice(&decoded_hex[..]);
            Ok(array)
        }
        _ => Err(AppError::Custom("✘ Key length invalid!".to_string()))
    }
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
