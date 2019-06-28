use crate::error::AppError;
use crate::types::{HexKey, Keccak256Hash};

use curve25519_dalek::scalar::Scalar;
use hex;
use num_bigint::{BigUint, RandBigInt, ToBigUint};
use std::result;
use std::str::FromStr;
use tiny_keccak::Keccak;

type Result<T> = result::Result<T, AppError>;

struct KeyStruct {
    pub_vk: Option<HexKey>,
    pub_sk: Option<HexKey>,
    priv_vk: Option<HexKey>,
    priv_sk: Option<HexKey>,
}

impl KeyStruct {
    pub fn init_with_priv_sk(mut self, priv_sk: HexKey) -> Self {
        self.priv_sk = Some(priv_sk);
        self
    }

    pub fn add_priv_vk(mut self, priv_vk: HexKey) -> Self {
        self.priv_vk = Some(priv_vk);
        self
    }

    pub fn add_pub_sk(mut self, pub_sk: HexKey) -> Self {
        self.pub_sk = Some(pub_sk);
        self
    }

    pub fn add_pub_vk(mut self, pub_vk: HexKey) -> Self {
        self.pub_vk = Some(pub_vk);
        self
    }

    pub fn get_priv_sk(self) -> HexKey {
        self.priv_sk.expect("No private spend key set in struct!")
    }

    pub fn get_priv_vk(self) -> HexKey {
        self.priv_vk.expect("No private view key set in struct!")
    }

    pub fn get_pub_sk(self) -> HexKey {
        self.pub_sk.expect("No public spend key set in struct!")
    }

    pub fn get_pub_vk(self) -> HexKey {
        self.pub_vk.expect("No public view key set in struct!")
    }
}

fn generate_256_bit_random_number() -> Result<BigUint> {
    Ok(rand::thread_rng().gen_biguint(256))
}

fn convert_256_bit_big_uint_to_byte_arr(big_uint: BigUint) -> Result<[u8; 32]> {
    let mut array = [0; 32];
    let bytes = &big_uint.to_bytes_le()[..array.len()];
    array.copy_from_slice(&bytes);
    Ok(array)
}

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

fn convert_keccak256_hash_to_scalar_mod_order(hash: Keccak256Hash) -> Result<Scalar> {
    convert_32_byte_arr_to_scalar_mod_order(hash)
}

// FIXME: Must we use this as opposed to Scalar::random?
fn generate_random_scalar() -> Result<Scalar> {
    generate_256_bit_random_number()
        .and_then(convert_256_bit_big_uint_to_byte_arr)
        .and_then(convert_32_byte_arr_to_scalar_mod_order)
}

fn convert_scalar_to_hex_key(scalar: Scalar) -> Result<HexKey> {
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

fn convert_hex_key_to_scalar(hex_key: HexKey) -> Result<Scalar> {
    convert_hex_key_to_32_byte_arr(hex_key).and_then(convert_canonical_32_byte_arr_to_scalar)
}

#[cfg(test)]
#[allow(unused_doc_comments)]
mod tests {
    use super::*;

    #[test]
    fn should_generate_256_bit_random_number() {
        let x: BigUint = generate_256_bit_random_number().unwrap();
        assert!(x > ToBigUint::to_biguint(&0).unwrap());
    }

    #[test]
    fn should_generate_random_32_byte_arr() {
        let result = generate_256_bit_random_number()
            .and_then(convert_256_bit_big_uint_to_byte_arr)
            .unwrap();
        assert!(result.len() == 32);
    }

    #[test]
    fn should_convert_32_byte_arr_to_scalar_mod_order() {
        let result = generate_256_bit_random_number()
            .and_then(convert_256_bit_big_uint_to_byte_arr)
            .and_then(convert_32_byte_arr_to_scalar_mod_order)
            .unwrap();
        assert!(result.to_bytes().len() == 32);
        assert!(result.is_canonical() == true)
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
    fn should_generate_random_scalar() {
        let result = generate_random_scalar().unwrap();
        assert!(result.to_bytes().len() == 32);
    }

    #[test]
    fn should_convert_scalar_to_hex() {
        let result = generate_random_scalar()
            .and_then(convert_scalar_to_hex_key)
            .unwrap();
        assert!(result.chars().count() == 64);
    }

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
        let scalar_hex = convert_scalar_to_hex_key(scalar).unwrap();
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
    fn should_convert_canonical_bytes_to_scalar() {
        let scalar = generate_random_scalar().unwrap();
        let scalar_clone = scalar.clone();
        let scalar_as_hex = convert_scalar_to_hex_key(scalar_clone).unwrap();
        let result = convert_canonical_32_byte_arr_to_scalar(scalar.to_bytes()).unwrap();
        let result_as_hex = convert_scalar_to_hex_key(result).unwrap();
        assert!(result_as_hex == scalar_as_hex);
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
        let scalar_clone = scalar.clone();
        let result = convert_scalar_to_hex_key(scalar)
            .and_then(convert_hex_key_to_scalar)
            .unwrap();
        assert!(scalar == result)
    }
}
