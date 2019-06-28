use crate::error::AppError;
use crate::types::{Hash, HexKey};

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

fn convert_32_byte_arr_to_scalar_mod_order(bytes: [u8; 32]) -> Result<Scalar> {
    Ok(Scalar::from_bytes_mod_order(bytes))
}

fn generate_random_scalar() -> Result<Scalar> {
    generate_256_bit_random_number()
        .and_then(convert_256_bit_big_uint_to_byte_arr)
        .and_then(convert_32_byte_arr_to_scalar_mod_order)
}

fn convert_scalar_to_hex(scalar: Scalar) -> Result<HexKey> {
    Ok(hex::encode(scalar.to_bytes()))
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
    fn should_convert_32_byte_arr_to_scalar() {
        let result = generate_256_bit_random_number()
            .and_then(convert_256_bit_big_uint_to_byte_arr)
            .and_then(convert_32_byte_arr_to_scalar_mod_order)
            .unwrap();
        assert!(result.to_bytes().len() == 32);
    }

    #[test]
    fn should_generate_random_scalar() {
        let result = generate_random_scalar().unwrap();
        assert!(result.to_bytes().len() == 32);
    }

    #[test]
    fn should_convert_scalar_to_hex() {
        let result = generate_random_scalar()
            .and_then(convert_scalar_to_hex)
            .unwrap();
        assert!(result.chars().count() == 64);
    }
}
