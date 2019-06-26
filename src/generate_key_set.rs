use crate::constants::{MONERO_L, MONERO_L_HEX};
use crate::error::AppError;
use crate::types::HexKey;
use num_bigint::{BigUint, RandBigInt, ToBigUint};
use std::result;
use std::str::FromStr;

type Result<T> = result::Result<T, AppError>;

struct Keys {
    pub_vk: Option<HexKey>,
    pub_sk: Option<HexKey>,
    priv_vk: Option<HexKey>,
    priv_sk: Option<HexKey>,
}

impl Keys {
    pub fn init_with_priv_sk(mut self, _priv_sk: HexKey) -> Self {
        self.priv_sk = Some(_priv_sk);
        self
    }

    pub fn add_priv_vk(mut self, _prive_vk: HexKey) -> Self {
        self.priv_vk = Some(_prive_vk);
        self
    }

    pub fn add_pub_sk(mut self, _pub_sk: HexKey) -> Self {
        self.pub_sk = Some(_pub_sk);
        self
    }

    pub fn add_pub_vk(mut self, _pub_vk: HexKey) -> Self {
        self.pub_vk = Some(_pub_vk);
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

fn convert_l_to_big_uint() -> Result<BigUint> {
    Ok(BigUint::from_str(MONERO_L)?)
}

fn generate_256_bit_random_number() -> Result<BigUint> {
    Ok(rand::thread_rng().gen_biguint(256))
}

fn take_modulus_l(_int: BigUint) -> Result<BigUint> {
    convert_l_to_big_uint().and_then(|_l| Ok(_int % _l))
}

fn convert_big_uint_to_hex_string(_int: BigUint) -> Result<HexKey> {
    Ok(_int.to_str_radix(16))
}

pub fn convert_hex_string_to_big_uint(_hex_str: String) -> Result<BigUint> {
    Ok(BigUint::parse_bytes(_hex_str.as_bytes(), 16)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converting_l_to_big_uint() {
        let x: BigUint = convert_l_to_big_uint().unwrap();
        assert!(x > ToBigUint::to_biguint(&0).unwrap());
    }

    #[test]
    fn generating_256_bit_random_number() {
        let x: BigUint = generate_256_bit_random_number().unwrap();
        assert!(x > ToBigUint::to_biguint(&0).unwrap());
    }

    #[test]
    fn taking_modulus_l() {
        let x: BigUint = generate_256_bit_random_number()
            .and_then(take_modulus_l)
            .unwrap();
        assert!(x > ToBigUint::to_biguint(&0).unwrap());
        assert!(x <= BigUint::from_str(MONERO_L).unwrap());
    }

    #[test]
    fn converting_hex_string_to_big_uint() {
        let expected_big_uint = ToBigUint::to_biguint(&12648430).unwrap();
        let hex_string = "c0ffee".to_string();
        let big_uint = convert_hex_string_to_big_uint(hex_string).unwrap();
        assert!(expected_big_uint == big_uint);
    }

    #[test]
    fn converting_big_uint_to_hex_string() {
        let int = 12648430;
        let expected_hex_string = "c0ffee".to_string();
        let big_uint = ToBigUint::to_biguint(&int).unwrap();
        let hex_string = convert_big_uint_to_hex_string(big_uint).unwrap();
        assert!(expected_hex_string == hex_string);
    }

    #[test]
    fn generate_key_convert_to_hex_and_back_again() {
        let key_big_uint = generate_256_bit_random_number()
            .and_then(take_modulus_l)
            .unwrap();
        let expected_key_big_uint = key_big_uint.clone();
        let key_hex_string = convert_big_uint_to_hex_string(key_big_uint).unwrap();
        let key_converted_back = convert_hex_string_to_big_uint(key_hex_string).unwrap();
        assert!(expected_key_big_uint == key_converted_back);
    }

    #[test]
    fn compare_string_l_to_hex_l() {
        let l_converted_to_hex = convert_l_to_big_uint()
            .and_then(convert_big_uint_to_hex_string)
            .unwrap();
        assert!(l_converted_to_hex == MONERO_L_HEX);
    }
}
