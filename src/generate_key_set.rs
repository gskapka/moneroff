use crate::constants::{MONERO_G, MONERO_L, MONERO_L_HEX};
use crate::error::AppError;
use crate::types::{Hash, HexKey};

use hex;
use num_bigint::{BigUint, RandBigInt, ToBigUint};
use std::result;
use std::str::FromStr;
use tiny_keccak::Keccak;

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

fn convert_big_uint_to_hex_string(_big_uint: BigUint) -> Result<HexKey> {
    Ok(hex::encode(_big_uint.to_bytes_be()))
}

pub fn convert_hex_string_to_big_uint(_hex_str: String) -> Result<BigUint> {
    Ok(BigUint::parse_bytes(_hex_str.as_bytes(), 16)?)
}

fn multiply_by_g(_x: BigUint) -> Result<BigUint> {
    Ok(_x * convert_hex_string_to_big_uint(MONERO_G.to_string())?)
}

fn keccak256_hash_bytes(_bytes: &[u8]) -> Result<Hash> {
    let mut res: Hash = [0; 32];
    let mut keccak256 = Keccak::new_keccak256();
    keccak256.update(_bytes);
    keccak256.finalize(&mut res);
    Ok(res)
}

fn cast_hash_to_big_uint(_hash: Hash) -> Result<BigUint> {
    Ok(BigUint::from_bytes_be(&_hash))
}

fn generate_priv_sk() -> Result<HexKey> {
    generate_256_bit_random_number()
        .and_then(take_modulus_l)
        .and_then(convert_big_uint_to_hex_string)
}
#[cfg(test)]
#[allow(unused_doc_comments)]
mod tests {
    use super::*;

    #[test]
    fn should_convert_l_to_big_uint() {
        let x: BigUint = convert_l_to_big_uint().unwrap();
        assert!(x > ToBigUint::to_biguint(&0).unwrap());
    }

    #[test]
    fn should_generate_256_bit_random_number() {
        let x: BigUint = generate_256_bit_random_number().unwrap();
        assert!(x > ToBigUint::to_biguint(&0).unwrap());
    }

    #[test]
    fn should_take_modulus_l() {
        let x: BigUint = generate_256_bit_random_number()
            .and_then(take_modulus_l)
            .unwrap();
        assert!(x > ToBigUint::to_biguint(&0).unwrap());
        assert!(x <= BigUint::from_str(MONERO_L).unwrap());
    }

    #[test]
    fn should_convert_hex_string_to_big_uint() {
        let expected_big_uint = ToBigUint::to_biguint(&12648430).unwrap();
        let hex_string = "c0ffee".to_string();
        let big_uint = convert_hex_string_to_big_uint(hex_string).unwrap();
        assert!(expected_big_uint == big_uint);
    }

    #[test]
    fn should_convert_big_uint_to_hex_string() {
        let int = 12648430;
        let expected_hex_string = "c0ffee".to_string();
        let big_uint = ToBigUint::to_biguint(&int).unwrap();
        let hex_string = convert_big_uint_to_hex_string(big_uint).unwrap();
        assert!(expected_hex_string == hex_string);
    }

    #[test]
    fn should_generate_key_convert_to_hex_and_back_again() {
        let key_big_uint = generate_256_bit_random_number()
            .and_then(take_modulus_l)
            .unwrap();
        let expected_key_big_uint = key_big_uint.clone();
        let key_hex_string = convert_big_uint_to_hex_string(key_big_uint).unwrap();
        let key_converted_back = convert_hex_string_to_big_uint(key_hex_string).unwrap();
        assert!(expected_key_big_uint == key_converted_back);
    }

    #[test]
    fn string_l_should_match_hex_l() {
        let l_converted_to_hex = convert_l_to_big_uint()
            .and_then(convert_big_uint_to_hex_string)
            .unwrap();
        assert!(l_converted_to_hex == MONERO_L_HEX);
    }

    #[test]
    fn should_multiply_by_g() {
        let monero_g_big_uint = convert_hex_string_to_big_uint(MONERO_G.to_string()).unwrap();
        let big_uint_0 = ToBigUint::to_biguint(&0).unwrap();
        let big_uint_1 = ToBigUint::to_biguint(&1).unwrap();
        let big_uint_2 = ToBigUint::to_biguint(&2).unwrap();
        let g_multiplied_by_0 = multiply_by_g(big_uint_0.clone()).unwrap();
        let g_multiplied_by_1 = multiply_by_g(big_uint_1.clone()).unwrap();
        let g_multiplied_by_2 = multiply_by_g(big_uint_2.clone()).unwrap();
        assert!(g_multiplied_by_0 == big_uint_0);
        assert!(g_multiplied_by_1 == monero_g_big_uint);
        assert!(g_multiplied_by_2 == monero_g_big_uint.clone() + monero_g_big_uint);
    }

    #[test]
    fn should_keccak_hash_big_uint() {
        let int: u16 = 1337;
        let big_uint = ToBigUint::to_biguint(&int).unwrap();
        let hashed_big_uint = keccak256_hash_big_uint(big_uint).unwrap();
        /**
         * NOTE:
         * let hash = web3.utils.keccak256(numAsHex)
         * let numAsHex = web3.utils.padLeft(web3.utils.numberToHex(1337), 4)
         * web3.utils.keccak256("0x0539")
         */
        let expected_hash = "faae50e630355f536a35f931b941e1578227e30c2cdfaa69c59c264484d40ed8";
        assert!(expected_hash == hex::encode(hashed_big_uint));
    }

    #[test]
    fn should_cast_hash_to_big_uint() {
        let int: u16 = 1337;
        let big_uint = ToBigUint::to_biguint(&int).unwrap();
        let hashed_big_uint = keccak256_hash_big_uint(big_uint).unwrap();
        /**
         * NOTE:
         * let hash = web3.utils.keccak256(numAsHex)
         * let numAsHex = web3.utils.padLeft(web3.utils.numberToHex(1337), 4)
         * web3.utils.toBN(hash).toString()
         */
        let expected_num_str = "113386201880660458774621863012707052048509714470544993940678801196504088579800".to_string();
        let expected_num_big_uint = BigUint::from_str(&expected_num_str).unwrap();
        let result = cast_hash_to_big_uint(hashed_big_uint).unwrap();
        assert!(result == expected_num_big_uint);
    }

    #[test]
    fn should_generate_random_private_spend_key() {
        let key = generate_priv_sk().unwrap();
        let chars = key.chars().count();
        assert!(chars == 64);
    }

    #[test]
    fn should_hash_bytes_correctly() {
        /**
         * NOTE:
         * expected_hash = web3.utils.toBN(hex_key_string)
         */
        let hex_key_string: HexKey = "faae50e630355f536a35f931b941e1578227e30c2cdfaa69c59c264484d40ed8".to_string();
        let expected_hash = "532bc0ce4f17550956943d3b883866c623be7f59cf07a0ec890ea037a10ab792".to_string();
        let hex_key_bytes = &hex::decode(hex_key_string).unwrap()[..];
        let hashed_bytes = keccak256_hash_bytes(&hex_key_bytes).unwrap();
        let result = hex::encode(hashed_bytes);
        assert!(result == expected_hash )
    }

    #[test]
    fn should_hash_a_hex_key_correctly() {
        /**
         * NOTE:
         * expected_hash = web3.utils.toBN(hex_key_string)
         */
        let hex_key_string: HexKey = "faae50e630355f536a35f931b941e1578227e30c2cdfaa69c59c264484d40ed8".to_string();
        let expected_hash = "532bc0ce4f17550956943d3b883866c623be7f59cf07a0ec890ea037a10ab792".to_string();
        let hashed_hex_key = keccak256_hash_hex_key(hex_key_string).unwrap();
        let result = hex::encode(hashed_hex_key);
        assert!(result == expected_hash )
    }
}
