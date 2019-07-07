use crate::cryptography::{
    keccak256_hash_bytes,
    multiply_key_by_basepoint,
    convert_hex_string_to_scalar,
    multiply_scalar_by_basepoint,
    generate_priv_vk_from_priv_sk,
    convert_32_byte_array_to_scalar,
    generate_random_scalar_mod_order,
    convert_hex_string_to_32_byte_array,
    multiply_compressed_point_by_basepoint,
};
use crate::error::AppError;
use crate::types::{HexString, HexKey, Key};
use cryptonote_base58::{from_base58, to_base58};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use std::result;

type Result<T> = result::Result<T, AppError>;

// FIXME: Use a type for the [u8; 32]
#[derive(Copy, Clone)]
struct MoneroKeys {
    pub priv_sk: Scalar,
    pub priv_vk: Option<Scalar>,
    pub pub_sk: Option<[u8; 32]>,
    pub pub_vk: Option<[u8; 32]>,
    pub address: Option<[u8; 69]>,
}

impl MoneroKeys {
    fn init(priv_sk: Scalar) -> Result<Self> {
        Ok(
            MoneroKeys {
                priv_sk: priv_sk,
                priv_vk: None,
                address: None,
                pub_sk: None,
                pub_vk: None,
            }
        )
    }

    pub fn generate_new_random_key() -> Result<Self> {
        Ok(MoneroKeys::init(generate_random_scalar_mod_order()?)?)
    }

    pub fn from_existing_key(priv_sk: String) -> Result<Self> {
        MoneroKeys::init(convert_hex_string_to_scalar(priv_sk)?)
    }

    fn add_priv_vk_to_self(mut self, priv_vk: Scalar) -> Result<Self> {
        self.priv_vk = Some(priv_vk);
        Ok(self)
    }

    pub fn get_priv_sk(self) -> Result<[u8; 32]> {
        Ok(self.priv_sk.to_bytes())
    }

    fn get_priv_sk_scalar(self) -> Result<Scalar> {
        Ok(self.priv_sk)
    }

    fn get_priv_vk_scalar(self) -> Result<Scalar> {
        match self.priv_vk {
            Some(priv_vk) => Ok(priv_vk),
            None => {
                generate_priv_vk_from_priv_sk(self.priv_sk)
                    .and_then(|x| self.add_priv_vk_to_self(x))
                    .and_then(|x| x.get_priv_vk_scalar())
            }
        }
    }

    pub fn get_priv_vk(self) -> Result<[u8; 32]> {
        self.get_priv_vk_scalar()
            .and_then(convert_scalar_to_bytes)
    }


fn check_key(key: HexKey) -> Result<HexKey> {
    check_key_is_valid_hex(key).and_then(check_hex_key_length)
}

fn generate_priv_vk_from_priv_sk(priv_sk: HexKey) -> Result<HexKey> {
    check_key(priv_sk)
        .and_then(keccak256_hash_hex_key)
        .and_then(convert_keccak256_hash_to_scalar_mod_order)
        .and_then(convert_scalar_to_hex_key)
}

fn generate_pub_key_from_priv_key(priv_key: HexKey) -> Result<HexKey> {
    check_key(priv_key)
        .and_then(convert_hex_key_to_scalar)
        .and_then(multiply_scalar_by_basepoint)
        .and_then(convert_scalar_to_hex_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_example_priv_sk() -> String {
        "401aab9897d1b585d8161afa28a054fd5a1e66bdf9355219266905a7db71500d"
            .to_string()
    }

    fn get_example_priv_vk() -> String {
        "7dce51f70c33131a321f7f47f2902476d833f81119beaf37f1660dbcc7a2050c"
            .to_string()
    }

    fn get_example_pub_sk() -> String {
        "0b5a01fa5c8d0733ddbc3dabedc621a3906a4f5462420c0e12691c1d278c8acf"
            .to_string()
    }

    fn get_example_pub_vk() -> String {
        "a3fbef25da640a49eddcdd2fc10998024c97acccb463217d4445d38fcb024428"
            .to_string()
    }

    fn get_example_address() -> String {
        "4244Mjbe7ee9gAfeM1cPuAUMn4QP5fkpj3MWtBnK1paubjNffQDMz2DDNCutG57VV11PJh5V5NyApMxF9BqMWpdy5XJMnCo"
            .to_string()
    }

    #[test]
    fn should_generate_random_key_struct() {
        let keys = MoneroKeys::generate_new_random_key().unwrap();
        let priv_sk = keys.get_priv_sk().unwrap();
        assert!(priv_sk.len() == 32);
    }

    #[test]
    fn should_generate_key_struct_from_exising() {
        let sk = get_example_priv_sk();
        let sk_vector = hex::decode(sk.clone()).unwrap();
        let sk_bytes = &sk_vector[..];
        let keys = MoneroKeys::from_existing_key(sk).unwrap();
        let priv_sk = keys.get_priv_sk().unwrap();
        assert!(priv_sk.len() == 32);
        assert!(priv_sk == sk_bytes);
    }

    #[test]
    fn should_generate_private_view_key_from_private_spend_key() {
        let priv_sk: HexKey =
            "fd4eef494e70a5d3b0309aa3ad0934dc07cc602731fd1b4b6a85702ddeeca007".to_string();
        let expected_key: HexKey =
            "d1546a8515e0488990db0f2d01666efc74bc26197c543047b766d8652db0b909".to_string();
        let priv_vk = generate_priv_vk_from_priv_sk(priv_sk).unwrap();
        assert!(priv_vk == expected_key);
        assert!(priv_vk.chars().count() == 64);
        let scalar = convert_hex_key_to_scalar(priv_vk).unwrap();
        assert!(scalar.is_canonical());
    }

    #[test]
    fn should_generate_private_view_key_correctly() {
        let priv_vk = get_example_priv_vk();
        let priv_vk_vector = hex::decode(priv_vk.clone()).unwrap();
        let priv_vk_bytes = &priv_vk_vector[..];
        let priv_sk = get_example_priv_sk();
        let keys = MoneroKeys::from_existing_key(priv_sk).unwrap();
        let priv_vk_from_struct = keys.get_priv_vk().unwrap();
        assert!(priv_vk_from_struct.len() == 32);
        assert!(priv_vk_from_struct == priv_vk_bytes);
    }

    #[test]
    fn should_generate_key_struct() {
        let priv_sk = generate_random_priv_sk().unwrap();
        let result = get_key_struct_from_priv_sk(priv_sk).unwrap();
        assert!(result.pub_vk.chars().count() == 64);
        assert!(result.pub_sk.chars().count() == 64);
        assert!(result.priv_sk.chars().count() == 64);
        assert!(result.priv_vk.chars().count() == 64);
    }

    #[test]
    fn should_generate_random_key_struct() {
        let result = get_random_key_struct().unwrap();
        assert!(result.pub_vk.chars().count() == 64);
        assert!(result.pub_sk.chars().count() == 64);
        assert!(result.priv_sk.chars().count() == 64);
        assert!(result.priv_vk.chars().count() == 64);
    }
}
