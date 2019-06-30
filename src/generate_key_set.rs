use crate::cryptography::{
    convert_hex_key_to_scalar,
    convert_keccak256_hash_to_scalar_mod_order,
    convert_scalar_to_hex_key,
    generate_random_scalar_mod_order,
    keccak256_hash_hex_key,
    multiply_scalar_by_basepoint,
    reduce_scalar_mod_l,
};
use crate::error::AppError;
use crate::types::HexKey;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;

use std::result;

type Result<T> = result::Result<T, AppError>;

struct KeyStruct {
    pub priv_sk: HexKey,
}

impl KeyStruct {
    pub fn init_with_priv_sk(mut self, priv_sk: HexKey) -> Self {
        self.priv_sk = priv_sk;
        self
    }
}

fn generate_random_priv_sk() -> Result<HexKey> {
    generate_random_scalar_mod_order().and_then(convert_scalar_to_hex_key)
}

fn check_hex_key_length(key: HexKey) -> Result<HexKey> {
    match hex::decode(&key).unwrap().len() {
        32 => Ok(key),
        _ => Err(AppError::Custom("✘ Key length invalid!".to_string())),
    }
}

fn check_key_is_valid_hex(key: HexKey) -> Result<HexKey> {
    hex::decode(&key)?;
    Ok(key)
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

    #[test]
    fn should_generate_random_private_spend_key() {
        let priv_sk = generate_random_priv_sk().unwrap();
        assert!(priv_sk.chars().count() == 64);
        let scalar = convert_hex_key_to_scalar(priv_sk).unwrap();
        assert!(scalar.is_canonical());
    }

    #[test]
    fn should_not_panic_if_key_length_correct() {
        let key = generate_random_scalar_mod_order()
            .and_then(convert_scalar_to_hex_key)
            .unwrap();
        let _result = check_key(key).unwrap();
    }

    #[test]
    #[should_panic]
    fn should_panic_if_key_length_too_long() {
        let key_long: HexKey =
            "fd4eef494e70a5d3b0309aa3ad0934dc07cc602731fd1b4b6a85702ddeeca00700".to_string();
        let _result = check_hex_key_length(key_long).unwrap();
    }

    #[test]
    #[should_panic]
    fn should_panic_if_key_length_too_short() {
        let key_short: HexKey =
            "fd4eef494e70a5d3b0309aa3ad0934dc07cc602731fd1b4b6a85702ddeeca0".to_string();
        let _result = check_hex_key_length(key_short).unwrap();
    }

    #[test]
    #[should_panic]
    fn should_panic_if_key_length_is_odd() {
        let invalid_hex: HexKey =
            "fd4eef494e70a5d3b0309aa3ad0934dc07cc602731fd1b4b6a85702ddeeca00".to_string();
        let _result = check_key_is_valid_hex(invalid_hex).unwrap();
    }

    #[test]
    #[should_panic]
    fn should_panic_if_key_not_valid_hex() {
        let invalid_hex: HexKey =
            "fd4eef494e70a5d3b0309aa3ad0934dc07cc602731fd1b4b6a85702ddeeca007xx".to_string();
        let _result = check_key_is_valid_hex(invalid_hex).unwrap();
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
    fn should_get_public_key_from_private_key_correctly() {
        let priv_sk: HexKey =
            "0ccdf1e0217221deb8d807c1ecdf9c0c00beffbc339cdfa5c203c1a022d9cf01".to_string();
        let priv_sk_clone = priv_sk.clone();
        let priv_vk = generate_priv_vk_from_priv_sk(priv_sk_clone).unwrap();
        let expected_pub_sk =
            "2794fe656a521e21e4135aa13381b42cbeb180e653deda210f2039ca1009d110".to_string();
        let expected_pub_vk =
            "d76344d2c5467758f0bcbf03925bc8bf4b659e163ec68c342c7ba94b9679a125".to_string();
        let pub_sk = generate_pub_key_from_priv_key(priv_sk).unwrap();
        let pub_vk = generate_pub_key_from_priv_key(priv_vk).unwrap();
        assert!(pub_sk == expected_pub_sk);
        assert!(pub_vk == expected_pub_vk);
    }
}
