use crate::constants::MONERO_L;
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

}
