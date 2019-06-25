use crate::constants::MONERO_L;
use crate::error::AppError;
use crate::types::Key;
use num_bigint::{BigUint, RandBigInt};
use std::result;

type Result<T> = result::Result<T, AppError>;

struct Keys {
    pub_vk: Option<Key>,
    pub_sk: Option<Key>,
    priv_vk: Option<Key>,
    priv_sk: Option<Key>,
}

impl Keys {
    pub fn init_with_priv_sk(mut self, _priv_sk: Key) -> Self {
        self.priv_sk = Some(_priv_sk);
        self
    }

    pub fn add_pub_sk(mut self, _pub_sk: Key) -> Self {
        self.pub_sk = Some(_pub_sk);
        self
    }

    pub fn add_priv_vk(mut self, _prive_vk: Key) -> Self {
        self.priv_vk = Some(_prive_vk);
        self
    }

    pub fn add_pub_vk(mut self, _pub_vk: Key) -> Self {
        self.pub_vk = Some(_pub_vk);
        self
    }

    pub fn get_priv_sk(self) -> Key {
        self.priv_sk.expect("No private spend key set in struct!")
    }

    pub fn get_pub_sk(self) -> Key {
        self.pub_sk.expect("No public spend key set in struct!")
    }

    pub fn get_priv_vk(self) -> Key {
        self.priv_vk.expect("No private view key set in struct!")
    }

    pub fn get_pub_vk(self) -> Key {
        self.pub_vk.expect("No public view key set in struct!")
    }
}

pub fn generate_256_bit_random_number() -> BigUint {
    // TODO: rm pub!
    rand::thread_rng().gen_biguint(256)
}
