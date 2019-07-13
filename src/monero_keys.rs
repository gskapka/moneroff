use std::{
    fmt,
    result,
};

use crate::types::{
    Key,
    Address
};

use crate::cryptography::{
    concatenate_address,
    convert_scalar_to_bytes,
    hash_public_keys_with_prefix,
    convert_hex_string_to_scalar,
    get_address_suffix_from_hash,
    multiply_scalar_by_basepoint,
    generate_priv_vk_from_priv_sk,
    generate_random_scalar_mod_order,
    convert_compressed_edwards_y_to_bytes,
};

use crate::error::AppError;
use cryptonote_base58::to_base58;
use curve25519_dalek::scalar::Scalar;

type Result<T> = result::Result<T, AppError>;

#[derive(Copy, Clone)]
pub struct MoneroKeys {
    pub priv_sk: Scalar,
    pub pub_sk: Option<Key>,
    pub pub_vk: Option<Key>,
    pub priv_vk: Option<Scalar>,
    pub address: Option<Address>,
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

    fn add_priv_vk_to_self(mut self, priv_vk: Scalar) -> Result<Self> {
        self.priv_vk = Some(priv_vk);
        Ok(self)
    }

    fn add_pub_sk_to_self(mut self, pub_sk: Key) -> Result<Self> {
        self.pub_sk = Some(pub_sk);
        Ok(self)
    }

    fn add_address_to_self(mut self, address: Address) -> Result<Self> {
        self.address = Some(address);
        Ok(self)
    }

    fn add_pub_vk_to_self(mut self, pub_vk: Key) -> Result<Self> {
        self.pub_vk = Some(pub_vk);
        Ok(self)
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

    pub fn generate_new_random_key() -> Result<Self> {
        Ok(MoneroKeys::init(generate_random_scalar_mod_order()?)?)
    }

    pub fn from_existing_key(priv_sk: String) -> Result<Self> {
        MoneroKeys::init(convert_hex_string_to_scalar(priv_sk)?)
    }

    pub fn get_priv_sk(self) -> Result<Key> {
        Ok(self.priv_sk.to_bytes())
    }

    pub fn get_priv_vk(self) -> Result<Key> {
        self.get_priv_vk_scalar()
            .and_then(convert_scalar_to_bytes)
    }

    pub fn get_pub_sk(self) -> Result<Key> {
        match self.pub_sk {
            Some(pub_sk) => Ok(pub_sk),
            None => {
                self.get_priv_sk_scalar()
                    .and_then(multiply_scalar_by_basepoint)
                    .and_then(convert_compressed_edwards_y_to_bytes)
                    .and_then(|x| self.add_pub_sk_to_self(x))
                    .and_then(|x| x.get_pub_sk())
            }
        }
    }

    pub fn get_pub_vk(self) -> Result<Key> {
        match self.pub_vk {
            Some(pub_vk) => Ok(pub_vk),
            None => {
                self.get_priv_vk_scalar()
                    .and_then(multiply_scalar_by_basepoint)
                    .and_then(convert_compressed_edwards_y_to_bytes)
                    .and_then(|x| self.add_pub_vk_to_self(x))
                    .and_then(|x| x.get_pub_vk())
            }
        }
    }

    pub fn get_address(self) -> Result<Address> {
        match self.address {
            Some(address) => Ok(address),
            None => {
                let prefix = [0x12];
                hash_public_keys_with_prefix(self, prefix)
                    .and_then(get_address_suffix_from_hash)
                    .and_then(|suffix| concatenate_address(self, prefix, suffix))
                    .and_then(|address| self.add_address_to_self(address))
                    .and_then(|updated_self| updated_self.get_address())
            }
        }
    }
}

impl fmt::Display for MoneroKeys {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let priv_sk = self.get_priv_sk()
            .expect(&"✘ Error getting private spend key!".to_string());
        let priv_vk = self.get_priv_vk()
            .expect(&"✘ Error getting private view key!".to_string());
        let pub_sk = self.get_pub_sk()
            .expect(&"✘ Error getting public spend key!".to_string());
        let pub_vk = self.get_pub_vk()
            .expect(&"✘ Error getting public view key!".to_string());
       let address = self.get_address()
            .expect(&"✘ Error getting address!".to_string());
        let address_for_display = format!(
            "\nAddress:\n\t{:?}\n",
            to_base58(address[..].to_vec())
                .expect(&"✘ Error encoding address!".to_string())
        );
        let priv_sk_for_display = format!(
            "\nPrivate Spend Key:\n\t0x{}\n",
            hex::encode(priv_sk)
        );
        let priv_vk_for_display = format!(
            "\nPrivate View Key:\n\t0x{}\n",
            hex::encode(priv_vk)
        );
        let pub_sk_for_display = format!(
            "\nPublic Spend Key:\n\t0x{}\n",
            hex::encode(pub_sk)
        );
        let pub_vk_for_display = format!(
            "\nPublic View Key:\n\t0x{}\n",
            hex::encode(pub_vk)
        );
        write!(
            f,
            "{}{}{}{}{}",
            priv_sk_for_display,
            priv_vk_for_display,
            pub_sk_for_display,
            pub_vk_for_display,
            address_for_display
        )
    }
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
    fn should_generate_key_struct_from_existing() {
        let sk_bytes = &hex::decode(get_example_priv_sk()).unwrap()[..];
        let keys = MoneroKeys::from_existing_key(get_example_priv_sk()).unwrap();
        let priv_sk = keys.get_priv_sk().unwrap();
        assert!(priv_sk.len() == 32);
        assert!(priv_sk == sk_bytes);
    }

    #[test]
    fn should_generate_public_spend_key_correctly() {
        let pub_sk_bytes = &hex::decode(get_example_pub_sk()).unwrap()[..];
        let keys = MoneroKeys::from_existing_key(get_example_priv_sk()).unwrap();
        let pub_sk_from_struct = keys.get_pub_sk().unwrap();
        assert!(pub_sk_from_struct.len() == 32);
        assert!(pub_sk_from_struct == pub_sk_bytes);
    }

    #[test]
    fn should_generate_private_view_key_correctly() {
        let priv_vk_bytes = &hex::decode(get_example_priv_vk()).unwrap()[..];
        let keys = MoneroKeys::from_existing_key(get_example_priv_sk()).unwrap();
        let priv_vk_from_struct = keys.get_priv_vk().unwrap();
        assert!(priv_vk_from_struct.len() == 32);
        assert!(priv_vk_from_struct == priv_vk_bytes);
    }

    #[test]
    fn should_generate_public_view_key_correctly() {
        let pub_vk_bytes = &hex::decode(get_example_pub_vk()).unwrap()[..];
        let keys = MoneroKeys::from_existing_key(get_example_priv_sk()).unwrap();
        let pub_vk_from_struct = keys.get_pub_vk().unwrap();
        assert!(pub_vk_from_struct.len() == 32);
        assert!(pub_vk_from_struct == pub_vk_bytes);
    }

    #[test]
    fn should_generate_address_correctly() {
        let keys = MoneroKeys::from_existing_key(get_example_priv_sk()).unwrap();
        let address_bytes = keys.get_address().unwrap();
        let address_base58 = to_base58(address_bytes.to_vec()).unwrap();
        assert!(address_base58 == get_example_address());
    }

    #[test]
    fn should_format_key_struct_with_no_panicking() {
        let keys = MoneroKeys::from_existing_key(get_example_priv_sk()).unwrap();
        println!("{}", keys)
    }
}
