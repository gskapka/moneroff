use crate::cryptography::{convert_keccak256_hash_to_scalar_mod_order, keccak256_hash_hex_key, reduce_scalar_mod_l, multiply_scalar_by_basepoint, convert_hex_key_to_scalar, convert_scalar_to_hex_key, generate_random_scalar_mod_order};
use crate::error::AppError;
use crate::types::HexKey;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;

use std::result;

type Result<T> = result::Result<T, AppError>;

struct PrivateSpendKey {
    pub key: Scalar,
}

struct PrivateViewKey {
    pub key: CompressedEdwardsY,
}

struct KeyStruct {
    pub pub_vk: PrivateSpendKey,
    pub priv_vk: PrivateViewKey,
}

impl KeyStruct {
    pub fn init_with_priv_sk(mut self, priv_sk: HexKey) -> Self {
        self.priv_sk = Some(priv_sk);
        self
    }

    pub fn init_with_random_priv_sk(mut self, priv_sk: HexKey) -> Self {
        self.priv_sk = Some(priv_sk);
        self
    }
}

//maybe these should go in crypto too, so only the four get exported?
fn generate_priv_sk() -> Result<HexKey> {
    generate_random_scalar_mod_order()
        .and_then(convert_scalar_to_hex_key)
}

fn generate_priv_vk_from_priv_sk(priv_sk: HexKey) -> Result<HexKey> {
    keccak256_hash_hex_key(priv_sk)
        .and_then(convert_keccak256_hash_to_scalar_mod_order)
        .and_then(convert_scalar_to_hex_key)
    /*
    convert_hex_key_to_scalar(priv_sk)
        .and_then(multiply_scalar_by_basepoint)
        .and_then(convert_scalar_to_hex_key)
        */
}
/*

fn generate_priv_vk_from_priv_sk(priv_sk: HexKey) -> Result<HexKey> {
    keccak256_hash_hex_key(priv_sk)
        .and_then(cast_hash_to_big_uint)
        .and_then(take_modulus_l)
        .and_then(convert_big_uint_to_hex_string)
}

fn add_priv_sk_to_struct(priv_sk: Key) -> Result<KeyStruct> {
    Ok(KeyStruct.init_with_priv_sk(priv_sk))
}


fn generate_pub_vk_from_priv_vk(priv_vk: Key) -> Result<HexKey> {
    cast_hash_to_big_uint(priv_vk)
        .and_then(multiply_by_g)
        .and_then(convert_big_uint_to_hex_string)
}


fn generate_pub_vk_in_struct(_keyStruct: KeyStruct) -> Result<HexKey> {
    generate_pub_vk_from_priv_vk(_keyStruct.getPrivateViewKey())
        .and_then(|_k| _keyStruct.addPublicViewKey(_k))
}

fn generate_pub_sk_in_struct(_keyStruct: KeyStruct) -> Result<HexKey> {
    generate_pub_sk_from_priv_sk(_keyStruct.getPrivateSpendKey())
        .and_then(|_k| _keyStruct.addPublicSpendKey(_k))
}

fn generate_priv_vk_in_struct(KeyStruct: _keyStruct) -> Result<KeyStruct> {
    keccak256_hash_hex_key(_keyStruct.getPrivateViewKey())
        .and_then(generate_priv_vk_from_priv_sk)
        .and_then(|_k| _keyStruct.addPrivateViewKey(_k))
}

fn generate_keys(_maybePrivSK: Option<Key>) -> Result<KeyStruct> {
    _maybePrivSK
        .unwrap_or(generate_priv_sk())
        .and_then(add_priv_sk_to_struct)
        .and_then(generate_priv_vk_in_struct)
        .and_then(generate_pub_vk_in_struct)
        .and_then(generate_pub_sk_in_struct)
}

NOTE Monero uses 25 words seed (method 2) from here:
https://monero.stackexchange.com/questions/7287/in-monero-can-you-sweep-a-wallet-if-you-only-have-the-private-spend-key#7289

[ ] Also should hard code some address pairs and test the generation of them!

Choose a random private spend key, typically by creating 256 random bits then "reducing" mod l. Call this key b (to match the whitepaper -- it's confusing I know).

Hash b with the chosen algorithm, H (Keccak_256 in our usage). Interpret the result as an integer and reduce it mod l as before. Call this key a.

Calculate B = bG and A = aG. These are your public spend and public view KeyStruct.
Hash (prefix (0x12 in standard Monero) + B + A) with H.
Append the first four bytes of the result to (prefix + B + A). This will be 69 bytes (1 + 32 + 32 + 4).
Convert to cnBase58. This is not as straightforward as regular base58, as it uses blocks and padding to result in fixed-length conversions. 69 bytes will always be 95 cnBase58 characters.

Note: the above is from the address generator site and rehashed here: https://steemit.com/monero/@luigi1111/understanding-monero-cryptography-privacy-introduction
Which latter also has some useful info re the final steps!

Then this is good about stealth addresses too: https://pastebin.com/bp5RKXuC


//  Note on builder style struct:
//  fn q(self, val: Q) -> Self { self.q = Some(val); self } // repeat for other fields
//  fn build(self) -> Foo { if q is Some, w is Some { give new foo } else { panic or return an Err/None } }
// TODO: Maybe rm?
pub fn hex_to_u64(b: &[u8]) -> Option<u64> {
    let a = std::str::from_utf8(b).ok()?;
    u64::from_str_radix(a, 16).ok()
}

//Utils if I can get it working
pub fn parse_sha256_to_u64(str: &str) -> Option<[u64; 4]> {
    if str.len() != 64 { return None; }
    let mut out = [0u64; 4];
    for (idx, val) in str.as_bytes().chunks(16).map(hex_to_u64).enumerate() {
        out[idx] = val?;
    }
    Some(out)
}

*/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_generate_private_spend_key() {
        let priv_sk = generate_priv_sk().unwrap();
        assert!(priv_sk.chars().count() == 64);
    }

    #[test]
    fn should_generate_private_view_key_from_private_spend_key() {
        let x: HexKey = "57ee6dd2f18d4ba0041fcf9df42bbc4d1ee3da9964fa3ca9ce1976f983b7ad08".to_string();
        println!("{:?}", x);
        let priv_vk = generate_priv_vk_from_priv_sk(x).unwrap();
        println!("{:?}", priv_vk);
        assert!(priv_vk.chars().count() == 64);
    }
}
