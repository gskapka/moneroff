use crate::types::{
    Key,
    Address,
    Keccak256Hash,
};

use crate::edwards_curve_cryptography::{
    multiply_scalar_by_basepoint,
    convert_compressed_edwards_y_to_bytes,
    convert_keccak256_hash_to_scalar_mod_order,
};

use hex;
use std::result;
use crate::error::AppError;
use crate::monero_keys::MoneroKeys;
use curve25519_dalek::scalar::Scalar;
use crate::keccak::keccak256_hash_bytes;

type Result<T> = result::Result<T, AppError>;

pub fn convert_private_key_to_public_key(key: Scalar) -> Result<Key> {
    multiply_scalar_by_basepoint(key)
        .and_then(convert_compressed_edwards_y_to_bytes)
}


pub fn convert_hex_string_to_32_byte_array(hex: String) -> Result<Key> {
    let decoded_hex = hex::decode(hex)?;
    let key_message = "✘ A Monero private key is 32 bytes long.".to_string();
    match decoded_hex.len() {
        32 => {
            let mut array = [0; 32];
            array[..].copy_from_slice(&decoded_hex[..]);
            Ok(array)
        }
        0..32 => Err(
                AppError::Custom(
                    format!(
                        "✘ Hex Error: Key length too short!\n{}",
                        key_message
                    )
                )
            ),
        _ => Err(
                AppError::Custom(
                    format!(
                        "✘ Hex Error: Key length too long!\n{}",
                        key_message
                    )
                )
            )
        }
}

pub fn generate_priv_vk_from_priv_sk(priv_sk: Scalar) -> Result<Scalar> {
    keccak256_hash_bytes(&priv_sk.to_bytes())
        .and_then(convert_keccak256_hash_to_scalar_mod_order)
}

pub fn concatenate_address(
    keys: MoneroKeys,
    prefix_byte: [u8; 1],
    suffix_bytes: [u8; 4]
) -> Result<Address> {
    let pub_sk: Key = keys.get_pub_sk()?;
    let pub_vk: Key = keys.get_pub_vk()?;
    let mut address_bytes = [0; 69];
    address_bytes[..1].copy_from_slice(&prefix_byte);
    address_bytes[1..33].copy_from_slice(&pub_sk);
    address_bytes[33..65].copy_from_slice(&pub_vk);
    address_bytes[65..69].copy_from_slice(&suffix_bytes[..4]);
    Ok(address_bytes)
}

pub fn hash_public_keys_with_prefix(
    keys: MoneroKeys,
    prefix: [u8; 1]
) -> Result<Keccak256Hash> {
    let pub_sk: Key = keys.get_pub_sk()?;
    let pub_vk: Key = keys.get_pub_vk()?;
    let mut bytes_to_hash = vec![0; 65];
    bytes_to_hash[..1].copy_from_slice(&prefix);
    bytes_to_hash[1..33].copy_from_slice(&pub_sk);
    bytes_to_hash[33..65].copy_from_slice(&pub_vk);
    keccak256_hash_bytes(&bytes_to_hash)
}

pub fn get_address_suffix_from_hash(hash: Keccak256Hash) -> Result<[u8; 4]> {
    let mut x = [0; 4];
    x.copy_from_slice(&hash[..4]);
    Ok(x)
}

#[cfg(test)]
#[allow(unused_doc_comments)]
mod tests {
    use super::*;
    use crate::monero_keys::generate_monero_keys_from;
    use crate::edwards_curve_cryptography::{
        convert_hex_string_to_scalar,
        convert_scalar_to_bytes,
    };


    fn get_example_priv_sk() -> String {
        "d3d21c30a27b2a2b64df410adbadc69eefb2be8e0c357d6a42f19638b343a606"
            .to_string()
    }

    fn get_example_priv_vk() -> String {
        "d1a9f90efc96a23469c0bb2f6a0515cb9a859b7d289b5e7f10d3c16912cd4308"
            .to_string()
    }

    fn get_example_pub_sk() -> String {
        "ebd1ab2b12454952289125922540cfa87642b4e6acb173de9bbe0f8c09584a11"
            .to_string()
    }

    fn get_example_pub_vk() -> String {
        "87bb6f60d6288907a51511017261435e449767a71e27d8487a38eaa4772f932e"
            .to_string()
    }

    fn get_example_address() -> String {
        "4AZRamrxefJEk3KeBP4FoLVBHwFxQ8KizeEaeDVtrM8D3w4mSmzxv1n2HAYshpaKH4GmWzNz6kJY7D884yBdrN5G6EZQrAR"
            .to_string()
    }

    #[test]
    fn should_convert_private_spend_key_to_public_correctly() {
        let priv_sk = convert_hex_string_to_scalar(get_example_priv_sk())
            .unwrap();
        let expected_pub_key = hex::decode(get_example_pub_sk())
            .unwrap();
        let result = convert_private_key_to_public_key(priv_sk)
            .unwrap();
        assert!(result.to_vec() == expected_pub_key);
    }

    #[test]
    fn should_convert_private_view_key_to_public_correctly() {
        let priv_vk = convert_hex_string_to_scalar(get_example_priv_vk())
            .unwrap();
        let expected_pub_key = hex::decode(get_example_pub_vk())
            .unwrap();
        let result = convert_private_key_to_public_key(priv_vk)
            .unwrap();
        assert!(result.to_vec() == expected_pub_key);
    }

    #[test]
    fn should_convert_64_char_hex_string_to_32_byte_array() {
        let result = convert_hex_string_to_32_byte_array(get_example_priv_sk())
            .unwrap();
        assert!(result.len() == 32);
    }

    #[test]
    fn should_error_if_hex_key_too_long() {
        let expected_error = "too long";
        let mut long_hex_string = get_example_priv_sk();
        long_hex_string.push('a');
        long_hex_string.push('b');
        match convert_hex_string_to_32_byte_array(long_hex_string) {
            Err(AppError::Custom(e)) => assert!(e.contains(expected_error)),
            Err(e) => panic!("Did not expect this error: {}", e),
            Ok(_) => panic!("Should not have succeeded!")
        }
    }

    #[test]
    fn should_error_if_hex_key_too_short() {
        let expected_error = "too short";
        let short_hex_string = "c0ffee".to_string();
        match convert_hex_string_to_32_byte_array(short_hex_string) {
            Err(AppError::Custom(e)) => assert!(e.contains(expected_error)),
            Err(e) => panic!("Did not expect this error: {}", e),
            Ok(_) => panic!("Should not have succeeded!")
        }
    }

    #[test]
    fn should_error_if_hex_key_odd_length() {
        let expected_error = hex::FromHexError::OddLength;
        let mut long_hex_string = get_example_priv_sk();
        long_hex_string.push('a');
        match convert_hex_string_to_32_byte_array(long_hex_string) {
            Err(AppError::HexError(e)) => assert!(e == expected_error),
            Err(e) => panic!("Did not expect this error: {}", e),
            Ok(_) => panic!("Should not have succeeded!")
        }
    }

    #[test]
    fn should_generate_priv_vk_from_priv_sk() {
        let result = convert_hex_string_to_scalar(get_example_priv_sk())
            .and_then(|x| generate_priv_vk_from_priv_sk(x))
            .and_then(convert_scalar_to_bytes)
            .unwrap();
        assert!(hex::encode(result) == get_example_priv_vk());
    }

    #[test]
    fn should_hash_public_keys_with_prefix() {
        let expected_bytes = [139, 87, 37, 191, 92, 201, 237, 245, 109, 192, 203, 124, 149, 58, 152, 44, 42, 25, 35, 13, 1, 208, 90, 97, 102, 231, 20, 166, 48, 7, 21, 106];
        let keys = generate_monero_keys_from(get_example_priv_sk())
            .unwrap();
        let dummy_prefix = [0xff];
        let result = hash_public_keys_with_prefix(keys, dummy_prefix)
            .unwrap();
        assert!(expected_bytes == result);
    }

    #[test]
    fn should_get_address_suffix_from_hash() {
        let expected_bytes = [96, 136, 140, 130];
        let dummy_hash = keccak256_hash_bytes(get_example_priv_sk().as_bytes())
            .unwrap();
        let result = get_address_suffix_from_hash(dummy_hash)
            .unwrap();
        println!("{:?}", result);
        assert!(result == expected_bytes)
    }

    #[test]
    fn should_concatenate_address() {
        use cryptonote_base58::to_base58;
        let keys = generate_monero_keys_from(get_example_priv_sk())
            .unwrap();
        assert!(hex::encode(keys.get_pub_vk().unwrap()) == get_example_pub_vk());
        assert!(hex::encode(keys.get_pub_sk().unwrap()) == get_example_pub_sk());
        let prefix = [0x12];
        let hash = hash_public_keys_with_prefix(keys, prefix)
            .unwrap();
        let suffix = get_address_suffix_from_hash(hash)
            .unwrap();
        let address_bytes = concatenate_address(keys, prefix, suffix)
            .unwrap();
        let result = to_base58(address_bytes.to_vec())
            .unwrap();
        assert!(result == get_example_address());
    }
}
