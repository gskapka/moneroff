use crate::types::{
    Key,
    Address,
    Keccak256Hash,
};

use hex;
use std::result;
use rand::thread_rng;
use tiny_keccak::Keccak;
use crate::error::AppError;
use crate::monero_keys::MoneroKeys;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};

type Result<T> = result::Result<T, AppError>;

pub fn generate_random_scalar() -> Result<Scalar> {
    Ok(Scalar::random(&mut thread_rng()))
}

pub fn generate_random_scalar_mod_order() -> Result<Scalar> {
    generate_random_scalar().and_then(reduce_scalar_mod_l)
}

pub fn convert_keccak256_hash_to_scalar_mod_order(hash: Keccak256Hash) -> Result<Scalar> {
    convert_key_to_scalar_mod_order(hash)
}

pub fn keccak256_hash_bytes(bytes: &[u8]) -> Result<Keccak256Hash> {
    let mut res: Keccak256Hash = [0; 32];
    let mut keccak256 = Keccak::new_keccak256();
    keccak256.update(bytes);
    keccak256.finalize(&mut res);
    Ok(res)
}

}

}

fn compress_edwards_point(e_point: EdwardsPoint) -> Result<CompressedEdwardsY> {
    Ok(e_point.compress())
}

pub fn multiply_scalar_by_basepoint(scalar: Scalar) -> Result<Scalar> {
    compress_edwards_point(scalar * ED25519_BASEPOINT_POINT)
        .and_then(|x| Ok(convert_compressed_edwards_y_to_scalar(x)?))
}

pub fn reduce_scalar_mod_l(scalar: Scalar) -> Result<Scalar> {
    Ok(scalar.reduce())
}

#[cfg(test)]
#[allow(unused_doc_comments)]
mod tests {
    use super::*;

    #[test]
    fn should_generate_random_scalar() {
        let result = generate_random_scalar().unwrap();
        assert!(result.to_bytes().len() == 32);
        assert!(result.is_canonical());
    }

    #[test]
    fn should_convert_32_byte_arr_to_scalar_mod_order() {
        let scalar = generate_random_scalar().unwrap();
        let result = convert_key_to_scalar_mod_order(scalar.to_bytes()).unwrap();
        assert!(result.to_bytes().len() == 32);
        assert!(result.is_canonical() == true);
    }
    #[test]
    fn should_generate_random_scalar_mod_order() {
        let result = generate_random_scalar_mod_order().unwrap();
        assert!(result.is_canonical());
    }

    #[test]
    fn should_keccak256_hash_bytes() {
        let bytes = [0x01, 0x02];
        let result = keccak256_hash_bytes(&bytes)
            .unwrap();
        assert!(result.len() == 32);
    }

    #[test]
    fn should_convert_keccak256_hash_to_scalar_mod_order() {
        let bytes = [0x01, 0x02];
        let result = keccak256_hash_bytes(&bytes)
            .and_then(convert_keccak256_hash_to_scalar_mod_order)
            .unwrap();
        assert!(result.to_bytes().len() == 32);
        assert!(result.is_canonical() == true)
    }

    #[test]
    fn should_compress_edwards_point_correctly() {
        use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        let result = compress_edwards_point(ED25519_BASEPOINT_POINT).unwrap();
        assert!(result.to_bytes().len() == 32);
    }

    #[test]
    fn should_multiply_scalar_by_basepoint() {
        generate_random_scalar()
            .and_then(reduce_scalar_mod_l)
            .and_then(multiply_scalar_by_basepoint)
            .unwrap();
    }

    #[test]
    fn should_reduce_scalar_mod_l() {
        let non_canonical_scalar = Scalar::from_bits([0xff; 32]);
        assert!(!non_canonical_scalar.is_canonical());
        let canonical_scalar = reduce_scalar_mod_l(non_canonical_scalar)
            .unwrap();
        assert!(canonical_scalar.is_canonical());
    }

}
