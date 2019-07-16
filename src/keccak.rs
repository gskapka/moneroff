use std::result;
use tiny_keccak::Keccak;
use crate::error::AppError;
use crate::types::Keccak256Hash;

type Result<T> = result::Result<T, AppError>;

pub fn keccak256_hash_bytes(bytes: &[u8]) -> Result<Keccak256Hash> {
    let mut res: Keccak256Hash = [0; 32];
    let mut keccak256 = Keccak::new_keccak256();
    keccak256.update(bytes);
    keccak256.finalize(&mut res);
    Ok(res)
}

#[cfg(test)]
#[allow(unused_doc_comments)]
mod tests {
    use super::*;

    #[test]
    fn should_keccak256_hash_bytes() {
        let bytes = [0x01, 0x02];
        let result = keccak256_hash_bytes(&bytes)
            .unwrap();
        assert!(result.len() == 32);
    }
}
