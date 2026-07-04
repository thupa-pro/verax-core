const HASH_LEN: usize = 32;

pub fn blake3(data: &[u8]) -> [u8; HASH_LEN] {
    *blake3::hash(data).as_bytes()
}

pub fn blake3_derive_key(context: &str, key_material: &[u8]) -> [u8; HASH_LEN] {
    let mut out = [0u8; HASH_LEN];
    let result = blake3::derive_key(context, key_material);
    out.copy_from_slice(&result);
    out
}

pub fn hash_artifact(data: &[u8]) -> [u8; HASH_LEN] {
    blake3::hash(data).into()
}

pub fn verify_content_hash(expected: &[u8; HASH_LEN], data: &[u8]) -> bool {
    &blake3(data) == expected
}

pub const HASH_SIZE: usize = HASH_LEN;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_basic() {
        let h = blake3(b"hello");
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn test_blake3_deterministic() {
        let a = blake3(b"test");
        let b = blake3(b"test");
        assert_eq!(a, b);
    }

    #[test]
    fn test_derive_key_deterministic() {
        let a = blake3_derive_key("Axiom-Artifact", b"data");
        let b = blake3_derive_key("Axiom-Artifact", b"data");
        assert_eq!(a, b);
    }

    #[test]
    fn test_derive_key_domain_separation() {
        let a = blake3_derive_key("Axiom-Artifact", b"data");
        let b = blake3_derive_key("Axiom-Statement", b"data");
        assert_ne!(a, b);
    }

    #[test]
    fn test_verify_content_hash() {
        let h = blake3(b"hello");
        assert!(verify_content_hash(&h, b"hello"));
        assert!(!verify_content_hash(&h, b"world"));
    }

    #[test]
    fn test_hash_artifact() {
        let h = hash_artifact(b"some content");
        assert_eq!(h.len(), 32);
    }
}
