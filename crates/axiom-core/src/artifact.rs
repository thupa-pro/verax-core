use crate::hash;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Artifact {
    hash: [u8; 32],
}

impl Artifact {
    pub fn new(data: &[u8]) -> Self {
        Self { hash: hash::blake3(data) }
    }

    pub fn from_hash(hash: [u8; 32]) -> Self {
        Self { hash }
    }

    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    pub fn verify(&self, data: &[u8]) -> bool {
        hash::verify_content_hash(&self.hash, data)
    }

    pub fn verify_strict(&self, data: &[u8]) -> Result<()> {
        if self.verify(data) {
            Ok(())
        } else {
            Err(Error::Crypto("artifact content hash mismatch".into()))
        }
    }
}

impl From<[u8; 32]> for Artifact {
    fn from(hash: [u8; 32]) -> Self {
        Self { hash }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_artifact_from_data() {
        let data = b"hello world";
        let art = Artifact::new(data);
        assert!(art.verify(data));
        assert!(!art.verify(b"wrong data"));
    }

    #[test]
    fn test_artifact_deterministic() {
        let a = Artifact::new(b"test");
        let b = Artifact::new(b"test");
        assert_eq!(a.hash(), b.hash());
    }

    #[test]
    fn test_artifact_verify_strict() {
        let art = Artifact::new(b"correct");
        assert!(art.verify_strict(b"correct").is_ok());
        assert!(art.verify_strict(b"wrong").is_err());
    }

    #[test]
    fn test_artifact_from_hash() {
        let hash = [0xabu8; 32];
        let art = Artifact::from_hash(hash);
        assert_eq!(art.hash(), &hash);
    }
}
