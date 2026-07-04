#![no_std]
#![deny(unsafe_code)]
#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

extern crate alloc;

pub mod artifact;
pub mod cbor;
pub mod cose;
pub mod ct;
pub mod error;
pub mod hash;
pub mod hsm;
pub mod predicate;
pub mod shred;
pub mod statement;
pub mod verify;

pub use artifact::Artifact;
pub use cbor::{RecoveryPolicy, Value as VeraxPayloadValue, VeraxPayload};
pub use cose::{
    CompositePublicKey, CompositeSignature, VerificationMode, composite_pubkey, composite_sign,
    composite_verify, extract_kid, extract_payload, extract_protected, extract_signature,
    extract_unprotected, parse_and_verify_composite, parse_and_verify_ed25519,
    parse_and_verify_mldsa65_only, sign_composite, sign_ed25519, sign_mldsa65_only,
};
pub use ct::{LogInclusionProof, SignedTreeHead, TemporalAnchor};
pub use error::{Error, Result};
pub use hash::{HASH_SIZE, blake3, blake3_derive_key, hash_artifact, verify_content_hash};
pub use hsm::{
    Algorithm as HsmAlgorithm, KeyAttributes, KeyReference, NullKeyStore, SecureKeyStore,
};
pub use predicate::Predicate;
pub use shred::{
    ErasureRecord, ShreddingKey, create_consent_payload, decrypt_pii, encrypt_pii,
    erasure_protocol, hash_ciphertext, hpke_decrypt_key, hpke_encrypt_key, shredding_commit,
};
pub use statement::Statement;
pub use verify::{
    TrustStore, VerificationWarnings, Warning, verify_statement, verify_statement_ed25519,
    verify_statement_with_warnings,
};
