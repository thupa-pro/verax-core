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
pub use cbor::{AxiomPayload, RecoveryPolicy, Value as AxiomPayloadValue};
pub use cose::{
    composite_pubkey, composite_sign, composite_verify,
    extract_kid, extract_payload, extract_protected, extract_signature, extract_unprotected,
    sign_composite, sign_ed25519, sign_mldsa65_only,
    parse_and_verify_composite, parse_and_verify_ed25519,
    parse_and_verify_mldsa65_only,
    CompositePublicKey, CompositeSignature, VerificationMode,
};
pub use ct::{LogInclusionProof, SignedTreeHead, TemporalAnchor};
pub use error::{Error, Result};
pub use hash::{blake3, blake3_derive_key, hash_artifact, verify_content_hash, HASH_SIZE};
pub use hsm::{Algorithm as HsmAlgorithm, KeyAttributes, KeyReference, SecureKeyStore, NullKeyStore};
pub use predicate::Predicate;
pub use shred::{
    create_consent_payload, decrypt_pii, encrypt_pii, erasure_protocol,
    hash_ciphertext, hpke_decrypt_key, hpke_encrypt_key,
    shredding_commit, ErasureRecord, ShreddingKey,
};
pub use statement::Statement;
pub use verify::{
    verify_statement, verify_statement_ed25519, verify_statement_with_warnings,
    TrustStore, VerificationWarnings, Warning,
};
