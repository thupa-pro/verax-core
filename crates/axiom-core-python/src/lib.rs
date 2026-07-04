//! Python bindings for the Axiom Protocol.
//!
//! This module exposes the core Axiom functionality to Python:
//! - Statement signing (Ed25519, Composite Ed25519+ML-DSA-65)
//! - Signature verification (Ed25519, Composite, and full protocol)
//! - PII shredding (encrypt, decrypt, shredding_commit)
//! - Payload encoding and decoding
//!
//! Error conditions are signaled via `ValueError` exceptions with
//! descriptive messages and numeric error codes matching the Axiom spec.

use std::collections::{HashMap, HashSet};
use pyo3::prelude::*;

use axiom_core::{
    AxiomPayload, Predicate, Statement, TrustStore, VerificationWarnings, Warning,
    CompositePublicKey, cose, hash::blake3,
    verify_statement_with_warnings,
    encrypt_pii, decrypt_pii, shredding_commit, ShreddingKey,
};

fn py_err<E: std::fmt::Display>(e: E) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(e.to_string())
}

fn py_err_display<E: std::fmt::Debug>(e: E) -> PyErr {
    pyo3::exceptions::PyValueError::new_err(format!("{e:?}"))
}

/// Maps axiom_core::Error to the normative FFI error code (Section B).
fn error_to_code(e: &axiom_core::Error) -> i32 {
    use axiom_core::Error;
    match e {
        Error::MalformedCose(_) => 1,
        Error::NonCanonicalEncoding => 2,
        Error::InvalidSignature => 3,
        Error::BrokenLineage(_) => 4,
        Error::LineageSubjectMismatch => 5,
        Error::TimestampMonotonicityViolation => 6,
        Error::RevokeIssuerMismatch => 7,
        Error::InvalidLogProof(_) => 8,
        Error::Revoked => 9,
        Error::InvalidField(_) => 10,
        Error::Crypto(_) => 11,
        Error::Decode(_) => 12,
        Error::HashLength { .. } => 13,
        Error::Io(_) => 14,
        Error::Payload(_) => 15,
        Error::Encode(_) => 16,
        Error::AnchorHashMismatch | Error::LineageDepthExceeded => 17,
        Error::RecoveryPolicyViolation(_) => 18,
    }
}

struct PyTrustStore {
    ed_vk: Option<ed25519_dalek::VerifyingKey>,
    comp_pk: Option<CompositePublicKey>,
    chain_cache: HashMap<[u8; 32], Vec<u8>>,
    trusted_log_key: Option<[u8; 32]>,
    revoked: HashSet<[u8; 32]>,
    not_revoked: HashSet<[u8; 32]>,
    checkpoint_timestamp: Option<u64>,
}

impl TrustStore for PyTrustStore {
    fn resolve_key(&self, _kid: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
        self.ed_vk
    }

    fn resolve_composite_key(&self, _kid: &[u8]) -> Option<CompositePublicKey> {
        self.comp_pk.clone()
    }

    fn fetch_statement(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.chain_cache.get(hash).cloned()
    }

    fn is_revoked_in_log(&self, stmt_hash: &[u8; 32], after_timestamp: u64) -> Option<bool> {
        let cp = self.checkpoint_timestamp?;
        if after_timestamp > cp {
            return None;
        }
        if self.revoked.contains(stmt_hash) {
            return Some(true);
        }
        if self.not_revoked.contains(stmt_hash) {
            return Some(false);
        }
        None
    }

    fn resolve_log_pubkey(&self, _log_id: &[u8; 32], candidate_key: &[u8; 32]) -> Option<[u8; 32]> {
        self.trusted_log_key.and_then(|tk| {
            if &tk == candidate_key { Some(tk) } else { None }
        })
    }
}

fn warnings_to_vec(warnings: &VerificationWarnings) -> Vec<String> {
    warnings.warnings.iter().map(|w| match w {
        Warning::TemporalEvidenceMissing => "temporal_evidence_missing".into(),
        Warning::RevocationStatusUnknown => "revocation_status_unknown".into(),
        Warning::StaleSth { .. } => "stale_sth".into(),
    }).collect()
}

fn payload_to_dict(py: Python, payload: &AxiomPayload) -> PyResult<PyObject> {
    let d = pyo3::types::PyDict::new(py);
    d.set_item("subject", pyo3::types::PyBytes::new(py, &payload.subject))?;
    d.set_item("predicate", payload.predicate.name())?;
    if let Some(obj) = &payload.object {
        d.set_item("object", pyo3::types::PyBytes::new(py, obj))?;
    }
    if let Some(ts) = payload.timestamp {
        d.set_item("timestamp", ts)?;
    }
    if let Some(lin) = &payload.lineage {
        d.set_item("lineage", pyo3::types::PyBytes::new(py, lin))?;
    }
    if let Some(nonce) = &payload.nonce {
        d.set_item("nonce", pyo3::types::PyBytes::new(py, nonce))?;
    }
    if let Some(ah) = &payload.anchor_hash {
        d.set_item("anchor_hash", pyo3::types::PyBytes::new(py, ah))?;
    }
    Ok(d.into())
}

/// A decoded Axiom payload with fields for subject, predicate, object,
/// timestamp, lineage, and nonce.
#[pyclass]
#[derive(Clone)]
struct Payload {
    #[pyo3(get)]
    subject: Vec<u8>,
    #[pyo3(get)]
    predicate: String,
    #[pyo3(get)]
    object: Option<Vec<u8>>,
    #[pyo3(get)]
    timestamp: Option<u64>,
    #[pyo3(get)]
    lineage: Option<Vec<u8>>,
    #[pyo3(get)]
    nonce: Option<Vec<u8>>,
}

#[pymethods]
impl Payload {
    fn __repr__(&self) -> String {
        format!("Payload(subject={}, predicate={})", hex::encode(&self.subject), self.predicate)
    }
}

/// Returns the Axiom library version string.
#[pyfunction]
fn axiom_version() -> String {
    concat!("axiom-core ", env!("CARGO_PKG_VERSION")).to_string()
}

/// Verifies an Ed25519-signed COSE statement.
///
/// Args:
///     cose: The COSE-encoded statement bytes.
///     pubkey: The 32-byte Ed25519 public key.
///
/// Returns:
///     The decoded payload CBOR bytes.
///
/// Raises ValueError on invalid signature or malformed input.
#[pyfunction]
fn verify_ed25519(cose: &[u8], pubkey: &[u8]) -> PyResult<Vec<u8>> {
    let arr: [u8; 32] = pubkey.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("pubkey must be exactly 32 bytes")
    })?;
    let pk = ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
    cose::parse_and_verify_ed25519(cose, &pk).map_err(py_err)
}

/// Verifies a Composite (Ed25519 + ML-DSA-65) COSE statement.
///
/// Args:
///     cose: The COSE-encoded statement bytes.
///     ed_pubkey: The 32-byte Ed25519 public key.
///     ml_dsa_pubkey: The 1952-byte ML-DSA-65 public key.
///
/// Returns:
///     The decoded payload CBOR bytes.
///
/// Raises ValueError on invalid signature or malformed input.
#[pyfunction]
fn verify_composite(cose: &[u8], ed_pubkey: &[u8], ml_dsa_pubkey: &[u8]) -> PyResult<Vec<u8>> {
    let ed_arr: [u8; 32] = ed_pubkey.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("ed_pubkey must be exactly 32 bytes")
    })?;
    let ml_arr: [u8; 1952] = ml_dsa_pubkey.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("ml_dsa_pubkey must be exactly 1952 bytes")
    })?;
    let comp_pk = CompositePublicKey { ed25519: ed_arr, mldsa65: ml_arr };
    cose::parse_and_verify_composite(cose, &comp_pk, axiom_core::cose::VerificationMode::Hybrid)
        .map_err(py_err)
}

/// Performs full protocol verification including signature, CT log anchoring,
/// chain resolution, and revocation status.
///
/// Args:
///     cose: The COSE-encoded statement bytes.
///     pubkey: The 32-byte Ed25519 public key.
///     chain_statements: Optional list of parent statement bytes for chain resolution.
///     trusted_log_key: Optional 32-byte trusted CT log public key.
///     revoked: Optional list of hex-encoded revoked statement hashes.
///     not_revoked: Optional list of hex-encoded non-revoked statement hashes.
///     checkpoint_timestamp: Optional checkpoint timestamp for revocation queries.
///
/// Returns:
///     A dict with keys: ``valid`` (bool), ``payload`` (dict or absent),
///     ``warnings`` (list of str), ``error`` (str or absent),
///     ``error_code`` (int or absent).
#[pyfunction]
#[pyo3(signature = (cose, pubkey, chain_statements=None, trusted_log_key=None, revoked=None, not_revoked=None, checkpoint_timestamp=None))]
#[allow(clippy::too_many_arguments)]
fn verify_full(
    py: Python,
    cose: &[u8],
    pubkey: &[u8],
    chain_statements: Option<Vec<Vec<u8>>>,
    trusted_log_key: Option<Vec<u8>>,
    revoked: Option<Vec<String>>,
    not_revoked: Option<Vec<String>>,
    checkpoint_timestamp: Option<u64>,
) -> PyResult<PyObject> {
    let ed_arr: [u8; 32] = pubkey.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("pubkey must be exactly 32 bytes")
    })?;
    let ed_vk = ed25519_dalek::VerifyingKey::from_bytes(&ed_arr)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string())).ok();

    let mut chain_cache = HashMap::new();
    if let Some(stmts) = &chain_statements {
        for stmt_bytes in stmts {
            let h = blake3(stmt_bytes);
            chain_cache.insert(h, stmt_bytes.clone());
        }
    }

    let tlk = trusted_log_key.and_then(|k| {
        let mut arr = [0u8; 32];
        if k.len() == 32 { arr.copy_from_slice(&k); Some(arr) } else { None }
    });

    let mut rev_set = HashSet::new();
    let mut not_rev_set = HashSet::new();
    if let Some(r) = &revoked {
        for h in r {
            if let Ok(bytes) = hex::decode(h)
                && bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    rev_set.insert(arr);
            }
        }
    }
    if let Some(nr) = &not_revoked {
        for h in nr {
            if let Ok(bytes) = hex::decode(h)
                && bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    not_rev_set.insert(arr);
            }
        }
    }

    let store = PyTrustStore {
        ed_vk,
        comp_pk: None,
        chain_cache,
        trusted_log_key: tlk,
        revoked: rev_set,
        not_revoked: not_rev_set,
        checkpoint_timestamp,
    };

    let result = verify_statement_with_warnings(cose, &store);
    let d = pyo3::types::PyDict::new(py);
    match result {
        Ok((stmt, warnings)) => {
            d.set_item("valid", true)?;
            if let Ok(payload) = stmt.decode_payload() {
                d.set_item("payload", payload_to_dict(py, &payload)?)?;
            }
            let warn_list: Vec<String> = warnings_to_vec(&warnings);
            d.set_item("warnings", warn_list)?;
        }
        Err(e) => {
            d.set_item("valid", false)?;
            d.set_item("error", e.to_string())?;
            d.set_item("error_code", error_to_code(&e))?;
            d.set_item("warnings", Vec::<String>::new())?;
        }
    }
    Ok(d.into())
}

/// Decodes a CBOR-encoded Axiom payload into a Payload object.
///
/// Args:
///     cbor: The CBOR-encoded payload bytes.
///
/// Returns:
///     A Payload object with subject, predicate, object, timestamp,
///     lineage, and nonce fields.
///
/// Raises ValueError on malformed CBOR.
#[pyfunction]
fn decode_payload(cbor: &[u8]) -> PyResult<Payload> {
    let p = AxiomPayload::decode(cbor).map_err(py_err)?;
    Ok(Payload {
        subject: p.subject.to_vec(),
        predicate: p.predicate.name().to_string(),
        object: p.object.map(|o| o.to_vec()),
        timestamp: p.timestamp,
        lineage: p.lineage.map(|l| l.to_vec()),
        nonce: p.nonce.map(|n| n.to_vec()),
    })
}

/// Creates a CBOR-encoded Axiom payload from a subject hash and predicate name.
///
/// Args:
///     subject: A 32-byte subject hash.
///     predicate: The predicate name string (e.g. "ATTESTS", "AUTHORS",
///         "DERIVED_FROM", "SUPERSEDES", "REVOKES", "ENDORSES", "APPENDS",
///         "COMPLIES_WITH", "RECOVERS").
///
/// Returns:
///     The CBOR-encoded payload bytes.
///
/// Raises ValueError on invalid subject length or unknown predicate.
#[pyfunction]
fn encode_payload(subject: &[u8], predicate: &str) -> PyResult<Vec<u8>> {
    if subject.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err("subject must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(subject);
    let pred = Predicate::from_u8(match predicate.to_uppercase().as_str() {
        "ATTESTS" => 0, "AUTHORS" => 1, "DERIVED_FROM" => 2,
        "SUPERSEDES" => 3, "REVOKES" => 4, "ENDORSES" => 5,
        "APPENDS" => 6, "COMPLIES_WITH" => 7, "RECOVERS" => 8,
        _ => return Err(pyo3::exceptions::PyValueError::new_err(format!("unknown predicate: {predicate}"))),
    }).map_err(py_err_display)?;
    let payload = AxiomPayload::new(arr, pred);
    Ok(payload.encode())
}

/// Signs a payload CBOR with an Ed25519 signing key.
///
/// Args:
///     payload_cbor: The CBOR-encoded payload bytes.
///     key_bytes: The 32-byte Ed25519 signing key (seed).
///
/// Returns:
///     The COSE-encoded statement bytes.
///
/// Raises ValueError on invalid key length or payload decode failure.
#[pyfunction]
fn sign_ed25519(payload_cbor: &[u8], key_bytes: &[u8]) -> PyResult<Vec<u8>> {
    let arr: [u8; 32] = key_bytes.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("key must be exactly 32 bytes")
    })?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&arr);
    let payload = AxiomPayload::decode(payload_cbor).map_err(py_err)?;
    let stmt = Statement::sign_ed25519(&payload, &sk).map_err(py_err)?;
    Ok(stmt.to_bytes().to_vec())
}

/// Signs a payload CBOR with a Composite (Ed25519 + ML-DSA-65) key pair.
///
/// Args:
///     payload_cbor: The CBOR-encoded payload bytes.
///     ed_key_bytes: The 32-byte Ed25519 signing key (seed).
///     ml_seed_bytes: The 32-byte ML-DSA-65 seed.
///
/// Returns:
///     The COSE-encoded statement bytes.
///
/// Raises ValueError on invalid key length or payload decode failure.
#[pyfunction]
fn sign_composite(payload_cbor: &[u8], ed_key_bytes: &[u8], ml_seed_bytes: &[u8]) -> PyResult<Vec<u8>> {
    let ed_arr: [u8; 32] = ed_key_bytes.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("ed_key must be exactly 32 bytes")
    })?;
    let ml_arr: [u8; 32] = ml_seed_bytes.try_into().map_err(|_| {
        pyo3::exceptions::PyValueError::new_err("ml_seed must be exactly 32 bytes")
    })?;
    let ed_sk = ed25519_dalek::SigningKey::from_bytes(&ed_arr);
    let ml_seed = ml_dsa::Seed::try_from(&ml_arr[..]).map_err(py_err_display)?;
    let ml_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_seed);
    let payload = AxiomPayload::decode(payload_cbor).map_err(py_err)?;
    let stmt = Statement::sign_composite(&payload, &ed_sk, &ml_sk).map_err(py_err)?;
    Ok(stmt.to_bytes().to_vec())
}

/// Encrypts plaintext using a ShreddingKey for PII protection.
///
/// Args:
///     key_bytes: The 32-byte shredding key.
///     plaintext: The plaintext bytes to encrypt.
///
/// Returns:
///     The ciphertext bytes.
///
/// Raises ValueError on invalid key length.
#[pyfunction]
fn encrypt(key_bytes: &[u8], plaintext: &[u8]) -> PyResult<Vec<u8>> {
    let key = ShreddingKey::from_bytes(key_bytes).map_err(py_err)?;
    encrypt_pii(&key, plaintext).map_err(py_err)
}

/// Decrypts ciphertext using a ShreddingKey.
///
/// Args:
///     key_bytes: The 32-byte shredding key.
///     ciphertext: The ciphertext bytes to decrypt.
///
/// Returns:
///     The plaintext bytes.
///
/// Raises ValueError on invalid key length or decryption failure.
#[pyfunction]
fn decrypt(key_bytes: &[u8], ciphertext: &[u8]) -> PyResult<Vec<u8>> {
    let key = ShreddingKey::from_bytes(key_bytes).map_err(py_err)?;
    decrypt_pii(&key, ciphertext).map_err(py_err)
}

/// Performs encrypt-and-commit in one operation for PII shredding.
///
/// Args:
///     key_bytes: The 32-byte shredding key.
///     plaintext: The plaintext bytes to process.
///
/// Returns:
///     A tuple ``(ciphertext, commitment)`` where commitment is the
///     blinding commitment bytes.
///
/// Raises ValueError on invalid key length.
#[pyfunction]
fn shredding_commit_fn(key_bytes: &[u8], plaintext: &[u8]) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let key = ShreddingKey::from_bytes(key_bytes).map_err(py_err)?;
    let (ct, comm) = shredding_commit(&key, plaintext).map_err(py_err)?;
    Ok((ct, comm.to_vec()))
}

#[pymodule]
fn axiom_core_python(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(axiom_version, m)?)?;
    m.add_function(wrap_pyfunction!(verify_ed25519, m)?)?;
    m.add_function(wrap_pyfunction!(verify_composite, m)?)?;
    m.add_function(wrap_pyfunction!(verify_full, m)?)?;
    m.add_function(wrap_pyfunction!(decode_payload, m)?)?;
    m.add_function(wrap_pyfunction!(encode_payload, m)?)?;
    m.add_function(wrap_pyfunction!(sign_ed25519, m)?)?;
    m.add_function(wrap_pyfunction!(sign_composite, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(shredding_commit_fn, m)?)?;
    m.add_class::<Payload>()?;
    Ok(())
}
