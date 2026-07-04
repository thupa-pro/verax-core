use std::collections::{HashMap, HashSet};

use napi_derive::napi;
use napi::bindgen_prelude::*;

use axiom_core::{
    AxiomPayload, Predicate, Statement, TrustStore, VerificationWarnings, Warning,
    CompositePublicKey, cose, hash::blake3,
    verify_statement_with_warnings,
    encrypt_pii, decrypt_pii, ShreddingKey,
};
use axiom_core::shredding_commit as core_shredding_commit;

fn map_err<E: std::fmt::Display>(e: E) -> napi::Error {
    napi::Error::from_reason(e.to_string())
}

#[napi(object)]
#[derive(Clone)]
pub struct JsPayload {
    pub subject: Buffer,
    pub predicate: String,
    pub object: Option<Buffer>,
    pub timestamp: Option<i64>,
    pub lineage: Option<Buffer>,
    pub nonce: Option<Buffer>,
    pub anchor_hash: Option<Buffer>,
}

#[napi(object)]
pub struct JsVerificationResult {
    pub valid: bool,
    pub payload: Option<JsPayload>,
    pub warnings: Vec<String>,
    pub error: Option<String>,
    /// Normative error code (1-18) per Section B of the Axiom spec.
    /// 0 on success; absent if valid == true.
    pub error_code: Option<i32>,
}

struct NapiTrustStore {
    ed_vk: Option<ed25519_dalek::VerifyingKey>,
    chain_cache: HashMap<[u8; 32], Vec<u8>>,
    trusted_log_key: Option<[u8; 32]>,
    revoked: HashSet<[u8; 32]>,
    not_revoked: HashSet<[u8; 32]>,
    checkpoint_timestamp: Option<u64>,
}

impl TrustStore for NapiTrustStore {
    fn resolve_key(&self, _kid: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
        self.ed_vk
    }

    fn resolve_composite_key(&self, _kid: &[u8]) -> Option<CompositePublicKey> {
        None
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

fn payload_to_js(payload: &AxiomPayload) -> JsPayload {
    JsPayload {
        subject: payload.subject.to_vec().into(),
        predicate: payload.predicate.name().to_string(),
        object: payload.object.as_ref().map(|o| o.to_vec().into()),
        timestamp: payload.timestamp.map(|t| t as i64),
        lineage: payload.lineage.as_ref().map(|l| l.to_vec().into()),
        nonce: payload.nonce.as_ref().map(|n| n.to_vec().into()),
        anchor_hash: payload.anchor_hash.as_ref().map(|a| a.to_vec().into()),
    }
}

#[napi]
pub fn version() -> String {
    concat!("axiom-core ", env!("CARGO_PKG_VERSION")).to_string()
}

#[napi]
pub fn verify_ed25519(cose: Buffer, pubkey: Buffer) -> Result<Buffer> {
    let arr: [u8; 32] = pubkey.as_ref().try_into().map_err(|_| {
        napi::Error::from_reason("pubkey must be exactly 32 bytes")
    })?;
    let pk = ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    let payload = cose::parse_and_verify_ed25519(cose.as_ref(), &pk).map_err(map_err)?;
    Ok(payload.into())
}

#[napi]
pub fn verify_composite(cose: Buffer, ed_pubkey: Buffer, ml_dsa_pubkey: Buffer) -> Result<Buffer> {
    let ed_arr: [u8; 32] = ed_pubkey.as_ref().try_into().map_err(|_| {
        napi::Error::from_reason("ed_pubkey must be exactly 32 bytes")
    })?;
    let ml_arr: [u8; 1952] = ml_dsa_pubkey.as_ref().try_into().map_err(|_| {
        napi::Error::from_reason("ml_dsa_pubkey must be exactly 1952 bytes")
    })?;
    let comp_pk = CompositePublicKey {
        ed25519: ed_arr,
        mldsa65: ml_arr,
    };
    let payload = cose::parse_and_verify_composite(
        cose.as_ref(), &comp_pk, axiom_core::cose::VerificationMode::Hybrid,
    ).map_err(map_err)?;
    Ok(payload.into())
}

#[napi]
pub fn verify_full(
    cose: Buffer,
    pubkey: Buffer,
    chain_statements: Option<Vec<Buffer>>,
    trusted_log_key: Option<Buffer>,
    revoked: Option<Vec<String>>,
    not_revoked: Option<Vec<String>>,
    checkpoint_timestamp: Option<i64>,
) -> Result<JsVerificationResult> {
    let ed_arr: [u8; 32] = pubkey.as_ref().try_into().map_err(|_| {
        napi::Error::from_reason("pubkey must be exactly 32 bytes")
    })?;
    let ed_vk = ed25519_dalek::VerifyingKey::from_bytes(&ed_arr)
        .map_err(|e| napi::Error::from_reason(e.to_string())).ok();

    let mut chain_cache = HashMap::new();
    if let Some(stmts) = &chain_statements {
        for stmt_bytes in stmts {
            let h = blake3(stmt_bytes.as_ref());
            chain_cache.insert(h, stmt_bytes.as_ref().to_vec());
        }
    }

    let tlk = trusted_log_key.and_then(|k| {
        let arr: [u8; 32] = k.as_ref().try_into().ok()?;
        Some(arr)
    });

    let mut rev_set = HashSet::new();
    let mut not_rev_set = HashSet::new();
    if let Some(r) = &revoked {
        for h in r {
            if let Ok(bytes) = hex::decode(h) {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    rev_set.insert(arr);
                }
            }
        }
    }
    if let Some(nr) = &not_revoked {
        for h in nr {
            if let Ok(bytes) = hex::decode(h) {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    not_rev_set.insert(arr);
                }
            }
        }
    }

    let store = NapiTrustStore {
        ed_vk,
        chain_cache,
        trusted_log_key: tlk,
        revoked: rev_set,
        not_revoked: not_rev_set,
        checkpoint_timestamp: checkpoint_timestamp.map(|t| t as u64),
    };

    match verify_statement_with_warnings(cose.as_ref(), &store) {
        Ok((stmt, warnings)) => {
            let payload = stmt.decode_payload().ok().map(|p| payload_to_js(&p));
            Ok(JsVerificationResult {
                valid: true,
                payload,
                warnings: warnings_to_vec(&warnings),
                error: None,
                error_code: None,
            })
        }
        Err(e) => Ok(JsVerificationResult {
            valid: false,
            payload: None,
            warnings: vec![],
            error: Some(e.to_string()),
            error_code: Some(error_to_code(&e)),
        }),
    }
}

#[napi]
pub fn decode_payload(cbor: Buffer) -> Result<JsPayload> {
    let p = AxiomPayload::decode(cbor.as_ref()).map_err(map_err)?;
    Ok(payload_to_js(&p))
}

#[napi]
pub fn encode_payload(subject: Buffer, predicate: String) -> Result<Buffer> {
    let arr: [u8; 32] = subject.as_ref().try_into().map_err(|_| {
        napi::Error::from_reason("subject must be exactly 32 bytes")
    })?;
    let pred = Predicate::from_u8(match predicate.to_uppercase().as_str() {
        "ATTESTS" => 0, "AUTHORS" => 1, "DERIVED_FROM" => 2,
        "SUPERSEDES" => 3, "REVOKES" => 4, "ENDORSES" => 5,
        "APPENDS" => 6, "COMPLIES_WITH" => 7, "RECOVERS" => 8,
        _ => return Err(napi::Error::from_reason(format!("unknown predicate: {predicate}"))),
    }).map_err(map_err)?;
    let payload = AxiomPayload::new(arr, pred);
    Ok(payload.encode().into())
}

#[napi]
pub fn sign_ed25519(payload_cbor: Buffer, key_bytes: Buffer) -> Result<Buffer> {
    let arr: [u8; 32] = key_bytes.as_ref().try_into().map_err(|_| {
        napi::Error::from_reason("key must be exactly 32 bytes")
    })?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&arr);
    let payload = AxiomPayload::decode(payload_cbor.as_ref()).map_err(map_err)?;
    let stmt = Statement::sign_ed25519(&payload, &sk).map_err(map_err)?;
    Ok(stmt.to_bytes().to_vec().into())
}

#[napi]
pub fn sign_composite(payload_cbor: Buffer, ed_key_bytes: Buffer, ml_seed_bytes: Buffer) -> Result<Buffer> {
    let ed_arr: [u8; 32] = ed_key_bytes.as_ref().try_into().map_err(|_| {
        napi::Error::from_reason("ed_key must be exactly 32 bytes")
    })?;
    let ml_arr: [u8; 32] = ml_seed_bytes.as_ref().try_into().map_err(|_| {
        napi::Error::from_reason("ml_seed must be exactly 32 bytes")
    })?;
    let ed_sk = ed25519_dalek::SigningKey::from_bytes(&ed_arr);
    let ml_seed = ml_dsa::Seed::try_from(&ml_arr[..]).map_err(map_err)?;
    let ml_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_seed);
    let payload = AxiomPayload::decode(payload_cbor.as_ref()).map_err(map_err)?;
    let stmt = Statement::sign_composite(&payload, &ed_sk, &ml_sk).map_err(map_err)?;
    Ok(stmt.to_bytes().to_vec().into())
}

#[napi]
pub fn encrypt(key_bytes: Buffer, plaintext: Buffer) -> Result<Buffer> {
    let key = ShreddingKey::from_bytes(key_bytes.as_ref()).map_err(map_err)?;
    encrypt_pii(&key, plaintext.as_ref()).map_err(map_err).map(|c| c.into())
}

#[napi]
pub fn decrypt(key_bytes: Buffer, ciphertext: Buffer) -> Result<Buffer> {
    let key = ShreddingKey::from_bytes(key_bytes.as_ref()).map_err(map_err)?;
    decrypt_pii(&key, ciphertext.as_ref()).map_err(map_err).map(|p| p.into())
}

#[napi]
pub fn shredding_commit_fn(key_bytes: Buffer, plaintext: Buffer) -> Result<Vec<Buffer>> {
    let key = ShreddingKey::from_bytes(key_bytes.as_ref()).map_err(map_err)?;
    let (ct, comm) = core_shredding_commit(&key, plaintext.as_ref()).map_err(map_err)?;
    Ok(vec![ct.into(), comm.to_vec().into()])
}
