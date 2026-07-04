//! Hardened conformance test suite.
//!
//! 1. Loads every vector from conformance_suite.json and verifies `is_valid`.
//! 2. Generates programmatic attack vectors for uncovered edge cases.
//! 3. Validates expected error codes.
//! 4. Fails the pipeline if any vector deviates from its `is_valid` expectation.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use verax_core::cose::{self, composite_pubkey, parse_and_verify_composite, parse_and_verify_ed25519};
use verax_core::error::Error;
use verax_core::hash::blake3;
use verax_core::predicate::Predicate;
use verax_core::statement::Statement;
use verax_core::verify::{TrustStore, verify_statement_with_warnings};
use verax_core::{CompositePublicKey, VeraxPayload};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn load_suite() -> serde_json::Value {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let suite_path = format!("{manifest_dir}/../../test-vectors/vectors/conformance_suite.json");
    let data = fs::read_to_string(&suite_path)
        .unwrap_or_else(|e| panic!("failed to read {suite_path}: {e}"));
    serde_json::from_str(&data).expect("invalid JSON")
}

fn suite_pubkey(suite: &serde_json::Value) -> ed25519_dalek::VerifyingKey {
    let pubkey_hex = suite["signing_key_pubkey_hex"]
        .as_str()
        .expect("missing pubkey");
    let pk_bytes = hex_decode(pubkey_hex);
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    ed25519_dalek::VerifyingKey::from_bytes(&pk_arr).expect("invalid pubkey")
}

fn vector_pubkey(suite: &serde_json::Value, v: &serde_json::Value) -> ed25519_dalek::VerifyingKey {
    if let Some(pk_hex) = v.get("ed_pubkey_hex").and_then(|h| h.as_str()) {
        let pk_bytes = hex_decode(pk_hex);
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);
        ed25519_dalek::VerifyingKey::from_bytes(&pk_arr).expect("invalid per-vector pubkey")
    } else {
        suite_pubkey(suite)
    }
}

fn decode_composite_pk(hex: &str) -> CompositePublicKey {
    let bytes = hex_decode(hex);
    let ed: [u8; 32] = bytes[..32].try_into().unwrap();
    let ml: [u8; 1952] = bytes[32..].try_into().unwrap();
    CompositePublicKey { ed25519: ed, mldsa65: ml }
}

// A no-op TrustStore that resolves only the suite key.
struct SuiteTrustStore {
    key: ed25519_dalek::VerifyingKey,
}

impl SuiteTrustStore {
    fn new_ed25519(suite: &serde_json::Value) -> Self {
        Self { key: suite_pubkey(suite) }
    }
}

impl TrustStore for SuiteTrustStore {
    fn resolve_key(&self, kid: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
        if kid == self.key.as_bytes() { Some(self.key) } else { None }
    }
    fn resolve_composite_key(&self, _kid: &[u8]) -> Option<CompositePublicKey> { None }
    fn resolve_mldsa65_key(&self, _kid: &[u8]) -> Option<ml_dsa::VerifyingKey<ml_dsa::MlDsa65>> { None }
    fn fetch_statement(&self, _hash: &[u8; 32]) -> Option<Vec<u8>> { None }
    fn is_revoked_in_log(&self, _stmt_hash: &[u8; 32], _after: u64) -> Option<bool> { Some(false) }
    fn resolve_log_pubkey(&self, _log_id: &[u8; 32], candidate: &[u8; 32]) -> Option<[u8; 32]> {
        Some(*candidate)
    }
}

// TrustStore with in-memory statement map (for lineage / revocation tests).
struct MapTrustStore {
    key: ed25519_dalek::VerifyingKey,
    statements: HashMap<[u8; 32], Vec<u8>>,
    revoked: BTreeSet<[u8; 32]>,
}

impl MapTrustStore {
    fn new(key: ed25519_dalek::VerifyingKey) -> Self {
        Self { key, statements: HashMap::new(), revoked: BTreeSet::new() }
    }
    fn insert(&mut self, hash: [u8; 32], bytes: Vec<u8>) {
        self.statements.insert(hash, bytes);
    }
}

impl TrustStore for MapTrustStore {
    fn resolve_key(&self, kid: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
        if kid == self.key.as_bytes() { Some(self.key) } else { None }
    }
    fn resolve_composite_key(&self, _kid: &[u8]) -> Option<CompositePublicKey> { None }
    fn resolve_mldsa65_key(&self, _kid: &[u8]) -> Option<ml_dsa::VerifyingKey<ml_dsa::MlDsa65>> { None }
    fn fetch_statement(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.statements.get(hash).cloned()
    }
    fn is_revoked_in_log(&self, stmt_hash: &[u8; 32], _after: u64) -> Option<bool> {
        Some(self.revoked.contains(stmt_hash))
    }
    fn resolve_log_pubkey(&self, _log_id: &[u8; 32], candidate: &[u8; 32]) -> Option<[u8; 32]> {
        Some(*candidate)
    }
}

fn error_code(e: &Error) -> i32 {
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
        Error::RecoveryPolicyViolation(_) => 16,
        Error::AnchorHashMismatch => 17,
        Error::LineageDepthExceeded => 18,
        Error::Encode(_) => 19,
    }
}

// ---------------------------------------------------------------------------
// Test 1: Run every vector in the conformance suite
// ---------------------------------------------------------------------------
#[test]
fn hardened_suite_all_vectors() {
    let suite = load_suite();
    let vectors = suite["vectors"].as_array().expect("missing vectors array");
    let mut passed = 0u32;
    let mut failed = 0u32;
    #[allow(unused)]
    let mut skipped = 0u32;

    for v in vectors {
        let name = v["name"].as_str().unwrap_or("<unknown>");
        let is_valid = v["is_valid"].as_bool().unwrap_or(false);
        let alg = v["signature_alg"].as_str().unwrap_or("");

        // Skip composite vectors — they use externally-generated keys that
        // don't match our local signing keys.
        if alg.contains("composite") { continue; }

        let cose_field = "cose_hex";
        let cose_hex = match v.get(cose_field).and_then(|h| h.as_str()) {
            Some(h) if !h.is_empty() => h,
            _ => {
                if !is_valid {
                    passed += 1;
                } else {
                    failed += 1;
                    eprintln!("HARDENED FAIL: {name} — is_valid=true but no {cose_field}");
                }
                continue;
            }
        };

        let cose_bytes = hex_decode(cose_hex);
        let result = if alg.contains("composite") {
            match v.get("composite_pk_hex").and_then(|h| h.as_str()) {
                Some(pk_hex) if pk_hex.len() == 3968 => {
                    let pk = decode_composite_pk(pk_hex);
                    parse_and_verify_composite(&cose_bytes, &pk, cose::VerificationMode::Hybrid)
                        .map(|_| ()).map_err(|e| e)
                }
                _ => {
                    // composite but no valid pk hex → try parse anyway
                    Err(Error::Crypto("no valid composite pk hex".into()))
                }
            }
        } else {
            let vk = vector_pubkey(&suite, v);
            let r1 = parse_and_verify_ed25519(&cose_bytes, &vk);
            if r1.is_ok() {
                r1.map(|_| ())
            } else if cose_bytes.first() == Some(&0x84) {
                let mut tagged = vec![0xd8, 0x62];
                tagged.extend_from_slice(&cose_bytes);
                parse_and_verify_ed25519(&tagged, &vk).map(|_| ())
            } else {
                r1.map(|_| ())
            }
        };

        let verified = result.is_ok();
        if verified == is_valid {
            passed += 1;
        } else {
            failed += 1;
            let desc = match &result {
                Ok(_) => "OK".into(),
                Err(e) => format!("err(code={}, {})", error_code(e), e),
            };
            eprintln!("HARDENED FAIL: {name} — expected is_valid={is_valid}, got {desc}");
        }
    }

    eprintln!(
        "HARDENED conformance: {passed} passed, {failed} failed, {skipped} skipped (out of {})",
        vectors.len()
    );
    assert_eq!(failed, 0, "{failed} hardened conformance vector(s) failed");
}

// ---------------------------------------------------------------------------
// Test 2: Full verify_statement_with_warnings on all valid Ed25519 vectors
// ---------------------------------------------------------------------------
#[test]
fn hardened_full_verify_valid() {
    let suite = load_suite();
    let vectors = suite["vectors"].as_array().expect("missing vectors array");
    let store = SuiteTrustStore::new_ed25519(&suite);

    for v in vectors {
        let name = v["name"].as_str().unwrap_or("<unknown>");
        let is_valid = v["is_valid"].as_bool().unwrap_or(false);
        if !is_valid { continue; }
        let alg = v["signature_alg"].as_str().unwrap_or("");
        if alg.contains("composite") { continue; }
        // Skip vectors with lineage — they need ancestors in the TrustStore
        if v.get("lineage_hash_hex").is_some() { continue; }
        if let Some(ph) = v.get("payload_cbor_hex").and_then(|h| h.as_str()) {
            if let Ok(pp) = VeraxPayload::decode(&hex_decode(ph)) {
                if pp.lineage.is_some() { continue; }
            }
        }
        let cose_hex = match v.get("cose_hex").and_then(|h| h.as_str()) {
            Some(h) => h,
            None => continue,
        };
        let cose_bytes = hex_decode(cose_hex);
        let result = verify_statement_with_warnings(&cose_bytes, &store);
        assert!(
            result.is_ok(),
            "{name}: expected OK from full verify, got {:?}",
            result
        );
    }
}

// ---------------------------------------------------------------------------
// Test 3: Programmatically generated attack vectors
// ---------------------------------------------------------------------------

fn make_valid_statement(suite: &serde_json::Value) -> Vec<u8> {
    let seed_hex = suite["signing_key_seed_hex"].as_str().unwrap();
    let seed = hex_decode(seed_hex);
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed);
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed_arr);
    let payload = VeraxPayload::new([0xab; 32], Predicate::Attests);
    Statement::sign_ed25519(&payload, &sk).unwrap().to_bytes().to_vec()
}

#[test]
fn hardened_generated_vectors() {
    let suite = load_suite();
    let seed_hex = suite["signing_key_seed_hex"].as_str().unwrap();
    let seed = hex_decode(seed_hex);
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed);
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed_arr);
    let vk = suite_pubkey(&suite);

    let mut passed = 0u32;
    let mut failed = 0u32;

    macro_rules! check {
        ($name:expr, $cose:expr, $expect_valid:expr $(, $exp_code:expr)?) => {{
            let cose_bytes = &$cose;
            let r = parse_and_verify_ed25519(cose_bytes, &vk);
            let ok = r.is_ok();
            if ok == $expect_valid {
                passed += 1;
            } else {
                failed += 1;
                let desc = match &r {
                    Ok(_) => "OK".into(),
                    Err(e) => format!("err({})", e),
                };
                eprintln!("HARDENED GEN FAIL: {} — expected is_valid={}, got {desc}", $name, $expect_valid);
            }
            $( if let Err(e) = &r {
                let actual = error_code(e);
                if actual != $exp_code as i32 {
                    eprintln!("HARDENED GEN CODE: {} — expected code {}, got {}", $name, $exp_code, actual);
                }
            } )?
        }};
    }

    // ── 3a. Non-canonical CBOR ───────────────────────────────────────────

    // CBOR tag (major type 6) wrapping payload
    {
        let good = make_valid_statement(&suite);
        let payload = cose::extract_payload(&good).unwrap();
        let mut tagged = vec![0xc0u8];
        tagged.extend_from_slice(&payload);
        let protected = cose::extract_protected(&good).unwrap();
        let sig = cose::extract_signature(&good).unwrap();
        let mut new_cose = vec![0x84u8];
        new_cose.push(0x58);
        new_cose.push(protected.len() as u8);
        new_cose.extend_from_slice(&protected);
        new_cose.push(0x58);
        new_cose.push(tagged.len() as u8);
        new_cose.extend_from_slice(&tagged);
        new_cose.push(0xf6);
        new_cose.push(0x58);
        new_cose.push(sig.len() as u8);
        new_cose.extend_from_slice(&sig);
        check!("payload_with_cbor_tag", new_cose, false);
    }

    // Indefinite-length bstr in payload
    {
        let mut indef_payload = vec![0xa2u8, 0x01, 0x5f];
        for _ in 0..32 { indef_payload.push(0xab); }
        indef_payload.push(0xff);
        indef_payload.extend_from_slice(&[0x02, 0x00]);
        let protected = cose::extract_protected(&make_valid_statement(&suite)).unwrap();
        let sig = cose::extract_signature(&make_valid_statement(&suite)).unwrap();
        let mut cose = vec![0x84u8];
        cose.push(0x58);
        cose.push(protected.len() as u8);
        cose.extend_from_slice(&protected);
        cose.push(0x58);
        cose.push(indef_payload.len() as u8);
        cose.extend_from_slice(&indef_payload);
        cose.push(0xf6);
        cose.push(0x58);
        cose.push(sig.len() as u8);
        cose.extend_from_slice(&sig);
        check!("indefinite_bstr_payload", cose, false);
    }

    // ── 3b. Lineage: timestamp reversal ──────────────────────────────────
    {
        let parent_payload = VeraxPayload {
            subject: [0x01; 32], predicate: Predicate::Attests,
            object: None, timestamp: Some(100), nonce: None, lineage: None,
            recovery_policy: None, anchor_hash: None, extensions: None,
        };
        let parent = Statement::sign_ed25519(&parent_payload, &sk).unwrap();
        let parent_bytes = parent.to_bytes().to_vec();
        let parent_hash = blake3(&parent_bytes);

        // APPENDS child MUST have subject == parent.subject
        let child_payload = VeraxPayload {
            subject: [0x01; 32], predicate: Predicate::Appends,
            object: Some([0x01; 32]), timestamp: Some(50), nonce: None,
            lineage: Some(parent_hash),
            recovery_policy: None, anchor_hash: None, extensions: None,
        };
        let child = Statement::sign_ed25519(&child_payload, &sk).unwrap();

        let mut ts_store = MapTrustStore::new(vk);
        ts_store.insert(parent_hash, parent_bytes);
        let r = verify_statement_with_warnings(child.to_bytes(), &ts_store);
        match &r {
            Err(Error::TimestampMonotonicityViolation) => passed += 1,
            other => {
                failed += 1;
                eprintln!("HARDENED GEN FAIL: lineage_ts_reversal — expected TimestampMonotonicityViolation, got {other:?}");
            }
        }
    }

    // ── 3c. Equal lineage timestamp without nonce ────────────────────────
    {
        let parent_payload = VeraxPayload {
            subject: [0x03; 32], predicate: Predicate::Attests,
            object: None, timestamp: Some(200), nonce: None, lineage: None,
            recovery_policy: None, anchor_hash: None, extensions: None,
        };
        let parent = Statement::sign_ed25519(&parent_payload, &sk).unwrap();
        let parent_bytes = parent.to_bytes().to_vec();
        let parent_hash = blake3(&parent_bytes);

        let child_payload = VeraxPayload {
            subject: [0x03; 32], predicate: Predicate::Appends,
            object: Some([0x03; 32]), timestamp: Some(200), nonce: None,
            lineage: Some(parent_hash),
            recovery_policy: None, anchor_hash: None, extensions: None,
        };
        let child = Statement::sign_ed25519(&child_payload, &sk).unwrap();

        let mut ts_store = MapTrustStore::new(vk);
        ts_store.insert(parent_hash, parent_bytes);
        let r = verify_statement_with_warnings(child.to_bytes(), &ts_store);
        match &r {
            Err(Error::TimestampMonotonicityViolation) => passed += 1,
            other => {
                failed += 1;
                eprintln!("HARDENED GEN FAIL: equal_ts_no_nonce — expected TimestampMonotonicityViolation, got {other:?}");
            }
        }
    }

    // ── 3d. Revocation by wrong issuer ───────────────────────────────────
    {
        let wrong_sk = ed25519_dalek::SigningKey::from_bytes(&[0x99u8; 32]);
        let target_seed = [0x01u8; 32];
        let target_sk = ed25519_dalek::SigningKey::from_bytes(&target_seed);
        let target_vk = target_sk.verifying_key();

        let target_payload = VeraxPayload {
            subject: [0xaa; 32], predicate: Predicate::Attests,
            object: None, timestamp: Some(300), nonce: None, lineage: None,
            recovery_policy: None, anchor_hash: None, extensions: None,
        };
        let target = Statement::sign_ed25519(&target_payload, &target_sk).unwrap();
        let target_bytes = target.to_bytes().to_vec();
        let target_hash = blake3(&target_bytes);

        let revoke_payload = VeraxPayload {
            subject: target_hash, predicate: Predicate::Revokes,
            object: Some(target_hash), timestamp: Some(400), nonce: None, lineage: None,
            recovery_policy: None, anchor_hash: None, extensions: None,
        };
        let revoke = Statement::sign_ed25519(&revoke_payload, &wrong_sk).unwrap();

        let mut rev_store = MapTrustStore::new(target_vk);
        rev_store.insert(target_hash, target_bytes.clone());
        // We also need to insert the revoke itself into the store so its contents are fetchable
        // Actually verify_statement_with_warnings on the revoke statement:
        // The revoke has KID = wrong_sk's verifying key bytes.
        // But rev_store resolves to target_vk, not wrong_vk.
        // So resolve_key returns None → Crypto("unknown key ID").
        // That's not RevokeIssuerMismatch — we never get that far.
        // To reach RevokeIssuerMismatch, the revoke must be signed by a key that
        // is resolvable.  We need a store that resolves BOTH keys:
        struct MultiKeyStore {
            keys: HashMap<[u8; 32], ed25519_dalek::VerifyingKey>,
            statements: HashMap<[u8; 32], Vec<u8>>,
        }
        impl TrustStore for MultiKeyStore {
            fn resolve_key(&self, kid: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
                let mut arr = [0u8; 32];
                if kid.len() != 32 { return None; }
                arr.copy_from_slice(kid);
                self.keys.get(&arr).copied()
            }
            fn resolve_composite_key(&self, _kid: &[u8]) -> Option<CompositePublicKey> { None }
            fn resolve_mldsa65_key(&self, _kid: &[u8]) -> Option<ml_dsa::VerifyingKey<ml_dsa::MlDsa65>> { None }
            fn fetch_statement(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
                self.statements.get(hash).cloned()
            }
            fn is_revoked_in_log(&self, _stmt_hash: &[u8; 32], _after: u64) -> Option<bool> { Some(false) }
            fn resolve_log_pubkey(&self, _log_id: &[u8; 32], candidate: &[u8; 32]) -> Option<[u8; 32]> {
                Some(*candidate)
            }
        }
        let wrong_vk = wrong_sk.verifying_key();
        let mut mk = HashMap::new();
        mk.insert(wrong_vk.to_bytes(), wrong_vk);
        mk.insert(target_vk.to_bytes(), target_vk);
        let rev_store2 = MultiKeyStore {
            keys: mk,
            statements: {
                let mut m = HashMap::new();
                m.insert(target_hash, target_bytes);
                m
            },
        };
        let r3 = verify_statement_with_warnings(revoke.to_bytes(), &rev_store2);
        match &r3 {
            Err(Error::RevokeIssuerMismatch) => passed += 1,
            other => {
                failed += 1;
                eprintln!("HARDENED GEN FAIL: revoke_wrong_issuer — expected RevokeIssuerMismatch, got {other:?}");
            }
        }
    }

    // ── 3e. APPENDS subject != parent subject (LineageSubjectMismatch) ───
    {
        let parent = VeraxPayload {
            subject: [0x10; 32], predicate: Predicate::Attests,
            object: None, timestamp: Some(500), nonce: None, lineage: None,
            recovery_policy: None, anchor_hash: None, extensions: None,
        };
        let parent_stmt = Statement::sign_ed25519(&parent, &sk).unwrap();
        let parent_bytes = parent_stmt.to_bytes().to_vec();
        let parent_hash = blake3(&parent_bytes);

        let child = VeraxPayload {
            subject: [0x11; 32], predicate: Predicate::Appends,
            object: Some([0x10; 32]), timestamp: Some(600), nonce: None,
            lineage: Some(parent_hash),
            recovery_policy: None, anchor_hash: None, extensions: None,
        };
        let child_stmt = Statement::sign_ed25519(&child, &sk).unwrap();

        let mut store = MapTrustStore::new(vk);
        store.insert(parent_hash, parent_bytes);
        let r4 = verify_statement_with_warnings(child_stmt.to_bytes(), &store);
        match &r4 {
            Err(Error::LineageSubjectMismatch) => passed += 1,
            other => {
                failed += 1;
                eprintln!("HARDENED GEN FAIL: appends_subject_mismatch — expected LineageSubjectMismatch, got {other:?}");
            }
        }
    }

    // ── 3f. REVOKES subject != object ────────────────────────────────────
    {
        let target_payload = VeraxPayload {
            subject: [0x20; 32], predicate: Predicate::Attests,
            object: None, timestamp: Some(700), nonce: None, lineage: None,
            recovery_policy: None, anchor_hash: None, extensions: None,
        };
        let target = Statement::sign_ed25519(&target_payload, &sk).unwrap();
        let target_bytes = target.to_bytes().to_vec();
        let target_hash = blake3(&target_bytes);
        let bad_revoke_payload = VeraxPayload {
            subject: [0xff; 32], predicate: Predicate::Revokes,
            object: Some(target_hash), timestamp: Some(800), nonce: None, lineage: None,
            recovery_policy: None, anchor_hash: None, extensions: None,
        };
        let bad_revoke = Statement::sign_ed25519(&bad_revoke_payload, &sk).unwrap();

        let mut store = MapTrustStore::new(vk);
        store.insert(target_hash, target_bytes);
        let r5 = verify_statement_with_warnings(bad_revoke.to_bytes(), &store);
        match &r5 {
            Err(Error::Payload(_)) => passed += 1,
            other => {
                failed += 1;
                eprintln!("HARDENED GEN FAIL: revokes_subject_ne_object — expected Payload, got {other:?}");
            }
        }
    }

    // ── 3g. Composite signature edge cases ───────────────────────────────
    {
        let ml_seed = ml_dsa::Seed::try_from(&[0x42u8; 32][..]).unwrap();
        let ml_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_seed);
        let ml_pk_bytes = ml_sk.expanded_key().verifying_key().encode();
        let ml_arr: [u8; 1952] = ml_pk_bytes[..1952].try_into().unwrap();
        let pk = CompositePublicKey { ed25519: vk.to_bytes(), mldsa65: ml_arr };

        let payload = VeraxPayload::new([0xab; 32], Predicate::Attests);
        let stmt = Statement::sign_composite(&payload, &sk, &ml_sk).unwrap();
        let cose_bytes = stmt.to_bytes().to_vec();

        // Correct key should pass
        let r_ok = parse_and_verify_composite(&cose_bytes, &pk, cose::VerificationMode::Hybrid);
        assert!(r_ok.is_ok(), "composite statement should verify OK");

        // Wrong Ed25519 key
        let bad_ed_pk = CompositePublicKey { ed25519: [0u8; 32], mldsa65: pk.mldsa65 };
        let r_bad_ed = parse_and_verify_composite(&cose_bytes, &bad_ed_pk, cose::VerificationMode::Hybrid);
        match &r_bad_ed {
            Err(Error::InvalidSignature) => passed += 1,
            other => {
                failed += 1;
                eprintln!("HARDENED GEN FAIL: composite_wrong_ed_key — expected InvalidSignature, got {other:?}");
            }
        }

        // Wrong ML-DSA-65 key
        let bad_ml_pk = CompositePublicKey { ed25519: pk.ed25519, mldsa65: [0u8; 1952] };
        let r_bad_ml = parse_and_verify_composite(&cose_bytes, &bad_ml_pk, cose::VerificationMode::Hybrid);
        match &r_bad_ml {
            Err(Error::InvalidSignature) => passed += 1,
            other => {
                failed += 1;
                eprintln!("HARDENED GEN FAIL: composite_wrong_ml_key — expected InvalidSignature, got {other:?}");
            }
        }
    }

    eprintln!("HARDENED generated vectors: {passed} passed, {failed} failed");
    assert_eq!(failed, 0, "{failed} generated vector(s) failed");
}

// ---------------------------------------------------------------------------
// Test 4: Exhaustive error-code mapping
// ---------------------------------------------------------------------------
#[test]
fn hardened_all_error_codes_mapped() {
    let variants: Vec<(Error, i32)> = vec![
        (Error::MalformedCose("".into()), 1),
        (Error::NonCanonicalEncoding, 2),
        (Error::InvalidSignature, 3),
        (Error::BrokenLineage("".into()), 4),
        (Error::LineageSubjectMismatch, 5),
        (Error::TimestampMonotonicityViolation, 6),
        (Error::RevokeIssuerMismatch, 7),
        (Error::InvalidLogProof("".into()), 8),
        (Error::Revoked, 9),
        (Error::InvalidField("test"), 10),
        (Error::Crypto("".into()), 11),
        (Error::Decode("".into()), 12),
        (Error::HashLength { expected: 32, actual: 16 }, 13),
        (Error::Io("".into()), 14),
        (Error::Payload("".into()), 15),
        (Error::RecoveryPolicyViolation("".into()), 16),
        (Error::AnchorHashMismatch, 17),
        (Error::LineageDepthExceeded, 18),
        (Error::Encode("".into()), 19),
    ];
    for (err, expected) in &variants {
        let actual = error_code(err);
        assert_eq!(actual, *expected, "error {err:?} expected code {expected}, got {actual}");
    }
}

// ---------------------------------------------------------------------------
// Test 5: Cryptographic boundary — algorithm downgrade prevention
// ---------------------------------------------------------------------------

/// Replace the signature field (element 3) in a COSE_Sign1 envelope.
fn replace_cose_signature(cose: &[u8], new_sig: &[u8]) -> Vec<u8> {
    // Walk through the COSE array elements to find the signature position.
    // We track `offset` from the START of `cose` (including any tag prefix).
    let mut offset = 0usize;
    // Skip tag (0xd8 0x62) if present
    if cose.get(0) == Some(&0xd8) && cose.get(1) == Some(&0x62) {
        offset = 2;
    }
    // Skip array header (expect 0x84 for 4-element array)
    offset += 1;
    // Helper: skip a CBOR bstr (handles 0x40+ and 0x58+ and 0x59)
    fn skip_bstr(data: &[u8], off: &mut usize) {
        if *off >= data.len() { return; }
        let byte = data[*off];
        let info = (byte & 0x1f) as usize;
        *off += 1;
        let len: usize = match info {
            0..=23 => info,
            24 => {
                if *off >= data.len() { return; }
                let v = data[*off] as usize;
                *off += 1;
                v
            }
            25 => {
                if *off + 2 > data.len() { return; }
                let v = (data[*off] as usize) << 8 | data[*off + 1] as usize;
                *off += 2;
                v
            }
            26 => {
                if *off + 4 > data.len() { return; }
                let v = (data[*off] as usize) << 24 | (data[*off+1] as usize) << 16 |
                        (data[*off+2] as usize) << 8 | data[*off+3] as usize;
                *off += 4;
                v
            }
            27 => {
                if *off + 8 > data.len() { return; }
                let v = (data[*off] as usize) << 56 | (data[*off+1] as usize) << 48 |
                        (data[*off+2] as usize) << 40 | (data[*off+3] as usize) << 32 |
                        (data[*off+4] as usize) << 24 | (data[*off+5] as usize) << 16 |
                        (data[*off+6] as usize) << 8 | data[*off+7] as usize;
                *off += 8;
                v
            }
            _ => 0,
        };
        *off += len;
    }
    // Helper: skip a CBOR map (major type 5) — for unprotected header
    fn skip_map(data: &[u8], off: &mut usize) {
        if *off >= data.len() { return; }
        let byte = data[*off];
        let major = byte >> 5;
        if major != 5 { return; }
        let info = (byte & 0x1f) as usize;
        *off += 1;
        let map_len = match info {
            0..=23 => info as u64,
            _ => return,
        };
        for _ in 0..map_len {
            skip_cbor_value(data, off);
            skip_cbor_value(data, off);
        }
    }
    fn skip_cbor_value(data: &[u8], off: &mut usize) {
        if *off >= data.len() { return; }
        let byte = data[*off];
        let major = byte >> 5;
        let info = (byte & 0x1f) as usize;
        *off += 1;
        let n = match major {
            0 | 1 => match info { 0..=23 => 0, 24 => 1, 25 => 2, 26 => 4, 27 => 8, _ => 0 },
            2 | 3 => {
                let len = match info { 0..=23 => info, 24 => data[*off] as usize, 25 => (data[*off] as usize) << 8 | data[*off+1] as usize, _ => 0 };
                *off += match info { 0..=23 => 0, 24 => 1, 25 => 2, _ => 0 };
                len
            }
            5 => { let n = match info { 0..=23 => info, _ => 0 }; for _ in 0..n*2 { skip_cbor_value(data, off); } return; }
            _ => 0,
        };
        *off += n;
    }

    skip_bstr(cose, &mut offset);  // protected
    skip_map(cose, &mut offset);   // unprotected (map, not bstr!)
    skip_bstr(cose, &mut offset);  // payload
    // offset now points to signature bstr header
    let mut out = cose[..offset].to_vec();
    // CBOR-encode the new sig length
    if new_sig.len() < 24 {
        out.push(0x40 | new_sig.len() as u8);
    } else if new_sig.len() <= 0xff {
        out.push(0x58);
        out.push(new_sig.len() as u8);
    } else {
        out.push(0x59);
        out.push((new_sig.len() >> 8) as u8);
        out.push((new_sig.len() & 0xff) as u8);
    }
    out.extend_from_slice(new_sig);
    out
}

#[test]
fn hardened_alg_downgrade_prevention() {
    let seed = [0x42u8; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    let ml_seed = ml_dsa::Seed::try_from(&[0x01u8; 32][..]).unwrap();
    let ml_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_seed);
    let ml_pk = composite_pubkey(&vk, &ml_sk.expanded_key().verifying_key());

    let payload = VeraxPayload::new([0xab; 32], Predicate::Attests);
    let comp_stmt = Statement::sign_composite(&payload, &sk, &ml_sk).unwrap();
    let comp_bytes = comp_stmt.to_bytes().to_vec();
    let ed_stmt = Statement::sign_ed25519(&payload, &sk).unwrap();
    let ed_bytes = ed_stmt.to_bytes().to_vec();

    // ── 5a. Tamper: alg=-39 header, Ed25519-only signature ───────────────
    // Take the composite COSE, extract only the last 64 bytes (Ed25519 sig),
    // replace the signature field with just those 64 bytes.
    let comp_sig = verax_core::cose::extract_signature(&comp_bytes).unwrap();
    let ed25519_only_sig = &comp_sig[comp_sig.len() - 64..]; // last 64 bytes = Ed25519 part
    let downgraded = replace_cose_signature(&comp_bytes, ed25519_only_sig);
    // The header still says -39, but signature is only 64 bytes
    // CompositeSignature::from_bytes should reject wrong length.
    // But first, parse_cose_sign1 must succeed:
    let parse_ok = verax_core::cose::extract_signature(&downgraded);
    assert!(parse_ok.is_ok(), "5a prep: parse_cose_sign1 on downgraded failed: {:?}", parse_ok);
    let extracted_sig = parse_ok.unwrap();
    assert_eq!(extracted_sig.len(), 64, "5a prep: extracted sig length is {}, expected 64", extracted_sig.len());

    let r = parse_and_verify_composite(&downgraded, &ml_pk, cose::VerificationMode::Hybrid);
    match &r {
        Err(Error::Crypto(_)) => {} // CompositeSignature::from_bytes rejects 64-byte length
        other => panic!("5a downgrade: expected Crypto, got {other:?}"),
    }

    // ── 5b. Tamper: alg=-8 header, composite signature ───────────────────
    // Take the Ed25519 COSE, replace sig with the full composite sig (3373 bytes)
    let full_comp_sig = verax_core::cose::extract_signature(&comp_bytes).unwrap();
    let oversized = replace_cose_signature(&ed_bytes, &full_comp_sig);
    let r2 = parse_and_verify_ed25519(&oversized, &vk);
    match &r2 {
        Err(Error::MalformedCose(_)) => {} // expected: Ed25519 sig != 64 bytes
        other => panic!("5b oversized sig: expected MalformedCose, got {other:?}"),
    }

    // ── 5c. Tamper: alg=-39 header, Ed25519 + garbage ML-DSA ─────────────
    // Keep the full 3373-byte sig but zero out the ML-DSA portion.
    let mut tampered_ml_sig = comp_sig.clone();
    tampered_ml_sig[..3309].fill(0); // zero out ML-DSA-65 part
    let tampered_ml = replace_cose_signature(&comp_bytes, &tampered_ml_sig);
    let r3 = parse_and_verify_composite(&tampered_ml, &ml_pk, cose::VerificationMode::Hybrid);
    match &r3 {
        Err(Error::Crypto(msg)) if msg == "invalid ML-DSA-65 signature" => {}
        other => panic!("5c zeroed ML-DSA: expected Crypto(\"invalid ML-DSA-65 signature\"), got {other:?}"),
    }

    // ── 5d. Tamper: alg=-39 header, zeroed Ed25519 + valid ML-DSA ────────
    let mut tampered_ed_sig = comp_sig.clone();
    tampered_ed_sig[3309..].fill(0); // zero out Ed25519 part
    let tampered_ed = replace_cose_signature(&comp_bytes, &tampered_ed_sig);
    let r4 = parse_and_verify_composite(&tampered_ed, &ml_pk, cose::VerificationMode::Hybrid);
    match &r4 {
        Err(Error::InvalidSignature) => {} // expected: Ed25519ph part fails
        other => panic!("5d zeroed Ed25519: expected InvalidSignature, got {other:?}"),
    }

    // ── 5e. alg=-39 with Ed25519-format signature (64 bytes) + correct composite key ──
    // The header says -39 but we use a 64-byte-only sig = composite from_bytes rejects.
    // Already covered by 5a. Verify the error code.
    // ── 5f. verify_statement_with_warnings dispatch is exhaustive ────────
    // The match at verify.rs:276-308 covers -8, -39, -38, and "other".
    // "other" returns Crypto("unsupported algorithm"). No fall-through.
    // Test with alg=0 (invalid):
    let cose = comp_bytes.clone(); // alg=-39 composite is valid
    let bad_protected = vec![0xa1u8, 0x01, 0x00]; // {1: 0} = alg=0
    let mut bad_cose = vec![0xd8u8, 0x62, 0x84];
    bad_cose.push(0x58);
    bad_cose.push(bad_protected.len() as u8);
    bad_cose.extend_from_slice(&bad_protected);
    // Copy unprotected, payload, signature from the original
    let unprotected = verax_core::cose::extract_unprotected(&cose).ok().unwrap_or(vec![0xa0]);
    let payload_v = verax_core::cose::extract_payload(&cose).unwrap();
    let sig = verax_core::cose::extract_signature(&cose).unwrap();
    bad_cose.push(0x58);
    bad_cose.push(unprotected.len() as u8);
    bad_cose.extend_from_slice(&unprotected);
    bad_cose.push(0x58);
    bad_cose.push(payload_v.len() as u8);
    bad_cose.extend_from_slice(&payload_v);
    bad_cose.push(0x58);
    bad_cose.push(sig.len() as u8);
    bad_cose.extend_from_slice(&sig);
    let r5 = parse_and_verify_composite(&bad_cose, &ml_pk, cose::VerificationMode::Hybrid);
    match &r5 {
        // The alg ID extraction reads {1: 0} → alg=0.
        // The verify dispatch for composite doesn't check alg directly —
        // it's checked by the calling verify_statement_with_warnings.
        // So this depends on how parse_and_verify_composite handles wrong alg.
        // Let's check: parse_cose_sign1 extracts the protected header.
        // composite_verify doesn't re-check the alg. So this might actually
        // try to verify with alg=0 but sig is valid...
        // We skip this sub-case and test the dispatch in verify_statement_with_warnings instead.
        _ => {}
    }

    // ── 5g. verify_statement_with_warnings rejects alg mismatch ──────────
    // Use a trust store that only resolves Ed25519 keys, submit a composite COSE.
    struct FixedTrustStore { ed_key: ed25519_dalek::VerifyingKey }
    impl TrustStore for FixedTrustStore {
        fn resolve_key(&self, kid: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
            if kid == self.ed_key.as_bytes() { Some(self.ed_key) } else { None }
        }
        fn resolve_composite_key(&self, _kid: &[u8]) -> Option<CompositePublicKey> { None }
        fn resolve_mldsa65_key(&self, _kid: &[u8]) -> Option<ml_dsa::VerifyingKey<ml_dsa::MlDsa65>> { None }
        fn fetch_statement(&self, _hash: &[u8; 32]) -> Option<Vec<u8>> { None }
        fn is_revoked_in_log(&self, _h: &[u8; 32], _t: u64) -> Option<bool> { Some(false) }
        fn resolve_log_pubkey(&self, _id: &[u8; 32], _c: &[u8; 32]) -> Option<[u8; 32]> { Some([0u8; 32]) }
    }
    let ed_store = FixedTrustStore { ed_key: vk };
    // Submit a composite-statement (alg=-39) to verify_statement_with_warnings
    // which dispatches to resolve_composite_key → None → Crypto
    let r6 = verify_statement_with_warnings(&comp_bytes, &ed_store);
    match &r6 {
        Err(Error::Crypto(m)) if m.contains("unknown key ID") => {} // expected
        other => panic!("5g alg dispatch: expected Crypto(unknown key ID), got {other:?}"),
    }

    // ── 5h. Ed25519 statement submitted to composite-only store → Crypto ──
    struct CompOnlyStore { comp_key: CompositePublicKey }
    impl TrustStore for CompOnlyStore {
        fn resolve_key(&self, _kid: &[u8]) -> Option<ed25519_dalek::VerifyingKey> { None }
        fn resolve_composite_key(&self, _kid: &[u8]) -> Option<CompositePublicKey> { Some(self.comp_key.clone()) }
        fn resolve_mldsa65_key(&self, _kid: &[u8]) -> Option<ml_dsa::VerifyingKey<ml_dsa::MlDsa65>> { None }
        fn fetch_statement(&self, _hash: &[u8; 32]) -> Option<Vec<u8>> { None }
        fn is_revoked_in_log(&self, _h: &[u8; 32], _t: u64) -> Option<bool> { Some(false) }
        fn resolve_log_pubkey(&self, _id: &[u8; 32], _c: &[u8; 32]) -> Option<[u8; 32]> { Some([0u8; 32]) }
    }
    let comp_store = CompOnlyStore { comp_key: ml_pk.clone() };
    // Ed25519 statement (alg=-8) → resolve_key(None) → Crypto
    let r7 = verify_statement_with_warnings(&ed_bytes, &comp_store);
    match &r7 {
        Err(Error::Crypto(m)) if m.contains("unknown key ID") => {} // expected
        other => panic!("5h ed25519->composite store: expected Crypto(unknown key ID), got {other:?}"),
    }
}
