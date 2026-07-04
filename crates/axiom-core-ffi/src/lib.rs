use core::ptr;
use std::collections::{HashMap, HashSet};

use ed25519_dalek::VerifyingKey;

use axiom_core::cose::parse_and_verify_composite;
use axiom_core::cose::parse_and_verify_ed25519;
use axiom_core::cose::parse_and_verify_mldsa65_only;
use axiom_core::cose::CompositePublicKey;
use axiom_core::cose::MLDSA65_PK_SIZE;
use axiom_core::cose::VerificationMode;
use axiom_core::error::Error;
use axiom_core::{
    AxiomPayload, Predicate, Statement, TrustStore, VerificationWarnings, Warning,
    hash::blake3, ShreddingKey,
    verify_statement_with_warnings,
    encrypt_pii, decrypt_pii, shredding_commit,
};

fn pk_from_slice(bytes: &[u8]) -> Result<VerifyingKey, Error> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        Error::InvalidField("pubkey must be exactly 32 bytes for Ed25519")
    })?;
    VerifyingKey::from_bytes(&arr).map_err(|e| Error::Crypto(e.to_string()))
}

/// Maps internal error variants to the normative FFI error codes defined in
/// Section B of the Axiom Protocol specification.
///
/// | Code | Name                     |
/// |------|--------------------------|
/// |  1   | MalformedCose            |
/// |  2   | NonCanonicalEncoding     |
/// |  3   | InvalidSignature         |
/// |  4   | BrokenLineage            |
/// |  5   | LineageSubjectMismatch   |
/// |  6   | TimestampMonotonicity    |
/// |  7   | RevokeIssuerMismatch     |
/// |  8   | InvalidLogProof          |
/// |  9   | Revoked                  |
/// | 10   | InvalidField             |
/// | 11   | Crypto                   |
/// | 12   | Decode                   |
/// | 13   | HashLength               |
/// | 14   | Io                       |
/// | 15   | Payload                  |
/// | 16   | Encode                   |
/// | 17   | SpecError                |
/// | 18   | RecoveryGuardianMismatch |
fn error_to_code(e: &Error) -> i32 {
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
        // Code 16 = Encode (CBOR encoding failure). No current code path
        // triggers this because AxiomPayload::encode() is infallible, but
        // the mapping is included for spec completeness.
        Error::Encode(_) => 16,
        // Code 17 = SpecError (protocol-level invariant violation).
        // AnchorHashMismatch and LineageDepthExceeded are both invariant
        // violations caught by the verifier.
        Error::AnchorHashMismatch | Error::LineageDepthExceeded => 17,
        // Code 18 = RecoveryGuardianMismatch (guardian key not in policy).
        Error::RecoveryPolicyViolation(_) => 18,
    }
}

fn make_copy(data: &[u8]) -> *mut u8 {
    if data.is_empty() {
        return ptr::null_mut();
    }
    let ptr = ffi_alloc(data.len());
    if ptr.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
    }
    ptr
}

// Use libc malloc/free for FFI-safe memory management
fn ffi_alloc(size: usize) -> *mut u8 {
    if size == 0 {
        return ptr::null_mut();
    }
    #[cfg(not(target_os = "windows"))]
    unsafe {
        libc::malloc(size) as *mut u8
    }
    #[cfg(target_os = "windows")]
    unsafe {
        let layout = std::alloc::Layout::from_size_align(size, 1).unwrap();
        std::alloc::alloc(layout)
    }
}

fn ffi_free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    #[cfg(not(target_os = "windows"))]
    unsafe {
        libc::free(ptr as *mut core::ffi::c_void);
    }
    #[cfg(target_os = "windows")]
    unsafe {
        let layout = std::alloc::Layout::from_size_align(0, 1).unwrap();
        std::alloc::dealloc(ptr, layout);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn axiom_version() -> *const core::ffi::c_char {
    static VERSION: &str = concat!("axiom-core ", env!("CARGO_PKG_VERSION"));
    static VERSION_CSTRING: core::sync::atomic::AtomicPtr<core::ffi::c_char> =
        core::sync::atomic::AtomicPtr::new(ptr::null_mut());

    let mut stored = VERSION_CSTRING.load(core::sync::atomic::Ordering::Relaxed);
    if stored.is_null() {
        if let Ok(cs) = std::ffi::CString::new(VERSION) {
            let leaked = cs.into_raw();
            match VERSION_CSTRING.compare_exchange(
                ptr::null_mut(),
                leaked,
                core::sync::atomic::Ordering::Relaxed,
                core::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => stored = leaked,
                Err(existing) => {
                    unsafe {
                        drop(std::ffi::CString::from_raw(leaked));
                    }
                    stored = existing;
                }
            }
        }
    }
    stored as *const core::ffi::c_char
}

#[unsafe(no_mangle)]
pub extern "C" fn axiom_verify_mldsa65_only(
    cose_data: *const u8,
    cose_len: usize,
    pubkey_data: *const u8,
    pubkey_len: usize,
    out_payload: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if cose_data.is_null() {
        return error_to_code(&Error::Decode("null cose_data".into()));
    }
    if pubkey_data.is_null() {
        return error_to_code(&Error::Decode("null pubkey_data".into()));
    }
    if out_payload.is_null() || out_len.is_null() {
        return error_to_code(&Error::Decode("null output pointer".into()));
    }
    let cose = unsafe { core::slice::from_raw_parts(cose_data, cose_len) };
    let pk_bytes = unsafe { core::slice::from_raw_parts(pubkey_data, pubkey_len) };
    if pk_bytes.len() != MLDSA65_PK_SIZE {
        return error_to_code(&Error::InvalidField(
            "ML-DSA-65 pubkey must be MLDSA65_PK_SIZE bytes",
        ));
    }
    let pk_arr: [u8; MLDSA65_PK_SIZE] = match pk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            return error_to_code(&Error::InvalidField(
                "ML-DSA-65 pubkey must be exactly MLDSA65_PK_SIZE bytes",
            ))
        }
    };
    let pk_raw = match ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(&pk_arr[..]) {
        Ok(pk) => pk,
        Err(e) => return error_to_code(&Error::Crypto(format!("ML-DSA-65 pubkey parse: {e}"))),
    };
    let pk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&pk_raw);
    let payload = match parse_and_verify_mldsa65_only(cose, &pk) {
        Ok(p) => p,
        Err(e) => return error_to_code(&e),
    };
    let len = payload.len();
    let buf = make_copy(&payload);
    if buf.is_null() {
        return error_to_code(&Error::Io("allocation failed".into()));
    }
    unsafe {
        ptr::write(out_payload, buf);
        ptr::write(out_len, len);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn axiom_verify_ed25519(
    cose_data: *const u8,
    cose_len: usize,
    pubkey_data: *const u8,
    pubkey_len: usize,
    out_payload: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if cose_data.is_null() {
        return error_to_code(&Error::Decode("null cose_data".into()));
    }
    if pubkey_data.is_null() {
        return error_to_code(&Error::Decode("null pubkey_data".into()));
    }
    if out_payload.is_null() || out_len.is_null() {
        return error_to_code(&Error::Decode("null output pointer".into()));
    }
    let cose = unsafe { core::slice::from_raw_parts(cose_data, cose_len) };
    let pk_bytes = unsafe { core::slice::from_raw_parts(pubkey_data, pubkey_len) };
    let pk = match pk_from_slice(pk_bytes) {
        Ok(pk) => pk,
        Err(e) => return error_to_code(&e),
    };
    let payload = match parse_and_verify_ed25519(cose, &pk) {
        Ok(p) => p,
        Err(e) => return error_to_code(&e),
    };
    let len = payload.len();
    let buf = make_copy(&payload);
    if buf.is_null() {
        return error_to_code(&Error::Io("allocation failed".into()));
    }
    unsafe {
        ptr::write(out_payload, buf);
        ptr::write(out_len, len);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn axiom_verify_composite(
    cose_data: *const u8,
    cose_len: usize,
    ed_pubkey_data: *const u8,
    ed_pubkey_len: usize,
    ml_dsa_pubkey_data: *const u8,
    ml_dsa_pubkey_len: usize,
    out_payload: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if cose_data.is_null() {
        return error_to_code(&Error::Decode("null cose_data".into()));
    }
    if ed_pubkey_data.is_null() {
        return error_to_code(&Error::Decode("null ed_pubkey_data".into()));
    }
    if ml_dsa_pubkey_data.is_null() {
        return error_to_code(&Error::Decode("null ml_dsa_pubkey_data".into()));
    }
    if out_payload.is_null() || out_len.is_null() {
        return error_to_code(&Error::Decode("null output pointer".into()));
    }
    let cose = unsafe { core::slice::from_raw_parts(cose_data, cose_len) };
    let ed_bytes = unsafe { core::slice::from_raw_parts(ed_pubkey_data, ed_pubkey_len) };
    let ml_bytes = unsafe { core::slice::from_raw_parts(ml_dsa_pubkey_data, ml_dsa_pubkey_len) };

    let ed_arr: [u8; 32] = match ed_bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            return error_to_code(&Error::InvalidField(
                "Ed25519 pubkey must be exactly 32 bytes",
            ))
        }
    };
    let ml_arr: [u8; MLDSA65_PK_SIZE] = match ml_bytes.try_into() {
        Ok(a) => a,
        Err(_) => {
            return error_to_code(&Error::InvalidField(
                "ML-DSA-65 pubkey must be exactly MLDSA65_PK_SIZE bytes",
            ))
        }
    };
    let comp_pk = CompositePublicKey {
        ed25519: ed_arr,
        mldsa65: ml_arr,
    };
    let payload = match parse_and_verify_composite(cose, &comp_pk, VerificationMode::Hybrid) {
        Ok(p) => p,
        Err(e) => return error_to_code(&e),
    };
    let len = payload.len();
    let buf = make_copy(&payload);
    if buf.is_null() {
        return error_to_code(&Error::Io("allocation failed".into()));
    }
    unsafe {
        ptr::write(out_payload, buf);
        ptr::write(out_len, len);
    }
    0
}

#[repr(C)]
pub struct FfiSlice {
    data: *const u8,
    len: usize,
}

struct FfiTrustStore {
    ed_vk: Option<ed25519_dalek::VerifyingKey>,
    chain_cache: HashMap<[u8; 32], Vec<u8>>,
    trusted_log_key: Option<[u8; 32]>,
    revoked: HashSet<[u8; 32]>,
    not_revoked: HashSet<[u8; 32]>,
    checkpoint_timestamp: Option<u64>,
}

impl TrustStore for FfiTrustStore {
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

#[unsafe(no_mangle)]
pub extern "C" fn axiom_free(ptr: *mut u8) {
    ffi_free(ptr);
}

/// Decodes a CBOR-encoded AxiomPayload into its component fields.
///
/// Matches the C signature specified in Section F of the Axiom Protocol:
/// ```c
/// int axiom_payload_decode(
///     const uint8_t* cbor_data, size_t cbor_len,
///     uint8_t* out_subject, uint32_t* out_predicate,
///     uint8_t* out_has_timestamp, uint64_t* out_timestamp,
///     uint8_t* out_has_object, uint8_t* out_object,
///     uint8_t* out_has_nonce, uint8_t* out_nonce,
///     uint8_t* out_has_lineage, uint8_t* out_lineage);
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn axiom_payload_decode(
    cbor_data: *const u8,
    cbor_len: usize,
    out_subject: *mut u8,
    out_predicate: *mut u32,
    out_has_timestamp: *mut u8,
    out_timestamp: *mut u64,
    out_has_object: *mut u8,
    out_object: *mut u8,
    out_has_nonce: *mut u8,
    out_nonce: *mut u8,
    out_has_lineage: *mut u8,
    out_lineage: *mut u8,
) -> i32 {
    if cbor_data.is_null() {
        return error_to_code(&Error::Decode("null cbor_data".into()));
    }
    if out_subject.is_null()
        || out_predicate.is_null()
        || out_has_timestamp.is_null()
        || out_timestamp.is_null()
        || out_has_object.is_null()
        || out_object.is_null()
        || out_has_nonce.is_null()
        || out_nonce.is_null()
        || out_has_lineage.is_null()
        || out_lineage.is_null()
    {
        return error_to_code(&Error::Decode("null output pointer".into()));
    }
    let cbor = unsafe { core::slice::from_raw_parts(cbor_data, cbor_len) };
    let payload = match AxiomPayload::decode(cbor) {
        Ok(p) => p,
        Err(e) => return error_to_code(&e),
    };
    unsafe {
        ptr::copy_nonoverlapping(payload.subject.as_ptr(), out_subject, 32);
        ptr::write(out_predicate, payload.predicate as u32);
        if let Some(ts) = payload.timestamp {
            ptr::write(out_has_timestamp, 1);
            ptr::write(out_timestamp, ts);
        } else {
            ptr::write(out_has_timestamp, 0);
        }
        if let Some(obj) = &payload.object {
            ptr::write(out_has_object, 1);
            ptr::copy_nonoverlapping(obj.as_ptr(), out_object, 32);
        } else {
            ptr::write(out_has_object, 0);
        }
        if let Some(nonce) = &payload.nonce {
            ptr::write(out_has_nonce, 1);
            ptr::copy_nonoverlapping(nonce.as_ptr(), out_nonce, 32);
        } else {
            ptr::write(out_has_nonce, 0);
        }
        if let Some(lin) = &payload.lineage {
            ptr::write(out_has_lineage, 1);
            ptr::copy_nonoverlapping(lin.as_ptr(), out_lineage, 32);
        } else {
            ptr::write(out_has_lineage, 0);
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn axiom_sign_ed25519(
    payload_data: *const u8,
    payload_len: usize,
    key_data: *const u8,
    key_len: usize,
    out_sig: *mut *mut u8,
    out_sig_len: *mut usize,
) -> i32 {
    if payload_data.is_null() || key_data.is_null() {
        return error_to_code(&Error::Decode("null input".into()));
    }
    if out_sig.is_null() || out_sig_len.is_null() {
        return error_to_code(&Error::Decode("null output pointer".into()));
    }
    let payload_bytes = unsafe { core::slice::from_raw_parts(payload_data, payload_len) };
    let key_bytes = unsafe { core::slice::from_raw_parts(key_data, key_len) };
    if key_bytes.len() != 32 {
        return error_to_code(&Error::InvalidField("ed25519 key must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(key_bytes);
    let sk = ed25519_dalek::SigningKey::from_bytes(&arr);
    let payload = match AxiomPayload::decode(payload_bytes) {
        Ok(p) => p,
        Err(e) => return error_to_code(&e),
    };
    let stmt = match Statement::sign_ed25519(&payload, &sk) {
        Ok(s) => s,
        Err(e) => return error_to_code(&e),
    };
    let sig_bytes = stmt.to_bytes();
    let len = sig_bytes.len();
    let buf = make_copy(&sig_bytes);
    if buf.is_null() {
        return error_to_code(&Error::Io("allocation failed".into()));
    }
    unsafe {
        ptr::write(out_sig, buf);
        ptr::write(out_sig_len, len);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn axiom_sign_composite(
    payload_data: *const u8,
    payload_len: usize,
    ed_key_data: *const u8,
    ed_key_len: usize,
    ml_seed_data: *const u8,
    ml_seed_len: usize,
    out_sig: *mut *mut u8,
    out_sig_len: *mut usize,
) -> i32 {
    if payload_data.is_null() || ed_key_data.is_null() || ml_seed_data.is_null() {
        return error_to_code(&Error::Decode("null input".into()));
    }
    if out_sig.is_null() || out_sig_len.is_null() {
        return error_to_code(&Error::Decode("null output pointer".into()));
    }
    let payload_bytes = unsafe { core::slice::from_raw_parts(payload_data, payload_len) };
    let ed_key_bytes = unsafe { core::slice::from_raw_parts(ed_key_data, ed_key_len) };
    let ml_seed_bytes = unsafe { core::slice::from_raw_parts(ml_seed_data, ml_seed_len) };
    if ed_key_bytes.len() != 32 {
        return error_to_code(&Error::InvalidField("ed key must be 32 bytes"));
    }
    if ml_seed_bytes.len() != 32 {
        return error_to_code(&Error::InvalidField("ml seed must be 32 bytes"));
    }
    let mut ed_arr = [0u8; 32];
    ed_arr.copy_from_slice(ed_key_bytes);
    let ed_sk = ed25519_dalek::SigningKey::from_bytes(&ed_arr);
    let ml_seed = match ml_dsa::Seed::try_from(ml_seed_bytes) {
        Ok(s) => s,
        Err(e) => return error_to_code(&Error::Crypto(format!("ml seed: {e}"))),
    };
    let ml_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_seed);
    let payload = match AxiomPayload::decode(payload_bytes) {
        Ok(p) => p,
        Err(e) => return error_to_code(&e),
    };
    let stmt = match Statement::sign_composite(&payload, &ed_sk, &ml_sk) {
        Ok(s) => s,
        Err(e) => return error_to_code(&e),
    };
    let sig_bytes = stmt.to_bytes();
    let len = sig_bytes.len();
    let buf = make_copy(&sig_bytes);
    if buf.is_null() {
        return error_to_code(&Error::Io("allocation failed".into()));
    }
    unsafe {
        ptr::write(out_sig, buf);
        ptr::write(out_sig_len, len);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn axiom_encrypt_pii(
    key_data: *const u8,
    key_len: usize,
    plaintext_data: *const u8,
    plaintext_len: usize,
    out_ct: *mut *mut u8,
    out_ct_len: *mut usize,
) -> i32 {
    if key_data.is_null() || plaintext_data.is_null() {
        return error_to_code(&Error::Decode("null input".into()));
    }
    if out_ct.is_null() || out_ct_len.is_null() {
        return error_to_code(&Error::Decode("null output pointer".into()));
    }
    let key_bytes = unsafe { core::slice::from_raw_parts(key_data, key_len) };
    let plaintext = unsafe { core::slice::from_raw_parts(plaintext_data, plaintext_len) };
    let key = match ShreddingKey::from_bytes(key_bytes) {
        Ok(k) => k,
        Err(e) => return error_to_code(&e),
    };
    let ct = match encrypt_pii(&key, plaintext) {
        Ok(c) => c,
        Err(e) => return error_to_code(&e),
    };
    let len = ct.len();
    let buf = make_copy(&ct);
    if buf.is_null() {
        return error_to_code(&Error::Io("allocation failed".into()));
    }
    unsafe {
        ptr::write(out_ct, buf);
        ptr::write(out_ct_len, len);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn axiom_decrypt_pii(
    key_data: *const u8,
    key_len: usize,
    ct_data: *const u8,
    ct_len: usize,
    out_pt: *mut *mut u8,
    out_pt_len: *mut usize,
) -> i32 {
    if key_data.is_null() || ct_data.is_null() {
        return error_to_code(&Error::Decode("null input".into()));
    }
    if out_pt.is_null() || out_pt_len.is_null() {
        return error_to_code(&Error::Decode("null output pointer".into()));
    }
    let key_bytes = unsafe { core::slice::from_raw_parts(key_data, key_len) };
    let ct = unsafe { core::slice::from_raw_parts(ct_data, ct_len) };
    let key = match ShreddingKey::from_bytes(key_bytes) {
        Ok(k) => k,
        Err(e) => return error_to_code(&e),
    };
    let pt = match decrypt_pii(&key, ct) {
        Ok(p) => p,
        Err(e) => return error_to_code(&e),
    };
    let len = pt.len();
    let buf = make_copy(&pt);
    if buf.is_null() {
        return error_to_code(&Error::Io("allocation failed".into()));
    }
    unsafe {
        ptr::write(out_pt, buf);
        ptr::write(out_pt_len, len);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn axiom_shredding_commit(
    key_data: *const u8,
    key_len: usize,
    plaintext_data: *const u8,
    plaintext_len: usize,
    out_ct: *mut *mut u8,
    out_ct_len: *mut usize,
    out_comm: *mut *mut u8,
    out_comm_len: *mut usize,
) -> i32 {
    if key_data.is_null() || plaintext_data.is_null() {
        return error_to_code(&Error::Decode("null input".into()));
    }
    if out_ct.is_null() || out_ct_len.is_null() || out_comm.is_null() || out_comm_len.is_null() {
        return error_to_code(&Error::Decode("null output pointer".into()));
    }
    let key_bytes = unsafe { core::slice::from_raw_parts(key_data, key_len) };
    let plaintext = unsafe { core::slice::from_raw_parts(plaintext_data, plaintext_len) };
    let key = match ShreddingKey::from_bytes(key_bytes) {
        Ok(k) => k,
        Err(e) => return error_to_code(&e),
    };
    let (ct, comm) = match shredding_commit(&key, plaintext) {
        Ok(c) => c,
        Err(e) => return error_to_code(&e),
    };
    let ct_len = ct.len();
    let ct_buf = make_copy(&ct);
    if ct_buf.is_null() {
        return error_to_code(&Error::Io("allocation failed".into()));
    }
    let comm_buf = make_copy(&comm);
    if comm_buf.is_null() {
        ffi_free(ct_buf);
        return error_to_code(&Error::Io("allocation failed".into()));
    }
    unsafe {
        ptr::write(out_ct, ct_buf);
        ptr::write(out_ct_len, ct_len);
        ptr::write(out_comm, comm_buf);
        ptr::write(out_comm_len, 32);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn axiom_encode_payload(
    subject_data: *const u8,
    subject_len: usize,
    predicate: u32,
    out_cbor: *mut *mut u8,
    out_cbor_len: *mut usize,
) -> i32 {
    if subject_data.is_null() {
        return error_to_code(&Error::Decode("null subject".into()));
    }
    if out_cbor.is_null() || out_cbor_len.is_null() {
        return error_to_code(&Error::Decode("null output pointer".into()));
    }
    let subject_bytes = unsafe { core::slice::from_raw_parts(subject_data, subject_len) };
    if subject_bytes.len() != 32 {
        return error_to_code(&Error::InvalidField("subject must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(subject_bytes);
    let pred = match Predicate::from_u8(predicate as u8) {
        Ok(p) => p,
        Err(e) => return error_to_code(&e),
    };
    let payload = AxiomPayload::new(arr, pred);
    let cbor = payload.encode();
    let len = cbor.len();
    let buf = make_copy(&cbor);
    if buf.is_null() {
        return error_to_code(&Error::Io("allocation failed".into()));
    }
    unsafe {
        ptr::write(out_cbor, buf);
        ptr::write(out_cbor_len, len);
    }
    0
}

#[repr(C)]
pub struct FfiVerifyResult {
    pub return_code: i32,
    pub payload: *mut u8,
    pub payload_len: usize,
    pub warnings: *mut u8,
    pub warnings_len: usize,
}

fn hex_hash_to_bytes(h: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(h).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

fn warnings_to_hex_csv(warnings: &VerificationWarnings) -> String {
    let parts: Vec<&str> = warnings.warnings.iter().map(|w| match w {
        Warning::TemporalEvidenceMissing => "temporal_evidence_missing",
        Warning::RevocationStatusUnknown => "revocation_status_unknown",
        Warning::StaleSth { .. } => "stale_sth",
    }).collect();
    if parts.is_empty() {
        return String::new();
    }
    parts.join(",")
}

#[unsafe(no_mangle)]
pub extern "C" fn axiom_verify_full(
    cose_data: *const u8,
    cose_len: usize,
    pubkey_data: *const u8,
    pubkey_len: usize,
    trusted_log_key_data: *const u8,
    trusted_log_key_len: usize,
    chain_slices: *const FfiSlice,
    chain_count: usize,
    revoked_csv: *const core::ffi::c_char,
    not_revoked_csv: *const core::ffi::c_char,
    checkpoint_timestamp: u64,
    out_result: *mut FfiVerifyResult,
) -> i32 {
    if cose_data.is_null() || pubkey_data.is_null() {
        return error_to_code(&Error::Decode("null input".into()));
    }
    if out_result.is_null() {
        return error_to_code(&Error::Decode("null output pointer".into()));
    }
    let cose = unsafe { core::slice::from_raw_parts(cose_data, cose_len) };
    let pk_bytes = unsafe { core::slice::from_raw_parts(pubkey_data, pubkey_len) };
    let ed_vk = if pk_bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(pk_bytes);
        ed25519_dalek::VerifyingKey::from_bytes(&arr).ok()
    } else {
        None
    };
    let tlk = if !trusted_log_key_data.is_null() && trusted_log_key_len == 32 {
        let mut arr = [0u8; 32];
        unsafe { ptr::copy_nonoverlapping(trusted_log_key_data, arr.as_mut_ptr(), 32); }
        Some(arr)
    } else {
        None
    };
    let mut chain_cache = HashMap::new();
    if !chain_slices.is_null() {
        let slices = unsafe { core::slice::from_raw_parts(chain_slices, chain_count) };
        for slice in slices {
            if !slice.data.is_null() && slice.len > 0 {
                let stmt_bytes = unsafe { core::slice::from_raw_parts(slice.data, slice.len) };
                let h = blake3(stmt_bytes);
                chain_cache.insert(h, stmt_bytes.to_vec());
            }
        }
    }
    let mut rev_set = HashSet::new();
    if !revoked_csv.is_null() {
        let c_str = unsafe { std::ffi::CStr::from_ptr(revoked_csv) };
        if let Ok(s) = c_str.to_str() {
            if !s.is_empty() {
                for h in s.split(',') {
                    if let Some(arr) = hex_hash_to_bytes(h.trim()) {
                        rev_set.insert(arr);
                    }
                }
            }
        }
    }
    let mut not_rev_set = HashSet::new();
    if !not_revoked_csv.is_null() {
        let c_str = unsafe { std::ffi::CStr::from_ptr(not_revoked_csv) };
        if let Ok(s) = c_str.to_str() {
            if !s.is_empty() {
                for h in s.split(',') {
                    if let Some(arr) = hex_hash_to_bytes(h.trim()) {
                        not_rev_set.insert(arr);
                    }
                }
            }
        }
    }
    let store = FfiTrustStore {
        ed_vk,
        chain_cache,
        trusted_log_key: tlk,
        revoked: rev_set,
        not_revoked: not_rev_set,
        checkpoint_timestamp: if checkpoint_timestamp > 0 { Some(checkpoint_timestamp) } else { None },
    };
    match verify_statement_with_warnings(cose, &store) {
        Ok((stmt, warnings)) => {
            let payload = match stmt.decode_payload() {
                Ok(p) => p.encode(),
                Err(_) => Vec::new(),
            };
            let warn_str = warnings_to_hex_csv(&warnings);
            let warn_bytes = warn_str.into_bytes();
            let payload_buf = make_copy(&payload);
            let warn_buf = make_copy(&warn_bytes);
            unsafe {
                ptr::write(out_result, FfiVerifyResult {
                    return_code: 0,
                    payload: payload_buf,
                    payload_len: payload.len(),
                    warnings: warn_buf,
                    warnings_len: warn_bytes.len(),
                });
            }
            0
        }
        Err(e) => {
            let code = error_to_code(&e);
            unsafe {
                ptr::write(out_result, FfiVerifyResult {
                    return_code: code,
                    payload: ptr::null_mut(),
                    payload_len: 0,
                    warnings: ptr::null_mut(),
                    warnings_len: 0,
                });
            }
            code
        }
    }
}
