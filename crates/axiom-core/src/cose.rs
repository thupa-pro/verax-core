use alloc::format;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::result::Result as CoreResult;
use ed25519_dalek::ed25519::signature::Signer as _;
use ed25519_dalek::ed25519::signature::Verifier as _;
use ml_dsa::Keypair;
use sha2::Digest as _;

use crate::error::{Error, Result};

const CONTEXT_STRING: &[u8] = b"Axiom-Provenance-v1";

fn build_protected_header(alg_id: i64, kid: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    crate::cbor::encode_uint_head(&mut buf, 0xa0, 2);
    crate::cbor::encode_uint_head(&mut buf, 0x00, 1);
    if alg_id < 0 {
        crate::cbor::encode_negative_int(&mut buf, alg_id);
    } else {
        crate::cbor::encode_uint(&mut buf, alg_id as u64);
    }
    crate::cbor::encode_uint_head(&mut buf, 0x00, 4);
    crate::cbor::encode_uint_head(&mut buf, 0x40, kid.len() as u64);
    buf.extend_from_slice(kid);
    buf
}

fn build_sig_structure(protected: &[u8], external_aad: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    crate::cbor::encode_uint_head(&mut buf, 0x80, 4);
    buf.push(0x6a);
    buf.extend_from_slice(b"Signature1");
    crate::cbor::encode_uint_head(&mut buf, 0x40, protected.len() as u64);
    buf.extend_from_slice(protected);
    crate::cbor::encode_uint_head(&mut buf, 0x40, external_aad.len() as u64);
    buf.extend_from_slice(external_aad);
    crate::cbor::encode_uint_head(&mut buf, 0x40, payload.len() as u64);
    buf.extend_from_slice(payload);
    buf
}

fn build_external_aad(unprotected: &[u8]) -> Vec<u8> {
    crate::hash::blake3(unprotected).to_vec()
}

type CosSign1Parts = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn parse_cose_sign1(data: &[u8]) -> Result<CosSign1Parts> {
    let mut offset = 0;
    if offset >= data.len() {
        return Err(Error::MalformedCose("empty data".into()));
    }

    // Handle CBOR tag 98 (COSE_Sign1 per RFC 9052): 0xd8 0x62
    let byte = data[offset];
    if byte == 0xd8 {
        // Major type 6, info=25 → 1-byte tag number follows
        offset += 1;
        if offset >= data.len() {
            return Err(Error::MalformedCose("truncated tag".into()));
        }
        let tag_num = data[offset];
        offset += 1;
        if tag_num != 98 {
            return Err(Error::MalformedCose(format!("expected tag 98 (COSE_Sign1), got tag {tag_num}")));
        }
    }

    if offset >= data.len() {
        return Err(Error::MalformedCose("no data after tag".into()));
    }
    let byte = data[offset];
    let major = byte >> 5;
    let info = (byte & 0x1f) as usize;
    offset += 1;

    if major != 4 {
        return Err(Error::MalformedCose(format!("expected array, got major {major}")));
    }

    let len = match info {
        0..=23 => info,
        24..=27 => {
            let nbytes = 1 << (info - 24);
            if offset + nbytes > data.len() {
                return Err(Error::MalformedCose("truncated array length".into()));
            }
            let mut len = 0usize;
            for i in 0..nbytes {
                len = (len << 8) | data[offset + i] as usize;
            }
            offset += nbytes;
            len
        }
        _ => return Err(Error::MalformedCose("reserved array info".into())),
    };

    if len != 4 {
        return Err(Error::MalformedCose(format!("COSE_Sign1 must have 4 elements, got {len}")));
    }

    let protected = crate::cbor::decode_bstr(data, &mut offset)?;
    let unprotected = decode_unprotected_header(data, &mut offset)?;
    let payload = crate::cbor::decode_bstr(data, &mut offset)?;
    let signature = crate::cbor::decode_bstr(data, &mut offset)?;

    Ok((protected, unprotected, payload, signature))
}

fn decode_unprotected_header(data: &[u8], offset: &mut usize) -> Result<Vec<u8>> {
    if *offset >= data.len() {
        return Err(Error::MalformedCose("truncated unprotected header".into()));
    }
    let start = *offset;
    let byte = data[*offset];
    let major = byte >> 5;
    if major != 5 {
        return Err(Error::MalformedCose("unprotected header must be a map".into()));
    }
    let info = (byte & 0x1f) as usize;
    *offset += 1;

    let map_len = match info {
        0..=23 => info as u64,
        24..=27 => {
            let nbytes = 1 << (info - 24);
            if *offset + nbytes > data.len() {
                return Err(Error::MalformedCose("truncated map length".into()));
            }
            let mut len = 0u64;
            for i in 0..nbytes {
                len = (len << 8) | data[*offset + i] as u64;
            }
            *offset += nbytes;
            len
        }
        _ => return Err(Error::MalformedCose("reserved map info".into())),
    };

    for _ in 0..map_len {
        crate::cbor::skip_value(data, offset)?;
        crate::cbor::skip_value(data, offset)?;
    }
    Ok(data[start..*offset].to_vec())
}

pub fn parse_and_verify_ed25519(data: &[u8], pubkey: &ed25519_dalek::VerifyingKey) -> Result<Vec<u8>> {
    let (protected, unprotected, payload, signature) = parse_cose_sign1(data)?;

    if signature.len() != 64 {
        return Err(Error::MalformedCose("Ed25519 signature must be 64 bytes".into()));
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&signature);

    let external_aad = build_external_aad(&unprotected);
    let to_verify = build_sig_structure(&protected, &external_aad, &payload);
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    pubkey.verify(&to_verify, &sig)?;

    Ok(payload)
}

pub(crate) fn sign_ed25519_with_unprotected(
    payload: &[u8],
    signing_key: &ed25519_dalek::SigningKey,
    unprotected: &[u8],
) -> Result<Vec<u8>> {
    let kid = signing_key.verifying_key().to_bytes();
    let protected = build_protected_header(-8, &kid);
    let external_aad = build_external_aad(unprotected);
    let to_sign = build_sig_structure(&protected, &external_aad, payload);
    let sig: ed25519_dalek::Signature = signing_key.sign(&to_sign);

    let mut buf = Vec::new();
    buf.extend_from_slice(&[0xd8, 0x62]);
    crate::cbor::encode_uint_head(&mut buf, 0x80, 4);
    crate::cbor::encode_uint_head(&mut buf, 0x40, protected.len() as u64);
    buf.extend_from_slice(&protected);
    buf.extend_from_slice(unprotected);
    crate::cbor::encode_uint_head(&mut buf, 0x40, payload.len() as u64);
    buf.extend_from_slice(payload);
    crate::cbor::encode_uint_head(&mut buf, 0x40, 64);
    buf.extend_from_slice(&sig.to_bytes());

    Ok(buf)
}

pub fn sign_ed25519(payload: &[u8], signing_key: &ed25519_dalek::SigningKey) -> Result<Vec<u8>> {
    let unprotected = vec![0xa0]; // empty map {}
    sign_ed25519_with_unprotected(payload, signing_key, &unprotected)
}

pub fn parse_and_verify_composite(
    data: &[u8],
    pubkey: &CompositePublicKey,
    mode: VerificationMode,
) -> Result<Vec<u8>> {
    let (protected, unprotected, payload, signature) = parse_cose_sign1(data)?;

    let comp_sig = CompositeSignature::from_bytes(&signature)?;
    let external_aad = build_external_aad(&unprotected);
    let to_verify = build_sig_structure(&protected, &external_aad, &payload);
    composite_verify(pubkey, &to_verify, &comp_sig, mode)?;

    Ok(payload)
}

pub(crate) fn sign_composite_with_unprotected(
    payload: &[u8],
    ed_sk: &ed25519_dalek::SigningKey,
    ml_sk: &ml_dsa::SigningKey<ml_dsa::MlDsa65>,
    unprotected: &[u8],
) -> Result<Vec<u8>> {
    let ed_pk = ed_sk.verifying_key().to_bytes();
    let ml_pk = ml_sk.verifying_key().encode();
    let mut pk_concat = ml_pk.to_vec();
    pk_concat.extend_from_slice(&ed_pk);
    let kid = crate::hash::blake3(&pk_concat);
    let protected = build_protected_header(-39, &kid);
    let external_aad = build_external_aad(unprotected);
    let to_sign = build_sig_structure(&protected, &external_aad, payload);

    let ed_hasher = sha2::Sha512::new()
        .chain_update(CONTEXT_STRING)
        .chain_update(&to_sign);
    let ed_sig: ed25519_dalek::Signature = ed_sk
        .sign_prehashed(ed_hasher, Some(CONTEXT_STRING))
        .map_err(|e| Error::Crypto(e.to_string()))?;

    let ml_sig: ml_dsa::Signature<ml_dsa::MlDsa65> =
        ml_dsa::Signer::try_sign(ml_sk, &to_sign)
            .map_err(|e| Error::Crypto(format!("ML-DSA-65 sign: {e}")))?;
    let ml_encoded = ml_sig.encode();

    let mut comp_sig = [0u8; COMPOSITE_SIG_SIZE];
    comp_sig[..MLDSA65_SIG_SIZE].copy_from_slice(&ml_encoded);
    comp_sig[MLDSA65_SIG_SIZE..].copy_from_slice(&ed_sig.to_bytes());

    let mut buf = Vec::new();
    buf.extend_from_slice(&[0xd8, 0x62]);
    crate::cbor::encode_uint_head(&mut buf, 0x80, 4);
    crate::cbor::encode_uint_head(&mut buf, 0x40, protected.len() as u64);
    buf.extend_from_slice(&protected);
    buf.extend_from_slice(unprotected);
    crate::cbor::encode_uint_head(&mut buf, 0x40, payload.len() as u64);
    buf.extend_from_slice(payload);
    crate::cbor::encode_uint_head(&mut buf, 0x40, COMPOSITE_SIG_SIZE as u64);
    buf.extend_from_slice(&comp_sig);

    Ok(buf)
}

pub fn sign_composite(
    payload: &[u8],
    ed_sk: &ed25519_dalek::SigningKey,
    ml_sk: &ml_dsa::SigningKey<ml_dsa::MlDsa65>,
) -> Result<Vec<u8>> {
    let unprotected = vec![0xa0]; // empty map {}
    sign_composite_with_unprotected(payload, ed_sk, ml_sk, &unprotected)
}

pub fn extract_payload(data: &[u8]) -> Result<Vec<u8>> {
    parse_cose_sign1(data).map(|(_, _, p, _)| p)
}

pub fn extract_protected(data: &[u8]) -> Result<Vec<u8>> {
    parse_cose_sign1(data).map(|(p, _, _, _)| p)
}

pub fn extract_signature(data: &[u8]) -> Result<Vec<u8>> {
    parse_cose_sign1(data).map(|(_, _, _, s)| s)
}

pub fn extract_unprotected(data: &[u8]) -> Result<Vec<u8>> {
    parse_cose_sign1(data).map(|(_, u, _, _)| u)
}

pub const MLDSA65_PK_SIZE: usize = 1952;
pub const MLDSA65_SIG_SIZE: usize = 3309;
pub const COMPOSITE_SIG_SIZE: usize = MLDSA65_SIG_SIZE + 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMode {
    Hybrid,
    ClassicalOnly,
    PQOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositePublicKey {
    pub ed25519: [u8; 32],
    pub mldsa65: [u8; MLDSA65_PK_SIZE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositeSignature {
    pub ed25519_sig: [u8; 64],
    pub mldsa65_sig: [u8; MLDSA65_SIG_SIZE],
}

impl CompositeSignature {
    pub fn to_bytes(&self) -> [u8; COMPOSITE_SIG_SIZE] {
        let mut out = [0u8; COMPOSITE_SIG_SIZE];
        out[..MLDSA65_SIG_SIZE].copy_from_slice(&self.mldsa65_sig);
        out[MLDSA65_SIG_SIZE..].copy_from_slice(&self.ed25519_sig);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != COMPOSITE_SIG_SIZE {
            return Err(Error::Crypto(format!(
                "composite signature: expected {COMPOSITE_SIG_SIZE} bytes, got {}",
                bytes.len()
            )));
        }
        let mut ml = [0u8; MLDSA65_SIG_SIZE];
        let mut ed = [0u8; 64];
        ml.copy_from_slice(&bytes[..MLDSA65_SIG_SIZE]);
        ed.copy_from_slice(&bytes[MLDSA65_SIG_SIZE..]);
        Ok(Self { ed25519_sig: ed, mldsa65_sig: ml })
    }
}

pub fn composite_sign(
    ed25519_sk: &ed25519_dalek::SigningKey,
    mldsa65_sk: &ml_dsa::SigningKey<ml_dsa::MlDsa65>,
    data: &[u8],
) -> CompositeSignature {
    let ed_hasher = sha2::Sha512::new()
        .chain_update(CONTEXT_STRING)
        .chain_update(data);
    let ed_sig: ed25519_dalek::Signature = ed25519_sk
        .sign_prehashed(ed_hasher, Some(CONTEXT_STRING))
        .expect("Ed25519ph signing should not fail");

    let ml_sig: ml_dsa::Signature<ml_dsa::MlDsa65> =
        ml_dsa::Signer::try_sign(mldsa65_sk, data)
            .expect("ML-DSA-65 signing should not fail");

    CompositeSignature {
        ed25519_sig: ed_sig.to_bytes(),
        mldsa65_sig: ml_sig.encode().into(),
    }
}

pub fn composite_verify(
    pubkey: &CompositePublicKey,
    data: &[u8],
    signature: &CompositeSignature,
    mode: VerificationMode,
) -> CoreResult<(), Error> {
    match mode {
        VerificationMode::Hybrid | VerificationMode::ClassicalOnly => {
            let ed_sig = ed25519_dalek::Signature::from_bytes(&signature.ed25519_sig);
            let ed_vk = ed25519_dalek::VerifyingKey::from_bytes(&pubkey.ed25519)
                .map_err(|_| Error::Crypto("invalid Ed25519 public key".into()))?;
            ed_vk
                .verify_prehashed(
                    sha2::Sha512::new()
                        .chain_update(CONTEXT_STRING)
                        .chain_update(data),
                    Some(CONTEXT_STRING),
                    &ed_sig,
                )
                .map_err(|_| Error::InvalidSignature)?;
        }
        VerificationMode::PQOnly => {}
    }

    match mode {
        VerificationMode::Hybrid | VerificationMode::PQOnly => {
            let ml_vk_raw =
                ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(&pubkey.mldsa65[..])
                    .map_err(|_| Error::Crypto("invalid ML-DSA-65 public key encoding".into()))?;
            let ml_vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&ml_vk_raw);
            let ml_sig_raw =
                ml_dsa::EncodedSignature::<ml_dsa::MlDsa65>::try_from(&signature.mldsa65_sig[..])
                    .map_err(|_| Error::Crypto("invalid ML-DSA-65 signature encoding".into()))?;
            let ml_sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(&ml_sig_raw)
                .ok_or_else(|| Error::Crypto("invalid ML-DSA-65 signature".into()))?;
            ml_dsa::Verifier::verify(&ml_vk, data, &ml_sig)
                .map_err(|_| Error::InvalidSignature)?;
        }
        VerificationMode::ClassicalOnly => {}
    }

    Ok(())
}

pub fn sign_mldsa65_only(
    payload: &[u8],
    sk: &ml_dsa::SigningKey<ml_dsa::MlDsa65>,
) -> Result<Vec<u8>> {
    let vk = sk.verifying_key();
    let kid = vk.encode();
    let protected = build_protected_header(-38, &kid);
    let unprotected = vec![0xa0];
    let external_aad = build_external_aad(&unprotected);
    let to_sign = build_sig_structure(&protected, &external_aad, payload);

    let sig: ml_dsa::Signature<ml_dsa::MlDsa65> =
        ml_dsa::Signer::try_sign(sk, &to_sign)
            .map_err(|e| Error::Crypto(format!("ML-DSA-65 sign: {e}")))?;
    let sig_encoded = sig.encode();

    let mut buf = Vec::new();
    buf.extend_from_slice(&[0xd8, 0x62]);
    crate::cbor::encode_uint_head(&mut buf, 0x80, 4);
    crate::cbor::encode_uint_head(&mut buf, 0x40, protected.len() as u64);
    buf.extend_from_slice(&protected);
    buf.extend_from_slice(&unprotected);
    crate::cbor::encode_uint_head(&mut buf, 0x40, payload.len() as u64);
    buf.extend_from_slice(payload);
    crate::cbor::encode_uint_head(&mut buf, 0x40, sig_encoded.len() as u64);
    buf.extend_from_slice(&sig_encoded);

    Ok(buf)
}

pub fn parse_and_verify_mldsa65_only(
    data: &[u8],
    pubkey: &ml_dsa::VerifyingKey<ml_dsa::MlDsa65>,
) -> Result<Vec<u8>> {
    let (protected, unprotected, payload, signature) = parse_cose_sign1(data)?;
    let sig_raw = ml_dsa::EncodedSignature::<ml_dsa::MlDsa65>::try_from(&signature[..])
        .map_err(|_| Error::Crypto("invalid ML-DSA-65 signature encoding".into()))?;
    let sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(&sig_raw)
        .ok_or_else(|| Error::Crypto("invalid ML-DSA-65 signature".into()))?;
    let external_aad = build_external_aad(&unprotected);
    let to_verify = build_sig_structure(&protected, &external_aad, &payload);
    ml_dsa::Verifier::verify(pubkey, &to_verify, &sig)
        .map_err(|_| Error::InvalidSignature)?;
    Ok(payload)
}

/// Extract the KID (key identifier) from a COSE Sign1 envelope.
///
/// The KID is stored in the protected header as CBOR map key 4.
/// For Axiom statements, this is the 32-byte Ed25519 public key.
pub fn extract_kid(data: &[u8]) -> Result<Vec<u8>> {
    let (protected, _unprotected, _payload, _signature) = parse_cose_sign1(data)?;
    let mut offset = 0;
    let map_len = crate::cbor::decode_map_len(&protected, &mut offset)?;
    for _ in 0..map_len as usize {
        if offset >= protected.len() {
            break;
        }
        let key = crate::cbor::decode_uint(&protected, &mut offset)?;
        if key == 4 {
            return crate::cbor::decode_bstr(&protected, &mut offset);
        }
        crate::cbor::skip_value(&protected, &mut offset)?;
    }
    Err(Error::Crypto("kid not found in COSE protected header".into()))
}

pub fn composite_pubkey(
    ed25519_vk: &ed25519_dalek::VerifyingKey,
    mldsa65_vk: &ml_dsa::VerifyingKey<ml_dsa::MlDsa65>,
) -> CompositePublicKey {
    let encoded = mldsa65_vk.encode();
    CompositePublicKey {
        ed25519: ed25519_vk.to_bytes(),
        mldsa65: encoded.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_ed_keypair() -> (ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
        let seed = [0x42u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn test_sign_verify_ed25519_roundtrip() {
        let (sk, vk) = test_ed_keypair();
        let payload = b"test payload data";
        let cose = sign_ed25519(payload, &sk).unwrap();
        let extracted = parse_and_verify_ed25519(&cose, &vk).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn test_extract_payload() {
        let (sk, _vk) = test_ed_keypair();
        let payload = b"hello axiom";
        let cose = sign_ed25519(payload, &sk).unwrap();
        let ext = extract_payload(&cose).unwrap();
        assert_eq!(ext, payload);
    }

    #[test]
    fn test_wrong_key_fails() {
        let (sk, _vk) = test_ed_keypair();
        let bad_seed = [0x99u8; 32];
        let bad_vk = ed25519_dalek::SigningKey::from_bytes(&bad_seed).verifying_key();
        let payload = b"test";
        let cose = sign_ed25519(payload, &sk).unwrap();
        assert!(parse_and_verify_ed25519(&cose, &bad_vk).is_err());
    }

    #[test]
    fn test_tampered_signature_fails() {
        let (sk, vk) = test_ed_keypair();
        let payload = b"test";
        let mut cose = sign_ed25519(payload, &sk).unwrap();
        let len = cose.len();
        cose[len - 1] ^= 0x01;
        assert!(parse_and_verify_ed25519(&cose, &vk).is_err());
    }

    #[test]
    fn test_composite_sign_verify_roundtrip() {
        let ed_seed = [0x42u8; 32];
        let ed_sk = ed25519_dalek::SigningKey::from_bytes(&ed_seed);
        let ed_vk = ed_sk.verifying_key();

        let mut ml_seed = [0u8; 32];
        for (i, b) in ml_seed.iter_mut().enumerate() {
            *b = i as u8;
        }
        let ml_seed_obj = ml_dsa::Seed::try_from(&ml_seed[..]).unwrap();
        let ml_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_seed_obj);
        let ml_vk = ml_sk.expanded_key().verifying_key();

        let pubkey = composite_pubkey(&ed_vk, &ml_vk);
        let payload = b"composite test payload";

        let cose = sign_composite(payload, &ed_sk, &ml_sk).unwrap();
        let extracted = parse_and_verify_composite(&cose, &pubkey, VerificationMode::Hybrid).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn test_composite_serialization() {
        let ed_seed = [0x42u8; 32];
        let ed_sk = ed25519_dalek::SigningKey::from_bytes(&ed_seed);

        let mut ml_seed = [0u8; 32];
        for (i, b) in ml_seed.iter_mut().enumerate() {
            *b = i as u8;
        }
        let ml_seed_obj = ml_dsa::Seed::try_from(&ml_seed[..]).unwrap();
        let ml_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_seed_obj);

        let data = b"test data for composite";
        let sig = composite_sign(&ed_sk, &ml_sk, data);
        let bytes = sig.to_bytes();
        let decoded = CompositeSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig, decoded);
    }

    #[test]
    fn test_mldsa65_sign_verify_roundtrip() {
        let mut ml_seed = [0u8; 32];
        ml_seed[0] = 0xaa;
        let ml_seed_obj = ml_dsa::Seed::try_from(&ml_seed[..]).unwrap();
        let ml_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_seed_obj);
        let ml_vk = ml_sk.expanded_key().verifying_key();

        let payload = b"ML-DSA-65 pure test payload";
        let cose = sign_mldsa65_only(payload, &ml_sk).unwrap();
        let extracted = parse_and_verify_mldsa65_only(&cose, &ml_vk).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn test_mldsa65_wrong_key_fails() {
        let mut seed_a = [0u8; 32];
        seed_a[0] = 0xaa;
        let seed_obj_a = ml_dsa::Seed::try_from(&seed_a[..]).unwrap();
        let sk_a = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed_obj_a);

        let mut seed_b = [0u8; 32];
        seed_b[0] = 0xbb;
        let seed_obj_b = ml_dsa::Seed::try_from(&seed_b[..]).unwrap();
        let sk_b = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed_obj_b);
        let vk_b = sk_b.expanded_key().verifying_key();

        let payload = b"wrong key test";
        let cose = sign_mldsa65_only(payload, &sk_a).unwrap();
        let result = parse_and_verify_mldsa65_only(&cose, &vk_b);
        assert_eq!(result, Err(Error::InvalidSignature));
    }

    #[test]
    fn test_mldsa65_tampered_cose_fails() {
        let mut seed = [0u8; 32];
        seed[0] = 0xcc;
        let seed_obj = ml_dsa::Seed::try_from(&seed[..]).unwrap();
        let ml_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed_obj);
        let ml_vk = ml_sk.expanded_key().verifying_key();

        let payload = b"tamper test";
        let mut cose = sign_mldsa65_only(payload, &ml_sk).unwrap();
        // Flip a bit in the protected header (position 15, in alg field)
        // This makes the sig_structure different from what was signed.
        if cose.len() > 15 {
            cose[15] ^= 0x01;
        }
        let result = parse_and_verify_mldsa65_only(&cose, &ml_vk);
        assert_eq!(result, Err(Error::InvalidSignature));
    }

    #[test]
    fn test_malformed_cose_fails() {
        assert!(parse_cose_sign1(b"").is_err());
        assert!(parse_cose_sign1(b"\x81\x01").is_err());
    }
}
