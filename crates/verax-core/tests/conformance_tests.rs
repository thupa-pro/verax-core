use std::fs;
use verax_core::VeraxPayload;
use verax_core::cose;

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
    let pubkey_bytes = hex_decode(pubkey_hex);
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pubkey_bytes);
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

#[test]
fn conformance_suite_verification() {
    let suite = load_suite();
    let vectors = suite["vectors"].as_array().expect("missing vectors array");
    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;

    for v in vectors {
        let name = v["name"].as_str().unwrap_or("<unknown>");
        let is_valid = v["is_valid"].as_bool().unwrap_or(false);
        let alg = v["signature_alg"].as_str().unwrap_or("");

        // Skip composite vectors (different verification path)
        if alg.contains("composite") {
            skipped += 1;
            continue;
        }

        let cose_hex = match v.get("cose_hex").and_then(|h| h.as_str()) {
            Some(h) if !h.is_empty() => h,
            _ => {
                // Empty COSE — should fail
                if !is_valid {
                    passed += 1;
                } else {
                    failed += 1;
                    eprintln!("CONFORMANCE FAIL: {name} — is_valid=true but no cose_hex");
                }
                continue;
            }
        };

        let cose_bytes = hex_decode(cose_hex);
        let vk = vector_pubkey(&suite, v);

        // Try verification — if it fails with untagged, try prepending tag 98
        let result = cose::parse_and_verify_ed25519(&cose_bytes, &vk);
        let verified = if result.is_ok() {
            true
        } else if cose_bytes.first() == Some(&0x84) {
            let mut tagged = vec![0xd8, 0x62];
            tagged.extend_from_slice(&cose_bytes);
            cose::parse_and_verify_ed25519(&tagged, &vk).is_ok()
        } else {
            false
        };

        if verified == is_valid {
            passed += 1;
        } else {
            failed += 1;
            eprintln!(
                "CONFORMANCE FAIL: {name} — expected is_valid={is_valid}, got verified={verified}"
            );
        }
    }

    eprintln!(
        "Conformance results: {passed} passed, {failed} failed, {skipped} skipped (out of {})",
        vectors.len()
    );
    assert_eq!(failed, 0, "{failed} conformance vector(s) failed");
}

#[test]
fn conformance_suite_payload_decode_valid_vectors() {
    let suite = load_suite();
    let vectors = suite["vectors"].as_array().expect("missing vectors array");
    let mut passed = 0;
    let mut total = 0;

    for v in vectors {
        let is_valid = v["is_valid"].as_bool().unwrap_or(false);
        if !is_valid {
            continue; // Only decode payloads from valid vectors
        }

        let name = v["name"].as_str().unwrap_or("<unknown>");
        let payload_hex = match v.get("payload_cbor_hex").and_then(|h| h.as_str()) {
            Some(h) => h,
            None => continue,
        };

        total += 1;
        let payload_bytes = hex_decode(payload_hex);
        match VeraxPayload::decode(&payload_bytes) {
            Ok(_payload) => {
                passed += 1;
            }
            Err(e) => {
                eprintln!("PAYLOAD DECODE FAIL: {name} — {e}");
            }
        }
    }

    eprintln!("Payload decode (valid vectors): {passed}/{total} passed");
    assert_eq!(passed, total, "some valid payloads failed to decode");
}
