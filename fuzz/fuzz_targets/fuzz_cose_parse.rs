#![no_main]

use libfuzzer_sys::fuzz_target;

/// Return an ML-DSA-65 verifying key derived from a fixed seed.
fn ml_dsa_ones() -> ml_dsa::VerifyingKey<ml_dsa::MlDsa65> {
    let seed = ml_dsa::Seed::try_from(&[1u8; 32][..]).unwrap();
    let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed);
    sk.verifying_key()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    let pk_bytes = &data[..32];
    let cose = &data[32..];

    // Ed25519 verify with a random-ish public key
    if let Ok(pk) = ed25519_dalek::VerifyingKey::from_bytes(
        std::convert::TryInto::try_into(pk_bytes).unwrap(),
    ) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = verax_core::cose::parse_and_verify_ed25519(cose, &pk);
        }));
    }

    // ML-DSA-65 verify with fixed key
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = verax_core::cose::parse_and_verify_mldsa65_only(cose, &ml_dsa_ones());
    }));

    // COSE extraction functions
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = verax_core::cose::extract_payload(cose);
    }));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = verax_core::cose::extract_protected(cose);
    }));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = verax_core::cose::extract_signature(cose);
    }));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = verax_core::cose::extract_unprotected(cose);
    }));
});
