#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    let pk_bytes = &data[..32];
    let cose = &data[32..];
    if let Ok(pk) = ed25519_dalek::VerifyingKey::from_bytes(
        std::convert::TryInto::try_into(pk_bytes).unwrap(),
    ) {
        let _ = axiom_core::cose::parse_and_verify_ed25519(cose, &pk);
        let _ = axiom_core::cose::parse_and_verify_mldsa65_only(cose, &ml_dsa_ones());
    }
});

fn ml_dsa_ones() -> ml_dsa::VerifyingKey<ml_dsa::MlDsa65> {
    let seed = ml_dsa::Seed::try_from(&[1u8; 32][..]).unwrap();
    let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed);
    sk.verifying_key()
}
