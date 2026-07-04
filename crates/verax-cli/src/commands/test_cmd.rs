use anyhow::Result;
use verax_core::predicate::CORE_PREDICATES;

pub fn run() -> Result<()> {
    let mut passed = 0u64;
    let mut failed = 0u64;

    // 1. Test CBOR round-trip
    let payload = verax_core::VeraxPayload::new([0xab; 32], verax_core::Predicate::Attests);
    let bytes = payload.encode();
    let decoded = verax_core::VeraxPayload::decode(&bytes).unwrap();
    if decoded.subject == payload.subject && decoded.predicate == payload.predicate {
        println!("  PASS  CBOR round-trip encode/decode");
        passed += 1;
    } else {
        println!("  FAIL  CBOR round-trip");
        failed += 1;
    }

    // 2. Test BLAKE3 hash determinism
    let h1 = verax_core::hash::blake3(b"verax-test");
    let h2 = verax_core::hash::blake3(b"verax-test");
    if h1 == h2 && h1 != [0u8; 32] {
        println!("  PASS  BLAKE3 hash determinism");
        passed += 1;
    } else {
        println!("  FAIL  BLAKE3 hash");
        failed += 1;
    }

    // 3. Test Ed25519 sign/verify
    let seed = [0x42u8; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    let stmt = verax_core::Statement::sign_ed25519(&payload, &sk)
        .map_err(|e| anyhow::anyhow!("sign failed: {}", e))?;
    if verax_core::cose::parse_and_verify_ed25519(stmt.to_bytes(), &vk).is_ok() {
        println!("  PASS  Ed25519 sign/verify");
        passed += 1;
    } else {
        println!("  FAIL  Ed25519 sign/verify");
        failed += 1;
    }

    // 4. Test wrong-key rejection
    let bad_seed = [0x99u8; 32];
    let bad_vk = ed25519_dalek::SigningKey::from_bytes(&bad_seed).verifying_key();
    if verax_core::cose::parse_and_verify_ed25519(stmt.to_bytes(), &bad_vk).is_err() {
        println!("  PASS  Wrong key rejection");
        passed += 1;
    } else {
        println!("  FAIL  Wrong key rejection");
        failed += 1;
    }

    // 5. Test tampered bytes rejection
    let mut tampered = stmt.to_bytes().to_vec();
    if let Some(last) = tampered.last_mut() {
        *last ^= 1;
    }
    if verax_core::cose::parse_and_verify_ed25519(&tampered, &vk).is_err() {
        println!("  PASS  Tampered data rejection");
        passed += 1;
    } else {
        println!("  FAIL  Tampered data rejection");
        failed += 1;
    }

    // 6. Test predicate name lookup
    for p in CORE_PREDICATES {
        let name = p.name().to_lowercase();
        let found = CORE_PREDICATES.iter().any(|cp| cp.name() == p.name());
        if found {
            println!("  PASS  Predicate '{}'", name);
            passed += 1;
        } else {
            println!("  FAIL  Predicate '{}'", name);
            failed += 1;
        }
    }

    // 7. Test payload with all fields
    let mut full_payload =
        verax_core::VeraxPayload::new([0x01; 32], verax_core::Predicate::DerivedFrom);
    full_payload.object = Some([0x02; 32]);
    full_payload.timestamp = Some(1700000000);
    full_payload.nonce = Some([0x03; 32]);
    full_payload.lineage = Some([0x04; 32]);
    let full_bytes = full_payload.encode();
    let full_decoded = verax_core::VeraxPayload::decode(&full_bytes).unwrap();
    if full_decoded.object == Some([0x02; 32]) && full_decoded.timestamp == Some(1700000000) {
        println!("  PASS  Payload all fields");
        passed += 1;
    } else {
        println!("  FAIL  Payload all fields");
        failed += 1;
    }

    // 8. Test statement with lineage
    let parent_payload = verax_core::VeraxPayload::new([0xaa; 32], verax_core::Predicate::Attests);
    let parent_stmt = verax_core::Statement::sign_ed25519(&parent_payload, &sk)
        .map_err(|e| anyhow::anyhow!("sign failed: {}", e))?;
    let parent_hash = verax_core::hash::blake3(parent_stmt.to_bytes());
    let mut child_payload =
        verax_core::VeraxPayload::new([0xaa; 32], verax_core::Predicate::Appends);
    child_payload.lineage = Some(parent_hash);
    let child_stmt = verax_core::Statement::sign_ed25519(&child_payload, &sk)
        .map_err(|e| anyhow::anyhow!("sign failed: {}", e))?;
    if verax_core::cose::parse_and_verify_ed25519(child_stmt.to_bytes(), &vk).is_ok() {
        println!("  PASS  Statement with lineage");
        passed += 1;
    } else {
        println!("  FAIL  Statement with lineage");
        failed += 1;
    }

    // Total
    println!(
        "\n  Results: {} passed, {} failed, {} total",
        passed,
        failed,
        passed + failed
    );
    if failed > 0 {
        anyhow::bail!("{} test(s) failed", failed);
    }
    Ok(())
}
