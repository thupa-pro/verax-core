use crate::output::{self, Report, Section, Status};
use anyhow::Result;
use std::time::Instant;

pub fn run() -> Result<()> {
    let payload = verax_core::VeraxPayload::new([0x01; 32], verax_core::Predicate::Attests);
    let seed = [0x42u8; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    // Hash benchmark
    let hash_start = Instant::now();
    let iterations = 10_000;
    for _ in 0..iterations {
        let _ = verax_core::hash::blake3(b"Verax Protocol Benchmark Data");
    }
    let hash_time = hash_start.elapsed().as_micros() as f64 / iterations as f64;

    // Sign benchmark
    let sign_start = Instant::now();
    let sign_iter = 1_000;
    for _ in 0..sign_iter {
        let _ = verax_core::Statement::sign_ed25519(&payload, &sk);
    }
    let sign_time = sign_start.elapsed().as_micros() as f64 / sign_iter as f64;

    // Verify benchmark
    let stmt = verax_core::Statement::sign_ed25519(&payload, &sk).unwrap();
    let cose_bytes = stmt.to_bytes().to_vec();
    let verify_start = Instant::now();
    for _ in 0..sign_iter {
        let _ = verax_core::cose::parse_and_verify_ed25519(&cose_bytes, &vk);
    }
    let verify_time = verify_start.elapsed().as_micros() as f64 / sign_iter as f64;

    // CBOR benchmarks
    let cbor_encode_start = Instant::now();
    let cbor_iter = 10_000;
    for _ in 0..cbor_iter {
        let _ = payload.encode();
    }
    let encode_time = cbor_encode_start.elapsed().as_micros() as f64 / cbor_iter as f64;

    let payload_bytes = payload.encode();
    let cbor_decode_start = Instant::now();
    for _ in 0..cbor_iter {
        let _ = verax_core::VeraxPayload::decode(&payload_bytes);
    }
    let decode_time = cbor_decode_start.elapsed().as_micros() as f64 / cbor_iter as f64;

    let sections = vec![
        Section {
            label: "BLAKE3 Hash".into(),
            status: Status::Info,
            detail: Some(format!("{:.1} \u{00b5}s/op", hash_time)),
            indent: 0,
        },
        Section {
            label: "Ed25519 Sign".into(),
            status: Status::Info,
            detail: Some(format!("{:.1} \u{00b5}s/op", sign_time)),
            indent: 0,
        },
        Section {
            label: "Ed25519 Verify".into(),
            status: Status::Info,
            detail: Some(format!("{:.1} \u{00b5}s/op", verify_time)),
            indent: 0,
        },
        Section {
            label: "CBOR Encode".into(),
            status: Status::Info,
            detail: Some(format!("{:.1} \u{00b5}s/op", encode_time)),
            indent: 0,
        },
        Section {
            label: "CBOR Decode".into(),
            status: Status::Info,
            detail: Some(format!("{:.1} \u{00b5}s/op", decode_time)),
            indent: 0,
        },
    ];

    let report = Report {
        title: "Benchmark Results".into(),
        sections,
        overall: None,
    };
    output::print_report(&report);
    Ok(())
}
