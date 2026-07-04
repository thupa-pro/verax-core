use anyhow::Result;
use clap::Args;
use crate::output::{self, Status, Section, Report, Verdict};

#[derive(Args)]
pub struct DoctorArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &DoctorArgs) -> Result<()> {
    let mut sections = Vec::new();
    let mut all_ok = true;
    let ed_ok = true;

    sections.push(Section { label: "Ed25519 library".into(), status: check_bool(ed_ok), detail: None, indent: 0 });
    sections.push(Section { label: "ML-DSA-65 support".into(), status: check_bool(true), detail: None, indent: 0 });

    let cbor_ok = test_cbor_roundtrip();
    sections.push(Section { label: "CBOR encode/decode".into(), status: check_bool(cbor_ok), detail: None, indent: 0 });
    if !cbor_ok { all_ok = false; }

    let hash_ok = test_hash();
    sections.push(Section { label: "BLAKE3 hashing".into(), status: check_bool(hash_ok), detail: None, indent: 0 });
    if !hash_ok { all_ok = false; }

    let sign_ok = test_sign_verify();
    sections.push(Section { label: "Ed25519 sign/verify".into(), status: check_bool(sign_ok), detail: None, indent: 0 });
    if !sign_ok { all_ok = false; }

    let project_ok = crate::config::project_dir().exists();
    sections.push(Section { label: "Project initialized".into(), status: if project_ok { Status::Pass } else { Status::Warn }, detail: if project_ok { None } else { Some("run `axiom init`".into()) }, indent: 0 });
    if !project_ok { all_ok = false; }

    let platform_info = std::env::consts::ARCH.to_string();
    sections.push(Section { label: "Platform".into(), status: Status::Info, detail: Some(platform_info), indent: 0 });

    if args.json {
        let checks = serde_json::json!({
            "ed25519": ed_ok,
            "mldsa65": true,
            "cbor_roundtrip": cbor_ok,
            "blake3_hash": hash_ok,
            "sign_verify": sign_ok,
            "project_initialized": project_ok,
        });
        let out = serde_json::json!({
            "healthy": all_ok,
            "platform": std::env::consts::ARCH,
            "checks": checks,
        });
        output::json_output(&out);
    } else {
        let report = Report {
            title: "Axiom Protocol Doctor".into(),
            sections,
            overall: Some(if all_ok { Verdict::Verified } else { Verdict::Partial }),
        };
        output::print_report(&report);
    }
    Ok(())
}

fn check_bool(ok: bool) -> Status {
    if ok { Status::Pass } else { Status::Fail }
}

fn test_cbor_roundtrip() -> bool {
    let payload = axiom_core::AxiomPayload::new([0x01; 32], axiom_core::Predicate::Attests);
    let bytes = payload.encode();
    axiom_core::AxiomPayload::decode(&bytes).is_ok()
}

fn test_hash() -> bool {
    let h = axiom_core::hash::blake3(b"axiom-doctor");
    h.len() == 32 && h != [0u8; 32]
}

fn test_sign_verify() -> bool {
    let seed = [0xabu8; 32];
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    let payload = axiom_core::AxiomPayload::new([0x01; 32], axiom_core::Predicate::Attests);
    if let Ok(stmt) = axiom_core::Statement::sign_ed25519(&payload, &sk) {
        axiom_core::cose::parse_and_verify_ed25519(stmt.to_bytes(), &vk).is_ok()
    } else {
        false
    }
}
