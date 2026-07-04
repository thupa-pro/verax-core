use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

use crate::output::{self, Status, Section, Report, Verdict};
use axiom_core::{AxiomPayload, cose, Predicate};

#[derive(Args)]
pub struct LintArgs {
    /// Path to the .axm statement file
    pub file: PathBuf,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &LintArgs) -> Result<()> {
    let data = std::fs::read(&args.file)?;

    let payload_bytes = cose::extract_payload(&data)
        .map_err(|e| anyhow::anyhow!("failed to parse COSE: {}", e))?;

    let payload = AxiomPayload::decode(&payload_bytes)
        .map_err(|e| anyhow::anyhow!("failed to decode payload: {}", e))?;

    let mut warnings: Vec<String> = Vec::new();
    let mut best_practices: Vec<String> = Vec::new();

    // Check 1: Missing timestamp
    if payload.timestamp.is_none() {
        warnings.push("missing timestamp — statements should include a timestamp for temporal ordering".into());
    }

    // Check 2: Check predicate
    match payload.predicate {
        Predicate::Attests | Predicate::Authors | Predicate::DerivedFrom
        | Predicate::Supersedes | Predicate::Revokes | Predicate::Appends
        | Predicate::Endorses | Predicate::CompliesWith | Predicate::Recovers => {
            best_practices.push(format!("recommended predicate: {:?}", payload.predicate));
        }
    }

    // Check 3: Check subject length
    if payload.subject.iter().all(|&b| b == 0) {
        warnings.push("subject is all zeros — likely invalid".into());
    }

    // Check 4: Object check for certain predicates
    if payload.predicate == Predicate::Revokes && payload.object.is_none() {
        warnings.push("REVOKES without object — should reference the revoked statement hash".into());
    }
    if payload.predicate == Predicate::Supersedes && payload.object.is_none() {
        warnings.push("SUPERSEDES without object — should reference the new key hash".into());
    }
    if payload.predicate == Predicate::DerivedFrom && payload.object.is_none() {
        warnings.push("DERIVED_FROM without object — should reference the source artifact".into());
    }

    // Check 5: Nonce without timestamp
    if payload.nonce.is_some() && payload.timestamp.is_none() {
        warnings.push("nonce present but no timestamp — nonce is only meaningful with repeated timestamps".into());
    }

    // Check 6: Lineage check
    if let Some(lineage) = payload.lineage
        && lineage.iter().all(|&b| b == 0) {
            warnings.push("lineage hash is all zeros".into());
    }

    // Check 7: Extensions
    if let Some(ref exts) = payload.extensions
        && !exts.is_empty() {
            warnings.push(format!("{} custom extension(s) — ensure these are interoperable", exts.len()));
    }

    // Check 8: Payload size
    if payload_bytes.len() > 1024 {
        warnings.push(format!("payload is {} bytes — consider keeping payloads under 1KB", payload_bytes.len()));
    }

    // Check 9: Algorithm strength — detect from COSE protected header bytes
    // Ed25519 uses alg -8, encoded as CBOR negative int: 0x27 (major 1, value 8)
    // ML-DSA-65 uses alg -39, composite uses a hybrid approach
    let is_ed25519 = if let Ok(prot) = cose::extract_protected(&data) {
        // Search for the algorithm ID in the protected header CBOR map
        // Pattern for Ed25519: key 0x01, value 0x27 (negative 8)
        prot.windows(4).any(|w| w == [0x01, 0x27, 0x04, 0x58])
    } else {
        true
    };
    if is_ed25519 {
        best_practices.push("Ed25519 signature — consider composite (Ed25519 + ML-DSA-65) for quantum resistance".into());
    }

    if args.json {
        let out = serde_json::json!({
            "file": args.file.to_string_lossy(),
            "subject": hex::encode(payload.subject),
            "predicate": format!("{:?}", payload.predicate),
            "warnings": warnings,
            "best_practices": best_practices,
            "pass": warnings.is_empty(),
        });
        output::json_output(&out);
    } else {
        let mut sections = Vec::new();

        for wp in &warnings {
            sections.push(Section { label: wp.clone(), status: Status::Warn, detail: None, indent: 1 });
        }
        for bp in &best_practices {
            sections.push(Section { label: bp.clone(), status: Status::Info, detail: None, indent: 1 });
        }

        if warnings.is_empty() {
            sections.push(Section { label: "No issues found".into(), status: Status::Pass, detail: None, indent: 0 });
        }

        let report = Report {
            title: "Protocol Lint".into(),
            sections,
            overall: Some(if warnings.is_empty() { Verdict::Verified } else { Verdict::Partial }),
        };
        output::print_report(&report);
    }

    Ok(())
}
