use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

use crate::output::{self, Report, Section, Status};
use verax_core::{VeraxPayload, cose, hash::blake3};

#[derive(Args)]
pub struct InspectArgs {
    /// Path to the .axm statement file
    pub file: PathBuf,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Show raw CBOR bytes
    #[arg(long)]
    pub raw: bool,
}

pub fn run(args: &InspectArgs) -> Result<()> {
    let data = std::fs::read(&args.file)?;

    let (protected, unprotected, payload_bytes, signature) = {
        let payload = cose::extract_payload(&data)
            .map_err(|e| anyhow::anyhow!("failed to parse COSE: {}", e))?;
        let prot = cose::extract_protected(&data).unwrap_or_default();
        let unprot = cose::extract_unprotected(&data).unwrap_or_default();
        let sig = cose::extract_signature(&data).unwrap_or_default();
        (prot, unprot, payload, sig)
    };

    let payload = VeraxPayload::decode(&payload_bytes)
        .map_err(|e| anyhow::anyhow!("failed to decode payload: {}", e))?;

    let stmt_hash = blake3(&data);
    let payload_hash = blake3(&payload_bytes);

    if args.json {
        let out = serde_json::json!({
            "file": args.file.to_string_lossy(),
            "statement_hash": hex::encode(stmt_hash),
            "payload_hash": hex::encode(payload_hash),
            "subject": hex::encode(payload.subject),
            "predicate": format!("{:?}", payload.predicate),
            "object": payload.object.map(hex::encode),
            "timestamp": payload.timestamp,
            "nonce": payload.nonce.map(hex::encode),
            "lineage": payload.lineage.map(hex::encode),
        });
        output::json_output(&out);
    } else {
        let mut sections = vec![
            Section {
                label: "Statement Hash (BLAKE3)".into(),
                status: Status::Info,
                detail: Some(hex::encode(stmt_hash)),
                indent: 0,
            },
            Section {
                label: "Subject".into(),
                status: Status::Info,
                detail: Some(hex::encode(payload.subject)),
                indent: 0,
            },
            Section {
                label: "Predicate".into(),
                status: Status::Info,
                detail: Some(format!("{:?}", payload.predicate)),
                indent: 0,
            },
        ];

        if let Some(obj) = payload.object {
            sections.push(Section {
                label: "Object".into(),
                status: Status::Info,
                detail: Some(hex::encode(obj)),
                indent: 0,
            });
        }
        if let Some(ts) = payload.timestamp {
            sections.push(Section {
                label: "Timestamp".into(),
                status: Status::Info,
                detail: Some(output::format_timestamp(ts)),
                indent: 0,
            });
        }
        if let Some(nonce) = payload.nonce {
            sections.push(Section {
                label: "Nonce".into(),
                status: Status::Info,
                detail: Some(hex::encode(nonce)),
                indent: 0,
            });
        }
        if let Some(lineage) = payload.lineage {
            sections.push(Section {
                label: "Lineage Parent".into(),
                status: Status::Info,
                detail: Some(hex::encode(lineage)),
                indent: 0,
            });
        }

        sections.push(Section {
            label: "Payload Hash".into(),
            status: Status::Info,
            detail: Some(hex::encode(payload_hash)),
            indent: 0,
        });
        sections.push(Section {
            label: "Signature Size".into(),
            status: Status::Info,
            detail: Some(format!("{} bytes", signature.len())),
            indent: 0,
        });

        if args.raw {
            sections.push(Section {
                label: "Protected Headers".into(),
                status: Status::Info,
                detail: Some(hex::encode(&protected)),
                indent: 0,
            });
            sections.push(Section {
                label: "Unprotected Headers".into(),
                status: Status::Info,
                detail: Some(hex::encode(&unprotected)),
                indent: 0,
            });
            sections.push(Section {
                label: "Signature".into(),
                status: Status::Info,
                detail: Some(hex::encode(&signature)),
                indent: 0,
            });
            sections.push(Section {
                label: "Payload Bytes".into(),
                status: Status::Info,
                detail: Some(hex::encode(&payload_bytes)),
                indent: 0,
            });
        }

        let report = Report {
            title: "Statement Inspection".into(),
            sections,
            overall: None,
        };
        output::print_report(&report);
    }
    Ok(())
}
