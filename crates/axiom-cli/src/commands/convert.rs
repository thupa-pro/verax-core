use anyhow::Result;
use clap::Args;
use std::io::Write;
use std::path::PathBuf;

use crate::output::{self, Status, Section, Report, Verdict};

#[derive(Args)]
pub struct ConvertArgs {
    /// Output format (json, cbor, hex)
    pub output_format: String,
    /// Input file
    pub input: PathBuf,
    /// Output file (default: stdout)
    pub output: Option<PathBuf>,
}

pub fn run(args: &ConvertArgs) -> Result<()> {
    let data = std::fs::read(&args.input)?;

    match args.output_format.as_str() {
        "json" => {
            let payload_bytes = axiom_core::cose::extract_payload(&data)
                .map_err(|e| anyhow::anyhow!("failed to parse COSE: {}", e))?;

            let payload = axiom_core::AxiomPayload::decode(&payload_bytes)
                .map_err(|e| anyhow::anyhow!("failed to decode payload: {}", e))?;

            let json = serde_json::json!({
                "subject": hex::encode(payload.subject),
                "predicate": format!("{:?}", payload.predicate),
                "object": payload.object.map(hex::encode),
                "timestamp": payload.timestamp,
                "nonce": payload.nonce.map(hex::encode),
                "lineage": payload.lineage.map(hex::encode),
            });

            let output = serde_json::to_string_pretty(&json)?;
            match &args.output {
                Some(path) => std::fs::write(path, &output)?,
                None => println!("{}", output),
            }
        }
        "cbor" | "axm" => {
            match &args.output {
                Some(path) => std::fs::write(path, &data)?,
                None => { std::io::stdout().write_all(&data)?; }
            }
        }
        "hex" => {
            let hex_str = hex::encode(&data);
            match &args.output {
                Some(path) => std::fs::write(path, &hex_str)?,
                None => println!("{}", hex_str),
            }
        }
        other => anyhow::bail!("unsupported format: '{}' (use: json, cbor, hex)", other),
    }

    let report = Report {
        title: "Conversion Complete".into(),
        sections: vec![
            Section { label: "Input".into(), status: Status::Info, detail: Some(args.input.to_string_lossy().into()), indent: 0 },
            Section { label: "Format".into(), status: Status::Info, detail: Some(args.output_format.clone()), indent: 0 },
            Section { label: "Output".into(), status: Status::Info, detail: Some(args.output.as_ref().map(|p| p.to_string_lossy().into()).unwrap_or_else(|| "stdout".into())), indent: 0 },
        ],
        overall: Some(Verdict::Verified),
    };
    output::print_report(&report);
    Ok(())
}
