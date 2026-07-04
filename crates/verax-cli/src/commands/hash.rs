use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

use crate::output::{self, Report, Section, Status, Verdict};

#[derive(Args)]
pub struct HashArgs {
    /// Path to the artifact to hash
    pub file: PathBuf,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &HashArgs) -> Result<()> {
    let data = std::fs::read(&args.file)?;
    let size = data.len() as u64;
    let hash = verax_core::hash::hash_artifact(&data);

    if args.json {
        let out = serde_json::json!({
            "algorithm": "BLAKE3",
            "size": size,
            "size_human": output::format_size(size),
            "root_hash": hex::encode(hash),
        });
        output::json_output(&out);
    } else {
        let report = Report {
            title: "Artifact Hash".into(),
            sections: vec![
                Section {
                    label: "Algorithm".into(),
                    status: Status::Info,
                    detail: Some("BLAKE3".into()),
                    indent: 0,
                },
                Section {
                    label: "Size".into(),
                    status: Status::Info,
                    detail: Some(output::format_size(size)),
                    indent: 0,
                },
                Section {
                    label: "Root Hash".into(),
                    status: Status::Info,
                    detail: Some(hex::encode(hash)),
                    indent: 0,
                },
            ],
            overall: Some(Verdict::Verified),
        };
        output::print_report(&report);
    }
    Ok(())
}
