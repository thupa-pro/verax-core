use crate::output::{self, Report, Section, Status, Verdict};
use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct EncryptArgs {
    /// Path to the file to encrypt
    pub file: PathBuf,
    /// Output path for ciphertext (default: file.enc)
    #[arg(long, short)]
    pub out: Option<PathBuf>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &EncryptArgs) -> Result<()> {
    let data = std::fs::read(&args.file)?;

    let key = verax_core::shred::ShreddingKey::generate();
    let ciphertext = verax_core::shred::encrypt_pii(&key, &data)
        .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;

    let out_path = args.out.clone().unwrap_or_else(|| {
        let p = args.file.clone();
        let s = p.to_string_lossy().to_string();
        PathBuf::from(format!("{}.enc", s))
    });

    std::fs::write(&out_path, &ciphertext)?;

    let stmt_hash = verax_core::hash::blake3(&ciphertext);

    if args.json {
        let out = serde_json::json!({
            "output": out_path.to_string_lossy(),
            "algorithm": "XChaCha20-Poly1305",
            "key_id": hex::encode(key.key_id()),
            "statement_hash": hex::encode(stmt_hash),
        });
        output::json_output(&out);
    } else {
        let report = Report {
            title: "Encryption Complete".into(),
            sections: vec![
                Section {
                    label: "Algorithm".into(),
                    status: Status::Info,
                    detail: Some("XChaCha20-Poly1305".into()),
                    indent: 0,
                },
                Section {
                    label: "Ciphertext".into(),
                    status: Status::Pass,
                    detail: Some(out_path.to_string_lossy().into()),
                    indent: 0,
                },
                Section {
                    label: "Key ID".into(),
                    status: Status::Info,
                    detail: Some(hex::encode(key.key_id())),
                    indent: 0,
                },
                Section {
                    label: "Hash".into(),
                    status: Status::Info,
                    detail: Some(hex::encode(stmt_hash)),
                    indent: 0,
                },
            ],
            overall: Some(Verdict::Verified),
        };
        output::print_report(&report);
    }
    Ok(())
}
