use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct ExportArgs {
    /// Format to export (markdown, json)
    pub export_format: String,
    /// Path to the statement file
    pub file: PathBuf,
    /// Output path
    pub output: Option<PathBuf>,
}

pub fn run(args: &ExportArgs) -> Result<()> {
    let data = std::fs::read(&args.file)?;
    let payload_bytes = axiom_core::cose::extract_payload(&data)
        .map_err(|e| anyhow::anyhow!("failed to parse: {}", e))?;
    let payload = axiom_core::AxiomPayload::decode(&payload_bytes)
        .map_err(|e| anyhow::anyhow!("failed to decode: {}", e))?;

    let hash = axiom_core::hash::blake3(&data);

    match args.export_format.as_str() {
        "markdown" | "md" => {
            let pred_str = format!("{:?}", payload.predicate);
            let object_str = payload.object.map(|o| format!("`{}`", hex::encode(o))).unwrap_or_else(|| "_none_".into());
            let ts_str = payload.timestamp.map(crate::output::format_timestamp).unwrap_or_else(|| "_none_".into());
            let nonce_str = payload.nonce.map(|n| format!("`{}`", hex::encode(n))).unwrap_or_else(|| "_none_".into());
            let lineage_str = payload.lineage.map(|l| format!("`{}`", hex::encode(l))).unwrap_or_else(|| "_none_".into());
            let md = format!(
                r#"# Axiom Statement

| Field | Value |
|-------|-------|
| Statement Hash | `{}` |
| Subject | `{}` |
| Predicate | `{}` |
| Object | {} |
| Timestamp | {} |
| Nonce | {} |
| Lineage | {} |
"#,
                hex::encode(hash),
                hex::encode(payload.subject),
                pred_str,
                object_str,
                ts_str,
                nonce_str,
                lineage_str,
            );
            match &args.output {
                Some(p) => std::fs::write(p, &md)?,
                None => println!("{}", md),
            }
        }
        "json" => {
            let out = serde_json::json!({
                "statement_hash": hex::encode(hash),
                "subject": hex::encode(payload.subject),
                "predicate": format!("{:?}", payload.predicate),
                "object": payload.object.map(hex::encode),
                "timestamp": payload.timestamp,
                "nonce": payload.nonce.map(hex::encode),
                "lineage": payload.lineage.map(hex::encode),
            });
            let json = serde_json::to_string_pretty(&out)?;
            match &args.output {
                Some(p) => std::fs::write(p, &json)?,
                None => println!("{}", json),
            }
        }
        "svg" | "pdf" => {
            anyhow::bail!("{} export not yet implemented — try 'markdown' or 'json'", args.export_format);
        }
        other => anyhow::bail!("unsupported export format: '{}' (use: markdown, json)", other),
    }

    println!("  Exported to {}", args.output.as_ref().map(|p| p.to_string_lossy().into_owned()).unwrap_or_else(|| "stdout".into()));
    Ok(())
}
