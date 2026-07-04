use anyhow::Result;
use clap::Args;
use std::path::PathBuf;
use axiom_core::{Statement, hash::blake3, cose, Predicate};

#[derive(Args)]
pub struct ExplainArgs {
    /// Path to the .axm statement file
    pub file: PathBuf,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &ExplainArgs) -> Result<()> {
    let data = std::fs::read(&args.file)?;
    let stmt = Statement::from_bytes(&data)
        .map_err(|e| anyhow::anyhow!("failed to parse COSE: {}", e))?;
    let payload = stmt.decode_payload()
        .map_err(|e| anyhow::anyhow!("failed to decode payload: {}", e))?;

    let stmt_hash = blake3(&data);
    let payload_bytes = cose::extract_payload(&data)
        .map_err(|e| anyhow::anyhow!("failed to extract payload: {}", e))?;
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
            "algorithm": "Ed25519",
        });
        crate::output::json_output(&out);
        return Ok(());
    }

    let subject_short = &hex::encode(payload.subject)[..16];
    let hash_short = &hex::encode(stmt_hash)[..16];

    println!("\n  Statement Explanation\n");

    println!("  This statement (hash {}):", hash_short);

    match payload.predicate {
        Predicate::Attests => {
            println!("  ATTESTS to the integrity of artifact `{}`", subject_short);
        }
        Predicate::Authors => {
            println!("  declares AUTHORSHIP of artifact `{}`", subject_short);
        }
        Predicate::DerivedFrom => {
            println!("  declares that artifact `{}` was DERIVED FROM", subject_short);
            if let Some(obj) = payload.object {
                println!("  artifact `{}`", hex::encode(obj));
            }
        }
        Predicate::Supersedes => {
            println!("  SUPERSEDES a previous key or statement");
            if let Some(obj) = payload.object {
                println!("  New key: `{}`", hex::encode(obj));
            }
        }
        Predicate::Revokes => {
            println!("  REVOKES a previous statement");
            if let Some(obj) = payload.object {
                println!("  Revoked statement: `{}`", hex::encode(obj));
            }
        }
        Predicate::Appends => {
            println!("  APPENDS new data to lineage of artifact `{}`", subject_short);
        }
        Predicate::Endorses => {
            println!("  ENDORSES artifact `{}`", subject_short);
        }
        Predicate::CompliesWith => {
            println!("  declares COMPLIANCE with a standard or policy");
        }
        Predicate::Recovers => {
            println!("  RECOVERS a lost key via guardian authorisation");
        }
    }

    println!();

    if let Some(ts) = payload.timestamp {
        println!("  The claim was made at {}", crate::output::format_timestamp(ts));
    }

    if let Some(lineage) = payload.lineage {
        println!("  This statement extends lineage from `{}`", hex::encode(lineage));
    }

    println!();
    println!("  Statement Hash: {}", hash_short);
    println!("  Payload Hash:   {}", hex::encode(payload_hash));
    println!("  Algorithm:      Ed25519");
    println!();

    Ok(())
}
