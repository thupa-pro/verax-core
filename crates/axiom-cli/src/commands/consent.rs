use anyhow::Result;
use clap::Args;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Args)]
pub struct ConsentArgs {
    /// Path to the artifact
    pub file: PathBuf,
    /// Path to the signing key
    #[arg(long)]
    pub key: PathBuf,
    /// Purpose of consent
    #[arg(long, default_value = "data-processing")]
    pub purpose: String,
    /// Output path
    #[arg(long)]
    pub out: Option<PathBuf>,
}

fn read_key_bytes(path: &PathBuf) -> Result<[u8; 32]> {
    let data = std::fs::read_to_string(path)?;
    let hex_line = data.lines()
        .find(|l| !l.starts_with('#') && !l.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("no key data in {}", path.display()))?;
    let bytes = hex::decode(hex_line.trim())?;
    if bytes.len() != 32 {
        anyhow::bail!("key must be 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

pub fn run(args: &ConsentArgs) -> Result<()> {
    let data = std::fs::read(&args.file)?;
    let key_bytes = read_key_bytes(&args.key)?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&key_bytes);

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let policy_hash = axiom_core::hash::blake3(b"consent-policy-default-v1");

    let consent_payload = axiom_core::shred::create_consent_payload(
        policy_hash,
        axiom_core::hash::blake3(&data).as_slice(),
        ts,
        args.purpose.as_bytes(),
    );

    let subject_hash = axiom_core::hash::blake3(&consent_payload.encode());
    let mut sign_payload = axiom_core::AxiomPayload::new(subject_hash, axiom_core::Predicate::CompliesWith);
    sign_payload.object = Some(policy_hash);
    sign_payload.timestamp = Some(ts);

    let stmt = axiom_core::Statement::sign_ed25519(&sign_payload, &sk)
        .map_err(|e| anyhow::anyhow!("signing failed: {}", e))?;

    let out_path = args.out.clone().unwrap_or_else(|| {
        let p = args.file.clone();
        let s = p.to_string_lossy().to_string();
        PathBuf::from(format!("{}.consent.axm", s))
    });

    std::fs::write(&out_path, stmt.to_bytes())?;
    println!("  Consent statement written to {}", out_path.to_string_lossy());
    Ok(())
}
