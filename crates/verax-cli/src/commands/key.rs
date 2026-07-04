use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::config;
use crate::output::{self, Report, Section, Status, Verdict};

#[derive(Subcommand)]
pub enum KeyCommands {
    /// Generate a new Ed25519 signing key
    Generate(KeyGenerateArgs),
    /// Import a key from hex
    Import(KeyImportArgs),
    /// Export a key to hex
    Export(KeyExportArgs),
    /// Rotate a key (create a SUPERSEDES statement)
    Rotate(KeyRotateArgs),
    /// List all keys in the project
    List,
}

#[derive(Args)]
pub struct KeyGenerateArgs {
    /// Name for the key (used as filename)
    pub name: Option<String>,
    /// Output path for the key file
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Args)]
pub struct KeyImportArgs {
    /// Name for the imported key
    pub name: String,
    /// Hex-encoded key (32 bytes for Ed25519 private key)
    pub hex: String,
}

#[derive(Args)]
pub struct KeyExportArgs {
    /// Name of the key to export
    pub name: String,
    /// Output path (default: stdout)
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Args)]
pub struct KeyRotateArgs {
    /// Current key to be superseded
    pub current_key_name: String,
    /// New key name
    pub new_key_name: String,
    /// Output path for the SUPERSEDES statement
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub fn run(command: &KeyCommands) -> Result<()> {
    match command {
        KeyCommands::Generate(args) => generate(args),
        KeyCommands::Import(args) => import(args),
        KeyCommands::Export(args) => export_key(args),
        KeyCommands::Rotate(args) => rotate(args),
        KeyCommands::List => list(),
    }
}

fn generate(args: &KeyGenerateArgs) -> Result<()> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| anyhow::anyhow!("random generation failed: {}", e))?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    let name = args.name.clone().unwrap_or_else(|| {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("key-{:x}", ts)
    });

    let out_path = args
        .out
        .clone()
        .unwrap_or_else(|| config::project_keys_dir().join(format!("{}.key", name)));

    let key_content = format!(
        "# Verax Ed25519 signing key\n# name: {name}\n# public: {}\n{}\n",
        hex::encode(vk.to_bytes()),
        hex::encode(seed)
    );

    std::fs::write(&out_path, key_content.as_bytes())?;

    let report = Report {
        title: "Key Generated".into(),
        sections: vec![
            Section {
                label: "Name".into(),
                status: Status::Info,
                detail: Some(name),
                indent: 0,
            },
            Section {
                label: "Algorithm".into(),
                status: Status::Info,
                detail: Some("Ed25519".into()),
                indent: 0,
            },
            Section {
                label: "Public Key".into(),
                status: Status::Info,
                detail: Some(hex::encode(vk.to_bytes())),
                indent: 0,
            },
            Section {
                label: "Saved".into(),
                status: Status::Pass,
                detail: Some(out_path.to_string_lossy().into()),
                indent: 0,
            },
        ],
        overall: Some(Verdict::Verified),
    };
    output::print_report(&report);
    Ok(())
}

fn import(args: &KeyImportArgs) -> Result<()> {
    let bytes = hex::decode(&args.hex)?;
    if bytes.len() != 32 {
        anyhow::bail!("Ed25519 private key must be 32 bytes");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let sk = ed25519_dalek::SigningKey::from_bytes(&arr);
    let vk = sk.verifying_key();

    let out_path = config::project_keys_dir().join(format!("{}.key", args.name));
    if out_path.exists() {
        anyhow::bail!("key '{}' already exists", args.name);
    }

    let content = format!(
        "# Verax Ed25519 signing key\n# name: {}\n# public: {}\n{}\n",
        args.name,
        hex::encode(vk.to_bytes()),
        hex::encode(bytes)
    );
    std::fs::write(&out_path, content.as_bytes())?;

    println!("  Imported key '{}'", args.name);
    println!("  Public: {}", hex::encode(vk.to_bytes()));
    Ok(())
}

fn export_key(args: &KeyExportArgs) -> Result<()> {
    let key_path = config::project_keys_dir().join(format!("{}.key", args.name));
    let data = std::fs::read_to_string(&key_path)
        .map_err(|_| anyhow::anyhow!("key '{}' not found in .verax/keys/", args.name))?;

    let hex_line = data
        .lines()
        .find(|l| !l.starts_with('#') && !l.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("no key data found"))?;

    match &args.out {
        Some(out) => std::fs::write(out, hex_line.trim().as_bytes())?,
        None => println!("{}", hex_line.trim()),
    }
    Ok(())
}

fn rotate(args: &KeyRotateArgs) -> Result<()> {
    let current_path = config::project_keys_dir().join(format!("{}.key", args.current_key_name));
    let current_data = std::fs::read_to_string(&current_path)
        .map_err(|_| anyhow::anyhow!("current key '{}' not found", args.current_key_name))?;
    let current_hex = current_data
        .lines()
        .find(|l| !l.starts_with('#') && !l.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("no key data in file"))?;
    let current_bytes = hex::decode(current_hex.trim())?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&current_bytes);
    let current_sk = ed25519_dalek::SigningKey::from_bytes(&arr);
    let current_vk = current_sk.verifying_key();

    let mut new_seed = [0u8; 32];
    getrandom::getrandom(&mut new_seed)
        .map_err(|e| anyhow::anyhow!("random generation failed: {}", e))?;
    let new_sk = ed25519_dalek::SigningKey::from_bytes(&new_seed);
    let new_vk = new_sk.verifying_key();

    let payload = verax_core::VeraxPayload {
        subject: current_vk.to_bytes(),
        predicate: verax_core::Predicate::Supersedes,
        object: Some(new_vk.to_bytes()),
        timestamp: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        ),
        nonce: None,
        lineage: None,
        anchor_hash: None,
        extensions: None,
        recovery_policy: None,
    };

    let stmt = verax_core::Statement::sign_ed25519(&payload, &current_sk)
        .map_err(|e| anyhow::anyhow!("signing failed: {}", e))?;

    let out_path = args.out.clone().unwrap_or_else(|| {
        config::project_keys_dir().join(format!(
            "{}.to.{}.axm",
            args.current_key_name, args.new_key_name
        ))
    });
    std::fs::write(&out_path, stmt.to_bytes())?;

    let new_key_path = config::project_keys_dir().join(format!("{}.key", args.new_key_name));
    let new_content = format!(
        "# Verax Ed25519 signing key\n# name: {}\n# public: {}\n# supersedes: {}\n{}\n",
        args.new_key_name,
        hex::encode(new_vk.to_bytes()),
        hex::encode(current_vk.to_bytes()),
        hex::encode(new_seed)
    );
    std::fs::write(&new_key_path, new_content.as_bytes())?;

    println!(
        "  Rotated key: {} \u{2192} {}",
        args.current_key_name, args.new_key_name
    );
    println!("  New public: {}", hex::encode(new_vk.to_bytes()));
    println!("  Rotation statement: {}", out_path.to_string_lossy());
    Ok(())
}

fn list() -> Result<()> {
    let keys_dir = config::project_keys_dir();
    if !keys_dir.exists() {
        println!("  No keys found (run `verax init` first)");
        return Ok(());
    }

    let mut entries: Vec<_> = Vec::new();
    for entry in std::fs::read_dir(keys_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map(|e| e == "key").unwrap_or(false) {
            let data = std::fs::read_to_string(&path)?;
            let name = data
                .lines()
                .find(|l| l.starts_with("# name:"))
                .and_then(|l| l.split(':').nth(1))
                .map(|s| s.trim())
                .unwrap_or("?");
            let pubkey = data
                .lines()
                .find(|l| l.starts_with("# public:"))
                .and_then(|l| l.split(':').nth(1))
                .map(|s| s.trim())
                .unwrap_or("?");
            entries.push((name.to_string(), pubkey.to_string(), path));
        }
    }

    if entries.is_empty() {
        println!("  No keys found in .verax/keys/");
        return Ok(());
    }

    println!("\n  Keys in .verax/keys/:\n");
    for (name, pubkey, _path) in &entries {
        let short = if pubkey.len() > 16 {
            &pubkey[..16]
        } else {
            pubkey
        };
        println!("  \u{2022} {:<20} {}", name, short);
    }
    println!();
    Ok(())
}
