use anyhow::Result;
use clap::{Args, Subcommand};

use crate::output::{self, Status, Section, Report, Verdict};

#[derive(Subcommand)]
pub enum DidCommands {
    /// Create a new DID document
    Create(DidCreateArgs),
    /// Resolve a DID to its public key
    Resolve(DidResolveArgs),
    /// Verify a DID signature
    Verify(DidVerifyArgs),
}

#[derive(Args)]
pub struct DidCreateArgs {
    /// Name for the key
    pub name: Option<String>,
    /// DID method (default: key)
    #[arg(long, default_value = "key")]
    pub method: String,
}

#[derive(Args)]
pub struct DidResolveArgs {
    /// DID to resolve (e.g., did:key:z6Mk...)
    pub did: String,
}

#[derive(Args)]
pub struct DidVerifyArgs {
    /// DID string
    pub did: String,
    /// Path to statement file to verify
    pub file: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(command: &DidCommands) -> Result<()> {
    match command {
        DidCommands::Create(args) => create(args),
        DidCommands::Resolve(args) => resolve(args),
        DidCommands::Verify(args) => verify(args),
    }
}

fn create(args: &DidCreateArgs) -> Result<()> {
    use crate::config;

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| anyhow::anyhow!("random generation failed: {}", e))?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    let enc = multibase::encode(multibase::Base::Base58Btc, vk.to_bytes());
    let did = format!("did:{}:{}", args.method, enc);

    let name = args.name.clone().unwrap_or_else(|| {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("did-{:x}", ts)
    });

    let key_path = config::project_keys_dir().join(format!("{}.key", name));
    let key_content = format!(
        "# Axiom DID key\n# name: {name}\n# did: {did}\n# public: {}\n{}\n",
        hex::encode(vk.to_bytes()),
        hex::encode(seed)
    );
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&key_path, key_content.as_bytes())?;

    let did_doc = serde_json::json!({
        "@context": "https://www.w3.org/ns/did/v1",
        "id": did,
        "verificationMethod": [{
            "id": format!("{}#keys-1", did),
            "type": "Ed25519VerificationKey2020",
            "controller": did,
            "publicKeyMultibase": enc,
        }],
        "authentication": [format!("{}#keys-1", did)],
        "assertionMethod": [format!("{}#keys-1", did)],
    });

    let doc_path = config::project_dir().join("trust").join(format!("{}.did.json", name));
    std::fs::write(&doc_path, serde_json::to_string_pretty(&did_doc)?)?;

    let report = Report {
        title: "DID Created".into(),
        sections: vec![
            Section { label: "DID".into(), status: Status::Pass, detail: Some(did), indent: 0 },
            Section { label: "Method".into(), status: Status::Info, detail: Some(args.method.clone()), indent: 0 },
            Section { label: "Public Key".into(), status: Status::Info, detail: Some(hex::encode(vk.to_bytes())), indent: 0 },
            Section { label: "Key File".into(), status: Status::Info, detail: Some(key_path.to_string_lossy().into()), indent: 0 },
            Section { label: "DID Document".into(), status: Status::Info, detail: Some(doc_path.to_string_lossy().into()), indent: 0 },
        ],
        overall: Some(Verdict::Verified),
    };
    output::print_report(&report);
    Ok(())
}

fn resolve(args: &DidResolveArgs) -> Result<()> {
    if !args.did.starts_with("did:") {
        anyhow::bail!("invalid DID: must start with 'did:'");
    }

    let parts: Vec<&str> = args.did.split(':').collect();
    if parts.len() < 3 {
        anyhow::bail!("invalid DID format: expected did:<method>:<identifier>");
    }

    let method = parts[1];
    let identifier = parts[2..].join(":");

    let decoded = multibase::decode(&identifier)
        .map_err(|_| anyhow::anyhow!("failed to decode multibase identifier"))?;

    let report = Report {
        title: "DID Resolution".into(),
        sections: vec![
            Section { label: "DID".into(), status: Status::Info, detail: Some(args.did.clone()), indent: 0 },
            Section { label: "Method".into(), status: Status::Info, detail: Some(method.into()), indent: 0 },
            Section { label: "Raw Key Bytes".into(), status: Status::Info, detail: Some(format!("{} bytes", decoded.1.len())), indent: 0 },
            Section { label: "Hex".into(), status: Status::Info, detail: Some(hex::encode(&decoded.1)), indent: 0 },
        ],
        overall: if decoded.1.len() == 32 { Some(Verdict::Verified) } else { Some(Verdict::Failed) },
    };
    output::print_report(&report);
    Ok(())
}

fn verify(args: &DidVerifyArgs) -> Result<()> {
    if !args.did.starts_with("did:") {
        anyhow::bail!("invalid DID: must start with 'did:'");
    }

    let identifier = args.did.split(':').skip(2).collect::<Vec<_>>().join(":");
    let decoded = multibase::decode(&identifier)
        .map_err(|_| anyhow::anyhow!("failed to decode multibase identifier"))?;

    let pk_bytes = decoded.1;
    if pk_bytes.len() != 32 {
        anyhow::bail!("expected 32-byte public key, got {} bytes", pk_bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pk_bytes);
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|e| anyhow::anyhow!("invalid Ed25519 public key: {}", e))?;

    let data = std::fs::read(&args.file)?;
    let result = axiom_core::cose::parse_and_verify_ed25519(&data, &vk);

    if args.json {
        let out = serde_json::json!({
            "valid": result.is_ok(),
            "did": args.did,
            "file": args.file,
            "error": result.as_ref().err().map(|e| format!("{}", e)),
        });
        output::json_output(&out);
    } else {
        let sections = vec![
            Section { label: "DID".into(), status: Status::Info, detail: Some(args.did.clone()), indent: 0 },
            Section { label: "File".into(), status: Status::Info, detail: Some(args.file.clone()), indent: 0 },
            Section {
                label: "Signature".into(),
                status: if result.is_ok() { Status::Pass } else { Status::Fail },
                detail: result.as_ref().err().map(|e| format!("{}", e)),
                indent: 0,
            },
        ];
        let report = Report {
            title: "DID Signature Verification".into(),
            sections,
            overall: Some(if result.is_ok() { Verdict::Verified } else { Verdict::Failed }),
        };
        output::print_report(&report);
    }
    Ok(())
}
