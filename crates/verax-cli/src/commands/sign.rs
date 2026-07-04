use crate::output;
use anyhow::Result;
use clap::Args;
use ml_dsa::Keypair;
use std::path::PathBuf;
use verax_core::cbor::VeraxPayload;
use verax_core::hash::blake3;
use verax_core::predicate::{CORE_PREDICATES, Predicate};
use verax_core::statement::Statement;

#[derive(Args)]
pub struct SignArgs {
    /// Path to the artifact file
    pub file: PathBuf,
    /// Predicate for the statement (e.g., attests, authors, derived_from)
    #[arg(long, default_value = "attests")]
    pub predicate: String,
    /// Path to the signing key (Ed25519 private key, hex-encoded, 32 bytes). Auto-generated if omitted.
    #[arg(long)]
    pub key: Option<PathBuf>,
    /// Ed25519 private key as hex (32 bytes). Auto-generated if omitted.
    #[arg(long)]
    pub key_hex: Option<String>,
    /// Use composite signature (Ed25519 + ML-DSA-65). Requires ML-DSA-65 key via --ml-dsa-key or --ml-dsa-key-hex.
    #[arg(long, short = 'c')]
    pub composite: bool,
    /// Path to ML-DSA-65 seed file (hex, 32 bytes). Auto-generated if omitted with --composite.
    #[arg(long)]
    pub ml_dsa_key: Option<PathBuf>,
    /// ML-DSA-65 seed as hex (32 bytes).
    #[arg(long)]
    pub ml_dsa_key_hex: Option<String>,
    /// Output path for the signed .axm file
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Optional object hash (32 bytes, hex)
    #[arg(long)]
    pub object: Option<String>,
    /// Optional timestamp (Unix epoch seconds)
    #[arg(long)]
    pub timestamp: Option<u64>,
    /// Optional nonce (32 bytes, hex)
    #[arg(long)]
    pub nonce: Option<String>,
    /// Optional lineage hash (32 bytes, hex) — the hash of the previous statement
    #[arg(long)]
    pub lineage: Option<String>,
    /// Path to a CT anchor file (CBOR-encoded TemporalAnchor). Embeds the anchor into the signed statement.
    #[arg(long)]
    pub ct_anchor_file: Option<PathBuf>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

fn parse_predicate(s: &str) -> Result<Predicate> {
    let normalized = s.trim().to_lowercase().replace('-', "_");
    for p in CORE_PREDICATES {
        if p.name().to_lowercase().replace('-', "_") == normalized
            || format!("{:?}", p).to_lowercase() == normalized
        {
            return Ok(*p);
        }
    }
    anyhow::bail!(
        "unknown predicate: '{}' (use: attests, authors, derived_from, supersedes, revokes, appends, endorses, complies_with)",
        s
    )
}

pub fn run(args: &SignArgs) -> Result<()> {
    let data = std::fs::read(&args.file)?;
    let subject = blake3(&data);

    let predicate = parse_predicate(&args.predicate)?;

    let mut payload = VeraxPayload::new(subject, predicate);

    if let Some(obj_hex) = &args.object {
        let obj_bytes = hex::decode(obj_hex)?;
        if obj_bytes.len() != 32 {
            anyhow::bail!("object hash must be 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&obj_bytes);
        payload.object = Some(arr);
    }

    if let Some(ts) = args.timestamp {
        payload.timestamp = Some(ts);
    }

    if let Some(nonce_hex) = &args.nonce {
        let nonce_bytes = hex::decode(nonce_hex)?;
        if nonce_bytes.len() != 32 {
            anyhow::bail!("nonce must be 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&nonce_bytes);
        payload.nonce = Some(arr);
    }

    if let Some(lineage_hex) = &args.lineage {
        let lineage_bytes = hex::decode(lineage_hex)?;
        if lineage_bytes.len() != 32 {
            anyhow::bail!("lineage hash must be 32 bytes");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&lineage_bytes);
        payload.lineage = Some(arr);
    }

    let is_composite = args.composite || args.ml_dsa_key.is_some() || args.ml_dsa_key_hex.is_some();

    let has_anchor = args.ct_anchor_file.is_some();

    let (cose_bytes, algorithm, pubkey_hex, ml_pubkey_hex) = if has_anchor {
        let anchor_path = args.ct_anchor_file.as_ref().unwrap();
        let anchor_data = std::fs::read(anchor_path)
            .map_err(|e| anyhow::anyhow!("failed to read CT anchor file: {e}"))?;
        let mut offset = 0;
        let inclusion_proof =
            verax_core::LogInclusionProof::from_cbor(&anchor_data, &mut offset)
                .map_err(|e| anyhow::anyhow!("failed to decode LogInclusionProof: {e}"))?;
        let log_sth = verax_core::SignedTreeHead::from_cbor(&anchor_data, &mut offset)
            .map_err(|e| anyhow::anyhow!("failed to decode SignedTreeHead: {e}"))?;
        let anchor = verax_core::TemporalAnchor {
            inclusion_proof,
            signed_tree_head: log_sth,
        };

        if is_composite {
            let ed_sk_bytes = read_signing_key(args)?;
            let ed_sk = ed25519_dalek::SigningKey::from_bytes(&ed_sk_bytes);
            let ed_vk = ed_sk.verifying_key();

            let ml_sk = read_mldsa_key(args)?;

            let stmt = Statement::sign_composite_and_anchor(&payload, &ed_sk, &ml_sk, &anchor)
                .map_err(|e| anyhow::anyhow!("composite signing with anchor failed: {e}"))?;
            let cose = stmt.to_bytes().to_vec();
            let ml_vk = ml_sk.verifying_key();
            let comp_pk = verax_core::composite_pubkey(&ed_vk, &ml_vk);

            (
                cose,
                "Ed25519 + ML-DSA-65 (Hybrid) + CT Anchor",
                hex::encode(comp_pk.ed25519),
                Some(hex::encode(comp_pk.mldsa65)),
            )
        } else {
            let sk_bytes = read_signing_key(args)?;
            let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
            let vk = sk.verifying_key();

            let stmt = Statement::sign_ed25519_and_anchor(&payload, &sk, &anchor)
                .map_err(|e| anyhow::anyhow!("signing with anchor failed: {e}"))?;
            (
                stmt.to_bytes().to_vec(),
                "Ed25519 + CT Anchor",
                hex::encode(vk.to_bytes()),
                None,
            )
        }
    } else if is_composite {
        let ed_sk_bytes = read_signing_key(args)?;
        let ed_sk = ed25519_dalek::SigningKey::from_bytes(&ed_sk_bytes);
        let ed_vk = ed_sk.verifying_key();

        let ml_sk = read_mldsa_key(args)?;

        let stmt = Statement::sign_composite(&payload, &ed_sk, &ml_sk)
            .map_err(|e| anyhow::anyhow!("composite signing failed: {}", e))?;
        let cose = stmt.to_bytes().to_vec();
        let ml_vk = ml_sk.verifying_key();
        let comp_pk = verax_core::composite_pubkey(&ed_vk, &ml_vk);

        (
            cose,
            "Ed25519 + ML-DSA-65 (Hybrid)",
            hex::encode(comp_pk.ed25519),
            Some(hex::encode(comp_pk.mldsa65)),
        )
    } else {
        let sk_bytes = read_signing_key(args)?;
        let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
        let vk = sk.verifying_key();

        let stmt = Statement::sign_ed25519(&payload, &sk)
            .map_err(|e| anyhow::anyhow!("signing failed: {}", e))?;
        (
            stmt.to_bytes().to_vec(),
            "Ed25519",
            hex::encode(vk.to_bytes()),
            None,
        )
    };

    let out_path = args.out.clone().unwrap_or_else(|| {
        let mut p = args.file.clone();
        let ext = p
            .extension()
            .map(|e| format!(".{}.axm", e.to_string_lossy()))
            .unwrap_or_else(|| ".axm".into());
        p.set_extension("");
        let stem = p.file_name().unwrap().to_string_lossy().into_owned();
        PathBuf::from(format!("{}{}", stem, ext))
    });

    std::fs::write(&out_path, &cose_bytes)?;

    let stmt_hash = blake3(&cose_bytes);

    if args.json {
        let mut obj = serde_json::json!({
            "output": out_path.to_string_lossy(),
            "subject": hex::encode(subject),
            "predicate": predicate.name(),
            "algorithm": algorithm,
            "pubkey": pubkey_hex,
            "statement_hash": hex::encode(stmt_hash),
            "signed": true,
        });
        if let Some(ml) = &ml_pubkey_hex {
            obj["mldsa_pubkey"] = serde_json::json!(ml);
        }
        output::json_output(&obj);
    } else {
        use crate::output::{Report, Section, Status, Verdict};
        let mut sections = vec![
            Section {
                label: "Output".into(),
                status: Status::Pass,
                detail: Some(out_path.to_string_lossy().into()),
                indent: 0,
            },
            Section {
                label: "Subject (BLAKE3)".into(),
                status: Status::Info,
                detail: Some(hex::encode(subject)),
                indent: 0,
            },
            Section {
                label: "Predicate".into(),
                status: Status::Info,
                detail: Some(predicate.name().into()),
                indent: 0,
            },
            Section {
                label: "Algorithm".into(),
                status: Status::Info,
                detail: Some(algorithm.into()),
                indent: 0,
            },
            Section {
                label: "Ed25519 Public Key".into(),
                status: Status::Info,
                detail: Some(pubkey_hex.clone()),
                indent: 0,
            },
        ];
        if let Some(ml) = &ml_pubkey_hex {
            sections.push(Section {
                label: "ML-DSA-65 Public Key".into(),
                status: Status::Info,
                detail: Some(ml.clone()),
                indent: 0,
            });
        }
        sections.push(Section {
            label: "Statement Hash".into(),
            status: Status::Info,
            detail: Some(hex::encode(stmt_hash)),
            indent: 0,
        });
        let report = Report {
            title: "Statement Signed".into(),
            sections,
            overall: Some(Verdict::Verified),
        };
        output::print_report(&report);
    }
    Ok(())
}

fn read_mldsa_key(args: &SignArgs) -> Result<ml_dsa::SigningKey<ml_dsa::MlDsa65>> {
    let seed = if let Some(key_path) = &args.ml_dsa_key {
        let data = std::fs::read_to_string(key_path)?;
        let hex_line = data
            .lines()
            .find(|l| !l.starts_with('#') && !l.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("no key data found in {}", key_path.display()))?;
        let hex_str = hex_line
            .trim()
            .strip_prefix("0x")
            .unwrap_or(hex_line.trim());
        let bytes = hex::decode(hex_str)?;
        if bytes.len() != 32 {
            anyhow::bail!("ML-DSA-65 seed must be 32 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    } else if let Some(hex_str) = &args.ml_dsa_key_hex {
        let hex_str = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
        let bytes = hex::decode(hex_str)?;
        if bytes.len() != 32 {
            anyhow::bail!("ML-DSA-65 seed must be 32 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    } else {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| anyhow::anyhow!("random generation failed: {}", e))?;
        seed
    };

    let ml_seed = ml_dsa::Seed::try_from(&seed[..])
        .map_err(|e| anyhow::anyhow!("invalid ML-DSA-65 seed: {}", e))?;
    let ml_sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&ml_seed);
    Ok(ml_sk)
}

fn read_signing_key(args: &SignArgs) -> Result<[u8; 32]> {
    if let Some(key_path) = &args.key {
        let data = std::fs::read_to_string(key_path)?;
        let hex_line = data
            .lines()
            .find(|l| !l.starts_with('#') && !l.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("no key data found in {}", key_path.display()))?;
        let hex_str = hex_line
            .trim()
            .strip_prefix("0x")
            .unwrap_or(hex_line.trim());
        let bytes = hex::decode(hex_str)?;
        if bytes.len() != 32 {
            anyhow::bail!("signing key must be 32 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(arr);
    }
    if let Some(hex_str) = &args.key_hex {
        let hex_str = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
        let bytes = hex::decode(hex_str)?;
        if bytes.len() != 32 {
            anyhow::bail!("signing key must be 32 bytes, got {}", bytes.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(arr);
    }
    // Auto-generate an ephemeral key
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| anyhow::anyhow!("random generation failed: {}", e))?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    // Save the key to the project keys directory
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let name = format!("ephemeral-{:x}", ts);
    let out_path = crate::config::project_keys_dir().join(format!("{}.key", name));
    std::fs::create_dir_all(out_path.parent().unwrap())?;
    let key_content = format!(
        "# Verax Ed25519 signing key (auto-generated)\n# name: {name}\n# public: {}\n{}\n",
        hex::encode(vk.to_bytes()),
        hex::encode(seed)
    );
    std::fs::write(&out_path, key_content.as_bytes())?;
    eprintln!(
        "  Generated ephemeral key: {} (public: {})",
        name,
        hex::encode(vk.to_bytes())
    );
    eprintln!("  Saved to: {}", out_path.to_string_lossy());

    Ok(seed)
}
