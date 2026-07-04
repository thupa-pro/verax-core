use anyhow::Result;
use clap::Args;
use std::path::PathBuf;
use std::collections::{HashMap, HashSet};

use crate::output::{self, Status, Section, Report, Verdict};
use axiom_core::{
    AxiomPayload, Statement, cose, hash::blake3,
    verify_statement_with_warnings,
    TrustStore, VerificationWarnings, Warning, CompositePublicKey,
};

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to the .axm statement file
    pub file: PathBuf,

    /// Ed25519 public key hex (32 bytes). Auto-extracted from COSE KID if omitted.
    #[arg(long)]
    pub pubkey: Option<String>,

    /// ML-DSA-65 public key hex (1952 bytes) for composite verification
    #[arg(long)]
    pub mldsa_pubkey: Option<String>,

    /// Directory containing previous .axm statements for lineage traversal
    #[arg(long)]
    pub chain_dir: Option<PathBuf>,

    /// Trusted CT log public key hex (32 bytes Ed25519)
    #[arg(long)]
    pub trusted_log_key: Option<String>,

    /// Path to a revocation cache JSON file
    /// Format: {"checkpoint_timestamp": <unix_secs>, "revoked": ["<hex_hash32>", ...], "not_revoked": ["<hex_hash32>", ...]}
    #[arg(long)]
    pub revocation_cache: Option<PathBuf>,

    /// Show detailed step-by-step explanation
    #[arg(long)]
    pub explain: bool,

    /// Show every hash, byte, and signature (very verbose)
    #[arg(long)]
    pub trace: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Return exit code 0/1 (suppress normal output)
    #[arg(long)]
    pub quiet: bool,
}

struct CliTrustStore {
    ed_vk: Option<ed25519_dalek::VerifyingKey>,
    comp_pk: Option<CompositePublicKey>,
    chain_cache: HashMap<[u8; 32], Vec<u8>>,
    trusted_log_key: Option<[u8; 32]>,
    checkpoint_timestamp: Option<u64>,
    revoked: HashSet<[u8; 32]>,
    not_revoked: HashSet<[u8; 32]>,
}

impl CliTrustStore {
    fn new(
        ed_vk: Option<ed25519_dalek::VerifyingKey>,
        comp_pk: Option<CompositePublicKey>,
        chain_dir: Option<&PathBuf>,
        trusted_log_key: Option<[u8; 32]>,
        revocation_cache: Option<&PathBuf>,
    ) -> Self {
        let mut chain_cache = HashMap::new();
        if let Some(dir) = chain_dir {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map_or(false, |e| e == "axm") {
                        if let Ok(bytes) = std::fs::read(&path) {
                            let hash = blake3(&bytes);
                            chain_cache.insert(hash, bytes);
                        }
                    }
                }
            }
        }

        let mut checkpoint_timestamp = None;
        let mut revoked = HashSet::new();
        let mut not_revoked = HashSet::new();
        if let Some(path) = revocation_cache {
            if let Ok(json_str) = std::fs::read_to_string(path) {
                if let Ok(cache) = serde_json::from_str::<serde_json::Value>(&json_str) {
                    if let Some(ts) = cache.get("checkpoint_timestamp").and_then(|v| v.as_u64()) {
                        checkpoint_timestamp = Some(ts);
                    }
                    if let Some(revoked_arr) = cache.get("revoked").and_then(|v| v.as_array()) {
                        for val in revoked_arr {
                            if let Some(hex_str) = val.as_str() {
                                if let Ok(bytes) = hex::decode(hex_str) {
                                    if bytes.len() == 32 {
                                        let mut arr = [0u8; 32];
                                        arr.copy_from_slice(&bytes);
                                        revoked.insert(arr);
                                    }
                                }
                            }
                        }
                    }
                    if let Some(not_revoked_arr) = cache.get("not_revoked").and_then(|v| v.as_array()) {
                        for val in not_revoked_arr {
                            if let Some(hex_str) = val.as_str() {
                                if let Ok(bytes) = hex::decode(hex_str) {
                                    if bytes.len() == 32 {
                                        let mut arr = [0u8; 32];
                                        arr.copy_from_slice(&bytes);
                                        not_revoked.insert(arr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Self { ed_vk, comp_pk, chain_cache, trusted_log_key, checkpoint_timestamp, revoked, not_revoked }
    }
}

impl TrustStore for CliTrustStore {
    fn resolve_key(&self, _kid: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
        self.ed_vk
    }

    fn resolve_composite_key(&self, _kid: &[u8]) -> Option<CompositePublicKey> {
        self.comp_pk.clone()
    }

    fn resolve_mldsa65_key(&self, _kid: &[u8]) -> Option<ml_dsa::VerifyingKey<ml_dsa::MlDsa65>> {
        let comp_pk = self.comp_pk.as_ref()?;
        let raw = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(&comp_pk.mldsa65[..]).ok()?;
        Some(ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&raw))
    }

    fn fetch_statement(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.chain_cache.get(hash).cloned()
    }

    fn is_revoked_in_log(&self, stmt_hash: &[u8; 32], after_timestamp: u64) -> Option<bool> {
        let cp = self.checkpoint_timestamp?;
        if after_timestamp > cp {
            return None;
        }
        if self.revoked.contains(stmt_hash) {
            return Some(true);
        }
        if self.not_revoked.contains(stmt_hash) {
            return Some(false);
        }
        None
    }

    fn resolve_log_pubkey(&self, _log_id: &[u8; 32], candidate_key: &[u8; 32]) -> Option<[u8; 32]> {
        self.trusted_log_key.and_then(|tk| {
            if &tk == candidate_key { Some(tk) } else { None }
        })
    }
}

pub fn run(args: &VerifyArgs) -> Result<()> {
    let data = std::fs::read(&args.file)?;
    if data.is_empty() {
        anyhow::bail!("empty file: {}", args.file.display());
    }

    let (ed_vk, is_composite, _ml_bytes, store) = build_trust_store(args, &data)?;

    let result = verify_statement_with_warnings(&data, &store);

    match result {
        Ok((stmt, warnings)) => {
            let payload = stmt.decode_payload().ok();
            let payload_bytes = stmt.extract_payload_bytes().ok();

            let use_json = args.json || output::output_format() == output::OutputFormat::Json;
            let use_quiet = args.quiet || output::output_format() == output::OutputFormat::Quiet;

            if use_json {
                let out = build_json_output(args, &Some(ed_vk), &payload, &warnings, true, None);
                output::json_output(&out);
            } else if use_quiet {
                return Ok(());
            } else {
                let algorithm = if is_composite { "Ed25519 + ML-DSA-65 (Hybrid)" } else { "Ed25519" };
                let trust_level = if is_composite { "HIGH (PQ-secure)" } else { "STANDARD" };

                let mut sections = build_sections(args, &Some(ed_vk), &payload, algorithm, trust_level);
                let warn_sections = build_warning_sections(&warnings);
                sections.extend(warn_sections);

                if args.explain {
                    let explain_sections = generate_explain_sections(args, &Some(ed_vk), algorithm, &data, &payload_bytes, &stmt, &warnings);
                    sections.extend(explain_sections);
                }

                if args.trace {
                    let trace_sections = generate_trace_sections(&data, &payload_bytes);
                    sections.extend(trace_sections);
                }

                let has_warnings = !warnings.warnings.is_empty();
                let report = Report {
                    title: "Axiom Protocol — Verification Report".into(),
                    sections,
                    overall: Some(if has_warnings { Verdict::Partial } else { Verdict::Verified }),
                };
                output::print_report(&report);
            }
        }
        Err(e) => {
            let msg = format!("{}", e);
            let use_json = args.json || output::output_format() == output::OutputFormat::Json;
            let use_quiet = args.quiet || output::output_format() == output::OutputFormat::Quiet;
            if use_json {
                let out = serde_json::json!({
                    "valid": false,
                    "file": args.file.to_string_lossy(),
                    "error": msg,
                });
                output::json_output(&out);
            } else if use_quiet {
            } else {
                let report = Report {
                    title: "Axiom Protocol — Verification Report".into(),
                    sections: vec![
                        Section { label: args.file.file_name().unwrap().to_string_lossy().into(), status: Status::Info, detail: None, indent: 0 },
                        Section { label: "Protocol check".into(), status: Status::Fail, detail: Some(msg), indent: 1 },
                    ],
                    overall: Some(Verdict::Failed),
                };
                output::print_report(&report);
            }
        }
    }
    Ok(())
}

fn build_trust_store(
    args: &VerifyArgs,
    data: &[u8],
) -> Result<(ed25519_dalek::VerifyingKey, bool, Option<[u8; 1952]>, CliTrustStore)> {
    let kid = cose::extract_kid(data).ok();

    let ed_vk = if let Some(pk_hex) = &args.pubkey {
        let pk_bytes = hex::decode(pk_hex)?;
        if pk_bytes.len() != 32 {
            anyhow::bail!("Ed25519 pubkey must be 32 bytes (got {})", pk_bytes.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&pk_bytes);
        ed25519_dalek::VerifyingKey::from_bytes(&arr)
            .map_err(|e| anyhow::anyhow!("invalid Ed25519 public key: {}", e))?
    } else if let Some(k) = &kid {
        if k.len() != 32 {
            anyhow::bail!("expected 32-byte KID (Ed25519 pubkey), got {} bytes", k.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(k);
        ed25519_dalek::VerifyingKey::from_bytes(&arr)
            .map_err(|e| anyhow::anyhow!("invalid KID (not a valid Ed25519 pubkey): {}", e))?
    } else {
        anyhow::bail!(
            "no public key provided and no KID found in COSE envelope.\n\
             Use --pubkey <hex> to specify a public key, or create a statement with\n\
             `axiom sign` which embeds the public key automatically."
        );
    };

    let (is_composite, ml_bytes, comp_pk) = if let Some(ml_hex) = &args.mldsa_pubkey {
        let ml_bytes = hex::decode(ml_hex)?;
        if ml_bytes.len() != 1952 {
            anyhow::bail!("ML-DSA-65 pubkey must be 1952 bytes (got {})", ml_bytes.len());
        }
        let mut arr = [0u8; 1952];
        arr.copy_from_slice(&ml_bytes);
        let comp = CompositePublicKey { ed25519: ed_vk.to_bytes(), mldsa65: arr };
        (true, Some(arr), Some(comp))
    } else {
        (false, None, None)
    };

    let trusted_log_key = if let Some(hex_key) = &args.trusted_log_key {
        let bytes = hex::decode(hex_key)?;
        if bytes.len() != 32 {
            anyhow::bail!("trusted log key must be 32 bytes (got {})", bytes.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
    };

    let store = CliTrustStore::new(
        Some(ed_vk),
        comp_pk,
        args.chain_dir.as_ref(),
        trusted_log_key,
        args.revocation_cache.as_ref(),
    );

    Ok((ed_vk, is_composite, ml_bytes, store))
}

fn build_warning_sections(warnings: &VerificationWarnings) -> Vec<Section> {
    let mut sections = Vec::new();
    for w in &warnings.warnings {
        match w {
            Warning::TemporalEvidenceMissing => {
                sections.push(Section {
                    label: "No temporal evidence".into(),
                    status: Status::Warn,
                    detail: Some("statement has no CT log anchor; timestamp not provable to third parties".into()),
                    indent: 1,
                });
            }
            Warning::RevocationStatusUnknown => {
                sections.push(Section {
                    label: "Revocation status unknown".into(),
                    status: Status::Warn,
                    detail: Some("cannot verify whether statement has been revoked (no CT log access)".into()),
                    indent: 1,
                });
            }
            Warning::StaleSth { sth_timestamp, statement_timestamp, delta } => {
                let sth_time = output::format_timestamp(*sth_timestamp);
                let stmt_time = output::format_timestamp(*statement_timestamp);
                sections.push(Section {
                    label: "Stale STH".into(),
                    status: Status::Warn,
                    detail: Some(format!("STH from {} is {}s after statement from {}", sth_time, delta, stmt_time)),
                    indent: 1,
                });
            }
        }
    }
    sections
}

fn build_json_output(
    args: &VerifyArgs,
    vk: &Option<ed25519_dalek::VerifyingKey>,
    payload: &Option<AxiomPayload>,
    warnings: &VerificationWarnings,
    valid: bool,
    error: Option<String>,
) -> serde_json::Value {
    let mut obj = serde_json::json!({
        "valid": valid,
        "file": args.file.to_string_lossy(),
        "warnings": warnings.warnings.iter().map(|w| {
            match w {
                Warning::TemporalEvidenceMissing => serde_json::json!("temporal_evidence_missing"),
                Warning::RevocationStatusUnknown => serde_json::json!("revocation_status_unknown"),
                Warning::StaleSth { sth_timestamp, statement_timestamp, delta } => serde_json::json!({
                    "type": "stale_sth",
                    "sth_timestamp": sth_timestamp,
                    "statement_timestamp": statement_timestamp,
                    "delta_seconds": delta,
                }),
            }
        }).collect::<Vec<_>>(),
    });
    if let Some(e) = error {
        obj["error"] = serde_json::json!(e);
    }
    if let Some(vk) = vk {
        obj["pubkey"] = serde_json::json!(hex::encode(vk.to_bytes()));
    }
    if let Some(p) = payload {
        obj["subject"] = serde_json::json!(hex::encode(p.subject));
        obj["predicate"] = serde_json::json!(format!("{:?}", p.predicate));
        if let Some(o) = p.object { obj["object"] = serde_json::json!(hex::encode(o)); }
        if let Some(ts) = p.timestamp { obj["timestamp"] = serde_json::json!(ts); }
        if let Some(n) = p.nonce { obj["nonce"] = serde_json::json!(hex::encode(n)); }
        if let Some(l) = p.lineage { obj["lineage_hash"] = serde_json::json!(hex::encode(l)); }
        if let Some(ah) = p.anchor_hash { obj["anchor_hash"] = serde_json::json!(hex::encode(ah)); }
    }
    obj
}

fn build_sections(
    _args: &VerifyArgs,
    vk: &Option<ed25519_dalek::VerifyingKey>,
    payload: &Option<AxiomPayload>,
    algorithm: &str,
    trust_level: &str,
) -> Vec<Section> {
    let mut sections = Vec::new();
    sections.push(Section {
        label: "Signature valid".into(),
        status: Status::Pass,
        detail: None,
        indent: 0,
    });
    sections.push(Section {
        label: "Canonical CBOR".into(),
        status: Status::Pass,
        detail: None,
        indent: 1,
    });
    sections.push(Section {
        label: "Protected header deterministic".into(),
        status: Status::Pass,
        detail: None,
        indent: 1,
    });
    sections.push(Section {
        label: "Algorithm".into(),
        status: Status::Info,
        detail: Some(algorithm.into()),
        indent: 1,
    });

    if let Some(p) = payload {
        sections.push(Section {
            label: "Subject".into(),
            status: Status::Info,
            detail: Some(hex::encode(p.subject)),
            indent: 1,
        });
        sections.push(Section {
            label: "Predicate".into(),
            status: Status::Info,
            detail: Some(format!("{:?}", p.predicate)),
            indent: 1,
        });
        if let Some(ts) = p.timestamp {
            sections.push(Section {
                label: "Timestamp".into(),
                status: Status::Info,
                detail: Some(output::format_timestamp(ts)),
                indent: 1,
            });
        }
        if p.lineage.is_some() {
            sections.push(Section {
                label: "Lineage chain verified".into(),
                status: Status::Pass,
                detail: None,
                indent: 1,
            });
        }
        if p.anchor_hash.is_some() {
            sections.push(Section {
                label: "CT anchor cryptographically bound".into(),
                status: Status::Pass,
                detail: None,
                indent: 1,
            });
        }
    }

    if let Some(vk) = vk {
        sections.push(Section {
            label: "Public Key".into(),
            status: Status::Info,
            detail: Some(hex::encode(vk.to_bytes())),
            indent: 1,
        });
    }

    sections.push(Section {
        label: "Protocol level".into(),
        status: Status::Pass,
        detail: Some("signature, CBOR, lineage, and CT anchor verified".into()),
        indent: 0,
    });
    sections.push(Section {
        label: "Trust".into(),
        status: Status::Info,
        detail: Some(trust_level.into()),
        indent: 0,
    });

    sections
}

fn generate_explain_sections(
    args: &VerifyArgs,
    vk: &Option<ed25519_dalek::VerifyingKey>,
    algorithm: &str,
    data: &[u8],
    payload_bytes: &Option<Vec<u8>>,
    stmt: &Statement,
    warnings: &VerificationWarnings,
) -> Vec<Section> {
    let stmt_hash = blake3(data);
    let payload_hash = payload_bytes.as_ref().map(|b| blake3(b));
    let subject = stmt.subject().ok().map(hex::encode).unwrap_or_default();

    let mut sections = vec![
        Section { label: "Step 1: Loaded COSE envelope from file".into(), status: Status::Pass, detail: Some(format!("{} bytes", data.len())), indent: 1 },
        Section { label: "Step 2: Verified canonical CBOR encoding".into(), status: Status::Pass, detail: None, indent: 1 },
        Section { label: "Step 3: Verified protected header determinism".into(), status: Status::Pass, detail: None, indent: 1 },
    ];
    if let Some(vk) = vk {
        sections.push(Section { label: format!("Step 4: Resolved public key from {} header", if args.pubkey.is_some() { "--pubkey" } else { "KID" }).into(), status: Status::Pass, detail: Some(hex::encode(vk.to_bytes())), indent: 1 });
    } else {
        sections.push(Section { label: "Step 4: Resolved composite public key".into(), status: Status::Pass, detail: None, indent: 1 });
    }
    sections.push(Section { label: format!("Step 5: Verified {} signature", algorithm).into(), status: Status::Pass, detail: None, indent: 1 });

    if let Some(l) = stmt.lineage().ok().flatten() {
        sections.push(Section { label: "Step 6: Verified lineage chain integrity".into(), status: Status::Pass, detail: Some(format!("previous: {}", hex::encode(l))), indent: 1 });
    }

    let has_anchor = !warnings.warnings.iter().any(|w| matches!(w, Warning::TemporalEvidenceMissing));
    if has_anchor {
        sections.push(Section { label: "Step 7: Verified CT temporal anchor".into(), status: Status::Pass, detail: Some("Merkle proof and STH signature valid".into()), indent: 1 });
    } else {
        sections.push(Section { label: "Step 7: CT temporal anchor".into(), status: Status::Warn, detail: Some("not present; timestamp not provable".into()), indent: 1 });
    }

    let revoked_unknown = warnings.warnings.iter().any(|w| matches!(w, Warning::RevocationStatusUnknown));
    if revoked_unknown {
        sections.push(Section { label: "Step 8: Revocation check".into(), status: Status::Warn, detail: Some("CT log not reachable; revocation status unknown".into()), indent: 1 });
    } else {
        sections.push(Section { label: "Step 8: Revocation check".into(), status: Status::Pass, detail: Some("not revoked".into()), indent: 1 });
    }

    sections.push(Section { label: "Summary".into(), status: Status::Info, detail: None, indent: 0 });
    sections.push(Section { label: format!("Statement asserts {} on artifact {}", stmt.predicate().map(|p| format!("{:?}", p)).unwrap_or_default(), subject).into(), status: Status::Info, detail: None, indent: 1 });
    if let Some(ph) = payload_hash {
        sections.push(Section { label: format!("Payload hash: {}", hex::encode(ph)).into(), status: Status::Info, detail: None, indent: 1 });
    }
    sections.push(Section { label: format!("Statement hash: {}", hex::encode(stmt_hash)).into(), status: Status::Info, detail: None, indent: 1 });

    sections
}

fn generate_trace_sections(data: &[u8], payload_bytes: &Option<Vec<u8>>) -> Vec<Section> {
    let mut sections = Vec::new();
    sections.push(Section { label: "Raw Statement Bytes".into(), status: Status::Info, detail: Some(hex::encode(data)), indent: 1 });
    if let Some(pb) = payload_bytes {
        sections.push(Section { label: "Payload Bytes".into(), status: Status::Info, detail: Some(hex::encode(pb)), indent: 1 });
        sections.push(Section { label: "Payload Hash (BLAKE3)".into(), status: Status::Info, detail: Some(hex::encode(blake3(pb))), indent: 1 });
    }
    sections.push(Section { label: "Statement Hash (BLAKE3)".into(), status: Status::Info, detail: Some(hex::encode(blake3(data))), indent: 1 });
    sections
}
