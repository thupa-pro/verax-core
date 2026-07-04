use anyhow::Result;
use clap::Args;
use std::path::PathBuf;
use axiom_core::{AxiomPayload, Statement, hash::blake3, predicate::Predicate};

#[derive(Args)]
pub struct GraphArgs {
    /// Path to the .axm statement file
    pub file: PathBuf,
    /// Max lineage depth to traverse
    #[arg(long, default_value = "50")]
    pub depth: usize,
    /// Output as SVG (not yet implemented — prints ASCII)
    #[arg(long)]
    pub svg: bool,
    /// Interactive mode
    #[arg(long, short)]
    pub interactive: bool,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Clone)]
struct StatementNode {
    hash: [u8; 32],
    payload: AxiomPayload,
    depth: usize,
}

pub fn run(args: &GraphArgs) -> Result<()> {
    let data = std::fs::read(&args.file)?;
    let stmt = Statement::from_bytes(&data)
        .map_err(|e| anyhow::anyhow!("failed to parse COSE: {}", e))?;
    let payload = stmt.decode_payload()
        .map_err(|e| anyhow::anyhow!("failed to decode payload: {}", e))?;

    let mut chain: Vec<StatementNode> = Vec::new();
    let mut hashes_seen: Vec<Vec<u8>> = Vec::new();

    let stmt_hash = blake3(&data);
    chain.push(StatementNode {
        hash: stmt_hash,
        payload: payload.clone(),
        depth: 0,
    });
    hashes_seen.push(stmt_hash.to_vec());

    let mut current_payload = payload;
    let mut depth = 0;

    while depth < args.depth {
        match current_payload.lineage {
            Some(prev_hash) => {
                let prev_hash_vec = prev_hash.to_vec();
                if hashes_seen.contains(&prev_hash_vec) {
                    break;
                }
                depth += 1;
                let prev_stmt = fetch_statement(&prev_hash);
                let prev_payload = prev_stmt.as_ref()
                    .and_then(|bytes| Statement::from_bytes(bytes).ok())
                    .and_then(|s| s.decode_payload().ok());

                chain.push(StatementNode {
                    hash: prev_hash,
                    payload: prev_payload.clone().unwrap_or_else(|| AxiomPayload::new([0; 32], Predicate::Attests)),
                    depth,
                });
                hashes_seen.push(prev_hash_vec);
                match prev_payload {
                    Some(p) => {
                        current_payload = p;
                    }
                    None => break,
                }
            }
            None => break,
        }
    }

    if args.json {
        let nodes: Vec<serde_json::Value> = chain.iter().rev().map(|n| {
            serde_json::json!({
                "hash": hex::encode(n.hash),
                "predicate": format!("{:?}", n.payload.predicate),
                "subject": hex::encode(n.payload.subject),
                "timestamp": n.payload.timestamp,
                "object": n.payload.object.map(hex::encode),
                "lineage": n.payload.lineage.map(hex::encode),
                "depth": n.depth,
            })
        }).collect();
        let out = serde_json::json!({
            "file": args.file.to_string_lossy(),
            "depth": args.depth,
            "nodes": nodes,
        });
        crate::output::json_output(&out);
    } else if args.interactive {
        run_interactive(&chain, &args.file)?;
    } else if args.svg {
        eprintln!("SVG output not yet implemented — printing ASCII graph");
        print_ascii_graph(&chain);
    } else {
        print_ascii_graph(&chain);
    }

    Ok(())
}

fn print_ascii_graph(chain: &[StatementNode]) {
    use nu_ansi_term::Style;

    println!("\n  Provenance DAG (root at top):\n");
    let max_depth = chain.iter().map(|n| n.depth).max().unwrap_or(0);

    for node in chain.iter().rev() {
        let depth_offset = max_depth - node.depth;

        let hash_str = hex::encode(node.hash);
        let pred_str = format!("{:?}", node.payload.predicate);
        let hash_prefix = &hash_str[..12];

        let label = if let Some(obj) = node.payload.object {
            format!("{} \u{2192} {}", hash_prefix, hex::encode(obj))
        } else {
            hash_prefix.to_string()
        };

        let styled = Style::new().bold().paint(format!("  {} [{}]", label, pred_str));
        println!("{}", styled);
        println!("  {}    subject: {}", " ".repeat(depth_offset), &hex::encode(node.payload.subject)[..12]);

        if let Some(ts) = node.payload.timestamp {
            println!("  {}    time: {}", " ".repeat(depth_offset), crate::output::format_timestamp(ts));
        }

        if node.depth != max_depth || node.depth != chain.first().unwrap_or(node).depth {
            println!("  {}    \u{2502}", " ".repeat(depth_offset));
            println!("  {}    \u{2502}", " ".repeat(depth_offset));
        }
    }
    println!();
}

fn run_interactive(chain: &[StatementNode], file: &std::path::Path) -> Result<()> {
    eprintln!("Interactive graph explorer for: {}", file.display());
    eprintln!("(Interactive mode requires terminal — showing static view)\n");
    print_ascii_graph(chain);

    for node in chain.iter().rev().take(5) {
        let h = hex::encode(node.hash);
        let p = format!("{:?}", node.payload.predicate);
        eprintln!("  \u{2502} \u{2190} Previous: {} [{}]", &h[..12], p);
    }
    eprintln!();
    Ok(())
}

fn fetch_statement(hash: &[u8; 32]) -> Option<Vec<u8>> {
    let hash_hex = hex::encode(hash);
    let paths = [
        format!(".axiom/cache/{}.axm", hash_hex),
        format!("{}.axm", hash_hex),
    ];
    for p in &paths {
        if let Ok(data) = std::fs::read(p) {
            return Some(data);
        }
    }
    None
}
