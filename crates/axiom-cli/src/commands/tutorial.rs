use anyhow::Result;
use std::io::Write;

pub fn run() -> Result<()> {
    println!("\n  \u{250C}{}\u{2510}", "\u{2500}".repeat(55));
    println!("  \u{2502}  {:^53}\u{2502}", "Axiom Protocol — Interactive Tutorial");
    println!("  \u{2514}{}\u{2518}\n", "\u{2500}".repeat(55));

    step(1, "Creating a statement", "We'll create a simple provenance statement.")?;
    wait();

    let tmp = std::env::temp_dir().join("axiom-tutorial");
    std::fs::create_dir_all(&tmp)?;
    let artifact = tmp.join("hello.txt");
    std::fs::write(&artifact, b"Hello, Axiom!")?;

    let artifact_hash = axiom_core::hash::blake3(b"Hello, Axiom!");
    println!("  Artifact hash: {}", hex::encode(artifact_hash));
    println!();

    step(2, "Generating a signing key", "Every statement needs a key.")?;
    wait();

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| anyhow::anyhow!("random generation failed: {}", e))?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    println!("  Public key: {}", hex::encode(vk.to_bytes()));
    println!();

    step(3, "Signing the statement", "We create a signed .axm file.")?;
    wait();

    let payload = axiom_core::AxiomPayload::new(artifact_hash, axiom_core::Predicate::Attests);
    let stmt = axiom_core::Statement::sign_ed25519(&payload, &sk)
        .map_err(|e| anyhow::anyhow!("signing failed: {}", e))?;
    let axm_path = tmp.join("hello.axm");
    std::fs::write(&axm_path, stmt.to_bytes())?;
    println!("  Written to: {}", axm_path.to_string_lossy());
    println!();

    step(4, "Verifying the statement", "Full protocol verification — checks signature, canonical CBOR, and key binding.")?;
    wait();

    match axiom_core::verify_statement_ed25519(stmt.to_bytes(), &vk)
        .map_err(|e| anyhow::anyhow!("verify failed: {}", e)) {
        Ok(_) => println!("  \u{2714} VERIFIED — Signature, canonical CBOR, and key binding all valid.\n"),
        Err(e) => println!("  \u{2718} FAILED — {}\n", e),
    }

    step(5, "Building a provenance chain", "Statements can link to form a chain.")?;
    wait();

    let stmt_hash = axiom_core::hash::blake3(stmt.to_bytes());
    let mut child_payload = axiom_core::AxiomPayload::new(artifact_hash, axiom_core::Predicate::Appends);
    child_payload.lineage = Some(stmt_hash);
    child_payload.timestamp = Some(100);
    let child_stmt = axiom_core::Statement::sign_ed25519(&child_payload, &sk)
        .map_err(|e| anyhow::anyhow!("signing failed: {}", e))?;
    let child_axm = tmp.join("hello-v2.axm");
    std::fs::write(&child_axm, child_stmt.to_bytes())?;
    println!("  Statement 1: {} -> Statement 2 (APPENDS)", &hex::encode(stmt_hash)[..16]);
    println!();

    step(6, "Understanding trust", "Trust comes from the key, not the chain.")?;
    wait();
    println!("  Any statement signed with a given key can be verified");
    println!("  by anyone who has the corresponding public key.");
    println!("  The public key is embedded as the KID in the COSE envelope,");
    println!("  so `axiom verify` works with zero flags.\n");

    println!("  \u{250C}{}\u{2510}", "\u{2500}".repeat(55));
    println!("  \u{2502}  {:^53}\u{2502}", "Tutorial Complete!");
    println!("  \u{2514}{}\u{2518}\n", "\u{2500}".repeat(55));
    println!("  What you learned:");
    println!("    axiom init        — create a project");
    println!("    axiom sign <file> — sign a statement (auto-generates key)");
    println!("    axiom verify <file> — verify a statement (auto-extracts key)");
    println!("    axiom graph <file> — visualize the provenance chain");
    println!("    axiom lint <file> — check for best practices\n");
    println!("  Try:  axiom examples image\n");

    std::fs::remove_dir_all(&tmp).ok();
    Ok(())
}

fn step(num: u8, title: &str, description: &str) -> Result<()> {
    println!("  \u{250C}{}\u{2510}", "\u{2500}".repeat(53));
    println!("  \u{2502} Step {}: {:<44}\u{2502}", num, title);
    println!("  \u{2514}{}\u{2518}\n", "\u{2500}".repeat(53));
    println!("  {}", description);
    Ok(())
}

fn wait() {
    print!("  \u{23F3}  Press Enter to continue...");
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    println!();
}
