use anyhow::Result;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum ExampleCommands {
    /// Image provenance chain
    Image,
    /// AI model lineage
    #[clap(name = "ai-model")]
    AiModel,
    /// Dataset provenance
    Dataset,
    /// Medical records
    Medical,
    /// Supply chain
    SupplyChain,
    /// Software release
    SoftwareRelease,
    /// Streaming data
    Streaming,
    /// List available examples
    List,
}

pub fn run(command: &ExampleCommands) -> Result<()> {
    match command {
        ExampleCommands::List => list(),
        ExampleCommands::Image => image_provenance(),
        ExampleCommands::AiModel => ai_model(),
        ExampleCommands::Dataset => dataset(),
        ExampleCommands::Medical => medical(),
        ExampleCommands::SupplyChain => supply_chain(),
        ExampleCommands::SoftwareRelease => software_release(),
        ExampleCommands::Streaming => streaming(),
    }
}

fn list() -> Result<()> {
    println!("\n  Available examples:\n");
    println!("    image         Image provenance chain");
    println!("    ai-model      AI model lineage");
    println!("    dataset       Dataset provenance");
    println!("    medical       Medical records");
    println!("    supply-chain  Supply chain");
    println!("    software-release  Software release");
    println!("    streaming     Streaming data\n");
    Ok(())
}

fn run_example(seed: &[u8; 32], label: &str, script: &str) -> Result<()> {
    let sk = ed25519_dalek::SigningKey::from_bytes(seed);
    let vk = sk.verifying_key();
    println!("\n  Example: {}\n", label);
    println!("  Public key: {}", hex::encode(vk.to_bytes()));
    println!("\n  Commands to run:\n");
    for line in script.lines() {
        println!("    $ {}", line);
    }
    println!();
    Ok(())
}

fn image_provenance() -> Result<()> {
    let seed = [0xe0; 32];
    run_example(&seed, "Image Provenance Chain", r#"axiom hash photo.jpg
axiom sign photo.jpg --predicate authors --key alice.key --out photo.vt
axiom verify photo.vt
axiom graph photo.vt"#)
}

fn ai_model() -> Result<()> {
    let seed = [0xe1; 32];
    run_example(&seed, "AI Model Lineage", r#"axiom sign dataset.csv --predicate attests --key data-team.key --out dataset.vt
axiom sign training-script.py --predicate derived_from --object <dataset-hash> --key engineer.key --out model-v1.vt
axiom sign model-v1.pt --predicate derived_from --object <training-hash> --key reviewer.key --out model-signed.vt
axiom graph model-signed.vt"#)
}

fn dataset() -> Result<()> {
    let seed = [0xe2; 32];
    run_example(&seed, "Dataset Provenance", r#"axiom sign raw-data.csv --predicate attests --key collector.key --out raw.vt
axiom sign clean-data.csv --predicate derived_from --object <raw-hash> --key pipeline.key --out clean.vt
axiom verify clean.vt --explain"#)
}

fn medical() -> Result<()> {
    let seed = [0xe3; 32];
    run_example(&seed, "Medical Records", r#"axiom encrypt patient-report.pdf
axiom sign patient-report.pdf.enc --predicate attests --key doctor.key --out record.vt
axiom verify record.vt"#)
}

fn supply_chain() -> Result<()> {
    let seed = [0xe4; 32];
    run_example(&seed, "Supply Chain", r#"axiom sign parts-list.csv --predicate attests --key supplier.key --out parts.vt
axiom sign inspection.pdf --predicate derived_from --object <parts-hash> --key qa.key --out inspection.vt
axiom sign shipping-label.pdf --predicate appends --lineage <inspection-hash> --key logistics.key --out shipment.vt
axiom verify shipment.vt"#)
}

fn software_release() -> Result<()> {
    let seed = [0xe5; 32];
    run_example(&seed, "Software Release", r#"axiom hash release.tar.gz
axiom sign release.tar.gz --predicate attests --key release-manager.key --out release.vt
axiom lint release.vt
axiom verify release.vt --json"#)
}

fn streaming() -> Result<()> {
    let seed = [0xe6; 32];
    run_example(&seed, "Streaming Data", r##"# Each chunk is signed and chained
axiom sign chunk-001.bin --predicate appends --key stream.key --out stream-001.vt
axiom sign chunk-002.bin --predicate appends --lineage <chunk-001-hash> --key stream.key --out stream-002.vt
axiom graph stream-002.vt"##)
}
