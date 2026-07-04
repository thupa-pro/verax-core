mod commands;
mod config;
mod output;

use clap::{Parser, Subcommand};
use std::process::ExitCode;

use output::OutputFormat;

#[derive(Parser)]
#[command(
    name = "axiom",
    version,
    about = "Axiom Protocol — verifiable provenance for any artifact",
    long_about = "A minimal protocol with exceptional tooling.\n\n\
Create, verify, and trace cryptographic provenance chains\n\
with deterministic CBOR encoding, Ed25519/ML-DSA-65 signatures,\n\
and Merkle-tree transparency logging.",
    after_help = "See 'axiom examples' for end-to-end walkthroughs."
)]
struct Cli {
    /// Output format: human-readable, JSON, or quiet (exit code only)
    #[arg(long, global = true, value_enum, default_value = "human")]
    format: FormatArg,

    /// Color output: auto, always, never
    #[arg(long, global = true, value_enum, default_value = "auto")]
    color: ColorArg,

    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::ValueEnum, Clone, Copy)]
enum FormatArg {
    Human,
    Json,
    Quiet,
}

#[derive(clap::ValueEnum, Clone, Copy)]
enum ColorArg {
    Auto,
    Always,
    Never,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new Axiom project in the current directory
    Init,
    /// Hash an artifact with BLAKE3
    Hash(commands::hash::HashArgs),
    /// Sign a statement (create a .axm file)
    Sign(commands::sign::SignArgs),
    /// Verify a signed statement (the most important command)
    Verify(commands::verify::VerifyArgs),
    /// Inspect a statement's contents in human-readable form
    Inspect(commands::inspect::InspectArgs),
    /// Visualize the provenance DAG
    Graph(commands::graph::GraphArgs),
    /// Key management (generate, import, export, rotate, list)
    #[command(subcommand)]
    Key(commands::key::KeyCommands),
    /// DID management (create, resolve, verify)
    #[command(subcommand)]
    Did(commands::did::DidCommands),
    /// Run protocol diagnostics
    Doctor(commands::doctor::DoctorArgs),
    /// Show version information
    Version(commands::version::VersionArgs),
    /// Shell completion generation and installation
    #[command(subcommand)]
    Completion(commands::completion::CompletionCommands),
    /// Encrypt an artifact
    Encrypt(commands::encrypt::EncryptArgs),
    /// Convert between formats (json, cbor, hex)
    Convert(commands::convert::ConvertArgs),
    /// Export statements to various formats (markdown, json)
    Export(commands::export_cmd::ExportArgs),
    /// Run protocol benchmarks
    Benchmark,
    /// Registry operations (list predicates)
    #[command(subcommand)]
    Registry(commands::registry::RegistryCommands),
    /// Run conformance tests against the suite
    Test,
    /// Transparency log operations
    #[command(subcommand)]
    Log(commands::log::LogCommands),
    /// Manage profiles
    Profile(commands::profile::ProfileArgs),
    /// Create a consent statement for data processing
    Consent(commands::consent::ConsentArgs),
    /// Lint a statement for protocol best practices
    Lint(commands::lint::LintArgs),
    /// Explain a statement in plain language
    Explain(commands::explain::ExplainArgs),
    /// Run built-in examples
    #[command(subcommand)]
    Examples(commands::examples::ExampleCommands),
    /// Start an interactive REPL shell
    Shell,
    /// Interactive tutorial for new users
    Tutorial,
    /// Shred (destroy) key material
    Shred {
        /// Path to the key file to shred
        key_file: Option<String>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let format = match cli.format {
        FormatArg::Human => OutputFormat::Human,
        FormatArg::Json => OutputFormat::Json,
        FormatArg::Quiet => OutputFormat::Quiet,
    };
    let color = match cli.color {
        ColorArg::Auto => output::ColorChoice::Auto,
        ColorArg::Always => output::ColorChoice::Always,
        ColorArg::Never => output::ColorChoice::Never,
    };
    output::init_globals(format, color);
    config::load_config();

    let result: Result<(), anyhow::Error> = match cli.command {
        Commands::Init => commands::init::run(),
        Commands::Hash(args) => commands::hash::run(&args),
        Commands::Sign(args) => commands::sign::run(&args),
        Commands::Verify(args) => commands::verify::run(&args),
        Commands::Inspect(args) => commands::inspect::run(&args),
        Commands::Graph(args) => commands::graph::run(&args),
        Commands::Key(cmd) => commands::key::run(&cmd),
        Commands::Did(cmd) => commands::did::run(&cmd),
        Commands::Doctor(args) => commands::doctor::run(&args),
        Commands::Version(args) => commands::version::run(&args),
        Commands::Completion(cmd) => commands::completion::run(&cmd),
        Commands::Encrypt(args) => commands::encrypt::run(&args),
        Commands::Convert(args) => commands::convert::run(&args),
        Commands::Export(args) => commands::export_cmd::run(&args),
        Commands::Benchmark => commands::benchmark::run(),
        Commands::Registry(cmd) => commands::registry::run(&cmd),
        Commands::Test => commands::test_cmd::run(),
        Commands::Log(cmd) => commands::log::run(&cmd),
        Commands::Profile(args) => commands::profile::run(&args),
        Commands::Consent(args) => commands::consent::run(&args),
        Commands::Lint(args) => commands::lint::run(&args),
        Commands::Explain(args) => commands::explain::run(&args),
        Commands::Examples(cmd) => commands::examples::run(&cmd),
        Commands::Shell => commands::shell::run(),
        Commands::Tutorial => commands::tutorial::run(),
        Commands::Shred { key_file } => shred(key_file),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let msg = format!("{}", e);
            if output::output_format() == output::OutputFormat::Json {
                let out = serde_json::json!({
                    "error": msg,
                    "exit_code": 1
                });
                output::json_output(&out);
            } else if output::output_format() != output::OutputFormat::Quiet {
                eprintln!("\u{2718} {}", msg);
            }
            ExitCode::FAILURE
        }
    }
}

fn shred(key_file: Option<String>) -> anyhow::Result<()> {
    let path = match key_file {
        Some(p) => std::path::PathBuf::from(p),
        None => config::project_keys_dir(),
    };

    if !path.exists() {
        anyhow::bail!("path does not exist: {}", path.display());
    }

    println!("\n  \u{26A0}  WARNING: Shredding key material is PERMANENT");
    println!("  Encrypted artifacts will become UNRECOVERABLE");
    println!("  Path: {}\n", path.display());

    if path.is_dir() {
        eprintln!("  Skipping directory shred for safety; use file paths only");
    } else {
        let len = std::fs::metadata(&path)?.len() as usize;
        let overwrite = vec![0u8; len.min(4096)];
        let mut file = std::fs::File::create(&path)?;
        use std::io::Write;
        for _ in 0..3 {
            file.write_all(&overwrite)?;
        }
        std::fs::remove_file(&path)?;
        println!("  Shredded: {}", path.display());
    }

    Ok(())
}
