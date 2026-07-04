use anyhow::Result;
use clap::Args;

#[derive(Args)]
pub struct VersionArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &VersionArgs) -> Result<()> {
    if args.json {
        let out = serde_json::json!({
            "name": "axiom",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Axiom Protocol CLI",
        });
        crate::output::json_output(&out);
    } else {
        println!("axiom {}", env!("CARGO_PKG_VERSION"));
    }
    Ok(())
}
