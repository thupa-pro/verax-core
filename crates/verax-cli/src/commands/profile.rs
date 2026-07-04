use anyhow::Result;
use clap::Args;

#[derive(Args)]
pub struct ProfileArgs {
    /// Profile name to use
    pub name: Option<String>,
    /// Show current profile
    #[arg(long)]
    pub show: bool,
}

pub fn run(args: &ProfileArgs) -> Result<()> {
    if args.show {
        println!("  Current profile: default");
        println!("  Algorithm:       Ed25519");
        println!("  Format:          .axm");
        return Ok(());
    }
    if let Some(name) = &args.name {
        println!("  Switched to profile: {}", name);
    } else {
        println!("  Profiles: default");
    }
    Ok(())
}
