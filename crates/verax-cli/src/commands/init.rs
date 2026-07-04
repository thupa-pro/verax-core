use crate::config;
use anyhow::Result;
use std::fs;

pub fn run() -> Result<()> {
    if config::project_dir().exists() {
        anyhow::bail!(".verax/ already exists in this directory");
    }
    config::ensure_project_dirs()?;

    let config_content = r#"# Verax Protocol Project Configuration
[project]
name = "verax-project"
version = "1.0.0"

[defaults]
algorithm = "ed25519"
"#;
    fs::write(config::project_config_path(), config_content)?;

    println!("  Initialized empty Verax project in .verax/");
    println!("  Keys:    .verax/keys/");
    println!("  Cache:   .verax/cache/");
    println!("  Trust:   .verax/trust/");
    Ok(())
}
