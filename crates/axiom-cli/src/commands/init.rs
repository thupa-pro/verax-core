use anyhow::Result;
use std::fs;
use crate::config;

pub fn run() -> Result<()> {
    if config::project_dir().exists() {
        anyhow::bail!(".axiom/ already exists in this directory");
    }
    config::ensure_project_dirs()?;

    let config_content = r#"# Axiom Protocol Project Configuration
[project]
name = "axiom-project"
version = "1.0.0"

[defaults]
algorithm = "ed25519"
"#;
    fs::write(config::project_config_path(), config_content)?;

    println!("  Initialized empty Axiom project in .axiom/");
    println!("  Keys:    .axiom/keys/");
    println!("  Cache:   .axiom/cache/");
    println!("  Trust:   .axiom/trust/");
    Ok(())
}
