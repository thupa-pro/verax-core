use anyhow::Result;
use clap::{Args, CommandFactory, Subcommand};
use std::path::PathBuf;
use std::io::Write;

use crate::Cli;

#[derive(Subcommand)]
pub enum CompletionCommands {
    /// Generate completion script for a shell (prints to stdout)
    Generate(GenerateArgs),
    /// Detect shell and install completions automatically
    Install,
}

#[derive(Args)]
pub struct GenerateArgs {
    /// Shell to generate completion for
    pub shell: clap_complete::Shell,
}

pub fn run(command: &CompletionCommands) -> Result<()> {
    match command {
        CompletionCommands::Generate(args) => generate(&args.shell),
        CompletionCommands::Install => install(),
    }
}

fn generate(shell: &clap_complete::Shell) -> Result<()> {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    clap_complete::generate(*shell, &mut cmd, name, &mut std::io::stdout());
    Ok(())
}

fn install() -> Result<()> {
    let shell = detect_shell()?;
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();

    let (dir, file_name, instruction) = shell_paths(&shell, &name)?;
    std::fs::create_dir_all(&dir)?;

    let path = dir.join(&file_name);
    let mut file = std::fs::File::create(&path)?;
    clap_complete::generate(shell, &mut cmd, &name, &mut file);
    file.flush()?;

    println!("  Completions installed for {} shell", shell);
    println!("  Script: {}", path.to_string_lossy());
    println!("  {}", instruction);
    Ok(())
}

fn detect_shell() -> Result<clap_complete::Shell> {
    let shell_var = std::env::var("SHELL")
        .map_err(|_| anyhow::anyhow!(
            "could not detect shell from $SHELL. Use `completion generate <shell>` instead.\n\
             Available shells: bash, zsh, fish, powershell, elvish"
        ))?;
    let shell_name = std::path::Path::new(&shell_var)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    match shell_name {
        "bash" => Ok(clap_complete::Shell::Bash),
        "zsh" => Ok(clap_complete::Shell::Zsh),
        "fish" => Ok(clap_complete::Shell::Fish),
        "powershell" | "pwsh" => Ok(clap_complete::Shell::PowerShell),
        "elvish" => Ok(clap_complete::Shell::Elvish),
        other => Err(anyhow::anyhow!(
            "unsupported shell: '{}'. Use `completion generate <shell>` with: bash, zsh, fish, powershell, elvish",
            other
        )),
    }
}

fn shell_paths(shell: &clap_complete::Shell, name: &str) -> Result<(PathBuf, String, String)> {
    let home = std::env::var("HOME").map_err(|_| anyhow::anyhow!("$HOME not set"))?;
    match shell {
        clap_complete::Shell::Bash => Ok((
            PathBuf::from(&home).join(".local/share/bash-completion/completions"),
            name.to_string(),
            "Ensure ~/.local/share/bash-completion/completions is in your BASH_COMPLETION_DIR, or source the file in your .bashrc".to_string(),
        )),
        clap_complete::Shell::Zsh => Ok((
            PathBuf::from(&home).join(".zsh/completions"),
            format!("_{name}"),
            format!("Add to your .zshrc: fpath=({} $fpath) && autoload -Uz compinit && compinit",
                PathBuf::from(&home).join(".zsh/completions").to_string_lossy()),
        )),
        clap_complete::Shell::Fish => Ok((
            PathBuf::from(&home).join(".config/fish/completions"),
            format!("{name}.fish"),
            "Fish completions are loaded automatically from ~/.config/fish/completions".into(),
        )),
        clap_complete::Shell::PowerShell => Ok((
            PathBuf::from(&home).join(".config/powershell"),
            format!("_{name}.ps1"),
            format!("Add to your PowerShell profile: . '{}'",
                PathBuf::from(&home).join(format!(".config/powershell/_{name}.ps1")).to_string_lossy()),
        )),
        _ => anyhow::bail!("auto-install not supported for this shell"),
    }
}
