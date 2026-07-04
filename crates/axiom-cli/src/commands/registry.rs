use anyhow::Result;
use clap::Subcommand;
use axiom_core::predicate::CORE_PREDICATES;
use crate::output::{self, Status, Section, Report};

#[derive(Subcommand)]
pub enum RegistryCommands {
    /// List all registered predicates
    Predicates,
}

pub fn run(command: &RegistryCommands) -> Result<()> {
    match command {
        RegistryCommands::Predicates => list_predicates(),
    }
}

fn list_predicates() -> Result<()> {
    let mut sections = Vec::new();
    for pred in CORE_PREDICATES {
        let code = format!("{}", *pred as u8);
        sections.push(Section {
            label: code,
            status: Status::Info,
            detail: Some(format!("{} — {}", pred.name(), pred.description())),
            indent: 0,
        });
    }

    let report = Report {
        title: format!("Registered Predicates ({} total)", CORE_PREDICATES.len()),
        sections,
        overall: None,
    };
    output::print_report(&report);
    Ok(())
}
