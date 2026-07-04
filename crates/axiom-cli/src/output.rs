use nu_ansi_term::{Style, Color};
use std::sync::OnceLock;
use std::io::IsTerminal;

pub const CHECK_MARK: &str = "\u{2714}";
pub const CROSS_MARK: &str = "\u{2718}";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
    Quiet,
}

static GLOBAL_FORMAT: OnceLock<OutputFormat> = OnceLock::new();
static GLOBAL_COLOR: OnceLock<ColorChoice> = OnceLock::new();

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

pub fn init_globals(format: OutputFormat, color: ColorChoice) {
    let _ = GLOBAL_FORMAT.set(format);
    let _ = GLOBAL_COLOR.set(color);
}

pub fn output_format() -> OutputFormat {
    GLOBAL_FORMAT.get().copied().unwrap_or(OutputFormat::Human)
}

fn use_color() -> bool {
    let choice = GLOBAL_COLOR.get().copied().unwrap_or(ColorChoice::Auto);
    match choice {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => {
            if std::env::var("NO_COLOR").is_ok() {
                return false;
            }
            std::io::stdout().is_terminal()
        }
    }
}

fn style(s: &str, style: Style) -> String {
    if use_color() {
        format!("{}", style.paint(s))
    } else {
        s.to_string()
    }
}

pub struct Report {
    pub title: String,
    pub sections: Vec<Section>,
    pub overall: Option<Verdict>,
}

pub struct Section {
    pub label: String,
    pub status: Status,
    pub detail: Option<String>,
    pub indent: usize,
}

#[derive(Clone, Copy)]
pub enum Status {
    Pass,
    Fail,
    Warn,
    Info,
}

impl Status {
    pub fn symbol(&self) -> &str {
        match self {
            Status::Pass => CHECK_MARK,
            Status::Fail => CROSS_MARK,
            Status::Warn => "\u{26A0}",
            Status::Info => "\u{2139}",
        }
    }

    pub fn style(&self) -> Style {
        match self {
            Status::Pass => Style::new().fg(Color::Green).bold(),
            Status::Fail => Style::new().fg(Color::Red).bold(),
            Status::Warn => Style::new().fg(Color::Yellow).bold(),
            Status::Info => Style::new().fg(Color::Cyan),
        }
    }
}

pub enum Verdict {
    Verified,
    Failed,
    Partial,
}

impl Verdict {
    pub fn label(&self) -> &str {
        match self {
            Verdict::Verified => "VERIFIED",
            Verdict::Failed => "FAILED",
            Verdict::Partial => "PARTIAL",
        }
    }

    pub fn style(&self) -> Style {
        match self {
            Verdict::Verified => Style::new().fg(Color::Green).bold(),
            Verdict::Failed => Style::new().fg(Color::Red).bold(),
            Verdict::Partial => Style::new().fg(Color::Yellow).bold(),
        }
    }
}

pub fn print_report(report: &Report) {
    if output_format() == OutputFormat::Quiet {
        return;
    }
    let line = "\u{2500}".repeat(57);
    println!("\u{250C}{}\u{2510}", line);
    println!("\u{2502}  {:^51}\u{2502}", report.title);
    println!("\u{251C}{}\u{2524}", line);
    for section in &report.sections {
        let indent_str = "  ".repeat(section.indent);
        let sym = section.status.symbol();
        let styled_sym = style(sym, section.status.style());
        match &section.detail {
            Some(d) => {
                let styled = style(&section.label, section.status.style());
                println!("{}{} {}  {}", indent_str, styled_sym, styled, d);
            }
            None => {
                let styled = style(&section.label, section.status.style());
                println!("{}{} {}", indent_str, styled_sym, styled);
            }
        }
    }
    if let Some(ref v) = report.overall {
        println!("\u{251C}{}\u{2524}", line);
        let label = style(v.label(), v.style());
        println!("\u{2502}  {:^51}\u{2502}", label);
    }
    println!("\u{2514}{}\u{2518}", line);
}

pub fn json_output<T: serde::Serialize>(value: &T) {
    if output_format() == OutputFormat::Quiet {
        return;
    }
    match serde_json::to_string_pretty(value) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("JSON serialization error: {}", e),
    }
}

pub fn format_timestamp(ts: u64) -> String {
    use chrono::DateTime;
    let Some(dt) = DateTime::from_timestamp(ts as i64, 0) else {
        return ts.to_string();
    };
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size > 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[unit_idx])
    } else {
        format!("{:.1} {}", size, UNITS[unit_idx])
    }
}
