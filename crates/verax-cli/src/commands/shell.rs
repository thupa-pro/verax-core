use anyhow::Result;

pub fn run() -> Result<()> {
    println!("\n  Verax interactive shell (type 'help' or 'exit')\n");

    let prompt = reedline::DefaultPrompt::new(
        reedline::DefaultPromptSegment::Basic("verax".to_string()),
        reedline::DefaultPromptSegment::Basic("> ".to_string()),
    );

    let mut rl = reedline::Reedline::create();

    loop {
        let sig = rl.read_line(&prompt);
        match sig {
            Ok(reedline::Signal::Success(line)) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match line {
                    "exit" | "quit" => break,
                    "help" => print_help(),
                    "hash" => println!("  Usage: hash <file>"),
                    "sign" => println!("  Usage: sign <file> --key <key> --predicate <pred>"),
                    "verify" => println!("  Usage: verify <file>"),
                    "inspect" => println!("  Usage: inspect <file>"),
                    "graph" => println!("  Usage: graph <file>"),
                    "lint" => println!("  Usage: lint <file>"),
                    "version" => println!("verax {}", env!("CARGO_PKG_VERSION")),
                    "doctor" => {
                        let args = crate::commands::doctor::DoctorArgs { json: false };
                        let _ = crate::commands::doctor::run(&args);
                    }
                    _ => {
                        println!("  Unknown command: {}", line);
                        println!("  Type 'help' for available commands");
                    }
                }
                // ignore history error
                let _ = line;
            }
            Ok(reedline::Signal::CtrlD) | Ok(reedline::Signal::CtrlC) => break,
            Err(e) => {
                eprintln!("readline error: {}", e);
                break;
            }
        }
    }
    println!();
    Ok(())
}

fn print_help() {
    println!("  Available commands:");
    println!("    hash     <file>       Hash an artifact");
    println!("    sign     <file>       Sign a statement");
    println!("    verify   <file>       Verify a statement");
    println!("    inspect  <file>       Inspect a statement");
    println!("    graph    <file>       Show provenance DAG");
    println!("    lint     <file>       Lint a statement");
    println!("    doctor                Run protocol diagnostics");
    println!("    version               Show version");
    println!("    help                  This help");
    println!("    exit                  Exit shell");
}
