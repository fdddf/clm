//! clm: switch between Claude Code and Codex CLI accounts on one machine, with one
//! shared setup. A Rust port of github.com/larcane97/clausona's CLI, compatible with its
//! `~/.clm` data.

// Each regex flagged in a loop sits behind a OnceLock and is compiled once.
#![allow(clippy::regex_creation_in_loops, clippy::type_complexity)]

mod checks;
mod commands;
mod env;
mod format;
mod links;
mod lock;
mod quota;
mod registry;
mod secrets;
mod service;
mod shell;
mod style;
mod tools;
mod types;
mod usage;
mod util;

use style::fail_icon;

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let code = match argv.split_first() {
        None => {
            println!("{}", commands::run_command("help", &[]).unwrap_or_default());
            0
        }
        Some((command, rest)) if command == "run" && rest.first().is_some_and(|p| !p.starts_with('-')) => {
            let profile = &rest[0];
            let mut tool_args = &rest[1..];
            // `run <profile> -- -p "q"`: the first `--` is clm's, not the tool's.
            if tool_args.first().is_some_and(|a| a == "--") {
                tool_args = &tool_args[1..];
            }
            match commands::run_profile(profile, tool_args) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("  {} {e}", fail_icon());
                    1
                }
            }
        }
        Some((command, rest)) => match commands::run_command(command, rest) {
            Ok(out) => {
                if !out.is_empty() {
                    println!("{out}");
                }
                0
            }
            Err(e) => {
                eprintln!("  {} {e}", fail_icon());
                1
            }
        },
    };
    std::process::exit(code);
}
