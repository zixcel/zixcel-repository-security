#![forbid(unsafe_code)]
use clap::{Parser, Subcommand};
use std::io::Write;
use std::{path::PathBuf, process::ExitCode};
use zeroize::Zeroizing;
use zixcel_repository_observer::{Github, Proposal, Result, model::Snapshot, observe, review};
mod input;
mod output;
#[derive(Parser)]
#[command(
    version,
    about = "Bounded read-only GitHub configuration observations; never applies settings"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Observe {
        #[arg(long)]
        repository: String,
        #[arg(long)]
        secret_metadata: bool,
    },
    Review {
        #[arg(long)]
        baseline: PathBuf,
        #[arg(long)]
        proposal: PathBuf,
        #[arg(long)]
        secret_metadata: bool,
    },
}
fn run(cli: Cli) -> Result<serde_json::Value> {
    let token =
        Zeroizing::new(std::env::var("ZIX_REPOSITORY_GITHUB_TOKEN").map_err(|_| "token_required")?);
    let mut reader = Github::new(&token)?;
    match cli.command {
        Command::Observe {
            repository,
            secret_metadata,
        } => serde_json::to_value(observe(&mut reader, &repository, secret_metadata)?)
            .map_err(|_| "serialization"),
        Command::Review {
            baseline,
            proposal,
            secret_metadata,
        } => {
            let baseline: Snapshot = input::read(&baseline)?;
            let proposal: Proposal = input::read(&proposal)?;
            let fresh = observe(&mut reader, &baseline.identity.repository, secret_metadata)?;
            review(&baseline, &fresh, &proposal)
        }
    }
}
fn main() -> ExitCode {
    match run(Cli::parse()).and_then(output::emit) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(std::io::stderr().lock(), "{{\"error\":\"{error}\"}}");
            ExitCode::from(2)
        }
    }
}
