pub use crate::engine_config::external;
use crate::{MAX_FILE, Result, definitions::text, digest, io, require};
use serde_json::Value;
use std::{
    path::PathBuf,
    process::{Command, Stdio},
};
pub struct Pass {
    pub name: &'static str,
    pub config: Vec<u8>,
    pub target: PathBuf,
}
#[derive(Clone)]
pub struct Hit {
    pub pass: String,
    pub file: String,
    pub rule: String,
    pub line: u64,
}
fn verify(e: &Value) -> Result<PathBuf> {
    let path = PathBuf::from(text(&e["path"])?);
    require(path.is_absolute())?;
    let sha = text(&e["sha256"])?;
    require(
        sha.len() == 64
            && sha
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
    )?;
    require(digest(&io::read(&path, 64 * 1024 * 1024)?) == sha)?;
    Ok(path)
}
pub fn run(e: &Value, passes: Vec<Pass>) -> Result<Vec<Hit>> {
    let exe = verify(e)?;
    let temp = tempfile::tempdir()?;
    let ignore = temp.path().join("ignore");
    io::private_bytes(&ignore, b"")?;
    let mut hits = Vec::new();
    for pass in passes {
        let config = temp.path().join("rules.toml");
        io::private_bytes(&config, &pass.config)?;
        let report = temp.path().join("report.json");
        if report.exists() {
            std::fs::remove_file(&report)?;
        }
        let mut command = Command::new(&exe);
        command
            .arg("dir")
            .arg(&pass.target)
            .args([
                "--no-banner",
                "--redact=100",
                "--max-archive-depth=0",
                "--max-decode-depth=0",
                "--ignore-gitleaks-allow",
                "--report-format=json",
            ])
            .arg(format!("--config={}", config.display()))
            .arg(format!("--gitleaks-ignore-path={}", ignore.display()))
            .arg(format!("--report-path={}", report.display()))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", temp.path())
            .env("GOMAXPROCS", "1")
            // Go's memory target is advisory; OS containment belongs to the launcher.
            .env("GOMEMLIMIT", "384MiB")
            .current_dir(&pass.target)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let status = crate::engine_process::run(&mut command, &report)?;
        require(matches!(status.code(), Some(0 | 1)))?;
        let data: Value = serde_json::from_slice(&io::read(&report, MAX_FILE)?)?;
        let list = data.as_array().ok_or("expected report array")?;
        require(!list.is_empty() == (status.code() == Some(1)))?;
        for finding in list {
            hits.push(Hit {
                pass: pass.name.into(),
                file: text(&finding["File"])?.into(),
                rule: text(&finding["RuleID"])?.into(),
                line: finding["StartLine"].as_u64().ok_or("expected line")?,
            });
        }
    }
    verify(e)?;
    Ok(hits)
}
