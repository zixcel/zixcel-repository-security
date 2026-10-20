use crate::{
    MAX_FILE, Result,
    definitions::{keys, text},
    digest, identity, io, require,
};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
use wait_timeout::ChildExt;
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
pub fn external(engine: Option<&Value>) -> Result<Option<Vec<u8>>> {
    let Some(e) = engine else { return Ok(None) };
    keys(e, &["path", "sha256", "config_file"], &["path", "sha256"])?;
    let Some(file) = e.get("config_file") else {
        return Ok(None);
    };
    let p = Path::new(text(file)?);
    require(p.is_absolute())?;
    let bytes = io::read(p, MAX_FILE)?;
    let doc: toml::Value = toml::from_str(std::str::from_utf8(&bytes)?)?;
    let table = doc.as_table().ok_or("expected TOML")?;
    require(
        table
            .keys()
            .all(|s| ["title", "extend", "rules", "allowlist", "allowlists"].contains(&s.as_str())),
    )?;
    if let Some(extension) = table.get("extend") {
        require(extension.as_table().is_some_and(|t| {
            t.keys()
                .all(|s| ["useDefault", "disabledRules"].contains(&s.as_str()))
        }))?;
    }
    let rules = doc
        .get("rules")
        .and_then(|v| v.as_array())
        .ok_or("explicit rules required")?;
    require((1..=256).contains(&rules.len()))?;
    let mut ids = BTreeSet::new();
    for rule in rules {
        let id = rule
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("expected rule id")?;
        require(identity(id, false) && ids.insert(id))?;
    }
    Ok(Some(bytes))
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
        let mut child = Command::new(&exe)
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
            .current_dir(&pass.target)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let status = match child.wait_timeout(Duration::from_secs(120))? {
            Some(s) => s,
            None => {
                child.kill()?;
                child.wait()?;
                return Err("engine timed out".into());
            }
        };
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
