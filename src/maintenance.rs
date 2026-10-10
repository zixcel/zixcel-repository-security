//! Explicit public-engine provisioning and repository community checks.
use crate::{MAX_FILE, Result, digest, io, require, scanner};
use serde_json::{Value, json};
use std::{
    io::{Cursor, Read},
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};
use wait_timeout::ChildExt;
pub const PIN: &str = include_str!("../tests/gitleaks-pin.json");
pub fn provision(
    output: &Path,
    exe: Option<&Path>,
    archive: Option<&Path>,
    download: bool,
) -> Result<()> {
    require(
        output.is_absolute()
            && !output.exists()
            && (usize::from(exe.is_some())
                + usize::from(archive.is_some())
                + usize::from(download)
                == 1),
    )?;
    let pin: Value = serde_json::from_str(PIN)?;
    let bytes = if let Some(exe) = exe {
        io::read(exe, 64 * 1024 * 1024)?
    } else {
        let temp = tempfile::tempdir()?;
        let file = temp.path().join("engine.tgz");
        let packed = if let Some(archive) = archive {
            io::read(archive, 64 * 1024 * 1024)?
        } else {
            // Sole network-capable command, opt-in, fixed public release URL without credentials.
            let mut child = Command::new("curl")
                .args([
                    "--disable",
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--location",
                    "--proto",
                    "=https",
                    "--proto-redir",
                    "=https",
                    "--max-time",
                    "120",
                    "--max-filesize",
                    "67108864",
                    "--output",
                ])
                .arg(&file)
                .arg(pin["url"].as_str().ok_or("invalid pin")?)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", temp.path())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            let status = match child.wait_timeout(Duration::from_secs(125))? {
                Some(s) => s,
                None => {
                    child.kill()?;
                    child.wait()?;
                    return Err("download timed out".into());
                }
            };
            require(status.success())?;
            io::read(&file, 64 * 1024 * 1024)?
        };
        require(digest(&packed) == pin["archive_sha256"])?;
        let mut tar = tar::Archive::new(
            flate2::read::GzDecoder::new(Cursor::new(packed)).take((128 * 1024 * 1024) as u64),
        );
        let mut bytes = None;
        for entry in tar.entries()? {
            let mut entry = entry?;
            if entry.path()?.as_ref() == Path::new("gitleaks") {
                require(
                    bytes.is_none()
                        && entry.header().entry_type().is_file()
                        && entry.size() <= 64 * 1024 * 1024,
                )?;
                let mut content = Vec::new();
                entry
                    .by_ref()
                    .take(64 * 1024 * 1024 + 1)
                    .read_to_end(&mut content)?;
                bytes = Some(content);
            }
        }
        bytes.ok_or("executable member missing")?
    };
    require(digest(&bytes) == pin["executable_sha256"])?;
    let path = output.join("gitleaks");
    io::private_bytes(&path, &bytes)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    io::private_json(
        &output.join("config.json"),
        &json!({"repository_id":"synthetic-source","gitleaks":{"path":path,"sha256":pin["executable_sha256"]}}),
    )?;
    Ok(())
}
pub fn oss(root: &Path) -> Result<()> {
    let root = io::physical_root(root)?;
    for name in [
        "LICENSE",
        "NOTICE",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "SECURITY.md",
        ".github/pull_request_template.md",
        ".github/ISSUE_TEMPLATE/config.yml",
    ] {
        io::read_source(&root, name)?;
    }
    let allowed = io::load(&root.join(".github/oss-policy.json"))?["allowed_vendor_archives"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    // ls-files includes deleted tracked entries; generated artifacts must never be tracked.
    let output = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(&root)
        .output()?;
    require(output.status.success() && output.stdout.len() <= crate::MAX_TOTAL)?;
    for name in output.stdout.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        let name = std::str::from_utf8(name)?;
        let parts = name.split('/').collect::<Vec<_>>();
        let first = parts[0];
        let forbidden = [
            "registration",
            "state",
            ".local",
            ".state",
            ".data",
            "secrets",
            "credentials",
            "target",
            "node_modules",
            "dist",
            "build",
            "coverage",
            ".cache",
            ".pytest_cache",
            ".ruff_cache",
            ".mypy_cache",
            ".tox",
            ".nox",
            "htmlcov",
        ]
        .contains(&first)
            || parts
                .iter()
                .any(|p| ["node_modules", "__pycache__"].contains(p))
            || ([".pyc", ".tsbuildinfo", ".tgz"]
                .iter()
                .any(|s| name.ends_with(s))
                && !allowed.contains(&json!(name)))
            || (parts.len() == 1
                && [".tar.gz", ".zip", ".whl", ".crate", ".profraw", ".profdata"]
                    .iter()
                    .any(|s| name.ends_with(s)))
            || (first.starts_with(".env")
                && ![".env.example", ".env.sample", ".env.template"].contains(&first));
        require(!forbidden)?;
    }
    let cargo: toml::Value =
        std::str::from_utf8(&io::read(&root.join("Cargo.toml"), MAX_FILE)?)?.parse()?;
    require(cargo["package"]["license"].as_str() == Some("Apache-2.0"))?;
    if root.join("package.json").exists() {
        require(io::load(&root.join("package.json"))?["license"] == "Apache-2.0")?;
    }
    // Check that current source inventory can be observed independently of CI.
    scanner::git_files(&root)?;
    Ok(())
}
