//! Owner-local repository community checks.
pub use crate::engine_install::{PIN, provision};
use crate::{MAX_FILE, Result, io, require, scanner};
use serde_json::json;
use std::{path::Path, process::Command};
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
    let cargo: toml::Value = toml::from_str(std::str::from_utf8(&io::read(
        &root.join("Cargo.toml"),
        MAX_FILE,
    )?)?)?;
    require(cargo["package"]["license"].as_str() == Some("Apache-2.0"))?;
    if root.join("package.json").exists() {
        require(io::load(&root.join("package.json"))?["license"] == "Apache-2.0")?;
    }
    // Check that current source inventory can be observed independently of CI.
    scanner::git_files(&root)?;
    Ok(())
}
