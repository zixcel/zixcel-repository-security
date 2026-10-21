//! Read local Git metadata without ambient configuration, hooks or unbounded pipes.
use crate::{MAX_FILES, Result, io, process_guard, require};
use std::{
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};
// At most MAX_FILES names, each bounded to 4096 bytes plus its NUL delimiter.
const MAX_OUTPUT: usize = MAX_FILES * 4097;
pub(crate) fn output(
    root: &Path,
    git: &[String],
    args: &[&str],
    input: Option<&[u8]>,
    allow_one: bool,
) -> Result<Vec<u8>> {
    let temp = tempfile::tempdir()?;
    let out = temp.path().join("out");
    let inp = temp.path().join("in");
    io::private_bytes(&out, b"")?;
    require(input.unwrap_or(b"").len() <= MAX_OUTPUT)?;
    io::private_bytes(&inp, input.unwrap_or(b""))?;
    let mut command = Command::new("git");
    command
        .args([
            "--no-pager",
            "--no-optional-locks",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.excludesFile=/dev/null",
        ])
        .arg(format!(
            "--work-tree={}",
            root.to_str().ok_or("invalid source path")?
        ))
        .args(git)
        .args(args)
        .current_dir(root)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", temp.path())
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::from(std::fs::File::open(inp)?))
        .stdout(Stdio::from(
            std::fs::OpenOptions::new().write(true).open(&out)?,
        ))
        .stderr(Stdio::null());
    let status = process_guard::run(
        &mut command,
        &out,
        Duration::from_secs(120),
        MAX_OUTPUT as u64,
    )?;
    require(status.success() || (allow_one && status.code() == Some(1)))?;
    io::read(&out, MAX_OUTPUT)
}
