//! Explicit pinned artifact provisioning; source inspection never calls download.
use crate::{Result, digest, engine_archive, io, require};
use serde_json::{Value, json};
use std::{
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};
use wait_timeout::ChildExt;
pub const PIN: &str = include_str!("../tests/gitleaks-pin.json");
fn download(url: &str) -> Result<Vec<u8>> {
    let temp = tempfile::tempdir()?;
    let file = temp.path().join("engine.tgz");
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
        .arg(url)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", temp.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    match child.wait_timeout(Duration::from_secs(125)) {
        Ok(Some(status)) => require(status.success())?,
        result => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(match result {
                Err(error) => error.into(),
                _ => "download timed out".into(),
            });
        }
    }
    io::read(&file, 64 * 1024 * 1024)
}
pub fn provision(
    output: &Path,
    exe: Option<&Path>,
    archive: Option<&Path>,
    fetch: bool,
) -> Result<()> {
    require(
        output.is_absolute()
            && !output.exists()
            && usize::from(exe.is_some()) + usize::from(archive.is_some()) + usize::from(fetch)
                == 1,
    )?;
    let pin: Value = serde_json::from_str(PIN)?;
    let (bytes, notices) = if let Some(exe) = exe {
        // Existing executable acceptance only; the caller retains its license bundle.
        (io::read(exe, 64 * 1024 * 1024)?, Default::default())
    } else {
        let packed = if let Some(archive) = archive {
            io::read(archive, 64 * 1024 * 1024)?
        } else {
            download(pin["url"].as_str().ok_or("invalid pin")?)?
        };
        require(digest(&packed) == pin["archive_sha256"])?;
        let contents = engine_archive::unpack(&packed)?;
        (contents.binary, contents.notices)
    };
    require(digest(&bytes) == pin["executable_sha256"])?;
    let path = output.join("gitleaks");
    io::private_bytes(&path, &bytes)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    for (name, content) in notices {
        io::private_bytes(&output.join(name), &content)?;
    }
    io::private_json(&output.join("engine-manifest.json"), &pin)?;
    // The usable configuration is written last; partial installations are not accepted.
    io::private_json(
        &output.join("config.json"),
        &json!({"repository_id":"synthetic-source","gitleaks":{"path":path,"sha256":pin["executable_sha256"]}}),
    )
}
