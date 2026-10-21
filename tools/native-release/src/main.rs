#![forbid(unsafe_code)]
use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};
use zix_cli::{
    files,
    release_bundle::{archive, licenses},
};
fn run() -> Result<(), &'static str> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let [source, binary, output] = arguments.as_slice() else {
        return Err("arguments");
    };
    if source.len() != 40
        || !source
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err("source_identity");
    }
    let manifest: toml::Value = toml::from_str(
        &fs::read_to_string("crates/repository-observer/Cargo.toml")
            .map_err(|_| "identity_missing")?,
    )
    .map_err(|_| "identity_invalid")?;
    let version = manifest["package"]["version"].as_str().ok_or("version")?;
    if version.split('.').count() != 3
        || version
            .split('.')
            .any(|s| s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()))
    {
        return Err("version");
    }
    let bytes = files::read(Path::new(binary), 64 * 1024 * 1024, true).map_err(|_| "binary")?;
    if !bytes.starts_with(b"\x7fELF") {
        return Err("binary");
    }
    let name = format!("zixcel-repository-observer-v{version}-x86_64-unknown-linux-gnu");
    let output = Path::new(output);
    fs::create_dir_all(output).map_err(|_| "output")?;
    let directory = output.join(&name);
    fs::create_dir(&directory).map_err(|_| "output_exists")?;
    let executable = directory.join("zix-repository-observer");
    fs::write(&executable, &bytes).map_err(|_| "output")?;
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o500)).map_err(|_| "output")?;
    let result = Command::new(&executable)
        .arg("--version")
        .env_clear()
        .output()
        .map_err(|_| "version")?;
    if !result.status.success()
        || String::from_utf8_lossy(&result.stdout).trim()
            != format!("zixcel-repository-observer {version}")
    {
        return Err("binary_identity");
    }
    for file in ["LICENSE", "LICENSE-MIT"] {
        fs::copy(file, directory.join(file)).map_err(|_| "owner_notice")?;
    }
    fs::copy(
        "crates/repository-observer/NOTICE",
        directory.join("NOTICE"),
    )
    .map_err(|_| "owner_notice")?;
    fs::copy("docs/repository-observer.md", directory.join("README.md"))
        .map_err(|_| "documentation")?;
    licenses::collect(&directory)?;
    let record = serde_json::json!({"schema":"zix-repository-observer-release/v1", "package":"zixcel-repository-observer",
        "version":version,"source":source,"repository":"https://github.com/zixcel/zixcel-repository-security",
        "target":"x86_64-unknown-linux-gnu","binary":"zix-repository-observer","binary_sha256":files::digest(&bytes)});
    fs::write(
        directory.join("RELEASE.json"),
        serde_json::to_vec_pretty(&record).map_err(|_| "record")?,
    )
    .map_err(|_| "output")?;
    archive::finish(output, &directory, &name)
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
