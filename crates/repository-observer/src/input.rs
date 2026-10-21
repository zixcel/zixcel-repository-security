use rustix::fs::{Mode, OFlags, open, openat};
use std::{
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path},
};
use zixcel_repository_observer::Result;
#[cfg(test)]
#[path = "input_tests.rs"]
mod tests;
pub fn read<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    if !path.is_absolute() {
        return Err("absolute_input_required");
    }
    let mut parts = path
        .components()
        .filter(|c| *c != Component::RootDir)
        .peekable();
    let mut fd = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| "input_unavailable")?;
    while let Some(component) = parts.next() {
        let Component::Normal(name) = component else {
            return Err("unsafe_input_path");
        };
        let flags = if parts.peek().is_some() {
            OFlags::DIRECTORY
        } else {
            OFlags::NONBLOCK
        };
        fd = openat(
            &fd,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | flags,
            Mode::empty(),
        )
        .map_err(|_| "input_unavailable")?;
    }
    let file = File::from(fd);
    let before = file.metadata().map_err(|_| "input_unavailable")?;
    if !before.is_file() || before.len() > 1024 * 1024 || before.mode() & 0o022 != 0 {
        return Err("unsafe_input");
    }
    let mut bytes = Vec::new();
    (&file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "input_read_failed")?;
    let after = file.metadata().map_err(|_| "input_unavailable")?;
    if bytes.len() > 1024 * 1024
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.mode() != after.mode()
    {
        return Err("input_changed_or_limit");
    }
    serde_json::from_slice(&bytes).map_err(|_| "input_schema")
}
