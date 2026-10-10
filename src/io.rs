//! Descriptor-relative, no-follow source and private output access (Unix/WSL).
use crate::{MAX_FILE, Result, require};
use rustix::fs::{Mode, OFlags, open, openat};
use serde_json::Value;
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};
fn parts(path: &Path) -> Result<Vec<&std::ffi::OsStr>> {
    path.components()
        .map(|c| match c {
            Component::RootDir => Ok(None),
            Component::Normal(p) => Ok(Some(p)),
            _ => Err("unsafe path".into()),
        })
        .collect::<Result<Vec<_>>>()
        .map(|v| v.into_iter().flatten().collect())
}
pub(crate) fn directory(path: &Path, create: bool) -> Result<std::os::fd::OwnedFd> {
    require(path.is_absolute())?;
    let mut fd = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    for p in parts(path)? {
        if create {
            match rustix::fs::mkdirat(&fd, p, Mode::from_raw_mode(0o700)) {
                Ok(()) => {}
                Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(e.into()),
            }
        }
        fd = openat(
            &fd,
            p,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
    }
    Ok(fd)
}
pub fn absolute(path: &Path) -> Result<PathBuf> {
    // Resolve lexical '..' without silently following symlink ancestors.
    let raw = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut out = PathBuf::from("/");
    for c in raw.components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(p) => out.push(p),
            _ => return Err("unsupported path".into()),
        }
    }
    Ok(out)
}
pub fn physical_root(path: &Path) -> Result<PathBuf> {
    require(path.is_absolute())?;
    let path = absolute(path)?;
    directory(&path, false)?;
    Ok(path)
}
pub fn read(path: &Path, bound: usize) -> Result<Vec<u8>> {
    let path = absolute(path)?;
    let parent = directory(path.parent().ok_or("missing parent")?, false)?;
    let fd = openat(
        &parent,
        path.file_name().ok_or("missing filename")?,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?;
    let f = File::from(fd);
    let before = f.metadata()?;
    require(before.is_file() && before.len() <= bound as u64)?;
    let mut data = Vec::new();
    (&f).take(bound as u64 + 1).read_to_end(&mut data)?;
    let after = f.metadata()?;
    require(data.len() <= bound && stamp(&before) == stamp(&after))?;
    Ok(data)
}
fn stamp(m: &fs::Metadata) -> (u64, i64, i64, i64, i64, u32) {
    (
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
        m.mode(),
    )
}
pub fn read_source(root: &Path, name: &str) -> Result<(Vec<u8>, String)> {
    require(
        !name.is_empty()
            && !name.starts_with('/')
            && name
                .split('/')
                .all(|p| !["", ".", "..", ".git"].contains(&p)),
    )?;
    let mut fd = directory(root, false)?;
    let path = Path::new(name);
    let p = parts(path)?;
    for part in &p[..p.len() - 1] {
        fd = openat(
            &fd,
            *part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )?;
    }
    let f = File::from(openat(
        &fd,
        p[p.len() - 1],
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    let before = f.metadata()?;
    require(before.is_file() && before.len() <= MAX_FILE as u64)?;
    let mut bytes = Vec::new();
    (&f).take(MAX_FILE as u64 + 1).read_to_end(&mut bytes)?;
    require(bytes.len() <= MAX_FILE && stamp(&before) == stamp(&f.metadata()?))?;
    Ok((
        bytes,
        if before.mode() & 0o111 != 0 {
            "100755"
        } else {
            "100644"
        }
        .into(),
    ))
}
pub fn private_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let path = absolute(path)?;
    let parent = directory(path.parent().ok_or("missing parent")?, true)?;
    // Reject hardlinks before truncating, in addition to no-follow protection.
    let mut f = File::from(openat(
        &parent,
        path.file_name().ok_or("missing filename")?,
        OFlags::WRONLY | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::from_raw_mode(0o600),
    )?);
    require(f.metadata()?.is_file() && f.metadata()?.nlink() == 1)?;
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    f.set_len(0)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
pub fn private_json(path: &Path, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    private_bytes(path, &bytes)
}
pub fn load(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&read(path, MAX_FILE)?)?)
}
pub fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}
