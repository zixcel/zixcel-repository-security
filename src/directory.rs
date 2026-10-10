//! Mounted-directory inspection ignores no files through Git provenance.
use crate::{Result, config, io, require, scanner};
use std::{collections::BTreeSet, os::fd::AsRawFd, path::Path};

/// Enumerate bounded entries without following symlinks or hiding runtime files.
/// Git administrative trees are recorded as an uninspected entry, never a pass.
/// # Errors
/// Reject unreadable, excessively deep, excessively large or changed trees.
pub fn files(root: &Path) -> Result<scanner::Files> {
    let root = io::physical_root(root)?;
    require(root.parent().is_some())?;
    let mut pending = vec![(io::directory(&root, false)?, std::path::PathBuf::new(), 0)];
    let mut names = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut entries = 0;
    while let Some((directory, prefix, depth)) = pending.pop() {
        require(depth <= 64)?;
        // Hold the descriptor throughout enumeration and child opening so a
        // replaced path cannot redirect inventory outside the selected tree.
        let anchored = format!("/proc/self/fd/{}", directory.as_raw_fd());
        for item in std::fs::read_dir(anchored)? {
            let item = item?;
            entries += 1;
            require(entries <= crate::MAX_FILES)?;
            let relative = prefix.join(item.file_name());
            let name = relative.to_str().ok_or("non UTF8 entry")?.to_owned();
            let kind = item.file_type()?;
            if kind.is_dir() && item.file_name() != ".git" {
                require(pending.len() < 256)?;
                directories.insert(name);
                let child = rustix::fs::openat(
                    &directory,
                    item.file_name(),
                    rustix::fs::OFlags::RDONLY
                        | rustix::fs::OFlags::DIRECTORY
                        | rustix::fs::OFlags::NOFOLLOW,
                    rustix::fs::Mode::empty(),
                )?;
                pending.push((child, relative, depth + 1));
            } else {
                names.insert(name);
            }
        }
    }
    Ok(scanner::Files {
        names: names.into_iter().collect(),
        ignored: BTreeSet::new(),
        deleted: vec![],
        directories: directories.into_iter().collect(),
    })
}

/// Run a fresh read-only directory scan and save a private receipt outside inputs.
/// # Errors
/// Reject unsafe output paths, malformed settings and incomplete preparation.
pub fn inspect(
    root: &Path,
    config: &Path,
    output: &Path,
    words: Option<&Path>,
    definitions: Option<&Path>,
    native: Option<&Path>,
) -> Result<i32> {
    let settings = config::load(config, words, definitions, native, true)?;
    let root = io::physical_root(root)?;
    let output = io::absolute(output)?;
    require(!output.starts_with(&root))?;
    for input in &settings.inputs {
        require(output != io::absolute(input)? && !io::same_file(&output, input))?;
    }
    let id = crate::definitions::text(&settings.config["repository_id"])?;
    let receipt = scanner::scan_directory(&root, &settings, id)?;
    let passed = receipt["status"] == "passed";
    io::private_json(&output, &receipt)?;
    println!("{}", serde_json::json!({"passed": passed}));
    Ok(i32::from(!passed))
}
