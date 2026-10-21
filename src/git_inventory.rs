//! Bounded path inventory shared by source inspection and repository policy checks.
use crate::{MAX_FILES, Result, git_process::output, require};
use std::{collections::BTreeSet, path::Path};
#[derive(PartialEq, Debug)]
pub struct Files {
    pub names: Vec<String>,
    pub ignored: BTreeSet<String>,
    pub deleted: Vec<String>,
    pub directories: Vec<String>,
}
fn names(bytes: &[u8]) -> Result<BTreeSet<String>> {
    let mut result = BTreeSet::new();
    let mut count = 0;
    for name in bytes.split(|b| *b == 0).filter(|s| !s.is_empty()) {
        count += 1;
        require(count <= MAX_FILES && name.len() <= 4096)?;
        result.insert(std::str::from_utf8(name)?.to_owned());
    }
    Ok(result)
}
pub(crate) fn tracked(root: &Path) -> Result<BTreeSet<String>> {
    require(root.join(".git").exists())?;
    names(&output(root, &[], &["ls-files", "-z"], None, false)?)
}
pub fn files(root: &Path) -> Result<Files> {
    let temp = tempfile::tempdir()?;
    let mut git = vec![];
    if !root.join(".git").exists() {
        git.push(format!("--git-dir={}/.git", temp.path().display()));
        output(
            temp.path(),
            &git,
            &["init", "--template=", "-q"],
            None,
            false,
        )?;
    }
    let mut observed = names(&output(
        root,
        &git,
        &["ls-files", "-c", "-o", "--exclude-standard", "-z"],
        None,
        false,
    )?)?;
    let deleted = names(&output(
        root,
        &git,
        &["ls-files", "--deleted", "-z"],
        None,
        false,
    )?)?
    .into_iter()
    .filter(|name| std::fs::symlink_metadata(root.join(name)).is_err())
    .collect::<Vec<_>>();
    for name in &deleted {
        observed.remove(name);
    }
    let ignored = if observed.is_empty() {
        BTreeSet::new()
    } else {
        let input = observed
            .iter()
            .flat_map(|n| n.bytes().chain([0]))
            .collect::<Vec<_>>();
        names(&output(
            root,
            &git,
            &["check-ignore", "--no-index", "-z", "--stdin"],
            Some(&input),
            true,
        )?)?
    };
    Ok(Files {
        names: observed.into_iter().collect(),
        ignored,
        deleted,
        directories: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn name_count_and_length_are_checked_during_collection() {
        let many = b"same\0".repeat(MAX_FILES + 1);
        assert!(names(&many).is_err());
        assert!(names(&vec![b'x'; 4097]).is_err());
        assert!(names(&[255, 0]).is_err());
        assert_eq!(names(b"a\0b\0").unwrap().len(), 2);
    }
}
