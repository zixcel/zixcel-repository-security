//! Synthetic local Git state only: no account, credential, network or real hook.
use std::{os::unix::fs::PermissionsExt, path::Path, process::Command};
use zixcel_repository_security::scanner;
fn git(root: &Path, args: &[&str]) {
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .status()
            .unwrap()
            .success()
    );
}
#[test]
fn observation_disables_fsmonitor_and_uses_the_requested_worktree() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("source");
    let other = temporary.path().join("other");
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(&other).unwrap();
    git(&root, &["init", "--template=", "-q"]);
    std::fs::write(root.join("source.txt"), b"synthetic source").unwrap();
    git(&root, &["add", "source.txt"]);
    let marker = temporary.path().join("unexpected-hook");
    let hook = temporary.path().join("hook");
    std::fs::write(
        &hook,
        format!("#!/bin/sh\nprintf executed > '{}'\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o700)).unwrap();
    git(&root, &["config", "core.fsmonitor", hook.to_str().unwrap()]);
    git(&root, &["config", "core.worktree", other.to_str().unwrap()]);
    let before = std::fs::read(root.join(".git/config")).unwrap();
    let files = scanner::git_files(&root).unwrap();
    assert_eq!(files.names, ["source.txt"]);
    assert!(!marker.exists());
    assert_eq!(std::fs::read(root.join(".git/config")).unwrap(), before);
}
#[test]
fn source_inventory_retains_deleted_tracking_evidence() {
    let temporary = tempfile::tempdir().unwrap();
    git(temporary.path(), &["init", "--template=", "-q"]);
    std::fs::write(temporary.path().join("removed.txt"), b"synthetic").unwrap();
    git(temporary.path(), &["add", "removed.txt"]);
    std::fs::remove_file(temporary.path().join("removed.txt")).unwrap();
    let observed = scanner::git_files(temporary.path()).unwrap();
    assert!(observed.names.is_empty());
    assert_eq!(observed.deleted, ["removed.txt"]);
}
#[test]
fn plain_directory_uses_only_ephemeral_git_metadata() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::write(temporary.path().join("source.txt"), b"synthetic").unwrap();
    let observed = scanner::git_files(temporary.path()).unwrap();
    assert_eq!(observed.names, ["source.txt"]);
    assert!(!temporary.path().join(".git").exists());
}
