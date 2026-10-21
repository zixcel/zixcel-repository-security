use super::read;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};
fn input(directory: &std::path::Path) -> std::path::PathBuf {
    let path = directory.join("input.json");
    fs::write(&path, br#"{"synthetic":true}"#).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}
#[test]
fn regular_private_bounded_json_is_read_without_following_any_symlink() {
    let temporary = tempfile::tempdir().unwrap();
    let path = input(temporary.path());
    let value: serde_json::Value = read(&path).unwrap();
    assert_eq!(value["synthetic"], true);
    let link = temporary.path().join("link.json");
    symlink(&path, &link).unwrap();
    assert!(read::<serde_json::Value>(&link).is_err());
    let directory_link = temporary.path().join("parent-link");
    symlink(temporary.path(), &directory_link).unwrap();
    assert!(read::<serde_json::Value>(&directory_link.join("input.json")).is_err());
}
#[test]
fn writable_oversized_nonregular_relative_and_invalid_inputs_are_refused() {
    let temporary = tempfile::tempdir().unwrap();
    let path = input(temporary.path());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o620)).unwrap();
    assert!(read::<serde_json::Value>(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, "invalid").unwrap();
    assert!(read::<serde_json::Value>(&path).is_err());
    fs::write(&path, vec![b' '; 1024 * 1024 + 1]).unwrap();
    assert!(read::<serde_json::Value>(&path).is_err());
    assert!(read::<serde_json::Value>(temporary.path()).is_err());
    assert!(read::<serde_json::Value>(std::path::Path::new("relative.json")).is_err());
}
