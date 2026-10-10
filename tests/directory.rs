//! Directory inventory must never apply repository ignore rules to mounted data.
use serde_json::json;
use std::{fs, path::Path};
use zixcel_repository_security::{config, io, scanner};

#[test]
fn ignored_hidden_file_is_detected_by_the_real_engine() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("mounted");
    fs::create_dir(&root).unwrap();
    fs::write(root.join(".gitignore"), ".env\n").unwrap();
    fs::write(root.join(".env"), "SYNTHETIC_DIRECTORY_SENTINEL").unwrap();
    let engine_path = std::env::var("ZIXCEL_TEST_GITLEAKS_CONFIG")
        .expect("real engine configuration is required");
    let engine = io::load(Path::new(&engine_path)).unwrap()["gitleaks"].clone();
    let settings_path = temp.path().join("settings.json");
    io::private_json(
        &settings_path,
        &json!({"repository_id":"directory-test","gitleaks":engine}),
    )
    .unwrap();
    let mut settings = config::load(&settings_path, None, None, None, true).unwrap();
    settings.terms = vec![json!({"id":"test-word","category":"word",
        "values":["SYNTHETIC_DIRECTORY_SENTINEL"]})];
    fs::create_dir(root.join("SYNTHETIC_DIRECTORY_SENTINEL")).unwrap();
    let receipt = scanner::scan_directory(&root, &settings, "directory-test").unwrap();
    assert_eq!(receipt["scope"], "directory-secret-disclosure/v1");
    assert_eq!(receipt["status"], "findings");
    assert!(
        receipt["inventory"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["path"] == ".env")
    );
    assert!(
        receipt["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["path"] == ".env")
    );
    // Raw values are never recorded; this synthetic directory name is location metadata.
    assert!(
        receipt["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["path"] == "SYNTHETIC_DIRECTORY_SENTINEL")
    );
}

#[test]
fn administrative_history_and_symlinks_are_not_a_clean_scan() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("mounted");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join(".git")).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", root.join("link")).unwrap();
    let inventory = zixcel_repository_security::directory::files(&root).unwrap();
    assert_eq!(inventory.names, vec![".git", "link"]);
    assert!(inventory.ignored.is_empty());
}
