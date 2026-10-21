//! Test the real hash-pinned distribution, not an executable-only stand-in.
use std::{os::unix::fs::PermissionsExt, path::Path};
use zixcel_repository_security::{io, maintenance};

#[test]
fn archive_install_preserves_notices_and_exact_manifest() {
    let archive = std::env::var("ZIXCEL_TEST_PINNED_GITLEAKS_ARCHIVE")
        .expect("real archive installation requires ZIXCEL_TEST_PINNED_GITLEAKS_ARCHIVE");
    let temporary = tempfile::tempdir().unwrap();
    let installed = temporary.path().join("accepted");
    maintenance::provision(&installed, None, Some(Path::new(&archive)), false).unwrap();
    assert!(installed.join("gitleaks").is_file());
    assert!(installed.join("LICENSE").is_file());
    assert!(installed.join("Go-runtime-LICENSE").is_file());
    assert!(installed.join("licenses").is_dir());
    assert_eq!(
        io::load(&installed.join("engine-manifest.json")).unwrap(),
        serde_json::from_str::<serde_json::Value>(maintenance::PIN).unwrap()
    );
    assert!(installed.join("config.json").is_file());
    assert_eq!(
        std::fs::metadata(installed.join("gitleaks"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let corrupt = temporary.path().join("corrupt.tgz");
    std::fs::write(&corrupt, b"not the pinned archive").unwrap();
    let rejected = temporary.path().join("rejected");
    assert!(maintenance::provision(&rejected, None, Some(&corrupt), false).is_err());
    assert!(!rejected.exists());
}
