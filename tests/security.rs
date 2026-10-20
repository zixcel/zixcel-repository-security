//! Synthetic-only regressions. Real detection tests require the pinned public engine.
use serde_json::{Value, json};
use std::{
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
};
use zixcel_repository_security::{
    self as sec,
    config::{self, Settings},
    definitions as defs, digest, engine, io, scanner,
};
struct Fixture {
    temp: tempfile::TempDir,
    root: PathBuf,
    settings: Settings,
    config: PathBuf,
    output: PathBuf,
}
impl Fixture {
    fn new(real: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        std::fs::create_dir(&root).unwrap();
        let config = temp.path().join("config.json");
        let output = temp.path().join("receipt.json");
        let engine = if real {
            let path = std::env::var("ZIXCEL_TEST_GITLEAKS_CONFIG")
                .expect("real-engine tests require ZIXCEL_TEST_GITLEAKS_CONFIG");
            io::load(Path::new(&path)).unwrap()["gitleaks"].clone()
        } else {
            let exe = temp.path().join("engine");
            write(&exe,b"#!/bin/sh\nfor arg in \"$@\"; do case \"$arg\" in --report-path=*) report=${arg#*=} ;; esac; done\nprintf '[]' > \"$report\"\n");
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o700)).unwrap();
            json!({"path":exe,"sha256":digest(&std::fs::read(&exe).unwrap())})
        };
        io::private_json(
            &config,
            &json!({"repository_id":"synthetic-source","gitleaks":engine}),
        )
        .unwrap();
        let settings = config::load(&config, None, None, None, false).unwrap();
        Self {
            temp,
            root,
            settings,
            config,
            output,
        }
    }
    fn scan(&self) -> Value {
        scanner::scan(&self.root, &self.settings, "synthetic-source").unwrap()
    }
    fn file(&self, bytes: impl AsRef<[u8]>) {
        write(&self.root.join("source.txt"), bytes.as_ref());
    }
    fn words(&mut self, value: &str) {
        self.settings.terms = vec![json!({"id":"word-01","category":"word","values":[value]})];
    }
    fn invoke(&self, command: &str, extras: &[&str]) -> std::process::Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_zixcel-repository-security"));
        cmd.arg(command)
            .arg("--config")
            .arg(&self.config)
            .arg("--output")
            .arg(&self.output);
        if command != "scan-inventory" && command != "scan-workspace" {
            cmd.arg("--root").arg(&self.root);
        }
        cmd.args(extras).output().unwrap()
    }
    fn stub(&mut self, body: &str) {
        let path = PathBuf::from(self.settings.config["gitleaks"]["path"].as_str().unwrap());
        let bytes = format!(
            "#!/bin/sh\nfor arg in \"$@\"; do case \"$arg\" in --report-path=*) report=${{arg#*=}} ;; esac; done\n{body}\n"
        );
        write(&path, bytes.as_bytes());
        self.settings.config["gitleaks"]["sha256"] = json!(digest(bytes.as_bytes()));
    }
}
fn write(path: &Path, data: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, data).unwrap();
}
fn archive(name: &str, bytes: &[u8], gzip: bool) -> Vec<u8> {
    let mut packed = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut packed);
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, name, bytes).unwrap();
        tar.finish().unwrap();
    }
    if gzip {
        use std::io::Write;
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gzip.write_all(&packed).unwrap();
        gzip.finish().unwrap()
    } else {
        packed
    }
}
fn unsafe_archive() -> Vec<u8> {
    let mut bytes = archive("placeholder", b"safe", false);
    bytes[..100].fill(0);
    bytes[..10].copy_from_slice(b"../escaped");
    bytes[148..156].fill(b' ');
    let sum: usize = bytes[..512].iter().map(|b| *b as usize).sum();
    bytes[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    bytes
}
fn git(root: &Path, args: &[&str]) {
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap()
            .success()
    );
}
fn term(v: &str) -> Value {
    json!({"id":"word-01","category":"word","values":[v]})
}
fn document(rules: Vec<Value>) -> Value {
    json!({"schema":defs::SCHEMA,"rules":rules})
}
fn rules_at(r: &Value, line: u64) -> std::collections::BTreeSet<String> {
    r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["line"] == line && !f["rule"].as_str().unwrap().starts_with("gitleaks:"))
        .map(|f| f["rule"].as_str().unwrap().to_owned())
        .collect()
}
#[test]
fn unicode_full_casefold_and_nfkc() {
    assert_eq!(defs::normalize("Ｓｔｒａße Σς ﬃ"), "strasse σσ ffi");
}
#[test]
fn literal_toml_escapes_meta_and_quotes() {
    let compiled = defs::literals(&[term("Ａ.+[X]\"\\")]).unwrap();
    let value: toml::Value = toml::from_str(std::str::from_utf8(&compiled).unwrap()).unwrap();
    assert_eq!(
        value["rules"][0]["regex"].as_str().unwrap(),
        "(?:a\\.\\+\\[x\\]\"\\\\)"
    );
}
#[test]
fn regex_native_fields_roundtrip() {
    let (_,regex)=defs::validate(&document(vec![json!({"id":"pattern-01","kind":"regex","regex":"(SYNTHETIC_[0-9]{4})","secretGroup":1,"entropy":0.0,"keywords":["SYNTHETIC_"]})])).unwrap();
    let doc: toml::Value =
        toml::from_str(&String::from_utf8(defs::patterns(&regex).unwrap()).unwrap()).unwrap();
    assert_eq!(doc["rules"][0]["secretGroup"].as_integer(), Some(1));
}
#[test]
fn definitions_reject_unknown_and_unsafe_fields() {
    for rules in [
        vec![],
        vec![json!({"id":"one","kind":"shell","command":"ignored"})],
        vec![json!({"id":"one","kind":"regex","regex":"x","allowlist":{}})],
        vec![json!({"id":"one","kind":"regex","regex":"x","secretGroup":true})],
        vec![json!({"id":"one","kind":"literal","values":["\n"]})],
        vec![json!({"id":"one","kind":"regex","regex":"x"}); 2],
    ] {
        assert!(defs::validate(&document(rules)).is_err());
    }
}
#[test]
fn definitions_bounds_and_top_level_validation() {
    for r in [
        json!({"id":"one","kind":"regex","regex":"x","entropy":9}),
        json!({"id":"one","kind":"regex","regex":"x","keywords":[""]}),
        json!({"id":"one","kind":"regex","regex":"x","secretGroup":65}),
        json!({"id":"one","kind":"literal","values":["　　"]}),
    ] {
        assert!(defs::validate(&document(vec![r])).is_err());
    }
    let mut d = document(vec![json!({"id":"one","kind":"regex","regex":"x"})]);
    d["extend"] = json!("url");
    assert!(defs::validate(&d).is_err());
}
#[test]
fn combined_ids_are_unique_and_bounded() {
    assert!(
        defs::combined(
            &[term("synthetic")],
            &[json!({"id":"word-01","regex":"safe"})]
        )
        .is_err()
    );
    assert!(defs::validate_terms(&vec![term("synthetic"); 257]).is_err());
}
#[test]
fn ignored_untracked_is_excluded_tracked_is_unwaivable() {
    let mut f = Fixture::new(false);
    git(&f.root, &["init", "-q"]);
    write(&f.root.join(".gitignore"), b"/registration/\n");
    write(&f.root.join("registration/account.json"), b"{}");
    assert_eq!(f.scan()["status"], "passed");
    git(&f.root, &["add", "-f", "registration/account.json"]);
    let r = f.scan();
    assert_eq!(r["findings"][0]["rule"], "tracked-excluded-data");
    f.settings.exceptions = vec![
        json!({"fingerprint":r["findings"][0]["fingerprint"],"expires":"2099-01-01","reason":"synthetic fixture","reviewer":"local-review"}),
    ];
    assert_eq!(f.scan()["status"], "findings");
}
#[test]
fn symlinks_and_binary_are_incomplete() {
    let f = Fixture::new(false);
    symlink(&f.config, f.root.join("link")).unwrap();
    f.file([255, 0, 255]);
    assert_eq!(f.scan()["status"], "incomplete");
}
#[test]
fn symlink_ancestor_source_is_refused() {
    let f = Fixture::new(false);
    symlink(f.temp.path(), f.root.join("linked")).unwrap();
    assert!(io::read_source(&f.root, "linked/config.json").is_err());
}
#[test]
fn path_traversal_and_git_metadata_refused() {
    let f = Fixture::new(false);
    for path in [
        "../config.json",
        "/etc/passwd",
        ".git/config",
        "./source.txt",
        "a//b",
    ] {
        assert!(io::read_source(&f.root, path).is_err());
    }
}
#[test]
fn archive_traversal_is_never_extracted() {
    let f = Fixture::new(false);
    write(&f.root.join("unsafe.tar"), &unsafe_archive());
    assert_eq!(f.scan()["status"], "incomplete");
    assert!(!f.temp.path().join("escaped").exists());
}
#[test]
fn nested_archives_share_budget() {
    let nested = archive("payload.txt", &vec![b'a'; 700], true);
    let mut outer = Vec::new();
    {
        let mut tar = tar::Builder::new(&mut outer);
        for name in ["one.tgz", "two.tgz"] {
            let mut header = tar::Header::new_gnu();
            header.set_size(nested.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, name, nested.as_slice())
                .unwrap();
        }
        tar.finish().unwrap();
    }
    // Account for the outer container independently: both nested payloads must
    // consume the same remaining expansion budget, rather than resetting it.
    let mut budget = scanner::Budget {
        bytes: outer.len() + nested.len() * 2 + 1000,
        entries: 10,
    };
    let docs = scanner::documents("root.tgz", &outer, 0, &mut budget);
    assert!(docs.iter().any(|(_, v)| v.is_none()));
}
#[test]
fn archive_depth_and_entry_bounds_are_incomplete() {
    let nested = archive("third.tgz", &archive("payload.txt", b"safe", true), true);
    let outer = archive("second.tgz", &nested, true);
    let mut budget = scanner::Budget {
        bytes: sec::MAX_TOTAL,
        entries: sec::MAX_FILES,
    };
    assert!(
        scanner::documents("first.tgz", &outer, 0, &mut budget)
            .iter()
            .any(|(_, v)| v.is_none())
    );
}
#[test]
fn archive_link_rejected() {
    let f = Fixture::new(false);
    let mut packed = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut packed);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_cksum();
        builder.append_link(&mut header, "link", "outside").unwrap();
        builder.finish().unwrap();
    }
    write(&f.root.join("links.tar"), &packed);
    assert_eq!(f.scan()["status"], "incomplete");
}
#[test]
fn missing_engine_cannot_pass() {
    let mut f = Fixture::new(false);
    f.settings
        .config
        .as_object_mut()
        .unwrap()
        .remove("gitleaks");
    assert_eq!(f.scan()["status"], "incomplete");
}
#[test]
fn changed_engine_digest_rejected() {
    let f = Fixture::new(false);
    let path = Path::new(f.settings.config["gitleaks"]["path"].as_str().unwrap());
    write(path, b"changed");
    assert!(scanner::scan(&f.root, &f.settings, "synthetic-source").is_err());
}
#[test]
fn engine_symlink_is_rejected() {
    let mut f = Fixture::new(false);
    let link = f.temp.path().join("engine-link");
    symlink(
        Path::new(f.settings.config["gitleaks"]["path"].as_str().unwrap()),
        &link,
    )
    .unwrap();
    f.settings.config["gitleaks"]["path"] = json!(link);
    assert!(scanner::scan(&f.root, &f.settings, "synthetic-source").is_err());
}
#[test]
fn malformed_missing_inconsistent_reports_fail_closed() {
    let mut f = Fixture::new(false);
    for script in [
        "true",
        "printf '{}' > \"$report\"",
        "printf '[]' > \"$report\"; exit 1",
        "printf '[{}]' > \"$report\"; exit 1",
    ] {
        f.stub(script);
        assert!(scanner::scan(&f.root, &f.settings, "synthetic-source").is_err());
    }
}
#[test]
fn out_of_inventory_and_invalid_line_reports_rejected() {
    let mut f = Fixture::new(false);
    for script in [
        "printf '[{\"File\":\"outside\",\"RuleID\":\"test\",\"StartLine\":1}]' > \"$report\"; exit 1",
        "printf '[{\"File\":\"files/source.txt\",\"RuleID\":\"test\",\"StartLine\":true}]' > \"$report\"; exit 1",
    ] {
        f.stub(script);
        assert!(scanner::scan(&f.root, &f.settings, "synthetic-source").is_err());
    }
}
#[test]
fn deleted_tracked_file_history_not_claimed() {
    let f = Fixture::new(false);
    git(&f.root, &["init", "-q"]);
    f.file(b"safe");
    git(&f.root, &["add", "source.txt"]);
    std::fs::remove_file(f.root.join("source.txt")).unwrap();
    let r = f.scan();
    assert_eq!(r["status"], "passed");
    assert_eq!(r["deleted_tracked_files"], json!(["source.txt"]));
    assert_eq!(r["deleted_file_history_inspected"], false);
}
#[test]
fn recreated_deleted_file_invalidates_snapshot() {
    let mut f = Fixture::new(false);
    git(&f.root, &["init", "-q"]);
    f.file(b"safe");
    git(&f.root, &["add", "source.txt"]);
    std::fs::remove_file(f.root.join("source.txt")).unwrap();
    f.stub(&format!(
        "printf '[]' > \"$report\"; printf 'changed' > '{}'",
        f.root.join("source.txt").display()
    ));
    assert!(scanner::scan(&f.root, &f.settings, "synthetic-source").is_err());
}
#[test]
fn changed_source_and_mode_invalidate_snapshot() {
    let mut f = Fixture::new(false);
    f.file(b"safe");
    f.stub(&format!(
        "printf '[]' > \"$report\"; chmod 700 '{}'",
        f.root.join("source.txt").display()
    ));
    assert!(scanner::scan(&f.root, &f.settings, "synthetic-source").is_err());
}
#[test]
fn disclosure_per_match_and_unicode_regressions() {
    let f = Fixture::new(true);
    let address = ["sample", "@", "synthetic.unit-domain.com"].concat();
    let phone = ["070", "-0000-0000"].concat();
    let home = ["/home/", "synthetic/"].concat();
    let header = ["-----BEGIN ", "PRIVATE KEY-----"].concat();
    let cases = vec![
        (address.clone(), vec!["email-address"]),
        ("sample@example.com".into(), vec![]),
        ("sample@EXAMPLE.ORG".into(), vec![]),
        ("sample@thing.invalid".into(), vec![]),
        (format!("https://{address}/path"), vec![]),
        (format!("ssh://{address}/path"), vec![]),
        (
            format!("https://{address}/path {address}"),
            vec!["email-address"],
        ),
        (
            format!("sample@example.com {address}"),
            vec!["email-address"],
        ),
        (
            format!("https://{address}/path\u{a0}{address}"),
            vec!["email-address"],
        ),
        ("git@github.com:owner/repository".into(), vec![]),
        (["git", "@github.com"].concat(), vec!["email-address"]),
        (phone.clone(), vec!["telephone"]),
        (format!("1{phone}"), vec![]),
        (format!("{phone}1"), vec![]),
        (format!("{phone} {phone}"), vec!["telephone"]),
        (
            ["classification = \"", "personal-confidential\""].concat(),
            vec!["private-classified-record"],
        ),
        ("classification = \"public\"".into(), vec![]),
        (
            ["birth", "day = \"synthetic-value\""].concat(),
            vec!["personal-profile-value"],
        ),
        (
            ["birth", "day = \"synthetic-unclosed"].concat(),
            vec!["personal-profile-value"],
        ),
        (
            ["birth", "day\u{a0}=\u{a0}\"synthetic-value\""].concat(),
            vec!["personal-profile-value"],
        ),
        (["birth", "day = \"\""].concat(), vec![]),
        (
            ["classification\u{a0}:\u{a0}\"", "personal-confidential\""].concat(),
            vec!["private-classified-record"],
        ),
        (home, vec!["machine-home-path"]),
        (
            ["C:", "\\Users\\", "synthetic\\"].concat(),
            vec!["machine-home-path"],
        ),
        (header, vec!["private-key"]),
    ];
    let payload = cases
        .iter()
        .map(|(s, _)| s.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for packed in [false, true] {
        if packed {
            std::fs::remove_file(f.root.join("source.txt")).unwrap();
            write(
                &f.root.join("source.tgz"),
                &archive("source.txt", payload.as_bytes(), true),
            );
        } else {
            f.file(&payload);
        }
        let r = f.scan();
        for (i, (_, expected)) in cases.iter().enumerate() {
            assert_eq!(
                rules_at(&r, (i + 1) as u64),
                expected.iter().map(|s| s.to_string()).collect(),
                "line {}",
                i + 1
            );
        }
        assert!(!r.to_string().contains(&address));
        assert!(r["engines"].get("builtin-disclosure").is_none());
    }
}
#[test]
fn complete_private_key_deduplicated() {
    let f = Fixture::new(true);
    f.file(format!(
        "{}\n{}\n{}\n",
        ["-----BEGIN ", "PRIVATE KEY-----"].concat(),
        "synthetic-not-a-key-".repeat(8),
        ["-----END ", "PRIVATE KEY-----"].concat()
    ));
    let r = f.scan();
    assert_eq!(r["findings"].as_array().unwrap().len(), 1);
    assert_eq!(r["findings"][0]["rule"], "gitleaks:private-key");
}
#[test]
fn normalized_word_and_regex_source_archive_locations() {
    let mut f = Fixture::new(true);
    f.words("Sensitive .+[Text]");
    f.settings.regexes = vec![json!({"id":"pattern-01","regex":"SYNTHETIC_NATIVE_[0-9]{4}"})];
    let payload = [
        "ordinary\nＳＥＮＳＩＴＩＶＥ .+[ＴＥＸＴ]\nSYNTHETIC_NATIVE_",
        "1234\n",
    ]
    .concat();
    for packed in [false, true] {
        if packed {
            std::fs::remove_file(f.root.join("source.txt")).unwrap();
            write(
                &f.root.join("fixture.tgz"),
                &archive("source.txt", payload.as_bytes(), true),
            );
        } else {
            f.file(&payload);
        }
        let r = f.scan();
        assert_eq!(r["findings"][0]["line"], 2);
        assert_eq!(r["findings"][1]["line"], 3);
        assert_eq!(r["findings"][1]["rule"], "configured-regex");
        assert_eq!(
            r["findings"][0]["path"],
            if packed {
                "fixture.tgz!source.txt"
            } else {
                "source.txt"
            }
        );
        assert!(!r.to_string().contains("Sensitive .+[Text]"));
    }
}
#[test]
fn binary_and_archive_name_normalization_never_creates_paths() {
    let mut f = Fixture::new(true);
    f.words("Restricted .+[Sample]");
    let filename = "ＲＥＳＴＲＩＣＴＥＤ .+[ＳＡＭＰＬＥ].exe";
    write(&f.root.join(filename), b"MZ\0\xff");
    let r = f.scan();
    assert_eq!(r["status"], "incomplete");
    assert_eq!(r["findings"][0]["line"], 0);
    std::fs::remove_file(f.root.join(filename)).unwrap();
    let member = "ＲＥＳＴＲＩＣＴＥＤ .+[ＳＡＭＰＬＥ]／data.txt";
    write(&f.root.join("source.tgz"), &archive(member, b"safe", true));
    let r = f.scan();
    assert_eq!(r["findings"][0]["path"], format!("source.tgz!{member}"));
    assert_eq!(r["findings"][0]["line"], 0);
}
#[test]
fn no_hidden_pattern_fallback() {
    let mut f = Fixture::new(false);
    f.words("Synthetic Marker");
    f.file("Synthetic Marker");
    assert_eq!(f.scan()["findings"], json!([]));
}
#[test]
fn old_and_new_policy_equally_enforced() {
    let f = Fixture::new(true);
    for (version, engines) in [
        (1, json!(["builtin-disclosure", "gitleaks"])),
        (2, json!(["gitleaks"])),
    ] {
        io::private_json(&f.root.join("repository-security.json"),&json!({"schema":format!("zixcel://repository-security/policy/v{version}"),"repository_id":"synthetic-source","scope":"source-secret-disclosure/v1","required_engines":engines,"gitleaks_version":"8.30.1"})).unwrap();
        assert_eq!(f.scan()["status"], "passed");
    }
}
#[test]
fn malformed_policy_fails_closed() {
    let f = Fixture::new(false);
    write(&f.root.join("repository-security.json"), b"{}");
    assert!(scanner::scan(&f.root, &f.settings, "synthetic-source").is_err());
}
#[test]
fn invalid_re2_cannot_pass() {
    let mut f = Fixture::new(true);
    f.settings.regexes = vec![json!({"id":"pattern-01","regex":"["})];
    assert!(scanner::scan(&f.root, &f.settings, "synthetic-source").is_err());
}
#[test]
fn exception_expiration_and_source_definition_binding() {
    let mut f = Fixture::new(true);
    f.words("Private Subject");
    f.file("Private Subject");
    let r = f.scan();
    f.settings.exceptions = vec![
        json!({"fingerprint":r["findings"][0]["fingerprint"],"expires":"2099-01-01","reason":"synthetic fixture","reviewer":"local-review"}),
    ];
    assert_eq!(f.scan()["status"], "passed");
    f.file("Private Subject changed");
    assert_eq!(f.scan()["status"], "findings");
    f.file("Private Subject");
    f.settings.terms[0]["values"] = json!(["Private Subject", "Another Synthetic"]);
    assert_eq!(f.scan()["status"], "findings");
    f.settings.terms[0]["values"] = json!(["Private Subject"]);
    f.settings.exceptions[0]["expires"] = json!("2000-01-01");
    assert_eq!(f.scan()["status"], "findings");
}
#[test]
fn additional_rules_never_weaken_baseline_and_archives() {
    use sha2::{Digest, Sha512};
    let mut f = Fixture::new(true);
    let alphabet = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let token = ["gh", "p_"].concat()
        + &Sha512::digest(b"never-issued-custom-rule-fixture")[..36]
            .iter()
            .map(|b| alphabet[*b as usize % alphabet.len()] as char)
            .collect::<String>();
    let payload = format!("token = \"{token}\"\nSYNTHETIC_CHECK_{}\n", "1234");
    let native = f.temp.path().join("rules.toml");
    write(&native,b"[[rules]]\nid='synthetic-marker'\nregex='SYNTHETIC_CHECK_[0-9]{4}'\n[allowlist]\nregexes=['ghp_']\n[[rules]]\nid='github-pat'\nregex='NEVER_MATCH_SYNTHETIC_OVERRIDE'\n");
    f.settings.config["gitleaks"]["config_file"] = json!(native);
    for packed in [false, true] {
        if packed {
            std::fs::remove_file(f.root.join("source.txt")).unwrap();
            write(
                &f.root.join("fixture.tgz"),
                &archive("source.txt", payload.as_bytes(), true),
            );
        } else {
            f.file(&payload);
        }
        let r = f.scan();
        let rules = r["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["rule"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(rules.contains(&"gitleaks:github-pat"));
        assert!(rules.contains(&"gitleaks-additional:synthetic-marker"));
        assert!(!r.to_string().contains(&token));
    }
}
#[test]
fn native_external_extend_path_and_top_level_rejected() {
    let f = Fixture::new(false);
    let path = f.temp.path().join("rules.toml");
    let mut e = f.settings.config["gitleaks"].clone();
    e["config_file"] = json!(path);
    for bytes in [
        "[extend]\npath='elsewhere'\n[[rules]]\nid='test'\nregex='test'",
        "unknown=true\n[[rules]]\nid='test'\nregex='test'",
        "rules=[]",
    ] {
        write(&path, bytes.as_bytes());
        assert!(engine::external(Some(&e)).is_err());
    }
}
#[test]
fn private_output_modes_symlinks_hardlinks_and_parent_links() {
    let f = Fixture::new(false);
    io::private_json(&f.output, &json!({})).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_eq!(std::fs::metadata(&f.output).unwrap().mode() & 0o777, 0o600);
    let link = f.temp.path().join("link");
    symlink(&f.config, &link).unwrap();
    assert!(io::private_json(&link, &json!({})).is_err());
    let hard = f.temp.path().join("hard");
    std::fs::hard_link(&f.config, &hard).unwrap();
    let before = std::fs::read(&f.config).unwrap();
    assert!(io::private_json(&hard, &json!({})).is_err());
    assert_eq!(std::fs::read(&f.config).unwrap(), before);
    let parent = f.temp.path().join("linked-dir");
    symlink(&f.root, &parent).unwrap();
    assert!(io::private_json(&parent.join("result"), &json!({})).is_err());
}
#[test]
fn cli_output_cannot_overwrite_source_settings_or_engine() {
    let f = Fixture::new(false);
    for path in [
        f.root.join("result.json"),
        f.config.clone(),
        PathBuf::from(f.settings.config["gitleaks"]["path"].as_str().unwrap()),
    ] {
        let out = Command::new(env!("CARGO_BIN_EXE_zixcel-repository-security"))
            .args(["scan", "--root"])
            .arg(&f.root)
            .arg("--config")
            .arg(&f.config)
            .arg("--output")
            .arg(path)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
    }
}
#[test]
fn common_and_cli_words_dedup_merge_with_dictionary() {
    let f = Fixture::new(true);
    f.file("Private Subject\nＳＥＮＳＩＴＩＶＥ　ＳＡＭＰＬＥ\n追加検査対象");
    let words = f.temp.path().join("words.json");
    let extra = f.temp.path().join("extra.json");
    let private = f.temp.path().join("private.json");
    io::private_json(&words,&json!({"schema":"zixcel://repository-security/words/v1","words":[{"id":"word-01","values":["sensitive sample"]}]})).unwrap();
    io::private_json(&extra,&json!({"schema":"zixcel://repository-security/words/v1","words":[{"id":"word-02","values":["追加検査対象"]}]})).unwrap();
    io::private_json(
        &private,
        &json!([{"id":"person-01","category":"person","values":["Private Subject"]}]),
    )
    .unwrap();
    let mut config = f.settings.config.clone();
    config["words_file"] = json!("words.json");
    config["private_dictionary_file"] = json!("private.json");
    io::private_json(&f.config, &config).unwrap();
    let loaded = config::load(&f.config, Some(&words), None, None, false).unwrap();
    assert_eq!(loaded.terms.len(), 2);
    let out = f.invoke("scan", &["--words-file", extra.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    let r = io::load(&f.output).unwrap();
    assert_eq!(r["findings"].as_array().unwrap().len(), 3);
    assert!(
        !String::from_utf8(out.stdout)
            .unwrap()
            .contains("Private Subject")
    );
}
#[test]
fn definitions_cli_same_file_and_output_protection() {
    let f = Fixture::new(true);
    f.file("Synthetic Private Marker");
    let path = f.temp.path().join("definitions.json");
    io::private_json(
        &path,
        &document(vec![
            json!({"id":"word-01","kind":"literal","values":["Synthetic Private Marker"]}),
        ]),
    )
    .unwrap();
    let mut config = f.settings.config.clone();
    config["definitions_file"] = json!("definitions.json");
    io::private_json(&f.config, &config).unwrap();
    assert_eq!(
        f.invoke("scan", &["--definitions-file", path.to_str().unwrap()])
            .status
            .code(),
        Some(1)
    );
    let before = std::fs::read(&path).unwrap();
    assert_eq!(
        f.invoke("scan", &["--output", path.to_str().unwrap()])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
#[test]
fn inventory_all_roots_and_empty_inventory() {
    let f = Fixture::new(false);
    let inventory = f.temp.path().join("inventory.csv");
    write(&inventory, b"name,relative_path\n");
    assert_eq!(
        f.invoke(
            "scan-inventory",
            &[
                "--inventory",
                inventory.to_str().unwrap(),
                "--workspace",
                f.temp.path().to_str().unwrap()
            ]
        )
        .status
        .code(),
        Some(2)
    );
    let second = f.temp.path().join("second");
    std::fs::create_dir(&second).unwrap();
    write(
        &inventory,
        b"\xef\xbb\xbfname,relative_path\nfirst,source\nsecond,second\n",
    );
    assert_eq!(
        f.invoke(
            "scan-inventory",
            &[
                "--inventory",
                inventory.to_str().unwrap(),
                "--workspace",
                f.temp.path().to_str().unwrap()
            ]
        )
        .status
        .code(),
        Some(0)
    );
    assert_eq!(io::load(&f.output).unwrap().as_array().unwrap().len(), 2);
    write(&inventory, b"name,relative_path\nfirst,../outside\n");
    assert_eq!(
        f.invoke(
            "scan-inventory",
            &[
                "--inventory",
                inventory.to_str().unwrap(),
                "--workspace",
                f.temp.path().to_str().unwrap()
            ]
        )
        .status
        .code(),
        Some(2)
    );
}
#[test]
fn snapshot_is_local_only_and_requires_passing_scan() {
    let f = Fixture::new(false);
    f.file("safe source");
    assert_eq!(
        f.invoke("prepare-snapshot", &["--message", "synthetic fixture"])
            .status
            .code(),
        Some(0)
    );
    let artifact = io::load(&f.output).unwrap();
    assert_eq!(
        artifact["schema"],
        "zixcel://github/source-snapshot-artifact/v1"
    );
    assert!(!f.root.join(".git").exists());
    for branch in ["../main", "main.lock", "main\nnext"] {
        assert_eq!(
            f.invoke(
                "prepare-snapshot",
                &["--message", "fixture", "--branch", branch]
            )
            .status
            .code(),
            Some(2)
        );
    }
    f.file([255]);
    assert_eq!(
        f.invoke("prepare-snapshot", &["--message", "fixture"])
            .status
            .code(),
        Some(2)
    );
}
#[test]
fn workspace_physical_selection_and_fresh_exceptions() {
    let f = Fixture::new(true);
    let workspace = f.temp.path().join("workspace");
    let root = workspace.join("organizations/synthetic/sample");
    std::fs::create_dir_all(&root).unwrap();
    git(&root, &["init", "-q"]);
    write(&root.join("source.txt"), b"safe source");
    let mut config = f.settings.config.clone();
    config["exceptions_file"] = json!("missing-exceptions.json");
    io::private_json(&f.config, &config).unwrap();
    let args = [
        "--workspace",
        workspace.to_str().unwrap(),
        "--repository-path",
        "organizations/synthetic/sample",
    ];
    assert_eq!(f.invoke("scan-workspace", &args).status.code(), Some(0));
    assert_eq!(
        f.invoke(
            "scan-workspace",
            &[
                "--workspace",
                workspace.to_str().unwrap(),
                "--repository-path",
                "organizations/synthetic/unknown"
            ]
        )
        .status
        .code(),
        Some(2)
    );
}
#[test]
fn provisioning_offline_and_wrong_hash() {
    let f = Fixture::new(false);
    let configured = std::env::var("ZIXCEL_TEST_PINNED_GITLEAKS_CONFIG")
        .or_else(|_| std::env::var("ZIXCEL_TEST_GITLEAKS_CONFIG"))
        .expect("production provisioning requires the independently pinned engine");
    let production = io::load(Path::new(&configured)).unwrap();
    let target = f.temp.path().join("provisioned");
    sec::maintenance::provision(
        &target,
        Some(Path::new(production["gitleaks"]["path"].as_str().unwrap())),
        None,
        false,
    )
    .unwrap();
    assert!(target.join("config.json").exists());
    let wrong = f.temp.path().join("wrong");
    write(&wrong, b"invalid");
    let missing = f.temp.path().join("rejected");
    assert!(sec::maintenance::provision(&missing, Some(&wrong), None, false).is_err());
    assert!(!missing.exists());
    assert!(sec::maintenance::provision(&missing, None, None, false).is_err());
}
#[test]
fn malformed_truncated_and_bad_crc_archives_are_incomplete() {
    let f = Fixture::new(false);
    for bytes in [Vec::new(), b"not a tar archive".to_vec(), vec![0; 512]] {
        write(&f.root.join("broken.tar"), &bytes);
        assert_eq!(f.scan()["status"], "incomplete");
    }
    std::fs::remove_file(f.root.join("broken.tar")).unwrap();
    let mut packed = archive("source.txt", b"safe", true);
    let last = packed.len() - 8;
    packed[last] ^= 1;
    write(&f.root.join("broken.tgz"), &packed);
    assert_eq!(f.scan()["status"], "incomplete");
}
#[test]
fn protected_definitions_and_native_inputs_are_not_overwritten() {
    let f = Fixture::new(false);
    let defs = f.temp.path().join("defs.json");
    io::private_json(
        &defs,
        &document(vec![
            json!({"id":"word-01","kind":"literal","values":["synthetic marker"]}),
        ]),
    )
    .unwrap();
    let native = f.temp.path().join("native.toml");
    write(&native, b"[[rules]]\nid='synthetic'\nregex='synthetic'\n");
    for (flag, path) in [("--definitions-file", defs), ("--gitleaks-config", native)] {
        let before = std::fs::read(&path).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_zixcel-repository-security"))
            .arg("scan")
            .arg("--config")
            .arg(&f.config)
            .arg("--root")
            .arg(&f.root)
            .arg(flag)
            .arg(&path)
            .arg("--output")
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
#[test]
fn library_regex_validation_cannot_bypass_unified_schema() {
    let mut f = Fixture::new(false);
    f.settings.regexes = vec![json!({"id":"pattern-01","regex":"safe","allowlist":{}})];
    assert!(scanner::scan(&f.root, &f.settings, "synthetic-source").is_err());
}
