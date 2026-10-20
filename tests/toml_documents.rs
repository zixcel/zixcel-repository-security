use serde_json::json;
use zixcel_repository_security::{definitions, engine};

#[test]
fn compiled_rules_remain_a_full_toml_document() {
    let policy = definitions::policy(&[json!({
        "id": "synthetic-extra", "regex": "SYNTHETIC_DOCUMENT_SENTINEL"
    })])
    .unwrap();
    let document: toml::Table = toml::from_str(std::str::from_utf8(&policy).unwrap()).unwrap();
    assert!(document["title"].is_str());
    let rules = document["rules"].as_array().unwrap();
    assert!(
        rules
            .iter()
            .any(|rule| rule["id"].as_str() == Some("zixcel-regex-synthetic-extra"))
    );
    assert!(
        rules
            .iter()
            .any(|rule| rule["id"].as_str() == Some("zixcel-disclosure-private-key"))
    );
}

#[test]
fn external_document_tables_parse_and_unknown_keys_still_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("rules.toml");
    let config = json!({"path": temp.path().join("unused-executable"),
        "sha256": "0".repeat(64), "config_file": file});
    std::fs::write(&file, "title = 'Synthetic policy'\n[[rules]]\nid = 'synthetic-rule'\nregex = 'SYNTHETIC_DOCUMENT_SENTINEL'\n").unwrap();
    assert!(engine::external(Some(&config)).unwrap().is_some());
    std::fs::write(&file, "unknown = 'refuse'\n").unwrap();
    assert!(engine::external(Some(&config)).is_err());
}
