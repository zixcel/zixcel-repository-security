mod support;
use serde_json::json;
use support::Synthetic;
use zixcel_repository_observer::{FetchError, model::State, observe};
#[test]
fn hidden_protection_is_unobserved_and_secrets_are_opt_in() {
    let mut reader = Synthetic::new();
    let snapshot = observe(&mut reader, "example/project", false).unwrap();
    assert_eq!(
        snapshot.observations["default_branch_protection"].state,
        State::Unobserved
    );
    assert_eq!(
        snapshot.observations["workflow_permissions"].state,
        State::Unobserved
    );
    assert!(!reader.paths.iter().any(|s| s.contains("/secrets")));
    assert!(reader.paths.iter().any(|s| s.contains("feature%2Fsafe")));
    assert_eq!(reader.identity_reads, 2);
}
#[test]
fn errors_do_not_become_empty_success() {
    for error in [
        FetchError::Denied,
        FetchError::Hidden,
        FetchError::Transport,
        FetchError::Budget,
        FetchError::Invalid,
    ] {
        let mut reader = Synthetic::new();
        reader.replies.insert(
            "/repos/example/project/actions/permissions/workflow".into(),
            Err(error),
        );
        let snapshot = observe(&mut reader, "example/project", false).unwrap();
        let state = &snapshot.observations["actions_defaults"].state;
        assert_eq!(
            *state,
            if error == FetchError::Denied {
                State::Denied
            } else {
                State::Unobserved
            }
        );
    }
}
#[test]
fn identity_change_or_unsafe_scope_never_produces_snapshot() {
    let mut reader = Synthetic::new();
    reader.replaced = true;
    assert!(observe(&mut reader, "example/project", false).is_err());
    for scope in [
        "example/../other",
        "example/project?x=1",
        "../project",
        "example/project#fragment",
    ] {
        let mut reader = Synthetic::new();
        assert!(observe(&mut reader, scope, false).is_err());
        assert!(reader.paths.is_empty());
    }
}
#[test]
fn secret_values_and_unselected_metadata_are_not_projected() {
    let mut reader = Synthetic::new();
    reader.replies.insert("/repos/example/project/actions/secrets?per_page=100&page=1".into(),
        Ok(json!({"total_count":1,"secrets":[{"name":"SYNTHETIC_TOKEN","created_at":"2026-01-01T00:00:00Z",
            "updated_at":"2026-01-01T00:00:00Z","value":"NEVER_RETAIN_THIS","unselected":"NEVER_RETAIN_THIS"}]})));
    let result = observe(&mut reader, "example/project", true).unwrap();
    let text = serde_json::to_string(&result).unwrap();
    assert!(text.contains("SYNTHETIC_TOKEN"));
    assert!(!text.contains("NEVER_RETAIN_THIS"));
}
#[test]
fn duplicate_and_count_drift_are_partial() {
    for response in [
        json!({"environments":[{"id":1,"name":"test","protection_rules":[],"deployment_branch_policy":null}],"total_count":2}),
        json!({"environments":[{"id":1,"name":"test","protection_rules":[],"deployment_branch_policy":null},
            {"id":1,"name":"test","protection_rules":[],"deployment_branch_policy":null}],"total_count":2}),
    ] {
        let mut reader = Synthetic::new();
        reader.replies.insert(
            "/repos/example/project/environments?per_page=100&page=1".into(),
            Ok(response),
        );
        let snapshot = observe(&mut reader, "example/project", false).unwrap();
        assert_eq!(snapshot.observations["environments"].state, State::Partial);
    }
}
#[test]
fn second_page_denial_preserves_partial_evidence() {
    let mut reader = Synthetic::new();
    reader.replies.insert(
        "/repos/example/project/rulesets?includes_parents=true&per_page=100&page=1".into(),
        Ok((1..=100).map(rule).collect()),
    );
    reader.replies.insert(
        "/repos/example/project/rulesets?includes_parents=true&per_page=100&page=2".into(),
        Err(FetchError::Denied),
    );
    let snapshot = observe(&mut reader, "example/project", false).unwrap();
    assert_eq!(snapshot.observations["rulesets"].state, State::Partial);
    assert_eq!(
        snapshot.observations["rulesets"]
            .data
            .as_array()
            .unwrap()
            .len(),
        100
    );
    assert!(reader.paths.len() <= 32);
}

fn rule(id: u64) -> Value {
    json!({"id":id,"name":"rule","target":"tag","source_type":"Repository", "source":"example/project","enforcement":"active"})
}
