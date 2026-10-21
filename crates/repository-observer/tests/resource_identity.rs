mod support;
use serde_json::json;
use support::Synthetic;
use zixcel_repository_observer::{model::State, observe};
#[test]
fn ruleset_detail_cannot_silently_change_the_listed_identity() {
    let mut reader = Synthetic::new();
    let mut listed = json!({"id":7,"name":"test","target":"tag","source_type":"Repository",
        "source":"example/project","enforcement":"active","conditions":null,"rules":[],"bypass_actors":[]});
    reader.replies.insert(
        "/repos/example/project/rulesets?includes_parents=true&per_page=100&page=1".into(),
        Ok(json!([listed.clone()])),
    );
    listed["id"] = json!(8);
    reader.replies.insert(
        "/repos/example/project/rulesets/7?includes_parents=true".into(),
        Ok(listed),
    );
    let snapshot = observe(&mut reader, "example/project", false).unwrap();
    assert_eq!(snapshot.observations["ruleset:7"].state, State::Unobserved);
    assert_eq!(
        snapshot.observations["ruleset:7"].reason,
        "ruleset_identity_changed"
    );
}
#[test]
fn unknown_environment_protection_is_incomplete_not_a_safe_empty_rule_set() {
    let mut reader = Synthetic::new();
    reader.replies.insert("/repos/example/project/environments?per_page=100&page=1".into(),
        Ok(json!({"total_count":1,"environments":[{"id":1,"name":"test","deployment_branch_policy":null,
            "protection_rules":[{"type":"future_protection_kind"}]}]})));
    let snapshot = observe(&mut reader, "example/project", false).unwrap();
    assert_eq!(snapshot.observations["environments"].state, State::Partial);
}
