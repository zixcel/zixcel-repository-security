mod support;
use serde_json::json;
use support::Synthetic;
use zixcel_repository_observer::{Change, Proposal, digest, model::Observation, observe, review};
fn rule() -> serde_json::Value {
    json!({"id":7,"name":"version integrity","target":"tag","source_type":"Repository",
        "source":"example/project","enforcement":"active","conditions":{"ref_name":{"include":["refs/tags/v*"],"exclude":[]}},
        "rules":[{"type":"deletion"}],"bypass_actors":[]})
}
fn plan(
    snapshot: &zixcel_repository_observer::model::Snapshot,
    component: &str,
    desired: serde_json::Value,
) -> Proposal {
    Proposal {
        schema: "zix-repository-proposal/v1".into(),
        repository_id: snapshot.identity.id,
        configuration_sha256: snapshot.configuration_sha256.clone(),
        changes: vec![Change {
            component: component.into(),
            expected_sha256: digest(&snapshot.observations[component].data),
            desired,
        }],
    }
}
#[test]
fn projected_ruleset_changes_require_current_owner_identity_and_explicit_review() {
    let mut baseline = observe(&mut Synthetic::new(), "example/project", false).unwrap();
    baseline
        .observations
        .insert("ruleset:7".into(), Observation::supported(rule()));
    baseline.configuration_sha256 = baseline.configuration_hash();
    let mut desired = rule();
    desired["rules"] = json!([{"type":"deletion"},{"type":"update"}]);
    let proposal = plan(&baseline, "ruleset:7", desired.clone());
    assert_eq!(
        review(&baseline, &baseline, &proposal).unwrap()["executable"],
        false
    );
    desired["source_type"] = json!("Organization");
    assert!(review(&baseline, &baseline, &plan(&baseline, "ruleset:7", desired)).is_err());
}
#[test]
fn environment_review_changes_do_not_grant_pattern_or_credential_scope() {
    let mut baseline = observe(&mut Synthetic::new(), "example/project", false).unwrap();
    let environment =
        json!({"id":8,"name":"release","deployment_branch_policy":null,"protection_rules":[]});
    baseline.observations.insert(
        "environments".into(),
        Observation::supported(json!([environment])),
    );
    baseline.configuration_sha256 = baseline.configuration_hash();
    let mut desired = baseline.observations["environments"].data.clone();
    desired[0]["protection_rules"] = json!([{"type":"required_reviewers","prevent_self_review":true,
        "reviewers":[{"type":"User","reviewer":{"id":99}}]}]);
    assert!(
        review(
            &baseline,
            &baseline,
            &plan(&baseline, "environments", desired.clone())
        )
        .is_ok()
    );
    desired[0]["deployment_branch_policy"] =
        json!({"protected_branches":true,"custom_branch_policies":false});
    assert!(
        review(
            &baseline,
            &baseline,
            &plan(&baseline, "environments", desired)
        )
        .is_err()
    );
}
