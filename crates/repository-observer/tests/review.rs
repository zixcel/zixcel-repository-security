mod support;
use serde_json::json;
use support::Synthetic;
use zixcel_repository_observer::{Change, Proposal, digest, model::State, observe, review};
#[test]
fn component_hash_is_independent_of_json_object_insertion_order() {
    let a: serde_json::Value =
        serde_json::from_str(r#"{"b":{"z":1,"a":2},"a":[{"b":3,"a":4}]}"#).unwrap();
    let b: serde_json::Value =
        serde_json::from_str(r#"{"a":[{"a":4,"b":3}],"b":{"a":2,"z":1}}"#).unwrap();
    assert_eq!(digest(&a), digest(&b));
}
fn proposal(snapshot: &zixcel_repository_observer::model::Snapshot) -> Proposal {
    Proposal {
        schema: "zix-repository-proposal/v1".into(),
        repository_id: snapshot.identity.id,
        configuration_sha256: snapshot.configuration_sha256.clone(),
        changes: vec![Change {
            component: "actions_defaults".into(),
            expected_sha256: digest(&snapshot.observations["actions_defaults"].data),
            desired: json!({"default_workflow_permissions":"read","can_approve_pull_request_reviews":true}),
        }],
    }
}
#[test]
fn fresh_recollection_yields_review_not_permission_or_execution() {
    let baseline = observe(&mut Synthetic::new(), "example/project", false).unwrap();
    let fresh = observe(&mut Synthetic::new(), "example/project", false).unwrap();
    let result = review(&baseline, &fresh, &proposal(&baseline)).unwrap();
    assert_eq!(result["approval_required"], true);
    assert_eq!(result["executable"], false);
}
#[test]
fn drift_tampering_identity_and_age_are_refused() {
    let baseline = observe(&mut Synthetic::new(), "example/project", false).unwrap();
    for scenario in 0..5 {
        let mut changed = baseline.clone();
        match scenario {
            0 => changed.identity.id = 99,
            1 => changed.observed_at = "2020-01-01T00:00:00Z".into(),
            2 => changed.observed_at = "2099-01-01T00:00:00Z".into(),
            3 => {
                changed
                    .observations
                    .get_mut("actions_defaults")
                    .unwrap()
                    .data = json!({})
            }
            _ => {
                changed
                    .observations
                    .get_mut("actions_defaults")
                    .unwrap()
                    .state = State::Denied;
                changed.configuration_sha256 = changed.configuration_hash();
            }
        }
        assert!(review(&baseline, &changed, &proposal(&baseline)).is_err());
    }
}
#[test]
fn changes_reject_unknown_fields_noops_duplicates_and_unsupported_targets() {
    let baseline = observe(&mut Synthetic::new(), "example/project", false).unwrap();
    for scenario in 0..5 {
        let mut plan = proposal(&baseline);
        match scenario {
            0 => plan.changes[0].desired["secret"] = json!("NOT_ALLOWED"),
            1 => plan.changes[0].desired = baseline.observations["actions_defaults"].data.clone(),
            2 => plan.changes.push(Change {
                component: plan.changes[0].component.clone(),
                expected_sha256: plan.changes[0].expected_sha256.clone(),
                desired: plan.changes[0].desired.clone(),
            }),
            3 => plan.changes[0].component = "secret_metadata".into(),
            _ => plan.changes[0].expected_sha256 = "00".repeat(32),
        }
        assert!(review(&baseline, &baseline, &plan).is_err());
    }
}
