use crate::{
    Read, Result,
    endpoints::{base, encoded},
    model::{Observation, Snapshot},
    pagination::list,
    project,
    projections::{one, protection, rule_detail, ruleset},
};
use std::collections::BTreeMap;
/// Two repository identity checks surround at most 32 HTTPS requests / 40 seconds.
/// Each list is bounded to two 100-record pages; resources are never mutated.
pub fn observe(
    reader: &mut impl Read,
    repository: &str,
    secret_metadata: bool,
) -> Result<Snapshot> {
    crate::repository(repository)?;
    let base = base(repository);
    let first = reader.get(&base).map_err(|_| "repository_not_observable")?;
    let identity = project::identity(&first, repository)?;
    let mut observations = BTreeMap::new();
    observations.insert(
        "actions_defaults".into(),
        one(
            reader,
            &format!("{base}/actions/permissions/workflow"),
            project::defaults,
        ),
    );
    observations.insert(
        "default_branch_protection".into(),
        one(
            reader,
            &format!(
                "{base}/branches/{}/protection",
                encoded(&identity.default_branch)
            ),
            protection,
        ),
    );
    let rules = list(
        reader,
        &format!("{base}/rulesets?includes_parents=true"),
        None,
        "id",
        ruleset,
    );
    for rule in rules.data.as_array().into_iter().flatten().take(8) {
        if let Some(id) = rule["id"].as_u64() {
            let mut detail = one(
                reader,
                &format!("{base}/rulesets/{id}?includes_parents=true"),
                rule_detail,
            );
            if detail.state == crate::model::State::Supported
                && ["id", "source", "source_type", "target"]
                    .iter()
                    .any(|key| detail.data[*key] != rule[*key])
            {
                detail = Observation::missing("ruleset_identity_changed");
            }
            observations.insert(format!("ruleset:{id}"), detail);
        }
    }
    let mut rules = rules;
    if rules.data.as_array().is_some_and(|v| v.len() > 8) {
        rules.state = crate::model::State::Partial;
        rules.reason = "ruleset_detail_limit".into();
    }
    observations.insert("rulesets".into(), rules);
    let environments = list(
        reader,
        &format!("{base}/environments"),
        Some("environments"),
        "id",
        project::environment,
    );
    // Deployment pattern lists and external custom protection apps need their own evidence.
    observations.insert("environments".into(), environments);
    observations.insert(
        "environment_deployment_patterns".into(),
        Observation::missing("pattern_and_custom_app_effectiveness_not_observed"),
    );
    observations.insert(
        "workflow_permissions".into(),
        Observation::missing(
            "effective_job_and_reusable_workflow_permissions_require_source_review",
        ),
    );
    observations.insert(
        "secret_metadata".into(),
        if secret_metadata {
            list(
                reader,
                &format!("{base}/actions/secrets"),
                Some("secrets"),
                "name",
                project::secret,
            )
        } else {
            Observation::missing("not_requested_no_secret_metadata_access")
        },
    );
    observations.insert(
        "organization_and_environment_secrets".into(),
        Observation::missing("not_in_repository_secret_metadata_scope"),
    );
    let last = reader
        .get(&base)
        .map_err(|_| "repository_identity_recheck_failed")?;
    if project::identity(&last, repository)? != identity {
        return Err("repository_identity_changed");
    }
    crate::snapshot::finish(identity, observations)
}
