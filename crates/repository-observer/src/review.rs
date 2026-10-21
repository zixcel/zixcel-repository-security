use crate::{
    Result, digest,
    model::{Snapshot, State},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub component: String,
    pub expected_sha256: String,
    /// Desired observation, not a GitHub API payload or an execution permission.
    pub desired: Value,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    pub schema: String,
    pub repository_id: u64,
    pub configuration_sha256: String,
    pub changes: Vec<Change>,
}
/// Fresh state must come from a new collection, not a receipt or caller assertion.
/// Returns a review document only; separate human authorization is still required.
pub fn review(baseline: &Snapshot, fresh: &Snapshot, proposal: &Proposal) -> Result<Value> {
    if baseline.schema != "zix-repository-observation/v1"
        || fresh.schema != baseline.schema
        || proposal.schema != "zix-repository-proposal/v1"
    {
        return Err("schema_rejected");
    }
    if baseline.identity != fresh.identity || baseline.identity.id != proposal.repository_id {
        return Err("repository_identity_changed");
    }
    for snapshot in [baseline, fresh] {
        let time =
            DateTime::parse_from_rfc3339(&snapshot.observed_at).map_err(|_| "invalid_time")?;
        let age = Utc::now().signed_duration_since(time).num_seconds();
        if !(-60..=86400).contains(&age) {
            return Err("stale_observation");
        }
        if snapshot.configuration_hash() != snapshot.configuration_sha256 {
            return Err("observation_tampered");
        }
    }
    if proposal.configuration_sha256 != baseline.configuration_sha256
        || fresh.configuration_sha256 != baseline.configuration_sha256
    {
        return Err("configuration_drift");
    }
    if proposal.changes.is_empty() || proposal.changes.len() > 8 {
        return Err("change_count");
    }
    let mut seen = BTreeSet::new();
    for change in &proposal.changes {
        if !seen.insert(&change.component) {
            return Err("duplicate_change");
        }
        let component = fresh
            .observations
            .get(&change.component)
            .ok_or("unknown_component")?;
        if component.state != State::Supported || digest(&component.data) != change.expected_sha256
        {
            return Err("unobserved_or_changed_component");
        }
        crate::change::validate(
            &change.component,
            &component.data,
            &change.desired,
            &fresh.identity.repository,
        )?;
        if change.desired == component.data {
            return Err("no_change");
        }
    }
    Ok(
        json!({"schema":"zix-repository-review/v1", "repository":fresh.identity,
        "configuration_sha256":fresh.configuration_sha256, "proposal_sha256":digest(proposal),
        "approval_required":true, "executable":false, "changes":proposal.changes}),
    )
}
