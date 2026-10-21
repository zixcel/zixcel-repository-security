use crate::{Result, project, projections::rule_detail};
use serde_json::Value;
fn stable(before: &Value, after: &Value, fields: &[&str]) -> Result<()> {
    if fields.iter().any(|field| before[*field] != after[*field]) {
        return Err("change_scope_identity");
    }
    Ok(())
}
/// Validate desired projections, never construct a write request or a credential value.
pub(crate) fn validate(
    component: &str,
    before: &Value,
    desired: &Value,
    repository: &str,
) -> Result<()> {
    let projected = if component == "actions_defaults" {
        project::defaults(desired)?
    } else if component.starts_with("ruleset:") {
        stable(before, desired, &["id", "target", "source_type", "source"])?;
        if before["source_type"] != "Repository" || before["source"] != repository {
            return Err("inherited_rule_requires_source_owner_review");
        }
        rule_detail(desired)?
    } else if component == "environments" {
        let before = before.as_array().ok_or("environment_schema")?;
        let after = desired.as_array().ok_or("environment_schema")?;
        if before.len() != after.len() || before.len() > 200 {
            return Err("environment_identity");
        }
        let mut projected = Vec::new();
        for (old, new) in before.iter().zip(after) {
            stable(old, new, &["id", "name", "deployment_branch_policy"])?;
            projected.push(project::environment(new)?);
        }
        Value::Array(projected)
    } else {
        return Err("unsupported_change_component");
    };
    if projected != *desired {
        return Err("unexpected_change_fields");
    }
    Ok(())
}
