use crate::{Result, model::Identity};
use serde_json::{Value, json};
pub(crate) fn identity(value: &Value, repository: &str) -> Result<Identity> {
    let id = value["id"]
        .as_u64()
        .filter(|id| *id > 0)
        .ok_or("repository_identity")?;
    let name = value["full_name"].as_str().ok_or("repository_identity")?;
    let branch = value["default_branch"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 255)
        .ok_or("repository_identity")?;
    if !name.eq_ignore_ascii_case(repository) {
        return Err("repository_scope_changed");
    }
    Ok(Identity {
        id,
        repository: name.into(),
        default_branch: branch.into(),
    })
}
pub(crate) fn fields(value: &Value, keys: &[&str]) -> Result<Value> {
    let object = value.as_object().ok_or("unexpected_response_schema")?;
    let mut output = serde_json::Map::new();
    for key in keys {
        output.insert(
            (*key).into(),
            object
                .get(*key)
                .ok_or("unexpected_response_schema")?
                .clone(),
        );
    }
    Ok(Value::Object(output))
}
pub(crate) fn secret(value: &Value) -> Result<Value> {
    for key in ["name", "created_at", "updated_at"] {
        if value[key].as_str().is_none_or(|s| s.len() > 256) {
            return Err("secret_metadata_schema");
        }
    }
    fields(value, &["name", "created_at", "updated_at"])
}
pub(crate) fn defaults(value: &Value) -> Result<Value> {
    if !matches!(
        value["default_workflow_permissions"].as_str(),
        Some("read" | "write")
    ) || !value["can_approve_pull_request_reviews"].is_boolean()
    {
        return Err("actions_schema");
    }
    fields(
        value,
        &[
            "default_workflow_permissions",
            "can_approve_pull_request_reviews",
        ],
    )
}
pub(crate) fn environment(value: &Value) -> Result<Value> {
    let reviewers = value["protection_rules"]
        .as_array()
        .ok_or("environment_schema")?;
    let mut rules = Vec::new();
    for rule in reviewers {
        let kind = rule["type"].as_str().ok_or("environment_schema")?;
        let projection = match kind {
            "required_reviewers" => {
                let people = rule["reviewers"]
                    .as_array()
                    .ok_or("environment_schema")?
                    .iter()
                    .map(|r| {
                        Ok(json!({"type":r["type"].as_str().ok_or("reviewer_schema")?,
                        "id":r["reviewer"]["id"].as_u64().ok_or("reviewer_schema")?}))
                    })
                    .collect::<Result<Vec<Value>>>()?;
                json!({"type":kind,"prevent_self_review":rule["prevent_self_review"],"reviewers":people})
            }
            "wait_timer" => fields(rule, &["type", "wait_timer"])?,
            "branch_policy" => json!({"type":kind}),
            _ => return Err("unsupported_environment_rule"),
        };
        rules.push(projection);
    }
    let mut result = fields(value, &["id", "name", "deployment_branch_policy"])?;
    result["protection_rules"] = Value::Array(rules);
    Ok(result)
}
