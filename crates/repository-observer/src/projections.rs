use crate::{Read, Result, model::Observation, project, transport::failure};
use serde_json::Value;
pub(crate) fn one(
    reader: &mut impl Read,
    path: &str,
    project: fn(&Value) -> Result<Value>,
) -> Observation {
    match reader.get(path) {
        Ok(value) => project(&value).map_or_else(Observation::missing, Observation::supported),
        Err(error) => failure(error),
    }
}
pub(crate) fn ruleset(value: &Value) -> Result<Value> {
    if value["id"].as_u64().is_none_or(|id| id == 0)
        || !matches!(value["target"].as_str(), Some("branch" | "tag" | "push"))
        || !matches!(
            value["enforcement"].as_str(),
            Some("active" | "disabled" | "evaluate")
        )
    {
        return Err("ruleset_schema");
    }
    project::fields(
        value,
        &[
            "id",
            "name",
            "target",
            "source_type",
            "source",
            "enforcement",
        ],
    )
}
pub(crate) fn rule_detail(value: &Value) -> Result<Value> {
    ruleset(value)?;
    if !value["rules"].is_array()
        || !value["bypass_actors"].is_array()
        || !(value["conditions"].is_object() || value["conditions"].is_null())
    {
        return Err("ruleset_detail_schema");
    }
    project::fields(
        value,
        &[
            "id",
            "name",
            "target",
            "source_type",
            "source",
            "enforcement",
            "conditions",
            "rules",
            "bypass_actors",
        ],
    )
}
pub(crate) fn protection(value: &Value) -> Result<Value> {
    let mut value = value.clone();
    strip_urls(&mut value);
    if !value.is_object() {
        return Err("protection_schema");
    }
    Ok(value)
}
fn strip_urls(value: &mut Value) {
    match value {
        Value::Object(fields) => {
            fields.retain(|k, _| !k.ends_with("url") && k != "node_id");
            fields.values_mut().for_each(strip_urls);
        }
        Value::Array(items) => items.iter_mut().for_each(strip_urls),
        _ => {}
    }
}
