use crate::{
    Read, endpoints,
    model::{Observation, State},
    transport::failure,
};
use serde_json::Value;
use std::collections::BTreeSet;
pub(crate) fn list(
    reader: &mut impl Read,
    path: &str,
    wrapper: Option<&str>,
    key: &str,
    project: fn(&Value) -> crate::Result<Value>,
) -> Observation {
    let mut data = Vec::new();
    let mut seen = BTreeSet::new();
    for page in 1..=2 {
        let response = match reader.get(&endpoints::page(path, page)) {
            Ok(value) => value,
            Err(error) => return incomplete(data, failure(error)),
        };
        let items = wrapper
            .map_or(&response, |field| &response[field])
            .as_array();
        let Some(items) = items.filter(|items| items.len() <= 100) else {
            return partial(data, "unexpected_page_schema");
        };
        for item in items {
            let Some(identity) = item.get(key).filter(|v| !v.is_null()) else {
                return partial(data, "missing_record_identity");
            };
            if !seen.insert(identity.to_string()) {
                return partial(data, "duplicate_page_identity");
            }
            match project(item) {
                Ok(value) => data.push(value),
                Err(reason) => return partial(data, reason),
            }
        }
        if items.len() < 100 {
            if let Some(total) = response.get("total_count") {
                if total.as_u64() != Some(data.len() as u64) {
                    return partial(data, "count_changed_or_incomplete");
                }
            }
            data.sort_by_key(|v| v[key].to_string());
            return Observation::supported(Value::Array(data));
        }
    }
    partial(data, "pagination_limit")
}
fn partial(data: Vec<Value>, reason: &str) -> Observation {
    Observation {
        state: State::Partial,
        reason: reason.into(),
        data: Value::Array(data),
    }
}
fn incomplete(data: Vec<Value>, error: Observation) -> Observation {
    if data.is_empty() {
        error
    } else {
        partial(data, &error.reason)
    }
}
