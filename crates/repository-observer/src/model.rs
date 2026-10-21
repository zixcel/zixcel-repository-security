use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Supported,
    Denied,
    Unobserved,
    Partial,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub state: State,
    pub reason: String,
    pub data: Value,
}
impl Observation {
    pub fn supported(data: Value) -> Self {
        Self {
            state: State::Supported,
            reason: "observed".into(),
            data,
        }
    }
    pub fn missing(reason: &str) -> Self {
        Self {
            state: State::Unobserved,
            reason: reason.into(),
            data: Value::Null,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub id: u64,
    pub repository: String,
    pub default_branch: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema: String,
    pub observed_at: String,
    pub identity: Identity,
    pub observations: BTreeMap<String, Observation>,
    pub configuration_sha256: String,
}
impl Snapshot {
    pub fn configuration_hash(&self) -> String {
        crate::digest(&(&self.identity, &self.observations))
    }
}
