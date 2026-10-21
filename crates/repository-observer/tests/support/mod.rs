use serde_json::{Value, json};
use std::collections::BTreeMap;
use zixcel_repository_observer::{FetchError, Read};
pub struct Synthetic {
    pub replies: BTreeMap<String, std::result::Result<Value, FetchError>>,
    pub paths: Vec<String>,
    pub identity_reads: usize,
    pub replaced: bool,
}
impl Synthetic {
    pub fn new() -> Self {
        Self {
            replies: BTreeMap::new(),
            paths: Vec::new(),
            identity_reads: 0,
            replaced: false,
        }
    }
}
impl Read for Synthetic {
    fn get(&mut self, path: &str) -> std::result::Result<Value, FetchError> {
        self.paths.push(path.into());
        if self.paths.len() > 32 {
            return Err(FetchError::Budget);
        }
        if path == "/repos/example/project" {
            self.identity_reads += 1;
            return Ok(
                json!({"id":if self.replaced && self.identity_reads > 1 { 2 } else { 1 },
                "full_name":"example/project","default_branch":"feature/safe"}),
            );
        }
        self.replies.get(path).cloned().unwrap_or_else(|| {
            if path.ends_with("actions/permissions/workflow") {
                Ok(json!({"default_workflow_permissions":"read","can_approve_pull_request_reviews":false}))
            } else if path.contains("/rulesets?") { Ok(json!([])) }
            else if path.contains("/environments?") { Ok(json!({"environments":[],"total_count":0})) }
            else { Err(FetchError::Hidden) }
        })
    }
}
