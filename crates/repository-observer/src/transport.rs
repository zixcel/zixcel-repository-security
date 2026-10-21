use crate::Result;
use crowsi_provider_read_http::{Error, HttpsRead};
use serde_json::Value;
use std::time::Duration;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchError {
    Denied,
    Hidden,
    Transport,
    Budget,
    Invalid,
}
pub trait Read {
    fn get(&mut self, path: &str) -> std::result::Result<Value, FetchError>;
}
pub struct Github {
    reader: HttpsRead,
}
impl Github {
    pub fn new(token: &str) -> Result<Self> {
        Ok(Self {
            reader: HttpsRead::new("https://api.github.com", token, Duration::from_secs(40), 32)
                .map_err(|_| "transport_configuration")?,
        })
    }
}
impl Read for Github {
    fn get(&mut self, path: &str) -> std::result::Result<Value, FetchError> {
        if !path.starts_with("/repos/") || path.contains(['#', '\r', '\n']) {
            return Err(FetchError::Invalid);
        }
        let bytes = self
            .reader
            .get(
                &format!("https://api.github.com{path}"),
                &[
                    ("accept", "application/vnd.github+json"),
                    ("x-github-api-version", "2026-03-10"),
                ],
                1024 * 1024,
            )
            .map_err(|e| match e {
                Error::Status(401 | 403 | 429) => FetchError::Denied,
                Error::Status(404) => FetchError::Hidden,
                Error::Budget => FetchError::Budget,
                _ => FetchError::Transport,
            })?;
        serde_json::from_slice(&bytes).map_err(|_| FetchError::Invalid)
    }
}
pub(crate) fn failure(error: FetchError) -> crate::model::Observation {
    use crate::model::{Observation, State};
    let (state, reason) = match error {
        FetchError::Denied => (State::Denied, "permission_or_rate_denied"),
        FetchError::Hidden => (State::Unobserved, "not_found_or_not_visible"),
        FetchError::Budget => (State::Unobserved, "request_or_time_budget"),
        FetchError::Transport => (State::Unobserved, "transport_or_body_limit"),
        FetchError::Invalid => (State::Unobserved, "unexpected_response_schema"),
    };
    Observation {
        state,
        reason: reason.into(),
        data: Value::Null,
    }
}
