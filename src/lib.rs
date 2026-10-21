//! Local-only source orchestration. Gitleaks is the sole pattern detector.
#![forbid(unsafe_code)]
pub mod cli;
pub mod config;
pub mod definitions;
pub mod directory;
pub mod engine;
mod engine_archive;
mod engine_config;
mod engine_install;
mod engine_process;
pub mod io;
pub mod maintenance;
pub mod scanner;
use serde_json::Value;
use sha2::{Digest, Sha256};
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub const MAX_FILE: usize = 16 * 1024 * 1024;
pub const MAX_TOTAL: usize = 256 * 1024 * 1024;
pub const MAX_FILES: usize = 20000;
pub const DISCLOSURE: &str = include_str!("../assets/disclosure.toml");
pub fn require(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err("local inspection precondition failed".into())
    }
}
pub fn digest(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String is infallible");
    }
    encoded
}
pub fn canonical(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("JSON value serializes")
}
pub fn hash(value: &Value) -> String {
    digest(&canonical(value))
}
pub fn identity(s: &str, private: bool) -> bool {
    !s.is_empty()
        && s.len() <= if private { 64 } else { 100 }
        && s.bytes().all(|c| {
            if private {
                c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'
            } else {
                c.is_ascii_alphanumeric() || b"._-".contains(&c)
            }
        })
}
