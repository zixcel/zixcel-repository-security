//! Repository-local, read-only observation. No setting mutation or approval grant.
#![forbid(unsafe_code)]
mod collect;
mod endpoints;
pub mod model;
mod pagination;
mod project;
mod projections;
mod review;
mod snapshot;
mod transport;
pub use collect::observe;
pub use review::{Change, Proposal, review};
pub use transport::{FetchError, Github, Read};
pub type Result<T> = std::result::Result<T, &'static str>;
pub fn digest(value: &impl serde::Serialize) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).expect("JSON model"))
    )
}
pub fn repository(input: &str) -> Result<()> {
    let parts: Vec<_> = input.split('/').collect();
    if parts.len() != 2
        || parts.iter().any(|p| {
            p.is_empty()
                || p.len() > 100
                || *p == "."
                || *p == ".."
                || !p
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        })
    {
        return Err("invalid_repository");
    }
    Ok(())
}
