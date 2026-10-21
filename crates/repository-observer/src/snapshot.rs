use crate::{
    Result,
    model::{Identity, Observation, Snapshot},
};
use chrono::Utc;
use std::collections::BTreeMap;
pub(crate) fn finish(
    identity: Identity,
    observations: BTreeMap<String, Observation>,
) -> Result<Snapshot> {
    let mut snapshot = Snapshot {
        schema: "zix-repository-observation/v1".into(),
        observed_at: Utc::now().to_rfc3339(),
        identity,
        observations,
        configuration_sha256: String::new(),
    };
    snapshot.configuration_sha256 = snapshot.configuration_hash();
    if serde_json::to_vec(&snapshot)
        .map_err(|_| "serialization")?
        .len()
        > 1024 * 1024
    {
        return Err("output_limit");
    }
    Ok(snapshot)
}
