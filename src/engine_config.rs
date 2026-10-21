//! Validate optional detector rules without granting filesystem includes.
use crate::{
    MAX_FILE, Result,
    definitions::{keys, text},
    identity, io, require,
};
use serde_json::Value;
use std::{collections::BTreeSet, path::Path};
pub fn external(engine: Option<&Value>) -> Result<Option<Vec<u8>>> {
    let Some(e) = engine else { return Ok(None) };
    keys(e, &["path", "sha256", "config_file"], &["path", "sha256"])?;
    let Some(file) = e.get("config_file") else {
        return Ok(None);
    };
    let p = Path::new(text(file)?);
    require(p.is_absolute())?;
    let bytes = io::read(p, MAX_FILE)?;
    let doc: toml::Value = toml::from_str(std::str::from_utf8(&bytes)?)?;
    let table = doc.as_table().ok_or("expected TOML")?;
    require(
        table
            .keys()
            .all(|s| ["title", "extend", "rules", "allowlist", "allowlists"].contains(&s.as_str())),
    )?;
    if let Some(extension) = table.get("extend") {
        require(extension.as_table().is_some_and(|t| {
            t.keys()
                .all(|s| ["useDefault", "disabledRules"].contains(&s.as_str()))
        }))?;
    }
    let rules = doc
        .get("rules")
        .and_then(|v| v.as_array())
        .ok_or("explicit rules required")?;
    require((1..=256).contains(&rules.len()))?;
    let mut ids = BTreeSet::new();
    for rule in rules {
        let id = rule
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or("expected rule id")?;
        require(identity(id, false) && ids.insert(id))?;
    }
    Ok(Some(bytes))
}
