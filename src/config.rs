use crate::{
    Result,
    definitions::{self, keys, text},
    identity, io, require,
};
use serde_json::Value;
use std::path::{Path, PathBuf};
#[derive(Clone)]
pub struct Settings {
    pub config: Value,
    pub terms: Vec<Value>,
    pub regexes: Vec<Value>,
    pub exceptions: Vec<Value>,
    pub inputs: Vec<PathBuf>,
}
pub fn load(
    path: &Path,
    words: Option<&Path>,
    definitions: Option<&Path>,
    native: Option<&Path>,
    fresh: bool,
) -> Result<Settings> {
    let path = io::absolute(path)?;
    let base = path.parent().ok_or("missing base")?;
    let mut config = io::load(&path)?;
    keys(
        &config,
        &[
            "schema",
            "repository_id",
            "gitleaks",
            "private_dictionary_file",
            "exceptions_file",
            "words_file",
            "definitions_file",
        ],
        &["repository_id"],
    )?;
    require(
        identity(text(&config["repository_id"])?, false)
            && config
                .get("schema")
                .is_none_or(|s| s == "zixcel://repository-security/config/v1"),
    )?;
    let mut inputs = vec![path.clone()];
    let relative = |v: &Value| -> Result<PathBuf> {
        let s = text(v)?;
        require(!s.trim().is_empty())?;
        io::absolute(&base.join(s))
    };
    if let Some(engine) = config.get_mut("gitleaks") {
        keys(
            engine,
            &["path", "sha256", "config_file"],
            &["path", "sha256"],
        )?;
        require(Path::new(text(&engine["path"])?).is_absolute())?;
        inputs.push(io::absolute(Path::new(text(&engine["path"])?))?);
        if let Some(p) = engine.get("config_file") {
            engine["config_file"] = serde_json::json!(relative(p)?);
        }
        if let Some(p) = native {
            engine["config_file"] = serde_json::json!(io::absolute(p)?);
        }
        if let Some(p) = engine.get("config_file") {
            inputs.push(PathBuf::from(text(p)?));
        }
    } else {
        require(native.is_none())?;
    }
    let mut terms = Vec::new();
    if let Some(v) = config.get("private_dictionary_file") {
        let p = relative(v)?;
        terms = io::load(&p)?
            .as_array()
            .ok_or("expected dictionary")?
            .clone();
        inputs.push(p);
    }
    let mut regexes = Vec::new();
    for (key, extra) in [("words_file", words), ("definitions_file", definitions)] {
        // Preserve common-before-CLI ordering, independently of filesystem path order.
        let mut ordered = Vec::new();
        if let Some(v) = config.get(key) {
            ordered.push(relative(v)?);
        }
        if let Some(p) = extra {
            let p = io::absolute(p)?;
            if !ordered.contains(&p) {
                ordered.push(p);
            }
        }
        for p in ordered {
            let data = io::load(&p)?;
            if key == "words_file" {
                keys(&data, &["schema", "words"], &["schema", "words"])?;
                require(data["schema"] == "zixcel://repository-security/words/v1")?;
                let words = data["words"].as_array().ok_or("expected words")?;
                require((1..=256).contains(&words.len()))?;
                for w in words {
                    keys(w, &["id", "values"], &["id", "values"])?;
                    terms.push(
                        serde_json::json!({"id":w["id"],"values":w["values"],"category":"word"}),
                    );
                }
            } else {
                let (l, r) = definitions::validate(&data)?;
                terms.extend(l);
                regexes.extend(r);
            }
            inputs.push(p);
        }
    }
    definitions::combined(&terms, &regexes)?;
    let mut exceptions = Vec::new();
    if let Some(v) = config.get("exceptions_file") {
        let p = relative(v)?;
        inputs.push(p.clone());
        if !fresh {
            exceptions = io::load(&p)?
                .as_array()
                .ok_or("expected exceptions")?
                .clone();
        }
    }
    if fresh {
        config.as_object_mut().unwrap().remove("exceptions_file");
    }
    Ok(Settings {
        config,
        terms,
        regexes,
        exceptions,
        inputs,
    })
}
