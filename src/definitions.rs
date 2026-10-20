use crate::{Result, identity, require};
use caseless::Caseless;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use unicode_normalization::UnicodeNormalization;
pub const SCHEMA: &str = "zixcel://repository-security/definitions/v1";
pub fn normalize(s: &str) -> String {
    s.nfkc().default_case_fold().collect()
}
pub fn keys(v: &Value, allowed: &[&str], required: &[&str]) -> Result<()> {
    let o = v.as_object().ok_or("expected object")?;
    require(
        o.keys().all(|k| allowed.contains(&k.as_str()))
            && required.iter().all(|k| o.contains_key(*k)),
    )
}
pub fn text(v: &Value) -> Result<&str> {
    v.as_str().ok_or_else(|| "expected string".into())
}
fn valid_value(v: &Value, min: usize, max: usize) -> bool {
    v.as_str().is_some_and(|s| {
        (min..=max).contains(&s.chars().count())
            && !s.contains(['\r', '\n', '\0'])
            && !normalize(s).trim().is_empty()
    })
}
pub fn validate_terms(terms: &[Value]) -> Result<()> {
    require(terms.len() <= 256)?;
    let mut ids = BTreeSet::new();
    for term in terms {
        keys(
            term,
            &["id", "category", "values"],
            &["id", "category", "values"],
        )?;
        require(
            identity(text(&term["id"])?, true)
                && ids.insert(text(&term["id"])?)
                && ["person", "company", "project", "word"].contains(&text(&term["category"])?),
        )?;
        let values = term["values"].as_array().ok_or("expected values")?;
        require((1..=32).contains(&values.len()) && values.iter().all(|v| valid_value(v, 2, 256)))?;
    }
    Ok(())
}
pub fn validate(data: &Value) -> Result<(Vec<Value>, Vec<Value>)> {
    keys(data, &["schema", "rules"], &["schema", "rules"])?;
    require(data["schema"] == SCHEMA)?;
    let rules = data["rules"].as_array().ok_or("expected rules")?;
    require((1..=256).contains(&rules.len()))?;
    let (mut terms, mut regexes, mut ids) = (Vec::new(), Vec::new(), BTreeSet::new());
    for rule in rules {
        require(identity(text(&rule["id"])?, true) && ids.insert(text(&rule["id"])?))?;
        match text(&rule["kind"])? {
            "literal" => {
                keys(
                    rule,
                    &["id", "kind", "category", "values"],
                    &["id", "kind", "values"],
                )?;
                terms.push(json!({"id":rule["id"],"category":rule.get("category").unwrap_or(&json!("word")),"values":rule["values"]}));
            }
            "regex" => {
                keys(
                    rule,
                    &["id", "kind", "regex", "secretGroup", "entropy", "keywords"],
                    &["id", "kind", "regex"],
                )?;
                let expr = text(&rule["regex"])?;
                require((1..=4096).contains(&expr.chars().count()) && !expr.contains('\0'))?;
                if let Some(v) = rule.get("secretGroup") {
                    require(v.as_u64().is_some_and(|n| n <= 64))?;
                }
                if let Some(v) = rule.get("entropy") {
                    require(
                        v.as_f64()
                            .is_some_and(|n| n.is_finite() && (0.0..=8.0).contains(&n)),
                    )?;
                }
                if let Some(v) = rule.get("keywords") {
                    let a = v.as_array().ok_or("expected keywords")?;
                    require(
                        (1..=32).contains(&a.len()) && a.iter().all(|v| valid_value(v, 1, 256)),
                    )?;
                }
                let mut r = rule.clone();
                r.as_object_mut().unwrap().remove("kind");
                regexes.push(r);
            }
            _ => return Err("unknown definition kind".into()),
        }
    }
    validate_terms(&terms)?;
    Ok((terms, regexes))
}
pub fn combined(terms: &[Value], regexes: &[Value]) -> Result<()> {
    validate_terms(terms)?;
    require(terms.len() + regexes.len() <= 256)?;
    if !regexes.is_empty() {
        for r in regexes {
            require(r.is_object())?;
        }
        let rules = regexes
            .iter()
            .map(|r| {
                let mut r = r.clone();
                r["kind"] = json!("regex");
                r
            })
            .collect::<Vec<_>>();
        validate(&json!({"schema": SCHEMA, "rules": rules}))?;
    }
    let mut ids = BTreeSet::new();
    for r in terms.iter().chain(regexes) {
        require(ids.insert(text(&r["id"])?))?;
    }
    Ok(())
}
fn compile(rules: Vec<Value>) -> Result<Vec<u8>> {
    Ok(toml::to_string(&json!({"title":"Compiled local definitions","rules":rules}))?.into_bytes())
}
pub fn literals(terms: &[Value]) -> Result<Vec<u8>> {
    compile(terms.iter().map(|t| {
        let values = t["values"].as_array().unwrap().iter().map(|v| normalize(v.as_str().unwrap()).chars().map(|c| if "\\.^$|?*+()[]{}".contains(c) {format!("\\{c}")} else {c.to_string()}).collect::<String>()).collect::<Vec<_>>();
        json!({"id":format!("zixcel-literal-{}",t["id"].as_str().unwrap()),"regex":format!("(?:{})",values.join("|"))})
    }).collect())
}
pub fn patterns(regexes: &[Value]) -> Result<Vec<u8>> {
    compile(
        regexes
            .iter()
            .map(|r| {
                let mut r = r.clone();
                r["id"] = json!(format!("zixcel-regex-{}", r["id"].as_str().unwrap()));
                r
            })
            .collect(),
    )
}
pub fn policy(regexes: &[Value]) -> Result<Vec<u8>> {
    let mut parsed: toml::Value = toml::from_str(crate::DISCLOSURE)?;
    if !regexes.is_empty() {
        let generated: toml::Value = toml::from_str(&String::from_utf8(patterns(regexes)?)?)?;
        parsed["rules"]
            .as_array_mut()
            .ok_or("missing disclosure rules")?
            .extend(
                generated["rules"]
                    .as_array()
                    .ok_or("missing compiled rules")?
                    .iter()
                    .cloned(),
            );
    }
    Ok(toml::to_string(&parsed)?.into_bytes())
}
