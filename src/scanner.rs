use crate::{
    DISCLOSURE, MAX_FILE, MAX_FILES, MAX_TOTAL, Result,
    config::Settings,
    definitions::{self, text},
    digest,
    engine::{self, Pass},
    hash, io, require,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Cursor, Read},
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};
use wait_timeout::ChildExt;
#[derive(PartialEq, Debug)]
pub struct Files {
    pub names: Vec<String>,
    pub ignored: BTreeSet<String>,
    pub deleted: Vec<String>,
    pub directories: Vec<String>,
}
fn git_output(
    root: &Path,
    git: &[String],
    args: &[&str],
    input: Option<&[u8]>,
    allow_one: bool,
) -> Result<Vec<u8>> {
    let temp = tempfile::tempdir()?;
    let out = temp.path().join("out");
    let inp = temp.path().join("in");
    io::private_bytes(&out, b"")?;
    io::private_bytes(&inp, input.unwrap_or(b""))?;
    let mut child = Command::new("git")
        .args(git)
        .args(args)
        .current_dir(root)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_INDEX_FILE")
        .stdin(Stdio::from(std::fs::File::open(inp)?))
        .stdout(Stdio::from(
            std::fs::OpenOptions::new().write(true).open(&out)?,
        ))
        .stderr(Stdio::null())
        .spawn()?;
    let status = match child.wait_timeout(Duration::from_secs(120))? {
        Some(s) => s,
        None => {
            child.kill()?;
            child.wait()?;
            return Err("git observation timed out".into());
        }
    };
    require(status.success() || (allow_one && status.code() == Some(1)))?;
    io::read(&out, MAX_TOTAL)
}
fn split_names(bytes: &[u8]) -> Result<BTreeSet<String>> {
    bytes
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| Ok(std::str::from_utf8(s)?.to_owned()))
        .collect()
}
pub fn git_files(root: &Path) -> Result<Files> {
    let temp = tempfile::tempdir()?;
    let mut git = vec!["-c".into(), "core.excludesFile=/dev/null".into()];
    if !root.join(".git").exists() {
        git_output(
            root,
            &[],
            &["init", "-q", temp.path().to_str().ok_or("invalid path")?],
            None,
            false,
        )?;
        git.extend([
            format!("--git-dir={}/.git", temp.path().display()),
            format!("--work-tree={}", root.display()),
        ]);
    }
    let mut names = split_names(&git_output(
        root,
        &git,
        &["ls-files", "-c", "-o", "--exclude-standard", "-z"],
        None,
        false,
    )?)?;
    let deleted = split_names(&git_output(
        root,
        &git,
        &["ls-files", "--deleted", "-z"],
        None,
        false,
    )?)?
    .into_iter()
    .filter(|name| std::fs::symlink_metadata(root.join(name)).is_err())
    .collect::<Vec<_>>();
    for name in &deleted {
        names.remove(name);
    }
    require(names.len() <= MAX_FILES)?;
    let ignored = if names.is_empty() {
        BTreeSet::new()
    } else {
        let input = names
            .iter()
            .flat_map(|n| n.bytes().chain([0]))
            .collect::<Vec<_>>();
        split_names(&git_output(
            root,
            &git,
            &["check-ignore", "--no-index", "--stdin", "-z"],
            Some(&input),
            true,
        )?)?
    };
    Ok(Files {
        names: names.into_iter().collect(),
        ignored,
        deleted,
        directories: Vec::new(),
    })
}
pub struct Budget {
    pub bytes: usize,
    pub entries: usize,
}
pub fn documents(
    name: &str,
    data: &[u8],
    depth: usize,
    budget: &mut Budget,
) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    if budget.bytes < data.len() || budget.entries == 0 {
        out.push((name.into(), None));
        budget.bytes = 0;
        budget.entries = 0;
        return out;
    }
    budget.bytes -= data.len();
    budget.entries -= 1;
    if archive_name(name) {
        if depth >= 2 {
            return vec![(name.into(), None)];
        }
        let inspect = || -> Result<Vec<(String, Option<String>)>> {
            let reader: Box<dyn Read> = if data.starts_with(&[0x1f, 0x8b]) {
                Box::new(flate2::read::GzDecoder::new(Cursor::new(data)))
            } else {
                Box::new(Cursor::new(data))
            };
            // Read through gzip EOF/CRC, with a bound including TAR headers and
            // padding. An empty/truncated stream must not become a clean archive.
            let mut expanded = Vec::new();
            reader
                .take((MAX_TOTAL + 1) as u64)
                .read_to_end(&mut expanded)?;
            require(
                expanded.len() >= 1024 && expanded.len() <= MAX_TOTAL && expanded.len() % 512 == 0,
            )?;
            let mut archive = tar::Archive::new(Cursor::new(expanded));
            let mut total = 0usize;
            let mut docs = Vec::new();
            for (index, item) in archive.entries()?.enumerate() {
                require(index < 4096)?;
                let mut item = item?;
                let path = item.path()?;
                let path = path.to_str().ok_or("non UTF8 archive path")?.to_owned();
                require(
                    !path.is_empty()
                        && !path.starts_with('/')
                        && !path.split('/').any(|p| p == "..")
                        && !item.header().entry_type().is_symlink()
                        && !item.header().entry_type().is_hard_link(),
                )?;
                let size = item.size();
                require(size <= MAX_FILE as u64)?;
                if item.header().entry_type().is_dir() {
                    require(budget.entries > 0)?;
                    budget.entries -= 1;
                    continue;
                }
                require(item.header().entry_type().is_file())?;
                total = total.checked_add(size as usize).ok_or("archive overflow")?;
                require(total <= MAX_TOTAL)?;
                let mut content = Vec::new();
                item.by_ref()
                    .take((MAX_FILE + 1) as u64)
                    .read_to_end(&mut content)?;
                require(content.len() == size as usize)?;
                docs.extend(documents(
                    &format!("{name}!{path}"),
                    &content,
                    depth + 1,
                    budget,
                ));
            }
            Ok(docs)
        };
        let mut inspect = inspect;
        match inspect() {
            Ok(docs) => out.extend(docs),
            Err(_) => out.push((name.into(), None)),
        }
    } else {
        out.push((
            name.into(),
            std::str::from_utf8(data)
                .ok()
                .filter(|s| !s.contains('\0'))
                .map(str::to_owned),
        ));
    }
    out
}
fn archive_name(name: &str) -> bool {
    name.ends_with(".tgz") || name.ends_with(".tar.gz") || name.ends_with(".tar")
}
fn lines(text: &str) -> impl Iterator<Item = &str> {
    // Python splitlines boundaries, preserving source line numbers in normalized scan.
    text.split([
        '\n', '\r', '\x0b', '\x0c', '\x1c', '\x1d', '\x1e', '\u{85}', '\u{2028}', '\u{2029}',
    ])
}
struct Staging {
    raw: tempfile::TempDir,
    normalized: tempfile::TempDir,
    locations: BTreeMap<String, String>,
    normalized_locations: BTreeMap<String, String>,
    names: BTreeSet<String>,
    normalized_names: BTreeSet<String>,
    total: usize,
}
impl Staging {
    fn new() -> Result<Self> {
        Ok(Self {
            raw: tempfile::tempdir()?,
            normalized: tempfile::tempdir()?,
            locations: BTreeMap::new(),
            normalized_locations: BTreeMap::new(),
            names: BTreeSet::new(),
            normalized_names: BTreeSet::new(),
            total: 0,
        })
    }
    fn normalized(&mut self, name: &str, text: &str, is_name: bool) -> Result<()> {
        // CRLF is one splitline boundary; all other splitlines retain their numbering.
        let content = if is_name {
            definitions::normalize(text)
        } else {
            let text = text.replace("\r\n", "\n");
            lines(&text)
                .map(definitions::normalize)
                .collect::<Vec<_>>()
                .join("\n")
        };
        self.total = self
            .total
            .checked_add(content.len())
            .ok_or("normalization overflow")?;
        require(content.len() <= MAX_FILE && self.total <= MAX_TOTAL)?;
        let fragment = format!("{}.txt", self.normalized_locations.len());
        io::private_bytes(&self.normalized.path().join(&fragment), content.as_bytes())?;
        self.normalized_locations
            .insert(fragment.clone(), name.into());
        if is_name {
            self.normalized_names.insert(fragment);
        }
        Ok(())
    }
    fn name(&mut self, name: &str, enabled: bool) -> Result<()> {
        if enabled && self.names.insert(name.into()) {
            self.normalized(name, name, true)?;
        }
        Ok(())
    }
}
fn exception_index(exceptions: &[Value]) -> Result<BTreeSet<String>> {
    let mut index = BTreeSet::new();
    let today = chrono::Utc::now().date_naive();
    for e in exceptions {
        definitions::keys(
            e,
            &["fingerprint", "expires", "reason", "reviewer"],
            &["fingerprint", "expires", "reason", "reviewer"],
        )?;
        let fp = text(&e["fingerprint"])?;
        require(
            fp.len() == 64
                && fp
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        )?;
        let date = chrono::NaiveDate::parse_from_str(text(&e["expires"])?, "%Y-%m-%d")?;
        if date >= today
            && !text(&e["reason"])?.trim().is_empty()
            && !text(&e["reviewer"])?.trim().is_empty()
        {
            index.insert(fp.into());
        }
    }
    Ok(index)
}
pub fn code_digest() -> String {
    hash(
        &json!({"lib.rs":digest(include_bytes!("lib.rs")),"io.rs":digest(include_bytes!("io.rs")),"config.rs":digest(include_bytes!("config.rs")),"definitions.rs":digest(include_bytes!("definitions.rs")),"engine.rs":digest(include_bytes!("engine.rs")),"scanner.rs":digest(include_bytes!("scanner.rs")),"directory.rs":digest(include_bytes!("directory.rs")),"cli.rs":digest(include_bytes!("cli.rs")),"maintenance.rs":digest(include_bytes!("maintenance.rs")),"Cargo.lock":digest(include_bytes!("../Cargo.lock")),"definitions-schema":digest(include_bytes!("../assets/definitions.v1.schema.json")),"disclosure.toml":digest(DISCLOSURE.as_bytes())}),
    )
}
pub fn scan(root: &Path, settings: &Settings, repository_id: &str) -> Result<Value> {
    scan_mode(root, settings, repository_id, false)
}
/// Inspect every directory entry without consulting Git ignore rules.
/// Errors remain incomplete and no file content is sent outside this process.
pub fn scan_directory(root: &Path, settings: &Settings, id: &str) -> Result<Value> {
    scan_mode(root, settings, id, true)
}
fn scan_mode(
    root: &Path,
    settings: &Settings,
    repository_id: &str,
    directory: bool,
) -> Result<Value> {
    let root = io::physical_root(root)?;
    require(crate::identity(repository_id, false))?;
    definitions::combined(&settings.terms, &settings.regexes)?;
    let mut config = settings.config.clone();
    config["repository_id"] = json!(repository_id);
    let mut policy = Value::Null;
    if !directory && std::fs::symlink_metadata(root.join("repository-security.json")).is_ok() {
        policy = serde_json::from_slice(&io::read_source(&root, "repository-security.json")?.0)?;
        definitions::keys(
            &policy,
            &[
                "schema",
                "repository_id",
                "scope",
                "required_engines",
                "gitleaks_version",
            ],
            &[
                "schema",
                "repository_id",
                "scope",
                "required_engines",
                "gitleaks_version",
            ],
        )?;
        require(
            policy["repository_id"] == repository_id
                && policy["scope"] == "source-secret-disclosure/v1"
                && policy["gitleaks_version"] == "8.30.1"
                && ((policy["schema"] == "zixcel://repository-security/policy/v1"
                    && policy["required_engines"] == json!(["builtin-disclosure", "gitleaks"]))
                    || (policy["schema"] == "zixcel://repository-security/policy/v2"
                        && policy["required_engines"] == json!(["gitleaks"]))),
        )?;
    }
    let exception_index = exception_index(&settings.exceptions)?;
    let definitions_digest = hash(&json!({"terms":settings.terms,"regexes":settings.regexes}));
    let terms_digest = hash(&json!(settings.terms));
    let rules_digest = code_digest();
    let native = engine::external(config.get("gitleaks"))?;
    let native_digest = native.as_ref().map(|b| digest(b));
    let literal = if settings.terms.is_empty() {
        None
    } else {
        Some(definitions::literals(&settings.terms)?)
    };
    let regex = if settings.regexes.is_empty() {
        None
    } else {
        Some(definitions::patterns(&settings.regexes)?)
    };
    let policy_rules = definitions::policy(&settings.regexes)?;
    let files = |root: &Path| {
        if directory {
            crate::directory::files(root)
        } else {
            git_files(root)
        }
    };
    let observed = files(&root)?;
    let mut stage = Staging::new()?;
    let mut inventory = Vec::new();
    let mut uninspected = Vec::new();
    let mut raw_hits: BTreeSet<(String, u64, String, Option<String>)> = BTreeSet::new();
    let mut total = 0usize;
    let mut budget = Budget {
        bytes: MAX_TOTAL,
        entries: MAX_FILES,
    };
    let mut file_hashes = BTreeMap::new();
    if directory {
        for (index, name) in observed
            .names
            .iter()
            .chain(&observed.directories)
            .enumerate()
        {
            stage.name(name, literal.is_some())?;
            total = total.checked_add(name.len()).ok_or("name byte bound")?;
            require(total <= MAX_TOTAL)?;
            let relative = format!("names/{index}.txt");
            io::private_bytes(&stage.raw.path().join(&relative), name.as_bytes())?;
            stage.locations.insert(relative, name.clone());
        }
    }
    for name in &observed.names {
        stage.name(name, literal.is_some())?;
        let (data, mode) = match io::read_source(&root, name) {
            Ok(v) => v,
            Err(_) => {
                uninspected.push(json!({"path":name,"reason":"unsafe-or-unsupported-file"}));
                continue;
            }
        };
        total = total.checked_add(data.len()).ok_or("byte bound")?;
        require(total <= MAX_TOTAL)?;
        let sha = digest(&data);
        file_hashes.insert(name.clone(), sha.clone());
        inventory.push(json!({"path":name,"sha256":sha,"mode":mode}));
        if observed.ignored.contains(name) {
            raw_hits.insert((name.clone(), 0, "tracked-excluded-data".into(), None));
        }
        for (doc, text) in documents(name, &data, 0, &mut budget) {
            stage.name(&doc, literal.is_some())?;
            let Some(text) = text else {
                uninspected.push(json!({"path":doc,"reason":"uninspected-format"}));
                continue;
            };
            if literal.is_some() {
                stage.normalized(&doc, &text, false)?;
            }
            if doc != *name {
                let basename = Path::new(doc.rsplit('!').next().unwrap())
                    .file_name()
                    .ok_or("invalid member basename")?
                    .to_str()
                    .ok_or("invalid basename")?;
                let relative = format!("archives/{}/{basename}", stage.locations.len());
                io::private_bytes(&stage.raw.path().join(&relative), text.as_bytes())?;
                stage.locations.insert(relative, doc);
            }
        }
        if !archive_name(name) {
            let relative = format!("files/{name}");
            io::private_bytes(&stage.raw.path().join(&relative), &data)?;
            stage.locations.insert(relative, name.clone());
        }
    }
    let source_digest = if directory {
        hash(&json!({"files":inventory,"directories":observed.directories}))
    } else {
        hash(&json!(inventory))
    };
    let mut engine_state = json!({"status":"not-configured"});
    if let Some(e) = config.get("gitleaks") {
        let mut passes = vec![
            Pass {
                name: "default",
                config: b"[extend]\nuseDefault = true\n".to_vec(),
                target: stage.raw.path().into(),
            },
            Pass {
                name: "policy",
                config: policy_rules.clone(),
                target: stage.raw.path().into(),
            },
        ];
        if let Some(bytes) = &native {
            passes.push(Pass {
                name: "additional",
                config: bytes.clone(),
                target: stage.raw.path().into(),
            });
        }
        if let Some(bytes) = &literal {
            passes.push(Pass {
                name: "literal",
                config: bytes.clone(),
                target: stage.normalized.path().into(),
            });
        }
        let hits = engine::run(e, passes)?;
        let relative = |file: &str, target: &Path| -> Result<String> {
            let path = Path::new(file);
            Ok(if path.is_absolute() {
                path.strip_prefix(target)?
                    .to_str()
                    .ok_or("invalid location")?
                    .to_owned()
            } else {
                file.to_owned()
            })
        };
        let complete_keys = hits
            .iter()
            .filter(|h| h.pass == "default" && h.rule == "private-key")
            .map(|h| Ok((relative(&h.file, stage.raw.path())?, h.line)))
            .collect::<Result<BTreeSet<_>>>()?;
        for hit in hits {
            let is_literal = hit.pass == "literal";
            let target = if is_literal {
                stage.normalized.path()
            } else {
                stage.raw.path()
            };
            let rel = relative(&hit.file, target)?;
            let locations = if is_literal {
                &stage.normalized_locations
            } else {
                &stage.locations
            };
            let path = locations
                .get(&rel)
                .ok_or("finding outside inventory")?
                .clone();
            let mut line = hit.line;
            let (rule, entity) = match hit.pass.as_str() {
                "literal" => {
                    let term = settings
                        .terms
                        .iter()
                        .find(|t| {
                            hit.rule == format!("zixcel-literal-{}", t["id"].as_str().unwrap())
                        })
                        .ok_or("unknown literal rule")?;
                    if stage.normalized_names.contains(&rel) {
                        line = 0;
                    }
                    (
                        if term["category"] == "word" {
                            "configured-word".into()
                        } else {
                            format!("registered-private-{}", text(&term["category"])?)
                        },
                        Some(text(&term["id"])?.to_owned()),
                    )
                }
                "policy" if hit.rule.starts_with("zixcel-regex-") => {
                    let r = settings
                        .regexes
                        .iter()
                        .find(|r| hit.rule == format!("zixcel-regex-{}", r["id"].as_str().unwrap()))
                        .ok_or("unknown regex rule")?;
                    ("configured-regex".into(), Some(text(&r["id"])?.to_owned()))
                }
                "policy" => {
                    if hit.rule == "zixcel-disclosure-private-key"
                        && complete_keys.contains(&(rel, hit.line))
                    {
                        continue;
                    }
                    (
                        hit.rule
                            .strip_prefix("zixcel-disclosure-")
                            .ok_or("unknown disclosure rule")?
                            .into(),
                        None,
                    )
                }
                "default" => (format!("gitleaks:{}", hit.rule), None),
                "additional" => (format!("gitleaks-additional:{}", hit.rule), None),
                _ => return Err("unknown engine pass".into()),
            };
            raw_hits.insert((path, line, rule, entity));
        }
        require(engine::external(Some(e))? == native)?;
        engine_state = json!({"status":"completed","sha256":e["sha256"],"default_rules":"completed","disclosure_rules":"completed","disclosure_rules_sha256":digest(DISCLOSURE.as_bytes()),"policy_rules_sha256":digest(&policy_rules),"additional_rules":if native.is_some(){"completed"}else{"not-configured"},"config_digest_sha256":native_digest,"compiled_literals":if literal.is_some(){"completed"}else{"not-configured"},"compiled_regex":if regex.is_some(){"completed"}else{"not-configured"},"compiled_literal_sha256":literal.as_ref().map(|b|digest(b)),"compiled_regex_sha256":regex.as_ref().map(|b|digest(b))});
    } else {
        uninspected.push(json!({"path":"","reason":"gitleaks-not-configured"}));
    }
    require(files(&root)? == observed)?;
    for item in &inventory {
        let (data, mode) = io::read_source(&root, text(&item["path"])?)?;
        require(digest(&data) == item["sha256"] && mode == item["mode"])?;
    }
    let mut findings = Vec::new();
    let mut open = 0;
    for (path, line, rule, entity) in raw_hits {
        let parent = path.split('!').next().unwrap();
        let fingerprint = hash(&json!([
            repository_id,
            path,
            line,
            rule,
            entity,
            file_hashes.get(parent),
            rules_digest,
            terms_digest,
            config["gitleaks"]["sha256"],
            native_digest,
            definitions_digest
        ]));
        let reviewed = rule != "tracked-excluded-data" && exception_index.contains(&fingerprint);
        if !reviewed {
            open += 1;
        }
        let mut f = json!({"path":path,"line":line,"rule":rule,"fingerprint":fingerprint,"disposition":if reviewed{"reviewed"}else{"open"}});
        if let Some(e) = entity {
            f["entity_ref"] = json!(e);
        }
        findings.push(f);
    }
    Ok(
        json!({"schema":"zixcel://repository-security/receipt/v1","repository_id":repository_id,"scope":if directory {"directory-secret-disclosure/v1"} else {"source-secret-disclosure/v1"},"status":if !uninspected.is_empty(){"incomplete"}else if open>0{"findings"}else{"passed"},"checked_at":chrono::Utc::now().to_rfc3339(),"policy_digest_sha256":hash(&policy),"source_digest_sha256":source_digest,"rules_digest_sha256":rules_digest,"configuration_digest_sha256":hash(&config),"private_dictionary_digest_sha256":terms_digest,"definitions_digest_sha256":definitions_digest,"exceptions_digest_sha256":hash(&json!(settings.exceptions)),"engines":{"gitleaks":engine_state,"dependency-vulnerabilities":"not-run","sast":"not-run"},"inventory":inventory,"findings":findings,"uninspected":uninspected,"deleted_tracked_files":observed.deleted,"deleted_file_history_inspected":false,"open_findings":open,"reviewed_findings":findings.len()-open}),
    )
}
