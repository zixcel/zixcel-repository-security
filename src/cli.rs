use crate::{Result, config, definitions::text, digest, io, maintenance, require, scanner};
use base64::Engine;
use clap::{Args, Parser, Subcommand};
use serde_json::json;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
#[derive(Parser)]
#[command(
    version,
    about = "Private, bounded source inspection using pinned Gitleaks"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand)]
enum Commands {
    Scan {
        #[arg(long)]
        root: PathBuf,
        #[command(flatten)]
        options: Options,
    },
    /// Inspect all mounted directory files, including ignored and untracked data.
    ScanDirectory {
        #[arg(long)]
        root: PathBuf,
        #[command(flatten)]
        options: Options,
    },
    ScanInventory {
        #[arg(long)]
        inventory: PathBuf,
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long,default_value_t=4,value_parser=clap::value_parser!(u8).range(1..=4))]
        jobs: u8,
        #[command(flatten)]
        options: Options,
    },
    ScanWorkspace {
        #[arg(long)]
        workspace: PathBuf,
        #[arg(long)]
        repository_path: Vec<String>,
        #[arg(long,default_value_t=4,value_parser=clap::value_parser!(u8).range(1..=4))]
        jobs: u8,
        #[command(flatten)]
        options: Options,
    },
    PrepareSnapshot {
        #[arg(long)]
        root: PathBuf,
        #[arg(long, default_value = "main")]
        branch: String,
        #[arg(long)]
        message: String,
        #[command(flatten)]
        options: Options,
    },
    /// Verify the public, pinned Linux x64 Gitleaks executable. Downloads require --download.
    ProvisionGitleaks {
        #[arg(long)]
        output_directory: PathBuf,
        #[arg(long,conflicts_with_all=["archive","download"])]
        executable: Option<PathBuf>,
        #[arg(long, conflicts_with = "download")]
        archive: Option<PathBuf>,
        #[arg(long)]
        download: bool,
    },
    CheckOssPolicy {
        #[arg(long)]
        root: PathBuf,
    },
}
#[derive(Args)]
struct Options {
    #[arg(long, env = "ZIXCEL_SECURITY_CONFIG")]
    config: PathBuf,
    #[arg(long, env = "ZIXCEL_SECURITY_RECEIPT")]
    output: PathBuf,
    #[arg(long, env = "ZIXCEL_SECURITY_WORDS_FILE")]
    words_file: Option<PathBuf>,
    #[arg(long, env = "ZIXCEL_SECURITY_DEFINITIONS_FILE")]
    definitions_file: Option<PathBuf>,
    #[arg(long, env = "ZIXCEL_SECURITY_GITLEAKS_CONFIG")]
    gitleaks_config: Option<PathBuf>,
}
#[derive(serde::Deserialize)]
struct Row {
    name: String,
    relative_path: String,
}
fn inventory(file: &Path, workspace: &Path) -> Result<Vec<(PathBuf, String)>> {
    let bytes = io::read(file, crate::MAX_FILE)?;
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes);
    csv::Reader::from_reader(bytes)
        .deserialize::<Row>()
        .map(|row| {
            let row = row?;
            let p = Path::new(&row.relative_path);
            require(
                !p.is_absolute()
                    && p.components()
                        .all(|c| matches!(c, std::path::Component::Normal(_))),
            )?;
            Ok((workspace.join(p), row.name))
        })
        .collect()
}
fn workspace_roots(workspace: &Path, selected: &[String]) -> Result<Vec<(PathBuf, String)>> {
    let workspace = io::physical_root(workspace)?;
    let mut roots = Vec::new();
    for org in std::fs::read_dir(workspace.join("organizations"))? {
        let org = org?;
        if !org.file_type()?.is_dir() {
            continue;
        }
        for repo in std::fs::read_dir(org.path())? {
            let repo = repo?;
            if !repo.file_type()?.is_dir() || !repo.path().join(".git").exists() {
                continue;
            }
            let root = io::physical_root(&repo.path())?;
            let name = if root.join("repository-security.json").exists() {
                text(&io::load(&root.join("repository-security.json"))?["repository_id"])?
                    .to_owned()
            } else {
                repo.file_name().into_string().map_err(|_| "nonUTF8 name")?
            };
            roots.push((root, name));
        }
    }
    roots.sort();
    let paths = roots
        .iter()
        .map(|(p, _)| {
            p.strip_prefix(&workspace)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    require(selected.iter().all(|s| paths.contains(s)))?;
    if !selected.is_empty() {
        roots.retain(|(p, _)| {
            selected.contains(
                &p.strip_prefix(&workspace)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned(),
            )
        });
    }
    Ok(roots)
}
fn inspect(
    options: &Options,
    roots: Vec<(PathBuf, String)>,
    jobs: usize,
    many: bool,
    fresh: bool,
    extra_inputs: &[PathBuf],
    snapshot: Option<(&str, &str)>,
) -> Result<i32> {
    let settings = config::load(
        &options.config,
        options.words_file.as_deref(),
        options.definitions_file.as_deref(),
        options.gitleaks_config.as_deref(),
        fresh,
    )?;
    require(!roots.is_empty())?;
    let output = io::absolute(&options.output)?;
    let mut paths = BTreeSet::new();
    for (root, name) in &roots {
        require(
            crate::identity(name, false) && root.is_absolute() && paths.insert(io::absolute(root)?),
        )?;
        require(!output.starts_with(io::absolute(root)?))?;
    }
    for input in settings.inputs.iter().chain(extra_inputs) {
        require(output != io::absolute(input)? && !io::same_file(&output, input))?;
    }
    let results = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        let settings = &settings;
        let roots = &roots;
        for offset in 0..jobs.min(roots.len()) {
            handles.push(scope.spawn(move || {
            (offset..roots.len()).step_by(jobs).map(|i| {
                let (root,name)=&roots[i];let result=scanner::scan(root,settings,name).unwrap_or_else(|_|json!({"repository_id":name,"status":"incomplete","error":"InspectionError"}));(i,result)
            }).collect::<Vec<_>>()
        }));
        }
        let mut ordered = Vec::new();
        for handle in handles {
            ordered.extend(handle.join().map_err(|_| "inspection worker failed")?);
        }
        ordered.sort_by_key(|(i, _)| *i);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
            ordered.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
        )
    })?;
    if let Some((branch, message)) = snapshot {
        require(results[0]["status"] == "passed")?;
        require(
            !branch.is_empty()
                && !branch.starts_with(['/', '-'])
                && !["..", "@{", "//", "\\", " ", "~", "^", ":", "?", "*", "["]
                    .iter()
                    .any(|s| branch.contains(s))
                && !branch.ends_with(['/', '.'])
                && !branch.ends_with(".lock")
                && !branch.chars().any(char::is_control),
        )?;
        require(!message.trim().is_empty() && message.len() <= 512)?;
        let mut files = Vec::new();
        let mut total = 0;
        for item in results[0]["inventory"]
            .as_array()
            .ok_or("expected inventory")?
        {
            let (data, mode) = io::read_source(&roots[0].0, text(&item["path"])?)?;
            require(
                digest(&data) == item["sha256"]
                    && mode == item["mode"]
                    && data.len() <= 1024 * 1024,
            )?;
            total += data.len();
            require(total <= 8 * 1024 * 1024 && files.len() < 4096)?;
            files.push(json!({"path":item["path"],"mode":mode,"content_base64":base64::engine::general_purpose::STANDARD.encode(data)}));
        }
        io::private_json(
            &output,
            &json!({"schema":"zixcel://github/source-snapshot-artifact/v1","branch":branch,"message":message,"files":files}),
        )?;
        println!(
            "{}",
            json!({"status":"prepared","artifact_digest_sha256":digest(&io::read(&output,crate::MAX_FILE)?),"source_digest_sha256":results[0]["source_digest_sha256"]})
        );
        return Ok(0);
    }
    io::private_json(
        &output,
        &if many {
            json!(results)
        } else {
            results[0].clone()
        },
    )?;
    let count = |status: &str| results.iter().filter(|r| r["status"] == status).count();
    println!(
        "{}",
        json!({"repositories":results.len(),"passed":count("passed"),"findings":count("findings"),"incomplete":count("incomplete")})
    );
    Ok(if count("passed") == results.len() {
        0
    } else {
        1
    })
}
pub fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Commands::Scan { root, options } => {
            let id = text(&io::load(&options.config)?["repository_id"])?.to_owned();
            inspect(&options, vec![(root, id)], 1, false, false, &[], None)
        }
        Commands::ScanDirectory { root, options } => crate::directory::inspect(
            &root,
            &options.config,
            &options.output,
            options.words_file.as_deref(),
            options.definitions_file.as_deref(),
            options.gitleaks_config.as_deref(),
        ),
        Commands::PrepareSnapshot {
            root,
            branch,
            message,
            options,
        } => {
            let id = text(&io::load(&options.config)?["repository_id"])?.to_owned();
            inspect(
                &options,
                vec![(root, id)],
                1,
                false,
                false,
                &[],
                Some((&branch, &message)),
            )
        }
        Commands::ScanInventory {
            inventory: file,
            workspace,
            jobs,
            options,
        } => inspect(
            &options,
            inventory(&file, &workspace)?,
            jobs as usize,
            true,
            false,
            &[file],
            None,
        ),
        Commands::ScanWorkspace {
            workspace,
            repository_path,
            jobs,
            options,
        } => inspect(
            &options,
            workspace_roots(&workspace, &repository_path)?,
            jobs as usize,
            true,
            true,
            &[],
            None,
        ),
        Commands::ProvisionGitleaks {
            output_directory,
            executable,
            archive,
            download,
        } => {
            maintenance::provision(
                &output_directory,
                executable.as_deref(),
                archive.as_deref(),
                download,
            )?;
            println!("{}", json!({"status":"provisioned","version":"8.30.1"}));
            Ok(0)
        }
        Commands::CheckOssPolicy { root } => {
            maintenance::oss(&root)?;
            println!("Repository community, license, and artifact policy checks passed.");
            Ok(0)
        }
    }
}
pub fn main() -> i32 {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(_) => {
            println!(
                "{}",
                json!({"status":"error","message":"invalid local configuration or preparation precondition"})
            );
            2
        }
    }
}
