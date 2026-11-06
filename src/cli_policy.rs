//! Mandatory dispatcher gate. A local installation HMAC is not independent
//! human identity, an OS sandbox, or authority to publish production releases.

use anyhow::{bail, Context, Result};
use crate::{CatalogCommands, Commands, LabTool};
use crate::policy_boundary_v23::{self as policy, ExpectedIntent, Permission};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const MAX_SCOPE_BYTES: u64 = 128 * 1024 * 1024;

#[cfg(test)]
mod regression_tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn repair_draft_default_output_does_not_mutate() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("fixed.py");
        let ledger = root.path().join("ledger.sqlite");
        fs::write(&source, b"value=42\n").unwrap();
        let args = vec!["--approval-request".to_owned(), "repair".to_owned(), source.to_str().unwrap().to_owned(),
            "--ledger".to_owned(), ledger.to_str().unwrap().to_owned()];
        let cli = crate::Cli::try_parse_from(std::iter::once("rph".to_owned()).chain(args.clone())).unwrap();
        let canonical = canonical_arguments(args.into_iter().map(OsString::from).collect()).unwrap();
        let dispatch = pre_dispatch(&cli.command, &canonical, None, true).unwrap();
        assert!(matches!(dispatch, Dispatch::Request(ref report) if report["status"] == "LOCAL_POLICY_APPROVAL_REQUEST_NO_MUTATION"));
        assert_eq!(fs::read(&source).unwrap(), b"value=42\n");
        assert!(!source.with_extension("healed.py").exists());
        assert!(!ledger.exists());
    }

    #[test]
    fn fixed_fixture_readonly_modes_reject_mutation_and_untyped_options() {
        let cases: Vec<(LabTool, Vec<&str>, bool)> = vec![
            (LabTool::SignedReleasePolicy, vec!["--policy", "policy.json", "--public-key", "key.pem", "--manifest", "manifest.json", "--signature", "manifest.sig", "--artifact", "fixed.bin"], cfg!(windows)),
            (LabTool::SignedReleasePolicy, vec!["--policy=p", "--public-key=k", "--manifest=m", "--signature=s", "--artifact=a", "--openssl=C:/operator/openssl.exe"], cfg!(windows)),
            (LabTool::SignedReleasePolicy, vec!["--policy=p", "--public-key=k", "--manifest=m", "--signature=s"], false),
            (LabTool::SignedReleasePolicy, vec!["--policy=p", "--public-key=k", "--manifest=m", "--signature=s", "--artifact=a", "--record-ledger=ledger.sqlite"], false),
            (LabTool::SignedReleasePolicy, vec!["--policy=p", "--public-key=k", "--manifest=m", "--signature=s", "--artifact=a", "--artifact=b"], false),
            (LabTool::EcosystemRuntime, vec![], true),
            (LabTool::EcosystemRuntime, vec!["--mode=capabilities"], true),
            (LabTool::EcosystemRuntime, vec!["--mode=web", "--target=private-bundle"], cfg!(windows)),
            (LabTool::EcosystemRuntime, vec!["--mode=orm", "--target=private-bundle"], cfg!(windows)),
            (LabTool::EcosystemRuntime, vec!["--mode=numpy", "--target=private-bundle"], cfg!(windows)),
            (LabTool::EcosystemRuntime, vec!["--mode=pandas", "--target=private-bundle"], cfg!(windows)),
            (LabTool::EcosystemRuntime, vec!["--mode=orm"], false),
            (LabTool::EcosystemRuntime, vec!["--target=private-bundle"], false),
            (LabTool::EcosystemRuntime, vec!["--mode=web", "--target=private-bundle", "--json=output.json"], false),
            (LabTool::EcosystemRuntime, vec!["--mode=install", "--target=private-bundle"], false),
            (LabTool::NativeSerialization, vec!["--mode=serialization", "--target=private-bundle"], cfg!(windows)),
            (LabTool::NativeSerialization, vec!["--mode=native", "--target=private-bundle"], cfg!(windows)),
            (LabTool::NativeSerialization, vec!["--mode=native"], false),
            (LabTool::NativeSerialization, vec!["--mode=native", "--target=private-bundle", "--target=other"], false),
            (LabTool::NativeSerialization, vec!["--mode=native", "--target=private-bundle", "--install"], false),
            (LabTool::TypedFlow, vec!["--mode=capabilities"], true),
            (LabTool::TypedFlow, vec!["--mode=native", "--target=private-bundle"], false),
            (LabTool::KnowledgeScale, vec!["--mode=million-benchmark", "--db=C:/private/corpus.sqlite", "--manifest=C:/private/corpus.json", "--sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--iterations=100"], cfg!(windows)),
            (LabTool::KnowledgeScale, vec!["--mode=million-benchmark", "--db=C:/private/corpus.sqlite", "--manifest=C:/private/corpus.json", "--sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--iterations=0"], false),
            (LabTool::KnowledgeScale, vec!["--mode=million-benchmark", "--db=C:/private/corpus.sqlite", "--manifest=C:/private/corpus.json", "--sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--iterations=1001"], false),
            (LabTool::KnowledgeScale, vec!["--mode=syntax-migrate", "--db=C:/private/corpus.sqlite", "--manifest=C:/private/corpus.json", "--sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--iterations=100"], false),
            (LabTool::KnowledgeScale, vec!["--mode=million-benchmark", "--db=relative.sqlite", "--manifest=C:/private/corpus.json", "--sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--iterations=100"], false),
            (LabTool::KnowledgeScale, vec!["--mode=million-benchmark", "--db=\\\\server/share/corpus.sqlite", "--manifest=C:/private/corpus.json", "--sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--iterations=100"], false),
            (LabTool::KnowledgeScale, vec!["--mode=million-benchmark", "--db=C:/private/corpus.sqlite:stream", "--manifest=C:/private/corpus.json", "--sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--iterations=100"], false),
            (LabTool::KnowledgeScale, vec!["--mode=million-benchmark", "--db=C:/private/corpus.sqlite", "--manifest=C:/private/corpus.json", "--sha256=not-a-pin", "--iterations=100"], false),
            (LabTool::KnowledgeScale, vec!["--mode=million-benchmark", "--db=C:/private/corpus.sqlite", "--db=C:/other.sqlite", "--manifest=C:/private/corpus.json", "--sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--iterations=100"], false),
            (LabTool::KnowledgeScale, vec!["--mode=million-benchmark", "--db=C:/private/corpus.sqlite", "--manifest=C:/private/corpus.json", "--sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "--iterations=100", "--output=C:/mutated"], false),
            (LabTool::AdaptiveJobs, vec!["--mode=schedule", "--input=jobs.json", "--workers=2", "--memory-mb=64"], true),
            (LabTool::AdaptiveJobs, vec!["--mode=variants", "--input=jobs.json"], true),
            (LabTool::AdaptiveJobs, vec!["--mode=correlation", "--input=jobs.json"], true),
            (LabTool::AdaptiveJobs, vec!["--mode=schedule"], false),
            (LabTool::AdaptiveJobs, vec!["--mode=schedule", "--input=jobs.json", "--workers=0"], false),
            (LabTool::AdaptiveJobs, vec!["--mode=schedule", "--input=jobs.json", "--python=arbitrary.exe"], false),
            (LabTool::AdaptiveJobs, vec!["--mode=live", "--input=jobs.json", "--python=arbitrary.exe"], false),
            (LabTool::AdaptiveJobs, vec!["--mode=live", "--input=jobs.json", "--python=fixed-operator-runtime.exe", "--workers=8"], true),
            (LabTool::AdaptiveJobs, vec!["--mode=live", "--input=jobs.json", "--python=fixed-operator-runtime.exe", "--workers=9"], false),
            (LabTool::AdaptiveJobs, vec!["--mode=live", "--input=jobs.json"], false),
            (LabTool::ReliabilityBench, vec!["--mode=trusted-repeat", "--python=fixed-operator-runtime.exe"], true),
            (LabTool::ReliabilityBench, vec!["--mode=latency-measure", "--python=fixed-operator-runtime.exe", "--runs=10", "--fixture-mode=normal", "--latency-profile=baseline"], true),
            (LabTool::ReliabilityBench, vec!["--mode=trusted-repeat", "--python=second-runtime.exe"], false),
            (LabTool::ReliabilityBench, vec!["--mode=trusted-repeat", "--python=fixed-operator-runtime.exe", "--runs=11"], false),
            (LabTool::ReliabilityBench, vec!["--mode=trusted-repeat", "--python=fixed-operator-runtime.exe", "--fixture-mode=always-fail"], false),
            (LabTool::ReliabilityBench, vec!["--mode=latency-measure", "--python=fixed-operator-runtime.exe", "--latency-profile=p95-regression"], false),
            (LabTool::ReliabilityBench, vec!["--mode=repair-pipeline", "--python=python", "--binary=arbitrary.exe", "--ruff=ruff"], false),
        ];
        for (tool, arguments, expected) in cases {
            let arguments: Vec<String> = arguments.into_iter().map(str::to_owned).collect();
            assert_eq!(readonly_lab(tool, &arguments, "fixed-operator-runtime.exe"), expected, "tool={tool:?} args={arguments:?}");
        }
    }

}

pub(crate) struct ApprovalLease {
    #[cfg(windows)]
    _key: crate::windows_policy::CheckedFile,
}

pub(crate) enum Dispatch {
    Request(Value),
    Execute(Option<ApprovalLease>),
}

pub(crate) fn canonical_arguments(args: Vec<OsString>) -> Result<Vec<String>> {
    let args: Vec<String> = args.into_iter().map(|v| v.into_string()
        .map_err(|_| anyhow::anyhow!("policy_unicode_arguments_required"))).collect::<Result<_>>()?;
    let mut result = Vec::new();
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--" { result.extend_from_slice(&args[index..]); break; }
        if args[index] == "--approval-token" {
            index += 2;
            if index > args.len() { bail!("policy_token_argument_missing"); }
            continue;
        }
        if args[index].starts_with("--approval-token=") || args[index] == "--approval-request" {
            index += 1;
            continue;
        }
        result.push(args[index].clone());
        index += 1;
    }
    Ok(result)
}

fn digest(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }

fn absolute(path: &Path) -> Result<PathBuf> {
    if path.components().any(|p| matches!(p, std::path::Component::ParentDir)) {
        bail!("policy_parent_traversal_not_accepted");
    }
    Ok(std::path::absolute(path)?)
}

fn file_state(role: &str, path: &Path) -> Result<Value> {
    let path = absolute(path)?;
    let name = path.to_str().context("policy_path_unicode_required")?;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(json!({"role":role,"path":name,"state":"ABSENT"}));
        }
        Err(_) => bail!("policy_target_metadata_unavailable"),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_SCOPE_BYTES {
        bail!("policy_target_not_bounded_plain_file");
    }
    #[cfg(windows)]
    let data = crate::windows_policy::open_readonly(&path, false, MAX_SCOPE_BYTES)?.read_bounded(MAX_SCOPE_BYTES)?;
    #[cfg(not(windows))]
    let data = fs::read(&path)?;
    if data.len() as u64 > MAX_SCOPE_BYTES { bail!("policy_target_read_budget"); }
    Ok(json!({"role":role,"path":name,"state":"EXISTS","sha256":digest(&data),"bytes":data.len()}))
}

fn database_states(role: &str, path: &Path, entries: &mut Vec<Value>) -> Result<()> {
    entries.push(file_state(role, path)?);
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        entries.push(file_state(&format!("{role}{suffix}"), Path::new(&name))?);
    }
    Ok(())
}

pub(crate) fn lab_options(args: &[String], valued: &[&str], switches: &[&str]) -> Result<BTreeMap<String, String>> {
    let mut parsed = BTreeMap::new();
    let mut index = 0;
    while index < args.len() {
        let (name, inline) = args[index].split_once('=').map_or((args[index].as_str(), None), |(k,v)| (k,Some(v)));
        let value = if valued.contains(&name) {
            if let Some(value) = inline { value.to_string() } else {
                index += 1;
                args.get(index).context("policy_adapter_option_value_missing")?.clone()
            }
        } else if switches.contains(&name) && inline.is_none() { "true".to_string() }
        else { bail!("policy_adapter_option_not_typed"); };
        if value.is_empty() || value.starts_with("--") || parsed.insert(name.to_string(), value).is_some() {
            bail!("policy_adapter_option_ambiguous");
        }
        index += 1;
    }
    Ok(parsed)
}

fn readonly_lab(tool: LabTool, args: &[String], selected_python: &str) -> bool {
    match tool {
        LabTool::AsyncTrace => args.len() == 1 && !args[0].starts_with('-'),
        LabTool::Dag => lab_options(args, &["--manifest"], &[]).is_ok_and(|o| o.contains_key("--manifest")),
        LabTool::RoleRouter => lab_options(args, &["--roles", "--tasks"], &[]).is_ok_and(|o| o.len() == 2),
        LabTool::AbiTags => lab_options(args, &["--wheel"], &[]).is_ok_and(|o| o.len() == 1),
        LabTool::Concurrency => lab_options(args, &["--method"], &["--qualify-default", "--allow-spawn-fallback"]).is_ok(),
        LabTool::KnowledgeScale => cfg!(windows) && lab_options(args,
            &["--mode", "--db", "--manifest", "--sha256", "--iterations"], &[]).is_ok_and(|o| {
                let local_absolute = |v: &String| {
                    let b = v.as_bytes();
                    b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':'
                        && (b[2] == b'\\' || b[2] == b'/')
                        && !b[3..].contains(&b':') && !b.contains(&0)
                        && !Path::new(v).components().any(|p| matches!(p, std::path::Component::ParentDir))
                };
                o.len() == 5 && o.get("--mode").is_some_and(|v| v == "million-benchmark")
                    && o.get("--db").is_some_and(local_absolute)
                    && o.get("--manifest").is_some_and(local_absolute)
                    && o.get("--sha256").is_some_and(|v| v.len() == 64
                        && v.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
                    && o.get("--iterations").is_some_and(|v| v.parse::<u32>()
                        .is_ok_and(|n| (5..=1000).contains(&n)))
            }),
        LabTool::ResourceMeter => {
            let Some(mode) = args.first() else { return false; };
            let options = if mode == "worker" { &["--iterations", "--memory-bytes", "--timeout-s"][..] }
                else if mode == "synthetic-queue" { &["--workers", "--jobs", "--hold-ms"][..] }
                else { return false; };
            lab_options(&args[1..], options, &[]).is_ok_and(|o| o.values().all(|v| v.parse::<f64>().is_ok_and(f64::is_finite)))
        }
        LabTool::EncryptedCatalog => lab_options(args, &["--mode"], &[])
            .is_ok_and(|o| matches!(o.get("--mode").map(String::as_str), None | Some("capabilities" | "trusted-selftest"))),
        // These adapters accept data paths only. Fixed Windows wheel manifests
        // are enforced inside the reviewed adapter before any package import;
        // target runtimes and signed verification require that Windows profile.
        // no install, caller source, output path, or ledger mode is classified RO.
        LabTool::EcosystemRuntime => lab_options(args, &["--mode", "--target"], &[])
            .is_ok_and(|o| match o.get("--mode").map(String::as_str) {
                None | Some("capabilities") => !o.contains_key("--target"),
                Some("web" | "orm" | "numpy" | "pandas") => cfg!(windows) && o.contains_key("--target"),
                _ => false,
            }),
        LabTool::NativeSerialization => lab_options(args, &["--mode", "--target"], &[])
            .is_ok_and(|o| match o.get("--mode").map(String::as_str) {
                None | Some("capabilities") => !o.contains_key("--target"),
                Some("serialization" | "native") => cfg!(windows) && o.contains_key("--target"),
                _ => false,
            }),
        LabTool::TypedFlow => lab_options(args, &["--mode"], &[])
            .is_ok_and(|o| matches!(o.get("--mode").map(String::as_str), None | Some("capabilities"))),
        LabTool::SignedReleasePolicy => cfg!(windows) && lab_options(args, &["--policy", "--public-key", "--manifest", "--signature", "--artifact", "--openssl"], &[])
            .is_ok_and(|o| ["--policy", "--public-key", "--manifest", "--signature", "--artifact"]
                .iter().all(|name| o.contains_key(*name))),
        LabTool::AdaptiveJobs => lab_options(args, &["--mode", "--input", "--workers", "--memory-mb", "--python"], &[])
            .is_ok_and(|o| {
                let live = o.get("--mode").map(String::as_str) == Some("live");
                o.contains_key("--input")
                    && (if live { o.get("--python").map(String::as_str) == Some(selected_python) }
                        else { !o.contains_key("--python")
                            && matches!(o.get("--mode").map(String::as_str), Some("schedule" | "variants" | "correlation")) })
                    && o.get("--workers").map_or(true, |v| v.parse::<u32>()
                        .is_ok_and(|n| n > 0 && n <= if live { 8 } else { 32 }))
                    && o.get("--memory-mb").map_or(true, |v| v.parse::<u32>()
                        .is_ok_and(|n| n > 0 && n <= 65_536))
            }),
        // Preserve the existing operator-selected outer interpreter contract:
        // fixed child code must use exactly that interpreter, no second EXE.
        LabTool::ReliabilityBench => lab_options(args, &["--mode", "--python", "--runs", "--fixture-mode", "--latency-profile"], &[])
            .is_ok_and(|o| o.get("--python").map(String::as_str) == Some(selected_python)
                && matches!(o.get("--mode").map(String::as_str), Some("trusted-repeat" | "latency-measure"))
                && o.get("--runs").map_or(true, |v| v == "10")
                && matches!(o.get("--fixture-mode").map(String::as_str), None | Some("normal"))
                && matches!(o.get("--latency-profile").map(String::as_str), None | Some("baseline"))),
        LabTool::AstCstTyping => lab_options(args, &["--mode", "--project", "--target-python", "--checker-python",
            "--typechecker-tools", "--libcst-tools", "--typechecker-tools39"], &[])
            .is_ok_and(|o| matches!(o.get("--mode").map(String::as_str), None | Some("capabilities" | "inspect"))),
        LabTool::TypecheckIntegration => lab_options(args, &["--mode"], &[])
            .is_ok_and(|o| matches!(o.get("--mode").map(String::as_str), None | Some("capabilities"))),
        LabTool::RealDocsBenchmark => lab_options(args, &[], &["--benchmark"]).is_ok(),
        LabTool::CodeModelRouter => lab_options(args, &["--mode", "--source-file", "--oracle-file", "--signature", "--key-file"], &[])
            .is_ok_and(|o| matches!(o.get("--mode").map(String::as_str), None | Some("capabilities" | "selftest" | "route"))),
        LabTool::SemanticRetrieval => lab_options(args, &["--mode", "--labels", "--auditor-key", "--label-signature", "--minimum-recall", "--minimum-mrr", "--top-k"], &[])
            .is_ok_and(|o| matches!(o.get("--mode").map(String::as_str), None | Some("capabilities" | "train" | "evaluated"))),
        LabTool::RealModelRouter => lab_options(args, &["--mode", "--labels", "--auditor-key", "--label-signature", "--query", "--max-p95-us", "--max-p95-cpu-us", "--task-domain"], &[])
            .is_ok_and(|o| matches!(o.get("--mode").map(String::as_str), None | Some("capabilities" | "evaluate"))),
        LabTool::GitReview => args == ["--status"],
        LabTool::PrereleaseMatrix => lab_options(args, &["--mode", "--expected", "--windows-root"], &[])
            .is_ok_and(|o| matches!(o.get("--mode").map(String::as_str), None | Some("identity" | "phase" | "grammar" | "suite" | "matrix"))),
        LabTool::RealQueue => lab_options(args, &["--mode", "--backend-profile"], &[])
            .is_ok_and(|o| matches!(o.get("--mode").map(String::as_str), Some("capabilities" | "availability"))),
        LabTool::SecurityControls => lab_options(args, &["--mode", "--root"], &[])
            .is_ok_and(|o| matches!(o.get("--mode").map(String::as_str), None | Some("audit" | "scan"))),
        LabTool::PowershellReal => lab_options(args, &["--mode", "--fixture"], &["--verify-archive"])
            .is_ok_and(|o| matches!(o.get("--mode").map(String::as_str),
                None | Some("capabilities" | "version" | "verify" | "literal" | "windows" | "negative"))),
        LabTool::Sources => match args.first().map(String::as_str) {
            Some("lookup") => lab_options(&args[1..], &["--database", "--python-version", "--package", "--package-version", "--platform"], &[])
                .is_ok_and(|o| o.len() == 5),
            Some("cite") => lab_options(&args[1..], &["--database", "--section-id", "--max-words", "--max-bytes"], &[])
                .is_ok_and(|o| o.len() == 4),
            _ => false,
        },
        LabTool::PackagePolicy => lab_options(args, &["--mode", "--path", "--kind", "--python-version", "--platform",
            "--prefix", "--base-prefix", "--stdlib-dir"], &[]).is_ok(),
        LabTool::Provenance => lab_options(args, &["--mode", "--source", "--sha256"], &[]).is_ok(),
        LabTool::ExampleCompile => args.len() >= 3 && !args[..3].iter().any(|v| v.starts_with('-'))
            && lab_options(&args[3..], &["--interpreter"], &[]).is_ok(),
        _ => false,
    }
}

fn directory_state(role: &str, path: &Path) -> Result<Value> {
    let path = absolute(path)?;
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() { bail!("policy_directory_not_plain"); }
    let mut names = fs::read_dir(&path)?.map(|e| e.map(|v| v.path())).collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    if names.len() > 200 { bail!("policy_directory_entry_budget"); }
    let mut files = Vec::new();
    for name in names { files.push(file_state("directory-entry", &name)?); }
    Ok(json!({"role":role,"path":path,"files":files}))
}

fn target_scope(command: &Commands) -> Result<Vec<Value>> {
    let mut state = Vec::new();
    match command {
        Commands::Repair { file, out, ledger, .. } => {
            state.push(file_state("repair-source", file)?);
            state.push(file_state("repair-output", out.as_deref().unwrap_or(&file.with_extension("healed.py")))?);
            database_states("repair-ledger", ledger, &mut state)?;
        }
        Commands::Update { watch: true, .. } => bail!("policy_watch_requires_per_cycle_fresh_approval"),
        Commands::Update { manifest, db, .. } => {
            state.push(file_state("version-manifest", manifest)?);
            database_states("knowledge-database", db, &mut state)?;
        }
        Commands::Catalog { command } => match command {
            CatalogCommands::Add { text_file, db, .. } => {
                state.push(file_state("source-document", text_file)?);
                database_states("catalog", db, &mut state)?;
            }
            CatalogCommands::ImportInstalled { db, .. } | CatalogCommands::Maintain { db, .. } => database_states("catalog", db, &mut state)?,
            CatalogCommands::Backup { db, out } => { database_states("catalog", db, &mut state)?; database_states("backup-output", out, &mut state)?; }
            CatalogCommands::Restore { backup, out, .. } => { database_states("backup-input", backup, &mut state)?; database_states("restore-output", out, &mut state)?; }
            _ => bail!("policy_readonly_command_has_no_mutation_scope"),
        },
        Commands::Lab { tool: LabTool::BackupDrill, arguments, .. } => {
            let options = lab_options(arguments, &["--database", "--archive-dir", "--id", "--cycles", "--interval-ms", "--action"], &[])?;
            let database = options.get("--database").context("policy_database_required")?;
            let archives = options.get("--archive-dir").context("policy_archive_directory_required")?;
            database_states("backup-source", Path::new(database), &mut state)?;
            state.push(directory_state("backup-archives", Path::new(archives))?);
        }
        Commands::Lab { tool: LabTool::ReleaseCanary, arguments, .. } => {
            let options = lab_options(arguments, &["--active", "--candidate", "--approval", "--key-file", "--python"], &["--inject-health-failure"])?;
            for option in ["--active", "--candidate", "--approval", "--key-file"] {
                state.push(file_state(option, Path::new(options.get(option).context("policy_canary_path_required")?))?);
            }
        }
        Commands::Lab { tool: LabTool::Sources, arguments, .. } if arguments.first().is_some_and(|v| v == "ingest") => {
            let options = lab_options(&arguments[1..], &["--database", "--policy", "--trust", "--manifest"], &[])?;
            for option in ["--policy", "--trust", "--manifest"] {
                state.push(file_state(option, Path::new(options.get(option).context("policy_source_input_missing")?))?);
            }
            database_states("sources-database", Path::new(options.get("--database").context("policy_source_database_missing")?), &mut state)?;
        }
        Commands::Lab { tool: LabTool::RealDocsBenchmark, arguments, .. } => {
            let options = lab_options(arguments, &["--json"], &["--benchmark"])?;
            state.push(file_state("benchmark-output", Path::new(options.get("--json").context("policy_benchmark_output_missing")?))?);
        }
        _ => bail!("policy_adapter_target_scope_unverified"),
    }
    Ok(state)
}

fn installation_root() -> Result<PathBuf> {
    Ok(std::env::current_exe()?.parent().context("policy_installation_missing")?.join(".rph-policy"))
}

fn path_key(path: &Path) -> Result<String> {
    // Resolve existing DOS/8.3 aliases before protecting the policy store.
    // For absent outputs, canonicalize the nearest existing ancestor only.
    let mut existing = absolute(path)?;
    let mut remainder = Vec::new();
    while !existing.exists() {
        remainder.push(existing.file_name().context("policy_path_anchor_missing")?.to_os_string());
        if !existing.pop() { bail!("policy_path_anchor_missing"); }
    }
    let mut normalized = fs::canonicalize(existing)?;
    for part in remainder.into_iter().rev() { normalized.push(part); }
    Ok(normalized.to_string_lossy().replace('\\', "/").trim_start_matches("//?/").to_ascii_lowercase())
}

fn reject_policy_targets(scope: &[Value], policy_root: &Path) -> Result<()> {
    let protected = path_key(policy_root)?;
    for row in scope {
        if let Some(path) = row.get("path").and_then(Value::as_str) {
            let candidate = path_key(Path::new(path))?;
            if candidate == protected || candidate.starts_with(&(protected.clone() + "/")) {
                bail!("policy_store_cannot_be_a_mutation_target");
            }
        }
    }
    Ok(())
}

pub(crate) fn pre_dispatch(command: &Commands, args: &[String], token: Option<&Path>, request: bool) -> Result<Dispatch> {
    let references: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut classification = policy::classify_cli(&references);
    if let Commands::Lab { tool, arguments, python, .. } = command {
        if readonly_lab(*tool, arguments, python) { classification.permission = Permission::ReadOnly; classification.risky_action = None; }
    }
    if classification.permission == Permission::DenyUnknown { bail!("policy_unknown_dispatch_refused"); }
    if classification.permission == Permission::ReadOnly {
        if token.is_some() { bail!("policy_token_not_needed_for_readonly"); }
        return if request { Ok(Dispatch::Request(json!({"status":"READ_ONLY_TYPED_COMMAND","mutation_performed":false,"classification":classification}))) }
            else { Ok(Dispatch::Execute(None)) };
    }
    let scope = match target_scope(command) {
        Ok(scope) => scope,
        Err(_) if request => return Ok(Dispatch::Request(json!({
            "status":"HOLD_NO_TYPED_MUTATION_TARGET_SCOPE","classification":classification,
            "mutation_performed":false,"approval_token_issued":false,
            "reason":"Adapter mode or target paths are not covered by the typed local-policy scope"
        }))),
        Err(_) => bail!("policy_mutation_target_scope_unverified"),
    };
    let store = installation_root()?;
    reject_policy_targets(&scope, &store)?;
    let command_hash = policy::command_sha256(&references)?;
    let artifact = file_state("running-cli-artifact", &std::env::current_exe()?)?;
    let artifact_hash = artifact["sha256"].as_str().context("policy_binary_missing")?;
    let target_hash = digest(&serde_json::to_vec(&scope)?);
    #[cfg(windows)]
    let actor = crate::windows_policy::actor_id()?;
    #[cfg(not(windows))]
    let actor = "platform-unverified".to_string();
    if request {
        return Ok(Dispatch::Request(json!({"status":"LOCAL_POLICY_APPROVAL_REQUEST_NO_MUTATION",
            "policy_id":"rust-cli-v23","actor_id":actor,"action":classification.risky_action,
            "command_sha256":command_hash,"artifact_sha256":artifact_hash,"target_sha256":target_hash,
            "targets":scope,"policy_store":store,"external_human_identity_verified":false,
            "trust":"FIXED_INSTALLATION_OWNER_PRIVATE_HMAC_ONLY","release_authorized":false,
            "mutation_performed":false})));
    }
    let token = token.context("policy_approval_token_required")?;
    #[cfg(not(windows))]
    { let _ = token; bail!("policy_native_installation_trust_not_implemented"); }
    #[cfg(windows)]
    {
        // No CLI/env override for store/key. A separately provisioned local
        // installation key is read from its held owner-private leaf HANDLE.
        let mut key = crate::windows_policy::open_readonly(&store.join("operator-key.json"), true, 1024)?;
        let raw_key = key.read_bounded(1024)?;
        let raw_token = crate::windows_policy::open_readonly(&absolute(token)?, true, 32_768)?.read_bounded(32_768)?;
        let action = classification.risky_action.as_deref().context("policy_action_missing")?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        let approved = policy::verify_intent(&raw_token, &raw_key, &ExpectedIntent {
            actor_id:&actor, action, command_sha256:&command_hash, artifact_sha256:artifact_hash,
            target_sha256:&target_hash }, now)?;
        if target_scope(command)? != scope { bail!("policy_target_changed_before_nonce"); }
        let consume_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        policy::consume_nonce(&store.join("nonce-ledger.jsonl"), &approved, consume_time)?;
        if target_scope(command)? != scope || file_state("running-cli-artifact", &std::env::current_exe()?)? != artifact {
            bail!("policy_target_or_artifact_changed_before_dispatch");
        }
        policy::recheck_intent_time(&approved,
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs())?;
        Ok(Dispatch::Execute(Some(ApprovalLease { _key:key })))
    }
}

pub(crate) struct ReadOnlyDatabase {
    pub(crate) connection: rusqlite::Connection,
    _snapshot: tempfile::NamedTempFile,
}

impl ReadOnlyDatabase {
    pub(crate) fn path(&self) -> &Path { self._snapshot.path() }
}

pub(crate) fn read_only_database(path: &Path) -> Result<ReadOnlyDatabase> {
    let path = absolute(path)?;
    #[cfg(windows)]
    let mut source = crate::windows_policy::open_readonly(&path, false, MAX_SCOPE_BYTES)?;
    for suffix in ["-wal", "-journal"] {
        let mut sidecar = path.as_os_str().to_os_string(); sidecar.push(suffix);
        if fs::metadata(&sidecar).is_ok_and(|m| m.len() > 0) {
            bail!("policy_readonly_requires_checkpointed_database");
        }
    }
    #[cfg(windows)]
    let bytes = source.read_bounded(MAX_SCOPE_BYTES)?;
    #[cfg(not(windows))]
    let bytes = { let meta=fs::symlink_metadata(&path)?; if !meta.is_file() || meta.len()>MAX_SCOPE_BYTES { bail!("policy_readonly_database_budget"); } fs::read(&path)? };
    let mut snapshot = tempfile::Builder::new().prefix("rph-readonly-").suffix(".sqlite").tempfile()?;
    snapshot.write_all(&bytes)?;
    snapshot.as_file().sync_all()?;
    // This is our own immutable temporary copy, never the caller's database.
    // Percent-encode URI metacharacters rather than interpreting caller SQL.
    let name = snapshot.path().to_str().context("policy_snapshot_unicode_required")?.replace('\\', "/");
    let encoded: String = name.bytes().map(|b| if b.is_ascii_alphanumeric() || b"/-._~:".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect();
    let uri = format!("file:{encoded}?mode=ro&immutable=1");
    let connection = rusqlite::Connection::open_with_flags(uri,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI)?;
    connection.execute_batch("PRAGMA query_only=ON")?;
    Ok(ReadOnlyDatabase { connection, _snapshot:snapshot })
}
