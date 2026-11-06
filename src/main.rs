mod dap;
mod knowledge;
mod ledger;
mod policy_boundary_v23;
mod process;
mod scan;
mod trace;
mod cli_policy;
#[cfg(windows)]
mod windows_policy;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(
    name = "rust-python-healer",
    version,
    about = "Python diagnose, veilige fix-kandidaten en versiegebonden kennis"
)]
struct Cli {
    /// Signed one-use local installation-policy token; never a caller-supplied key.
    #[arg(long, global = true, conflicts_with = "approval_request")]
    approval_token: Option<PathBuf>,
    /// Print the exact local approval context without dispatching or consuming a nonce.
    #[arg(long, global = true, conflicts_with = "approval_token")]
    approval_request: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Onderhandel DAP-initialisatie via stdin/stdout; runtime-debugging nog niet beschikbaar.
    Dap,
    /// Vergelijk vaste CPython-AST-, bytecode- en tracebackregressies met versie-baselines.
    VersionRegression {
        #[arg(long, default_value = process::DEFAULT_PYTHON)]
        python: String,
        /// Alternatief referentiemanifest; zonder deze optie wordt de ingebedde baseline gelezen.
        #[arg(long)]
        manifest: Option<PathBuf>,
    },
    /// Dwing zes vooraf vastgelegde kwaliteitsgrenzen af op getekende rapporten.
    Qualify {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        trust: PathBuf,
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long, default_value = process::DEFAULT_PYTHON)]
        python: String,
    },
    /// Voer uitsluitend ingebouwde, reproduceerbare propertytests met shrinking uit.
    Property {
        #[arg(long, default_value_t = 42)]
        seed: u32,
        #[arg(long, default_value_t = 100)]
        cases: usize,
        #[arg(long = "property", value_parser = [
            "roundtrip_nonnegative", "hex_digest_length", "mutant_double_equals_self"
        ])]
        name: String,
        #[arg(long, default_value = process::DEFAULT_PYTHON)]
        python: String,
    },
    /// Classificeer vastgelegde statische veiligheids- en codekwaliteitregels.
    Static {
        file: Option<PathBuf>,
        #[arg(long, conflicts_with = "file")]
        classify: Option<String>,
        #[arg(long, default_value = process::DEFAULT_PYTHON)]
        python: String,
    },
    /// Draai een ingebouwde, lokaal begrensde onderzoeksadapter op geselecteerde bewijsdata.
    Lab {
        #[arg(value_enum)]
        tool: LabTool,
        #[arg(long, default_value = process::DEFAULT_PYTHON)]
        python: String,
        /// Adapterparameters volgen na '--'; geen externe Python-code wordt geladen.
        #[arg(last = true)]
        arguments: Vec<String>,
    },
    /// Beschrijf Python-implementatie, free-threaded build, SOABI en GIL-status.
    Runtime {
        #[arg(long, default_value = process::DEFAULT_PYTHON)]
        python: String,
    },
    /// Diagnoseer syntax/compilatie zonder Python-broncode uit te voeren.
    Check {
        file: PathBuf,
        #[arg(long, default_value = process::DEFAULT_PYTHON)]
        python: String,
    },
    /// Analyseer een vastgelegde Python-traceback zonder de bron uit te voeren.
    Trace {
        log_file: PathBuf,
        /// Expliciet vrijgeven van paden, bronregels en exceptiondetails.
        #[arg(long)]
        show_sensitive: bool,
    },
    /// Controleer geÃƒÆ’Ã‚Â¯nstalleerde package-metadata voor de gekozen interpreter.
    Deps {
        #[arg(long = "package", required = true)]
        packages: Vec<String>,
        /// Optioneel geselecteerde dependency-extras (geen installaties).
        #[arg(long = "extra")]
        extras: Vec<String>,
        #[arg(long, default_value = process::DEFAULT_PYTHON)]
        python: String,
        /// Optionele extra map met .dist-info-fixtures of distributiemetadata.
        #[arg(long = "metadata-dir")]
        metadata_dirs: Vec<PathBuf>,
    },
    /// Controleer wheel RECORD-bestandshashes zonder modules te importeren.
    Record {
        #[arg(long = "package", required = true)]
        packages: Vec<String>,
        #[arg(long = "metadata-dir")]
        metadata_dirs: Vec<PathBuf>,
        #[arg(long, default_value = process::DEFAULT_PYTHON)]
        python: String,
    },
    /// Inventariseer projectmanifesten en lockfiles zonder setup.py uit te voeren.
    Project {
        path: PathBuf,
        #[arg(long, default_value = process::DEFAULT_PYTHON)]
        python: String,
    },
    /// Analyseer eerder gemeten herhalingen; voert geen gebruikerscode uit.
    Flaky {
        evidence: PathBuf,
        #[arg(long, default_value = process::DEFAULT_PYTHON)]
        python: String,
    },
    /// Lees functies, imports en mogelijke aanroepen via CPython AST, zonder uitvoering.
    Ast {
        file: PathBuf,
        #[arg(long, default_value = process::DEFAULT_PYTHON)]
        python: String,
    },
    /// Inventariseer lokale distributiemetadata als onbevestigde SBOM-kandidaat.
    Sbom {
        #[arg(long, default_value = process::DEFAULT_PYTHON)]
        python: String,
        #[arg(long = "metadata-dir")]
        metadata_dirs: Vec<PathBuf>,
        #[arg(long, requires = "metadata_dirs")]
        only_metadata_dir: bool,
    },
    /// Scan een complete Python-projectmap parallel, zonder code uit te voeren.
    Scan {
        path: PathBuf,
        #[arg(long, default_value = process::DEFAULT_PYTHON)]
        python: String,
        #[arg(long, default_value_t = 500)]
        limit: usize,
        #[arg(long, default_value_t = 4)]
        workers: usize,
    },
    /// Test alle CPython-versies 3.9 t/m de laatst bekende stabiele versie.
    Matrix {
        file: PathBuf,
        #[arg(long, default_value = "config/versions.json")]
        manifest: PathBuf,
        /// Extra interpreters als 3.9=/pad/naar/python3.9 (herhaalbaar).
        #[arg(long = "interpreter")]
        interpreters: Vec<String>,
        #[arg(long, default_value = process::DEFAULT_PYTHON)]
        python: String,
    },
    /// Controleer of importeer officiÃƒÆ’Ã‚Â«le Python- en PyPI-kennisupdates.
    Update {
        #[arg(long)]
        apply: bool,
        #[arg(long)]
        auto: bool,
        #[arg(long)]
        watch: bool,
        #[arg(long = "package")]
        packages: Vec<String>,
        #[arg(long, default_value = process::DEFAULT_PYTHON)]
        python: String,
        #[arg(long, default_value = "config/versions.json")]
        manifest: PathBuf,
        #[arg(long, default_value = ".rust-healer/knowledge.sqlite")]
        db: PathBuf,
    },
    /// Bouw een kandidaat met uitsluitend Ruff's veilige autofixes.
    Repair {
        file: PathBuf,
        #[arg(long, default_value = process::DEFAULT_PYTHON)]
        python: String,
        #[arg(long, default_value = "ruff")]
        ruff: String,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value = ".rust-healer/bench.sqlite")]
        ledger: PathBuf,
        /// Expliciete hertest van eerder gemeten configuraties.
        #[arg(long)]
        retest: bool,
    },
    /// Doorzoek of breid de versie-/broncatalogus uit.
    Catalog {
        #[command(subcommand)]
        command: CatalogCommands,
    },
    /// Inspecteer de bewijsregistratie van tests en varianten.
    Bench {
        #[arg(long, default_value = ".rust-healer/bench.sqlite")]
        ledger: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LabTool {
    Dag,
    Graph,
    Sources,
    Metrics,
    AsyncTrace,
    Concurrency,
    DecisionAudit,
    RoleRouter,
    AbiTags,
    ReleaseNotes,
    EvidenceSnapshot,
    ExampleCompile,
    ReleaseQuality,
    StubApi,
    ResourceMeter,
    BackupDrill,
    Vector,
    HumanApproval,
    TransitiveResolver,
    StdlibApi,
    ReliabilityBench,
    AdaptiveJobs,
    TrustedDebugger,
    RealDocsBenchmark,
    ReleaseCanary,
    DistributionProbe,
    KnowledgeExpansion,
    WatchedUpdater,
    EcosystemDiagnostics,
    SignedReleasePolicy,
    RealOrchestrator,
    DualAuditorGate,
    DapRuntime,
    PackagePolicy,
    SecurityControls,
    KnowledgeUpdates,
    PlatformConstraints,
    EncryptedCatalog,
    VulnerabilityAudit,
    TypedFlow,
    RemoteDap,
    PlatformMatrix,
    SecurityIntegrations,
    RealEcosystem,
    Provenance,
    KnowledgeScale,
    FreeThreadedNative,
    RuntimeVariants,
    TypecheckIntegration,
    PrereleaseMatrix,
    AstCstTyping,
    SemanticRetrieval,
    EcosystemRuntime,
    GitReview,
    PowershellReal,
    NativeSerialization,
    StdlibNativeComplete,
    OfficialSupplyChain,
    RealQueue,
    RealModelRouter,
    CodeModelRouter,
    OciLayout,
}

impl LabTool {
    fn script(self) -> &'static str {
        match self {
            Self::Dag => include_str!("../python/dag_scheduler.py"),
            Self::Graph => include_str!("../python/versioned_graph_db.py"),
            Self::Sources => include_str!("../python/source_policy.py"),
            Self::Metrics => include_str!("../python/experiment_metrics.py"),
            Self::AsyncTrace => include_str!("../python/async_trace_parser.py"),
            Self::Concurrency => include_str!("../python/concurrency_probe.py"),
            Self::DecisionAudit => include_str!("../python/decision_audit.py"),
            Self::RoleRouter => include_str!("../python/role_router.py"),
            Self::AbiTags => include_str!("../python/abi_tags.py"),
            Self::ReleaseNotes => include_str!("../python/release_notes.py"),
            Self::EvidenceSnapshot => include_str!("../python/evidence_snapshot.py"),
            Self::ExampleCompile => include_str!("../python/example_compile.py"),
            Self::ReleaseQuality => include_str!("../python/release_quality.py"),
            Self::StubApi => include_str!("../python/stub_api_index.py"),
            Self::ResourceMeter => include_str!("../python/resource_meter.py"),
            Self::BackupDrill => include_str!("../python/backup_drill.py"),
            Self::Vector => include_str!("../python/vector_retrieval.py"),
            Self::HumanApproval => include_str!("../python/human_approval.py"),
            Self::TransitiveResolver => include_str!("../python/transitive_resolver.py"),
            Self::StdlibApi => include_str!("../python/stdlib_api_extract.py"),
            Self::ReliabilityBench => include_str!("../python/reliability_bench.py"),
            Self::AdaptiveJobs => include_str!("../python/adaptive_jobs.py"),
            Self::TrustedDebugger => include_str!("../python/trusted_runtime_debugger_v21.py"),
            Self::RealDocsBenchmark => include_str!("../python/real_docs_benchmark_v21.py"),
            Self::ReleaseCanary => include_str!("../python/release_canary_v21.py"),
            Self::DistributionProbe => include_str!("../python/distribution_probe_v21.py"),
            Self::KnowledgeExpansion => include_str!("../python/knowledge_expansion_v21.py"),
            Self::WatchedUpdater => include_str!("../python/watched_updater_v21.py"),
            Self::EcosystemDiagnostics => include_str!("../python/ecosystem_diagnostics_v21.py"),
            Self::SignedReleasePolicy => include_str!("../python/signed_release_policy_v21.py"),
            Self::RealOrchestrator => include_str!("../python/real_orchestrator_v21.py"),
            Self::DualAuditorGate => include_str!("../python/dual_auditor_gate_v21.py"),
            Self::DapRuntime => include_str!("../python/dap_runtime_v22.py"),
            Self::PackagePolicy => include_str!("../python/package_policy_v22.py"),
            Self::SecurityControls => include_str!("../python/security_controls_v22.py"),
            Self::KnowledgeUpdates => include_str!("../python/knowledge_updates_v22.py"),
            Self::PlatformConstraints => include_str!("../python/platform_constraints_v22.py"),
            Self::EncryptedCatalog => include_str!("../python/encrypted_catalog_v22.py"),
            Self::VulnerabilityAudit => include_str!("../python/vulnerability_audit_v22.py"),
            Self::TypedFlow => include_str!("../python/typed_flow_v22.py"),
            Self::RemoteDap => include_str!("../python/remote_dap_v23.py"),
            Self::PlatformMatrix => include_str!("../python/platform_matrix_v23.py"),
            Self::SecurityIntegrations => include_str!("../python/security_integrations_v23.py"),
            Self::RealEcosystem => include_str!("../python/real_ecosystem_v23.py"),
            Self::Provenance => include_str!("../python/provenance_v23.py"),
            Self::KnowledgeScale => include_str!("../python/knowledge_scale_v23.py"),
            Self::FreeThreadedNative => include_str!("../python/freethreaded_native_v23.py"),
            Self::RuntimeVariants => include_str!("../python/runtime_variants_v23.py"),
            Self::TypecheckIntegration => include_str!("../python/typecheck_integration_v23.py"),
            Self::PrereleaseMatrix => include_str!("../python/prerelease_matrix_v23.py"),
            Self::AstCstTyping => include_str!("../python/ast_cst_typing_v23.py"),
            Self::SemanticRetrieval => include_str!("../python/semantic_retrieval_v23.py"),
            Self::EcosystemRuntime => include_str!("../python/ecosystem_runtime_v23.py"),
            Self::GitReview => include_str!("../python/git_review_v23.py"),
            Self::PowershellReal => include_str!("../python/powershell_real_v23.py"),
            Self::NativeSerialization => include_str!("../python/native_serialization_v23.py"),
            Self::StdlibNativeComplete => include_str!("../python/stdlib_native_complete_v23.py"),
            Self::OfficialSupplyChain => include_str!("../python/official_supply_chain_v23.py"),
            Self::RealQueue => include_str!("../python/real_queue_v23.py"),
            Self::RealModelRouter => include_str!("../python/real_model_router_v23.py"),
            Self::CodeModelRouter => include_str!("../python/code_model_router_v24.py"),
            Self::OciLayout => include_str!("../python/oci_layout_v25.py"),
        }
    }
}

#[derive(Subcommand)]
enum CatalogCommands {
    /// Controleer of onderhoud de SQLite/FTS5-index, inclusief external-content-integriteit.
    Maintain {
        #[arg(long, default_value = "check", value_parser = ["check", "rebuild", "optimize"])]
        action: String,
        #[arg(long, default_value = ".rust-healer/knowledge.sqlite")]
        db: PathBuf,
    },
    /// Maak een consistente SQLite-back-up van de committed WAL-status.
    Backup {
        #[arg(long, default_value = ".rust-healer/knowledge.sqlite")]
        db: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Herstel een eerder gecontroleerde back-up uitsluitend in een nieuw bestand.
    Restore {
        #[arg(long)]
        backup: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        sha256: String,
    },
    /// Importeer alleen metadata van aanwezige packages; importeert geen modules.
    ImportInstalled {
        #[arg(long, default_value = ".rust-healer/knowledge.sqlite")]
        db: PathBuf,
        #[arg(long, default_value = process::DEFAULT_PYTHON)]
        python: String,
    },
    /// Voeg een bronbestand met herkomst en expliciete versie toe.
    Add {
        text_file: PathBuf,
        #[arg(long)]
        source: String,
        #[arg(long)]
        uri: String,
        #[arg(long)]
        title: String,
        #[arg(long)]
        package: String,
        #[arg(long)]
        version: String,
        #[arg(long, default_value = "unknown")]
        python_constraint: String,
        #[arg(long, default_value = ".rust-healer/knowledge.sqlite")]
        db: PathBuf,
    },
    /// Full-text FTS5 zoeken met versie en bronvermelding.
    Search {
        query: String,
        #[arg(long, default_value_t = 10)]
        limit: usize,
        #[arg(long, default_value = ".rust-healer/knowledge.sqlite")]
        db: PathBuf,
    },
    Stats {
        #[arg(long, default_value = ".rust-healer/knowledge.sqlite")]
        db: PathBuf,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct CheckResult {
    compile: String,
    error_type: Option<String>,
    message: Option<String>,
    line: Option<usize>,
    column: Option<usize>,
    audit_observation: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ColonProposal {
    changed: bool,
}

fn sha256(content: &[u8]) -> String {
    hex::encode(Sha256::digest(content))
}

fn embedded_resource(contents: &str, suffix: &str) -> Result<tempfile::NamedTempFile> {
    use std::io::Write;
    let mut file = tempfile::Builder::new().suffix(suffix).tempfile()?;
    file.write_all(contents.as_bytes())?;
    Ok(file)
}

fn validate_file_size(file: &Path) -> Result<Vec<u8>> {
    let metadata =
        fs::metadata(file).with_context(|| format!("kan {} niet lezen", file.display()))?;
    if !metadata.is_file() || metadata.len() > 4_000_000 {
        bail!(
            "verwacht een Python-bestand van hoogstens 4 MB: {}",
            file.display()
        );
    }
    Ok(fs::read(file)?)
}

fn compile_only(file: &Path, python: &str) -> Result<CheckResult> {
    let mut cmd = Command::new(python);
    cmd.args(["-I", "-S", "-B", "-c", include_str!("../python/verify.py")])
        .arg(file);
    let output = process::bounded_output(cmd, Duration::from_secs(8), 64_000)
        .with_context(|| format!("Python-validator kon niet starten: {python}"))?;
    if !output.status.success() {
        bail!(
            "statische Python-validatie faalde: {}",
            process::redacted_stderr(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("onverwacht resultaat van Python-validator")
}

fn missing_colon_candidate(file: &Path, python: &str) -> Result<Option<Vec<u8>>> {
    let output_file = tempfile::Builder::new().suffix(".py").tempfile()?;
    let mut cmd = Command::new(python);
    cmd.args([
        "-I",
        "-S",
        "-B",
        "-c",
        include_str!("../python/syntax_colon.py"),
    ])
    .arg(file)
    .arg(output_file.path());
    let result = process::bounded_output(cmd, Duration::from_secs(8), 64_000)
        .context("conservatieve syntaxhersteller kon niet starten")?;
    if !result.status.success() {
        bail!(
            "syntaxhersteller faalde: {}",
            process::redacted_stderr(&result.stderr)
        );
    }
    let proposal: ColonProposal = serde_json::from_slice(&result.stdout)?;
    if proposal.changed {
        Ok(Some(validate_file_size(output_file.path())?))
    } else {
        Ok(None)
    }
}

fn variant_id(engine: &str, code: &[u8], config: &str) -> (String, String, String) {
    let code_sha = sha256(code);
    let config_sha = sha256(config.as_bytes());
    let id = sha256(format!("{engine}:{code_sha}:{config_sha}").as_bytes());
    (format!("V-{}", &id[..16]), code_sha, config_sha)
}

struct EvaluationInput<'a> {
    engine: &'a str,
    config: &'a str,
    parent: Option<&'a str>,
    code: &'a [u8],
    file: &'a Path,
    python: &'a str,
    retest: bool,
}

fn evaluate(
    conn: &rusqlite::Connection,
    input: &EvaluationInput<'_>,
) -> Result<ledger::Evaluation> {
    let (id, code_sha, config_sha) = variant_id(input.engine, input.code, input.config);
    ledger::register(
        conn,
        &id,
        &code_sha,
        &config_sha,
        input.engine,
        input.parent,
    )?;
    // The duplicate check occurs BEFORE each verification, unless explicitly RETEST.
    if !input.retest {
        if let Some(previous) = ledger::previous(conn, &id)? {
            return Ok(previous);
        }
    }
    let start = Instant::now();
    let check = compile_only(input.file, input.python)?;
    let duration_ms = start.elapsed().as_millis();
    // Never equate compilation with behaviorally proven correctness.
    let item = ledger::Evaluation {
        variant_id: id,
        // Even compile-only workflows need a separate sandbox/resource audit.
        safety: "NOT_RUN".into(),
        correctness: if check.compile == "PASS" {
            "NOT_RUN"
        } else {
            "FAIL"
        }
        .into(),
        // One wall-time sample is evidence, but not a speed benchmark.
        speed: "NOT_RUN".into(),
        reliability: "NOT_RUN".into(),
        compatibility: "NOT_RUN".into(),
        futureproof: "NOT_RUN".into(),
        compile: check.compile.clone(),
        tests: "NOT_RUN".into(),
        duration_ms,
        log: check
            .message
            .unwrap_or_else(|| "compile() succeeded; no execution".into()),
        cached: false,
    };
    ledger::record(conn, &item)?;
    Ok(item)
}

fn repair(
    file: &Path,
    python: &str,
    ruff: &str,
    out: Option<&Path>,
    ledger_path: &Path,
    retest: bool,
) -> Result<()> {
    let source = validate_file_size(file)?;
    let conn = ledger::open(ledger_path)?;
    let baseline = evaluate(
        &conn,
        &EvaluationInput {
            engine: "baseline",
            config: "compile-only:v1",
            parent: None,
            code: &source,
            file,
            python,
            retest,
        },
    )?;
    let mut version_cmd = Command::new(ruff);
    version_cmd.arg("--version");
    let version = process::bounded_output(version_cmd, Duration::from_secs(5), 16_000)
        .with_context(|| format!("Ruff ontbreekt: {ruff}; installeer Ruff afzonderlijk"))?;
    if !version.status.success() {
        bail!("Ruff --version faalde");
    }
    let ruff_version = String::from_utf8_lossy(&version.stdout).trim().to_owned();
    let tempfile = tempfile::Builder::new().suffix(".py").tempfile()?;
    fs::write(tempfile.path(), &source)?;
    let mut fix_cmd = Command::new(ruff);
    fix_cmd
        .args(["check", "--fix", "--isolated"])
        .arg(tempfile.path());
    let output = process::bounded_output(fix_cmd, Duration::from_secs(20), 200_000)?;
    if output.status.code() != Some(0) && output.status.code() != Some(1) {
        bail!(
            "Ruff kon geen kandidaat maken: {}",
            process::redacted_stderr(&output.stderr)
        );
    }
    let candidate = fs::read(tempfile.path())?;
    let config = format!("ruff-safe-only:v1:{ruff_version};isolated=true");
    let healed = evaluate(
        &conn,
        &EvaluationInput {
            engine: "ruff-safe",
            config: &config,
            parent: Some(&baseline.variant_id),
            code: &candidate,
            file: tempfile.path(),
            python,
            retest,
        },
    )?;
    let mut selected = candidate.clone();
    let mut selected_eval = healed.clone();
    let mut colon_eval = None;
    if healed.compile != "PASS" {
        if let Some(colon_code) = missing_colon_candidate(tempfile.path(), python)? {
            fs::write(tempfile.path(), &colon_code)?;
            let config = format!("missing-colon:v1:{ruff_version};compiler-verified");
            let attempt = evaluate(
                &conn,
                &EvaluationInput {
                    engine: "missing-colon",
                    config: &config,
                    parent: Some(&healed.variant_id),
                    code: &colon_code,
                    file: tempfile.path(),
                    python,
                    retest,
                },
            )?;
            if attempt.compile == "PASS" {
                selected = colon_code;
                selected_eval = attempt.clone();
            }
            colon_eval = Some(attempt);
        }
    }
    let changed = selected != source;
    let mut saved = None;
    if changed && selected_eval.compile == "PASS" {
        let candidate_path = out
            .map(Path::to_path_buf)
            .unwrap_or_else(|| file.with_extension("healed.py"));
        if candidate_path == file
            || (candidate_path.exists()
                && fs::canonicalize(&candidate_path)? == fs::canonicalize(file)?)
        {
            bail!("kandidaat mag het origineel nooit overschrijven");
        }
        if candidate_path.exists() {
            if fs::read(&candidate_path)? != selected {
                bail!(
                    "output bestaat al met andere inhoud: {}",
                    candidate_path.display()
                );
            }
        } else {
            // A new file is created atomically by OS create_new; never replaces an existing file.
            use std::io::Write;
            let mut handle = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate_path)?;
            handle.write_all(&selected)?;
        }
        saved = Some(candidate_path.to_string_lossy().to_string());
    }
    let status = if changed && selected_eval.compile == "PASS" {
        "CANDIDATE_ONLY"
    } else if changed {
        "REJECTED_INVALID_COMPILE"
    } else {
        "UNCHANGED"
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status":status,"winner":"NONE",
            "reason":"No isolated behavioral tests or cross-version proof; no fully qualified winner",
            "ruff_version":ruff_version,"candidate_saved":saved,"changed":changed,
        "baseline":baseline,"candidate":selected_eval,
        "ruff_candidate":healed,"syntax_candidate":colon_eval,
        }))?
    );
    Ok(())
}

fn trusted_platform_prelude() -> Result<String> {
    let privacy = serde_json::to_string(include_str!("../python/windows_private_paths.py"))?;
    let blobs = serde_json::to_string(include_str!("../python/windows_blob_reader_v029.py"))?;
    let platform = serde_json::to_string(include_str!("../python/platform_privacy_v028.py"))?;
    let memory = serde_json::to_string(include_str!("../python/process_memory.py"))?;
    let checker = serde_json::to_string(include_str!("../python/windows_checker_process_v028.py"))?;
    let security = serde_json::to_string(include_str!("../python/windows_descriptor_security_v029.py"))?;
    let model = serde_json::to_string(include_str!("../python/model_evidence_io_v029.py"))?;
    let ecosystem_integrity = serde_json::to_string(include_str!("../python/ecosystem_wheel_integrity_v030.py"))?;
    let preview_module = serde_json::to_string(include_str!("../python/prerelease_matrix_v23.py"))?;
    let preview_suite = serde_json::to_string(include_str!("../python/version_suite.py"))?;
    Ok(format!(
        "import types, os\n_RPH_PINNED_PIP_WHEEL=os.environ.get('RPH_PINNED_PIP_WHEEL')\n_RPH_WINDOWS_PRIVACY=types.ModuleType('rph_bundled_windows_privacy')\nexec({privacy},_RPH_WINDOWS_PRIVACY.__dict__)\n_RPH_WINDOWS_BLOB_READER=types.ModuleType('rph_bundled_windows_blob_reader')\n_RPH_WINDOWS_BLOB_READER._RPH_WINDOWS_PRIVACY=_RPH_WINDOWS_PRIVACY\nexec({blobs},_RPH_WINDOWS_BLOB_READER.__dict__)\n_RPH_PLATFORM_PRIVACY=types.ModuleType('rph_bundled_platform_privacy')\n_RPH_PLATFORM_PRIVACY._RPH_WINDOWS_PRIVACY=_RPH_WINDOWS_PRIVACY\nexec({platform},_RPH_PLATFORM_PRIVACY.__dict__)\n_RPH_PROCESS_MEMORY=types.ModuleType('rph_bundled_process_memory')\nexec({memory},_RPH_PROCESS_MEMORY.__dict__)\n_RPH_WINDOWS_CHECKER=types.ModuleType('rph_bundled_windows_checker')\nexec({checker},_RPH_WINDOWS_CHECKER.__dict__)\n_RPH_WINDOWS_SECURITY=types.ModuleType('rph_bundled_windows_security')\n_RPH_WINDOWS_SECURITY._RPH_WINDOWS_BLOB_READER=_RPH_WINDOWS_BLOB_READER\n_RPH_WINDOWS_SECURITY._RPH_WINDOWS_PRIVACY=_RPH_WINDOWS_PRIVACY\nexec({security},_RPH_WINDOWS_SECURITY.__dict__)\n_RPH_ECOSYSTEM_INTEGRITY=types.ModuleType('rph_bundled_ecosystem_wheel_integrity')\n_RPH_ECOSYSTEM_INTEGRITY._RPH_WINDOWS_PRIVACY=_RPH_WINDOWS_PRIVACY\nexec({ecosystem_integrity},_RPH_ECOSYSTEM_INTEGRITY.__dict__)\n_RPH_MODEL_EVIDENCE_IO=types.ModuleType('rph_bundled_model_evidence_io')\n_RPH_MODEL_EVIDENCE_IO._RPH_WINDOWS_PRIVACY=_RPH_WINDOWS_PRIVACY\n_RPH_MODEL_EVIDENCE_IO._RPH_WINDOWS_BLOB=_RPH_WINDOWS_BLOB_READER\nexec({model},_RPH_MODEL_EVIDENCE_IO.__dict__)\n_RPH_PREVIEW_MODULE_SOURCE={preview_module}\n_RPH_PREVIEW_SUITE_SOURCE={preview_suite}\n"
    ))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let args = cli_policy::canonical_arguments(std::env::args_os().skip(1).collect())?;
    let _approval_lease = match cli_policy::pre_dispatch(
        &cli.command, &args, cli.approval_token.as_deref(), cli.approval_request,
    ).map_err(|_| anyhow::anyhow!("policy_dispatch_refused_target_not_dispatched"))? {
        cli_policy::Dispatch::Request(request) => {
            println!("{}", serde_json::to_string_pretty(&request)?);
            return Ok(());
        }
        cli_policy::Dispatch::Execute(lease) => lease,
    };
    match cli.command {
        Commands::Dap => dap::serve_stdio()?,
        Commands::VersionRegression { python, manifest } => {
            let default_manifest = if manifest.is_none() {
                Some(embedded_resource(
                    include_str!("../config/version_regression_cases.json"),
                    ".json",
                )?)
            } else {
                None
            };
            let selected = manifest.as_deref().unwrap_or_else(|| {
                default_manifest
                    .as_ref()
                    .expect("embedded reference exists")
                    .path()
            });
            let mut cmd = Command::new(&python);
            cmd.args([
                "-I",
                "-S",
                "-B",
                "-c",
                include_str!("../python/version_regression.py"),
                "--manifest",
            ])
            .arg(selected);
            let output = process::bounded_output(cmd, Duration::from_secs(20), 100_000)
                .context("versiegebonden AST/bytecode-regressietests konden niet starten")?;
            if !output.status.success() {
                bail!("versiegebonden regressietests faalden");
            }
            let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            if report["untrusted_source_executed"] != false
                || report["project_code_loaded"] != false
                || report["reference_authenticity"] != "UNSIGNED_NOT_VERIFIED"
                || report["full_python_compatibility"] != "NOT_VERIFIED"
            {
                bail!("regressietest gaf onjuiste of ongecontroleerde claims");
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report["status"] != "BASELINE_MATCH" {
                std::process::exit(2);
            }
        }
        Commands::Qualify {
            policy,
            trust,
            evidence,
            python,
        } => {
            let mut cmd = Command::new(&python);
            cmd.args([
                "-I",
                "-S",
                "-B",
                "-c",
                include_str!("../python/qualification_policy.py"),
                "--policy",
            ])
            .arg(&policy)
            .arg("--trust")
            .arg(&trust)
            .arg("--evidence")
            .arg(&evidence);
            let output = process::bounded_output(cmd, Duration::from_secs(20), 500_000)
                .context("zes-assige kwalificatiecontrole kon niet starten")?;
            if !output.status.success() {
                bail!("kwalificatiecontrole weigerde ongeldige of niet-geverifieerde rapporten");
            }
            let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            if report["status"] != "POLICY_EVALUATED_NOT_BEHAVIORALLY_PROVEN"
                || report["source_executed"] != false
                || report["independent_execution_verified"] != false
                || report["release_authorized"] != false
            {
                bail!("kwalificatiecontrole gaf onjuiste bewijs- of releaseclaims");
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report["decision"] != "POLICY_PRIMARY_EXISTS" {
                std::process::exit(2);
            }
        }
        Commands::Property {
            seed,
            cases,
            name,
            python,
        } => {
            let mut cmd = Command::new(&python);
            cmd.args([
                "-I",
                "-S",
                "-B",
                "-c",
                include_str!("../python/property_harness.py"),
                "--seed",
            ])
            .arg(seed.to_string())
            .arg("--cases")
            .arg(cases.to_string())
            .arg("--property")
            .arg(name);
            let output = process::bounded_output(cmd, Duration::from_secs(15), 100_000)
                .context("vastgelegde propertytest kon niet starten")?;
            if !output.status.success() {
                bail!("propertytest weigerde ongeldige fixtures of overschreden limieten");
            }
            let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            if report["user_source_executed"] != false
                || report["external_packages_imported"] != false
                || report["behavioral_equivalence_proven"] != false
            {
                bail!("propertytest gaf onjuiste bronuitvoerings- of compatibiliteitsclaims");
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report["status"] != "PASS" && report["status"] != "EXPECTED_MUTANT_KILLED" {
                std::process::exit(2);
            }
        }
        Commands::Static {
            file,
            classify,
            python,
        } => {
            if file.is_none() && classify.is_none() {
                bail!("verwacht een Python-bronbestand of --classify <regel-ID>");
            }
            let mut cmd = Command::new(&python);
            cmd.args([
                "-I",
                "-S",
                "-B",
                "-c",
                include_str!("../python/static_quality.py"),
            ]);
            if let Some(rule) = classify {
                cmd.arg("--classify").arg(rule);
            } else if let Some(path) = file {
                cmd.arg(path);
            }
            let output = process::bounded_output(cmd, Duration::from_secs(20), 500_000)
                .context("statische kwaliteitsinspectie kon niet starten")?;
            if !output.status.success() {
                bail!("statische kwaliteitsinspectie weigerde input");
            }
            let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report["status"] != "CLASSIFIED" && report["status"] != "INSPECTED_PARTIAL" {
                std::process::exit(2);
            }
        }
        Commands::Lab {
            tool,
            python,
            mut arguments,
        } => {
            if arguments.len() > 36 || arguments.iter().any(|v| v.len() > 4096) {
                bail!("te veel of te lange adapterparameters");
            }
            // Source-policy lookup/cite uses SQLite's writable default opener.
            // Route it to our checkpointed immutable copy, never caller data.
            let _read_only_source_snapshot = if matches!(tool, LabTool::Sources)
                && arguments.first().is_some_and(|v| v == "lookup" || v == "cite") {
                let options = cli_policy::lab_options(&arguments[1..],
                    &["--database", "--python-version", "--package", "--package-version", "--platform", "--section-id", "--max-words", "--max-bytes"], &[])?;
                let source = options.get("--database").context("policy_source_database_missing")?;
                let snapshot = cli_policy::read_only_database(Path::new(source))?;
                let name = snapshot.path().to_str().context("policy_snapshot_unicode_required")?.to_string();
                for index in 0..arguments.len() {
                    if arguments[index] == "--database" { arguments[index + 1] = name.clone(); break; }
                    if arguments[index].starts_with("--database=") { arguments[index] = format!("--database={name}"); break; }
                }
                Some(snapshot)
            } else { None };
            if matches!(tool, LabTool::BackupDrill) {
                // For an explicitly requested backup/restore drill, use the
                // same transactional migration logic as the Rust catalog.
                // A verification-only request must never change its source.
                let typed = cli_policy::lab_options(&arguments,
                    &["--database", "--archive-dir", "--id", "--cycles", "--interval-ms", "--action"], &[])?;
                let verifying = typed.get("--action").is_some_and(|v| v == "verify");
                if !verifying {
                    let source = arguments
                        .windows(2)
                        .find(|pair| pair[0] == "--database")
                        .map(|pair| PathBuf::from(&pair[1]))
                        .context("--database ontbreekt bij backup-drill")?;
                    let metadata = fs::symlink_metadata(&source)?;
                    if !metadata.file_type().is_file() || metadata.len() > 128 * 1024 * 1024 {
                        bail!("backup vereist een bestaand, begrensd SQLite-bronbestand");
                    }
                    #[cfg(unix)]
                    if std::os::unix::fs::MetadataExt::nlink(&metadata) != 1 {
                        bail!("backup weigert een extern hardlinkpad");
                    }
                    drop(knowledge::open(&source)?);
                }
            }
            let code = if matches!(tool, LabTool::RealModelRouter) {
                let trusted_semantic =
                    serde_json::to_string(include_str!("../python/semantic_retrieval_v23.py"))?;
                format!(
                    "import sys, types\nsemanticmodel = types.ModuleType('semantic_retrieval_v23')\nsemanticmodel._RPH_MODEL_EVIDENCE_IO=_RPH_MODEL_EVIDENCE_IO\nexec({trusted_semantic}, semanticmodel.__dict__)\nsys.modules['semantic_retrieval_v23'] = semanticmodel\n{}",
                    tool.script()
                )
            } else if matches!(tool, LabTool::StdlibNativeComplete) {
                let trusted_stdlib =
                    serde_json::to_string(include_str!("../python/stdlib_api_extract.py"))?;
                format!(
                    "import types\nstdlibscanner = types.ModuleType('stdlibscanner')\nexec({trusted_stdlib}, stdlibscanner.__dict__)\n{}",
                    tool.script()
                )
            } else if matches!(tool, LabTool::AstCstTyping) {
                let trusted_typechecker =
                    serde_json::to_string(include_str!("../python/typecheck_integration_v23.py"))?;
                format!(
                    "import types\ntypecheck = types.ModuleType('rph_private_typecheck_v23')\ntypecheck._RPH_WINDOWS_PRIVACY = _RPH_WINDOWS_PRIVACY\ntypecheck._RPH_WINDOWS_CHECKER = _RPH_WINDOWS_CHECKER\nexec({trusted_typechecker}, typecheck.__dict__)\n{}",
                    tool.script()
                )
            } else if matches!(tool, LabTool::KnowledgeScale) {
                let trusted_corpus = serde_json::to_string(
                    include_str!("../python/corpus_scale_v031.py"))?;
                format!(
                    "import types\n_RPH_CORPUS_SCALE=types.ModuleType('rph_bundled_corpus_scale')\n_RPH_CORPUS_SCALE._RPH_WINDOWS_PRIVACY=_RPH_WINDOWS_PRIVACY\n_RPH_CORPUS_SCALE._RPH_PROCESS_MEMORY=_RPH_PROCESS_MEMORY\nexec({trusted_corpus},_RPH_CORPUS_SCALE.__dict__)\n{}",
                    tool.script()
                )
            } else if matches!(tool, LabTool::RemoteDap) {
                // Embed both trusted local sources; never import a similarly
                // named module from the untrusted project or temporary cwd.
                let trusted_dap =
                    serde_json::to_string(include_str!("../python/dap_runtime_v22.py"))?;
                format!(
                    "import types\ndap = types.ModuleType('rph_private_dap_v22')\ndap._RPH_WINDOWS_PRIVACY = _RPH_WINDOWS_PRIVACY\nexec({trusted_dap}, dap.__dict__)\n{}",
                    tool.script()
                )
            } else if matches!(tool, LabTool::DecisionAudit) {
                let trusted_qualification =
                    serde_json::to_string(include_str!("../python/qualification_policy.py"))?;
                format!(
                    "import sys, types\n_qual = types.ModuleType('qualification_policy')\nexec({trusted_qualification}, _qual.__dict__)\nsys.modules['qualification_policy'] = _qual\n{}",
                    tool.script()
                )
            } else {
                tool.script().to_string()
            };
            let code = format!("{}\n{code}", trusted_platform_prelude()?);
            let mut cmd = Command::new(&python);
            // Windows CreateProcess limits the complete command line to 32K.
            // Bundled trusted dependencies can exceed it; keep the reviewed
            // source in an owned temporary script, alive until the child exits.
            #[cfg(windows)]
            let adapter_script = embedded_resource(&code, ".py")?;
            #[cfg(windows)]
            cmd.args(["-I", "-S", "-B"]).arg(adapter_script.path());
            #[cfg(not(windows))]
            cmd.args(["-I", "-S", "-B", "-c", &code]);
            cmd.args(arguments);
            let adapter_deadline = if matches!(tool, LabTool::PrereleaseMatrix) {
                Duration::from_secs(600)
            } else {
                Duration::from_secs(45)
            };
            let output = process::bounded_output(cmd, adapter_deadline, 1_500_000)
                .context("onderzoeksadapter kon niet starten")?;
            if !output.status.success() {
                bail!("onderzoeksadapter: ongeldig bewijs of niet-ondersteunde bewerking");
            }
            let report: serde_json::Value = serde_json::from_slice(&output.stdout)
                .context("onderzoeksadapter retourneerde geen geldige JSON")?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Commands::Runtime { python } => {
            let mut cmd = Command::new(&python);
            cmd.args([
                "-I",
                "-S",
                "-B",
                "-c",
                include_str!("../python/runtime_probe.py"),
            ]);
            let output = process::bounded_output(cmd, Duration::from_secs(10), 64_000)
                .with_context(|| format!("Python-runtimeinspectie faalde: {python}"))?;
            if !output.status.success() {
                bail!(
                    "Python-runtimeprobe faalde: {}",
                    process::redacted_stderr(&output.stderr)
                );
            }
            let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            if result["status"] != "INSPECTED" {
                bail!("runtimeprobe retourneerde geen bevestigde metadatastructuur");
            }
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Check { file, python } => {
            validate_file_size(&file)?;
            let result = compile_only(&file, &python)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            if result.compile != "PASS" {
                std::process::exit(2);
            }
        }
        Commands::Trace {
            log_file,
            show_sensitive,
        } => {
            let result = trace::analyze_file(&log_file, show_sensitive)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
            if result["status"] != "DIAGNOSED" {
                std::process::exit(2);
            }
        }
        Commands::Deps {
            packages,
            extras,
            python,
            metadata_dirs,
        } => {
            if packages.len() > 50 || extras.len() > 20 || metadata_dirs.len() > 10 {
                bail!("maximaal 50 packages, 20 extras en 10 metadata-mappen");
            }
            let mut cmd = Command::new(&python);
            cmd.args([
                "-I",
                "-S",
                "-B",
                "-c",
                include_str!("../python/dependencies.py"),
            ]);
            for package in &packages {
                cmd.arg("--package").arg(package);
            }
            for extra in &extras {
                cmd.arg("--extra").arg(extra);
            }
            for directory in &metadata_dirs {
                cmd.arg("--metadata-dir").arg(directory);
            }
            let output = process::bounded_output(cmd, Duration::from_secs(30), 2_000_000)
                .with_context(|| format!("kan Python-metadata niet inspecteren: {python}"))?;
            if !output.status.success() {
                bail!(
                    "dependency-metadata-inspectie faalde: {}",
                    process::redacted_stderr(&output.stderr)
                );
            }
            let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            if result["status"] != "INSPECTED" {
                bail!("onverwacht dependency-rapport");
            }
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Record {
            packages,
            metadata_dirs,
            python,
        } => {
            if packages.len() > 25 || metadata_dirs.len() > 10 {
                bail!("maximaal 25 packages en 10 extra metadata-mappen");
            }
            let mut cmd = Command::new(&python);
            cmd.args([
                "-I",
                "-S",
                "-B",
                "-c",
                include_str!("../python/wheel_record.py"),
            ]);
            for package in &packages {
                cmd.arg("--package").arg(package);
            }
            for directory in &metadata_dirs {
                cmd.arg("--metadata-dir").arg(directory);
            }
            let output = process::bounded_output(cmd, Duration::from_secs(60), 500_000)
                .context("wheel RECORD-controle kon niet starten")?;
            if !output.status.success() {
                bail!("wheel RECORD-controle faalde (onbekend resultaat)");
            }
            let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            if result["status"] != "INSPECTED_NOT_INSTALLED" {
                bail!("onverwacht wheel RECORD-resultaat");
            }
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Project { path, python } => {
            let mut cmd = Command::new(&python);
            cmd.args([
                "-I",
                "-S",
                "-B",
                "-c",
                include_str!("../python/project_manifest.py"),
            ])
            .arg(&path);
            let output = process::bounded_output(cmd, Duration::from_secs(20), 500_000)
                .context("projectmanifest-inspectie kon niet starten")?;
            if !output.status.success() {
                bail!("projectmanifest-inspectie kon geen betrouwbare uitkomst leveren");
            }
            let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            if result["source_executed"] != false || result["dependency_resolution"] != "NOT_RUN" {
                bail!("onverwacht projectmanifest-rapport");
            }
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Commands::Flaky { evidence, python } => {
            let mut cmd = Command::new(&python);
            cmd.args([
                "-I",
                "-S",
                "-B",
                "-c",
                include_str!("../python/flaky_evidence.py"),
            ])
            .arg(&evidence);
            let output = process::bounded_output(cmd, Duration::from_secs(15), 500_000)
                .context("flaky-evidence-analyse kon niet starten")?;
            if !output.status.success() {
                bail!("flaky-evidence-analyse weigerde ongeldige metingen");
            }
            let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            if report["status"] != "ANALYZED_NOT_INDEPENDENTLY_VERIFIED"
                || report["behavioral_correctness"] != "NOT_VERIFIED"
            {
                bail!("flaky-evidence-analyse gaf onbekende verificatiestatus");
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
            let summary = &report["summary"];
            if ["FLAKY", "INCOMPLETE", "INSUFFICIENT", "REPEATABLE_FAIL"]
                .iter()
                .any(|name| summary[name].as_u64().unwrap_or(0) > 0)
            {
                std::process::exit(2);
            }
        }
        Commands::Ast { file, python } => {
            let mut cmd = Command::new(&python);
            cmd.args([
                "-I",
                "-S",
                "-B",
                "-c",
                include_str!("../python/ast_graph.py"),
            ])
            .arg(&file);
            let output = process::bounded_output(cmd, Duration::from_secs(20), 500_000)
                .context("AST-inspectie kon niet starten")?;
            if !output.status.success() {
                bail!("AST-inspectie kon geen gecontroleerd resultaat leveren");
            }
            let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            if report["source_executed"] != false || report["compile_proven"] != false {
                bail!("AST-inspectie retourneerde onjuiste uitvoeringsclaims");
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report["status"] != "INSPECTED_PARTIAL" {
                std::process::exit(2);
            }
        }
        Commands::Sbom {
            python,
            metadata_dirs,
            only_metadata_dir,
        } => {
            let mut cmd = Command::new(&python);
            cmd.args([
                "-I",
                "-S",
                "-B",
                "-c",
                include_str!("../python/sbom_inventory.py"),
            ]);
            for directory in &metadata_dirs {
                cmd.arg("--metadata-dir").arg(directory);
            }
            if only_metadata_dir {
                cmd.arg("--only-metadata-dir");
            }
            let output = process::bounded_output(cmd, Duration::from_secs(30), 1_000_000)
                .context("SBOM-metadata-inspectie kon niet starten")?;
            if !output.status.success() {
                bail!("SBOM-metadata-inspectie weigerde ongeldige of onveilige data");
            }
            let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
            if report["source_executed"] != false
                || report["modules_executed"] != false
                || report["publisher_verified"] != false
                || report["vulnerabilities_scanned"] != false
                || report["dependency_resolution"] != "NOT_RUN"
            {
                bail!("SBOM-inventarisatie gaf onjuiste uitvoerings- of verificatieclaims");
            }
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report["status"] != "INVENTORIED_UNVERIFIED" {
                std::process::exit(2);
            }
        }
        Commands::Scan {
            path,
            python,
            limit,
            workers,
        } => {
            let report = scan::project(&path, &python, limit, workers)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if report["status"] != "PASS" {
                std::process::exit(2);
            }
        }
        Commands::Matrix {
            file,
            manifest,
            interpreters,
            python,
        } => {
            validate_file_size(&file)?;
            let suite = embedded_resource(include_str!("../python/version_suite.py"), ".py")?;
            let mut cmd = Command::new(&python);
            cmd.args([
                "-I",
                "-S",
                "-B",
                "-c",
                include_str!("../python/compat_matrix.py"),
            ])
            .arg(&file)
            .arg("--manifest")
            .arg(&manifest)
            .arg("--suite-path")
            .arg(suite.path());
            for item in interpreters {
                cmd.arg("--interpreter").arg(item);
            }
            let output = process::bounded_output(cmd, Duration::from_secs(180), 100_000)
                .context("matrix-runner kon niet starten")?;
            if !output.status.success() {
                bail!(
                    "matrix-runner faalde: {}",
                    process::redacted_stderr(&output.stderr)
                );
            }
            println!("{}", String::from_utf8(output.stdout)?);
        }
        Commands::Update {
            apply,
            auto,
            watch,
            packages,
            python,
            manifest,
            db,
        } => {
            if watch && !apply {
                bail!("--watch vereist --apply");
            }
            let schema = embedded_resource(include_str!("../sql/knowledge.sql"), ".sql")?;
            let mut cmd = Command::new(&python);
            cmd.args([
                "-I",
                "-S",
                "-B",
                "-c",
                include_str!("../python/knowledge_updater.py"),
            ])
            .arg("--manifest")
            .arg(&manifest)
            .arg("--schema")
            .arg(schema.path())
            .arg("--db")
            .arg(&db)
            .arg("--mode")
            .arg(if apply { "apply" } else { "check" });
            if auto {
                cmd.arg("--auto");
            }
            if watch {
                cmd.arg("--watch");
            }
            for package in packages {
                cmd.arg("--package").arg(package);
            }
            if watch {
                let status = cmd.status().context("updater kon niet starten")?;
                if !status.success() {
                    bail!("updater gestopt met fout");
                }
            } else {
                let output = process::bounded_output(cmd, Duration::from_secs(600), 100_000)
                    .context("updater kon niet starten")?;
                println!("{}", String::from_utf8_lossy(&output.stdout));
                if !output.status.success() {
                    bail!(
                        "updater faalde: {}",
                        process::redacted_stderr(&output.stderr)
                    );
                }
            }
        }
        Commands::Repair {
            file,
            python,
            ruff,
            out,
            ledger,
            retest,
        } => {
            repair(&file, &python, &ruff, out.as_deref(), &ledger, retest)?;
        }
        Commands::Catalog { command } => match command {
            CatalogCommands::Maintain { action, db } => {
                let conn = knowledge::open(&db)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&knowledge::maintain(&conn, &action)?)?
                );
            }
            CatalogCommands::Backup { db, out } => {
                let conn = knowledge::open(&db)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&knowledge::backup(&conn, &out)?)?
                );
            }
            CatalogCommands::Restore {
                backup,
                out,
                sha256,
            } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&knowledge::restore(&backup, &out, &sha256)?)?
                );
            }
            CatalogCommands::ImportInstalled { db, python } => {
                let mut conn = knowledge::open(&db)?;
                let imported = knowledge::import_installed(&mut conn, &python)?;
                println!("{}", json!({"imported": imported, "db": db}));
            }
            CatalogCommands::Add {
                text_file,
                source,
                uri,
                title,
                package,
                version,
                python_constraint,
                db,
            } => {
                let conn = knowledge::open(&db)?;
                let meta = knowledge::DocumentMeta {
                    source: &source,
                    uri: &uri,
                    title: &title,
                    package: &package,
                    version: &version,
                    python_constraint: &python_constraint,
                };
                knowledge::add_file(&conn, &meta, &text_file)?;
                println!("{}", json!({"added":true,"uri":uri,"version":version}));
            }
            CatalogCommands::Search { query, limit, db } => {
                let snapshot = cli_policy::read_only_database(&db)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&knowledge::search(&snapshot.connection, &query, limit)?)?
                );
            }
            CatalogCommands::Stats { db } => {
                let snapshot = cli_policy::read_only_database(&db)?;
                println!("{}", knowledge::stats(&snapshot.connection)?);
            }
        },
        Commands::Bench { ledger } => {
            let snapshot = cli_policy::read_only_database(&ledger)?;
            println!("{}", ledger::summary(&snapshot.connection)?);
        }
    }
    Ok(())
}
