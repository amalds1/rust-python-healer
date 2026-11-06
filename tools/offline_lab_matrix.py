"""Offline per-interpreter Rust-adapter smoke tests (no updater/network calls).

Only trusted fixtures and explicitly listed embedded adapters are invoked.
These checks are not a replacement for the full end-to-end feature matrix.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def check_version(label, interpreter, binary):
    entries = []

    def run(name, arguments, expected_status=None, exit_code=0):
        process = subprocess.run([str(binary)] + list(arguments), cwd=str(ROOT),
                                 capture_output=True, text=True, timeout=25,
                                 check=False)
        if process.returncode != exit_code:
            raise AssertionError("{} subprocess returned {}; details redacted".format(
                name, process.returncode))
        data = json.loads(process.stdout) if process.stdout else {}
        if expected_status is not None and data.get("status") != expected_status:
            raise AssertionError("{} unexpected status; no PASS recorded".format(name))
        entries.append({"name": name, "status": "PASS"})
        return data

    with tempfile.TemporaryDirectory(prefix="rph-offline-lab-") as folder:
        base = Path(folder)
        identity = subprocess.run([str(interpreter), "-I", "-S", "-B", "-c",
                                   "import sys;print('%s.%s' % sys.version_info[:2])"],
                                  capture_output=True, text=True, timeout=8,
                                  check=False)
        if identity.returncode != 0 or identity.stdout.strip() != label:
            raise AssertionError("actual CPython version mismatch: " + label)
        entries.append({"name": "real_interpreter", "status": "PASS"})
        compiled = run("property_randomized", ["property", "--seed", "691",
                    "--cases", "80", "--property", "hex_digest_length",
                    "--python", str(interpreter)], "PASS")
        if compiled.get("user_source_executed") is not False:
            raise AssertionError("property unexpectedly executed source")
        run("property_mutation_shrinking", ["property", "--seed", "691",
            "--cases", "80", "--property", "mutant_double_equals_self",
            "--python", str(interpreter)], "EXPECTED_MUTANT_KILLED")
        run("static_classifier", ["static", "--classify", "SEC001",
            "--python", str(interpreter)], "CLASSIFIED")
        source = base / "statically_inspected.py"
        source.write_text("value = eval('2+2')\n", encoding="utf-8")
        static = run("static_source_no_execution", ["static", str(source),
                      "--python", str(interpreter)], "INSPECTED_PARTIAL")
        if static.get("source_executed") is not False:
            raise AssertionError("static analysis executed untrusted source")
        manifest = base / "queue.json"
        manifest.write_text(json.dumps({
            "schema_version": 1, "max_pending": 4, "workers": 1,
            "tasks": [{"id": "first", "deps": [], "priority": 2,
                       "duration_ms": 1, "deadline_ms": None},
                      {"id": "second", "deps": ["first"], "priority": 1,
                       "duration_ms": 2, "deadline_ms": None}],
            "actions": []}), encoding="utf-8")
        dag = run("lab_dag_graph", ["lab", "dag", "--python", str(interpreter),
                   "--", "--manifest", str(manifest)])
        if dag.get("topological_order") != ["first", "second"] or dag.get("task_code_executed") is not False:
            raise AssertionError("DAG precedence/code isolation violated")
        manifest.write_text('{"schema_version":1,"tasks":[],"tasks":[]}', encoding="utf-8")
        run("lab_dag_duplicate_keys_rejected", ["lab", "dag", "--python", str(interpreter),
            "--", "--manifest", str(manifest)], exit_code=1)
        graph = base / "graph.sqlite"
        report = run("lab_graph_database_init", ["lab", "graph", "--python", str(interpreter),
                     "--", "--db", str(graph), "init"])
        if report.get("source_executed") is not False:
            raise AssertionError("graph database executed untrusted source")
        roles = base / "role-request.json"
        roles.write_text(json.dumps({"schema_version": 1, "budget_units": 100,
                                      "max_reserved_slots": 4,
                                      "tasks": [{"task_id": "trusted-fixture",
                                                 "required_capabilities": ["python_syntax", "ast"],
                                                 "priority": 50, "risk_tier": "LOW",
                                                 "max_cost_units": 50,
                                                 "max_latency_ms": 600000,
                                                 "min_quality_percent": 0}],
                                      "model_feedback": {}}), encoding="utf-8")
        router = run("lab_36_specialist_role_router", ["lab", "role-router",
                     "--python", str(interpreter), "--", "--roles",
                     str(ROOT / "config/agent_roles.json"), "--tasks", str(roles)],
                     "PLANNED_ONLY_NOT_EXECUTED")
        if router.get("active_agents_started") != 0:
            raise AssertionError("role plan started unauthorised models")
        abi = run("lab_wheel_tag_abi", ["lab", "abi-tags", "--python", str(interpreter),
                 "--", "--wheel", "sample_pkg-1.0-py3-none-any.whl"])
        if abi.get("compatibility") != "POSSIBLE_TAG_MATCH_NOT_INSTALLED":
            raise AssertionError("pure Python wheel tag not recognized")
        scratch = base / "snapshots.sqlite"
        snapshots = run("lab_snapshot_integrity", ["lab", "evidence-snapshot",
                        "--python", str(interpreter), "--", "--db", str(scratch), "init"])
        if snapshots.get("status") != "LOCAL_LEDGER_INTACT_NOT_EXTERNAL_ATTESTATION":
            raise AssertionError("snapshot ledger integrity missing")
        queue_report = run("lab_measured_synthetic_queue", ["lab", "resource-meter",
                           "--python", str(interpreter), "--", "synthetic-queue",
                           "--workers", "2", "--jobs", "8", "--hold-ms", "1"],
                           "MEASURED_SYNTHETIC_SCHEDULER_NOT_PRODUCTION")
        if queue_report.get("jobs_completed") != 8:
            raise AssertionError("queue did not process all trusted fixture jobs")
        wal_db = base / "old-catalog.sqlite"
        with sqlite3.connect(str(wal_db)) as dbconn:
            dbconn.executescript((ROOT / "sql" / "knowledge.sql").read_text(encoding="utf-8"))
            dbconn.execute("PRAGMA user_version=1")
            dbconn.execute("INSERT INTO documents(source,uri,title,package,version,python_constraint,content,sha256) "
                           "VALUES('fixture','https://example.invalid/one','P','stdlib','3.9','','waldata','sha')")
        archive_dir = base / "watched-backups"
        archive_dir.mkdir(mode=0o700)
        drill = run("lab_periodic_wal_backup_migration_and_restore", [
            "lab", "backup-drill", "--python", str(interpreter), "--",
            "--database", str(wal_db), "--archive-dir", str(archive_dir),
            "--action", "watch", "--id", "offline", "--cycles", "2",
            "--interval-ms", "8"], "PERIODIC_LOCAL_DRILLS_VERIFIED")
        if drill.get("all_restores_verified") is not True:
            raise AssertionError("backups were not restored")
        with sqlite3.connect(str(wal_db)) as dbconn:
            if dbconn.execute("PRAGMA user_version").fetchone()[0] != 2:
                raise AssertionError("catalog migration missing before backup")
        vector_db = base / "vector.sqlite"
        run("lab_vector_database_init", ["lab", "vector", "--python", str(interpreter),
            "--", "--db", str(vector_db), "init"],
            "STRUCTURALLY_SYNCED_NOT_SEMANTICALLY_VALIDATED")
        vector_args = ["--python-minor", label, "--package", "stdlib",
                       "--package-version", label]
        run("lab_vector_version_partition", ["lab", "vector", "--python",
            str(interpreter), "--", "--db", str(vector_db), "partition"] + vector_args + [
            "--dimension", "2", "--model", "caller-supplied-fixed-fixture"],
            "PARTITION_REGISTERED")
        source_id = "f" * 64
        source_url = "https://example.invalid/stdlib-trusted"
        recorded = run("lab_vector_source_binding", ["lab", "vector", "--python",
            str(interpreter), "--", "--db", str(vector_db), "put"] + vector_args + [
            "--chunk", "trusted", "--source-uri", source_url,
            "--source-sha256", source_id, "--vector", "[1,0]",
            "--content", "python versioned source"], "CHUNK_VECTOR_RECORDED")
        if recorded.get("source_executed") is not False:
            raise AssertionError("vector ingest executed documentation code")
        results = run("lab_hybrid_fts_vector_search", ["lab", "vector", "--python",
            str(interpreter), "--", "--db", str(vector_db), "hybrid"] + vector_args + [
            "--source-uri", source_url, "--source-sha256", source_id,
            "--vector", "[1,0]", "--text", "python"],
            "HYBRID_FTS5_VECTOR_RRF_HARD_FILTERS_NOT_SEMANTIC_ATTESTATION")
        if len(results.get("matches", [])) != 1:
            raise AssertionError("hybrid retrieval did not preserve source provenance")
        empty = run("lab_hybrid_wrong_source_is_empty", ["lab", "vector", "--python",
            str(interpreter), "--", "--db", str(vector_db), "hybrid"] + vector_args + [
            "--source-uri", source_url, "--source-sha256", "e" * 64,
            "--vector", "[1,0]", "--text", "python"],
            "HYBRID_FTS5_VECTOR_RRF_HARD_FILTERS_NOT_SEMANTIC_ATTESTATION")
        if empty.get("matches"):
            raise AssertionError("source SHA filter was bypassed")
        dependency = base / "resolver-catalog.json"
        dependency.write_text(json.dumps({"catalog": {
            "a": [{"version": "1.0", "requires": [{"name": "b", "specifier": ">=2"}]}],
            "b": [{"version": "1.0"}, {"version": "2.0"}]},
            "roots": [{"name": "a"}]}), encoding="utf-8")
        run("lab_transitive_resolver", ["lab", "transitive-resolver",
            "--python", str(interpreter), "--", "--input", str(dependency),
            "--python-version", label], "SATISFIABLE_IN_LOCAL_FINAL_RELEASE_CATALOG")
        repeats = run("lab_repeated_real_trusted_processes", [
            "lab", "reliability-bench", "--python", str(interpreter), "--",
            "--mode", "trusted-repeat", "--python", str(interpreter),
            "--runs", "10"], "TRUSTED_TEN_REPEATS_MATCH")
        if repeats.get("independent_processes_recorded") != 10:
            raise AssertionError("ten independent process executions not observed")
        latency = run("lab_ten_real_process_latency_gates", [
            "lab", "reliability-bench", "--python", str(interpreter), "--",
            "--mode", "latency-measure", "--python", str(interpreter),
            "--runs", "10"], "MEASURED_THRESHOLDS_PASS")
        if latency.get("independent_processes_measured") != 10:
            raise AssertionError("latency histogram lacks ten independently measured processes")
        jobs = base / "live-trusted-jobs.json"
        jobs.write_text(json.dumps({"jobs": [
            {"id": "first", "duration_ms": 60, "memory_mb": 2, "deps": []},
            {"id": "second", "duration_ms": 60, "memory_mb": 2, "deps": []},
            {"id": "third", "duration_ms": 5, "memory_mb": 2, "deps": ["first", "second"]}
        ]}), encoding="utf-8")
        execution = run("lab_adaptive_real_trusted_worker_slots", [
            "lab", "adaptive-jobs", "--python", str(interpreter), "--",
            "--mode", "live", "--python", str(interpreter),
            "--input", str(jobs), "--workers", "2", "--memory-mb", "4"],
            "TRUSTED_REAL_SUBPROCESS_EXECUTOR_PASS")
        if execution.get("observed_independent_processes") != 3 or execution.get(
                "actual_peak_overlapping_processes", 0) < 2:
            raise AssertionError("live adaptive work did not exhibit two actual overlapping processes")
        runtime = run("v021_trusted_debugger_real_breakpoints", [
            "lab", "trusted-debugger", "--python", str(interpreter), "--",
            "--mode", "trace", "--breakpoints-json", '[{"line":8}]',
            "--watches-json", '["first"]'], "TRUSTED_RUNTIME_TRACE")
        if runtime.get("line_events", 0) < 1 or not runtime.get("stops") or \
                runtime.get("project_source_executed") is not False:
            raise AssertionError("trusted debugger had no real breakpoints or executed project source")
        monitor_expected = ("TRUSTED_SYS_MONITORING_OBSERVED" if int(label.split(".")[1]) >= 12
                            else "NOT_SUPPORTED")
        run("v021_trusted_debugger_monitoring_version_gate", [
            "lab", "trusted-debugger", "--python", str(interpreter), "--",
            "--mode", "monitoring"], monitor_expected)
        stdlib = run("v021_genuine_installed_stdlib_docstrings", [
            "lab", "real-docs-benchmark", "--python", str(interpreter)],
            "EXTRACTED_REAL_LOCAL_STDLIB_AST_DOCSTRINGS")
        if stdlib.get("distinct_genuine_chunks", 0) < 10000 or \
                stdlib.get("runtime_stdlib_root_selected") is not True:
            raise AssertionError("stdlib corpus was not the actual interpreter's unique docstrings")
        ecosystem_source = base / "trusted-ecosystem.py"
        ecosystem_source.write_text("import numpy as np\nx=np.array([1,2,3])\n"
                                    "np.reshape(x,(2,2))\n", encoding="utf-8")
        ecosystem = run("v021_ecosystem_static_diagnostics", [
            "lab", "ecosystem-diagnostics", "--python", str(interpreter), "--",
            "--source", str(ecosystem_source)], "STATIC_DIAGNOSIS_UNVERIFIED")
        if ecosystem.get("source_executed") is not False or \
                ecosystem.get("packages_imported") is not False:
            raise AssertionError("ecosystem source or imports were executed")
        dap = run("v022_real_framed_trusted_dap", [
            "lab", "dap-runtime", "--python", str(interpreter), "--",
            "--selftest"], "TRUSTED_DAP_REAL_FRAMED_FIXTURE_PASS")
        if dap.get("unknown_source_executed") is not False:
            raise AssertionError("DAP must never launch untrusted project code")
        policy = run("v022_pep751_610_668_package_policy", [
            "lab", "package-policy", "--python", str(interpreter), "--",
            "--mode", "capabilities"], "READ_ONLY_PACKAGE_POLICY_AVAILABLE")
        if policy.get("network_used") is not False or policy.get("install_performed") is not False:
            raise AssertionError("package-policy made an install or network request")
        hook = run("v022_real_observation_only_audit_hook", [
            "lab", "security-controls", "--python", str(interpreter), "--",
            "--mode", "audit"], "AUDIT_HOOK_OBSERVED_TRUSTED_FIXTURE_ONLY")
        if hook.get("security_boundary") is not False:
            raise AssertionError("sys.addaudithook must not claim to be a sandbox")
        knowledge = run("v022_pinned_knowledge_updates_capability", [
            "lab", "knowledge-updates", "--python", str(interpreter)],
            "LOCAL_PINNED_KNOWLEDGE_CAPABILITIES_ONLY")
        if knowledge.get("unknown_code_executed") is not False:
            raise AssertionError("knowledge module unexpectedly executed source")
        platform = run("v022_actual_linux_libc_platform_probe", [
            "lab", "platform-constraints", "--python", str(interpreter), "--",
            "--mode", "linux"], "LOCAL_LINUX_PLATFORM_DIAGNOSTICS")
        if platform.get("runtime", {}).get("status") != "LOCAL_LIBC_PROBED":
            raise AssertionError("glibc not really inspected on this Linux runtime")
        encrypted = run("v022_real_aes256_gcm_sqlite_rotation", [
            "lab", "encrypted-catalog", "--python", str(interpreter), "--",
            "--mode", "trusted-selftest"],
            "TRUSTED_LOCAL_AES256_GCM_ROTATION_AND_RESTORE_PASS")
        if encrypted.get("unknown_project_code_executed") is not False:
            raise AssertionError("encrypted DB probe executed unknown source")
        vulnerability = run("v022_locally_signed_advisory_capability", [
            "lab", "vulnerability-audit", "--python", str(interpreter)],
            "LOCAL_SIGNED_FEED_CAPABILITY_ONLY")
        if vulnerability.get("official_feed_live_verified") is not False:
            raise AssertionError("unattested local advisory feed claimed official identity")
        typing = run("v022_bounded_multi_module_type_cfg_alias_analysis", [
            "lab", "typed-flow", "--python", str(interpreter)],
            "BOUNDED_STATIC_ANALYSIS_CAPABILITIES")
        if typing.get("unknown_source_execution") is not False:
            raise AssertionError("static typed graph executed target source")
        remote = run("v023_mtls_dap_path_translation", [
            "lab", "remote-dap", "--python", str(interpreter), "--",
            "--fixture-pathmap-selftest"], "SAFE_BOUNDED_LEXICAL_PATH_MAPPING")
        if remote.get("remote_filesystem_verified") is not False:
            raise AssertionError("remote path mapping wrongly claimed real filesystem proof")
        native = run("v023_platform_native_runtime_inspection", [
            "lab", "platform-matrix", "--python", str(interpreter)],
            "ACTUAL_RUNNING_CPYTHON_ABI_INSPECTED")
        if native.get("real_interpreter_queried") is not True:
            raise AssertionError("native runtime info not from real interpreter")
        boundary = run("v023_hostile_tool_bytes_data_only", [
            "lab", "security-integrations", "--python", str(interpreter)],
            "HOSTILE_TOOL_BYTES_QUARANTINED_DATA_ONLY")
        if boundary.get("proposed_tool_calls_executed") is not False:
            raise AssertionError("untrusted tool instructions were executed")
        provenance = run("v023_publisher_source_provenance_capabilities", [
            "lab", "provenance", "--python", str(interpreter)],
            "READ_ONLY_PROVENANCE_CAPABILITIES")
        if provenance.get("publisher_authenticated") is not False:
            raise AssertionError("untrusted publisher identity was claimed authentic")
        ecosystem_v23 = run("v023_real_framework_installed_evidence", [
            "lab", "real-ecosystem", "--python", str(interpreter)],
            "ACTUAL_INSTALLED_ECOSYSTEM_EVIDENCE_INCOMPLETE")
        if ecosystem_v23.get("unknown_project_source_executed") is not False:
            raise AssertionError("framework inventory executed unknown project")
        knowledge_scale = run("v023_knowledge_scale_bounded_capabilities", [
            "lab", "knowledge-scale", "--python", str(interpreter)],
            "KNOWLEDGE_SCALE_BOUNDED_CAPABILITIES_ONLY")
        if knowledge_scale.get("million_document_benchmark_proven") is not False:
            raise AssertionError("millions-of-documents benchmark claimed without corpus")
        free_threaded = run("v023_free_threaded_build_identity_is_not_assumed", [
            "lab", "free-threaded-native", "--python", str(interpreter)],
            "NOT_RUNNING_SUPPORTED_FREE_THREADED_BUILD")
        if free_threaded.get("free_threaded_build_verified") is not False:
            raise AssertionError("normal GIL CPython was misclassified as a free-threaded build")
        variants = run("v023_real_cpython_separated_from_pypy", [
            "lab", "runtime-variants", "--python", str(interpreter)],
            "ACTUAL_CPYTHON_RUNTIME_OBSERVED")
        if variants.get("cpython_native_extension_result_reused_for_pypy") is not False:
            raise AssertionError("CPython native extension was wrongly claimed compatible with PyPy")
        typecheck = run("v023_real_external_typechecker_gated_capability", [
            "lab", "typecheck-integration", "--python", str(interpreter)],
            "TRUSTED_MYPY_PYRIGHT_ADAPTER_AVAILABLE")
        if typecheck.get("mypy_executed") is not False or typecheck.get("pyright_executed") is not False:
            raise AssertionError("type checker capability falsely claimed actual execution")
        preview = run("v023_prerelease_phase_identity_is_not_assumed", [
            "lab", "prerelease-matrix", "--python", str(interpreter)],
            "ACTUAL_FINAL_OR_OTHER_IMPLEMENTATION")
        if preview.get("supported_stable_3_16_qualified") is not False:
            raise AssertionError("future prerelease wrongly claimed full stable qualification")
        cst = run("v023_native_libcst_ast_and_two_type_oracle_capabilities", [
            "lab", "ast-cst-typing", "--python", str(interpreter)],
            "AST_LIBCST_TYPE_ORACLE_ADAPTER_AVAILABLE")
        if cst.get("external_checks_executed") is not False:
            raise AssertionError("type oracle capability falsely claimed executed checkers")
        semantic = run("v023_real_learned_lsa_semantic_adapter_capability", [
            "lab", "semantic-retrieval", "--python", str(interpreter)],
            "LOCAL_TRAINED_SEMANTIC_ENCODER_AVAILABLE_NOT_YET_RUN")
        if semantic.get("labels_consumed_during_training") is not False:
            raise AssertionError("held-out semantic relevance labels leaked into training")
        frameworks = run("v023_real_framework_runtime_capability_gated", [
            "lab", "ecosystem-runtime", "--python", str(interpreter)],
            "PINNED_REAL_FRAMEWORK_FIXTURE_ADAPTER_AVAILABLE")
        if frameworks.get("real_frameworks_executed") is not False:
            raise AssertionError("framework capability falsely claimed a runtime check")
        git_review = run("v023_signed_local_git_review_not_external_pr", [
            "lab", "git-review", "--python", str(interpreter), "--", "--status"],
            "LOCAL_MERGE_APPROVAL_NOT_EXTERNAL_PR")
        if git_review.get("external_github_pr_approved") is not False:
            raise AssertionError("local signed merge wrongly claimed genuine external PR")
        powershell = run("v023_real_powershell_optional_pinned_capability", [
            "lab", "powershell-real", "--python", str(interpreter)],
            "REAL_POWERSHELL_OPTIONAL_PINNED_ADAPTER")
        if powershell.get("native_windows_host_verified") is not False:
            raise AssertionError("Linux PowerShell parser wrongly claimed native Windows OS")
        native_serialization = run("v023_actual_arrow_cffi_orjson_native_adapter_capability", [
            "lab", "native-serialization", "--python", str(interpreter)],
            "PINNED_NATIVE_SERIALIZATION_ADAPTER_AVAILABLE")
        if native_serialization.get("real_packages_imported") is not False:
            raise AssertionError("native package capability falsely claimed runtime import")
        stdlib_native = run("v023_broad_stdlib_ast_plus_native_api_capability", [
            "lab", "stdlib-native-complete", "--python", str(interpreter)],
            "BROAD_STDLIB_API_CAPABILITIES_ONLY")
        if stdlib_native.get("full_c_api_claimed") is not False:
            raise AssertionError("bounded stdlib extractor claimed a complete C API map")
        verified_chain = run("v023_official_sigstore_rekor_supply_chain_capability", [
            "lab", "official-supply-chain", "--python", str(interpreter)],
            "OFFICIAL_SUPPLY_CHAIN_VERIFIER_ADAPTER_AVAILABLE")
        if verified_chain.get("external_verifier_executed") is not False:
            raise AssertionError("supply-chain capability falsely claimed a real verification")
        queue_capability = run("v023_real_redis_celery_separate_worker_capability", [
            "lab", "real-queue", "--python", str(interpreter), "--", "--mode", "capabilities"],
            "REAL_REDIS_CELERY_PRIVATE_ADAPTER_AVAILABLE")
        if (queue_capability.get("redis_server_executed") is not False or
                queue_capability.get("crossprocess_tested") is not False or
                queue_capability.get("unknown_project_source_executed") is not False):
            raise AssertionError("queue capability claimed actual broker/worker execution")
        learned_models = run("v023_trained_dual_model_router_capability", [
            "lab", "real-model-router", "--python", str(interpreter)],
            "TWO_GENUINELY_TRAINABLE_LOCAL_MODELS_NOT_YET_RUN")
        if learned_models.get("trained_model_inference_executed") is not False:
            raise AssertionError("model router capability falsely claimed inference execution")
        code_model_capability = run("v024_compiler_trained_code_model_capability", [
            "lab", "code-model-router", "--python", str(interpreter)],
            "ACTUAL_CODE_MODEL_ROUTER_ADAPTER_AVAILABLE")
        if code_model_capability.get("training_or_model_inference_executed") is not False:
            raise AssertionError("code model capability wrongly claimed real training")
        actual_code_models = run("v024_two_trained_code_models_actual_heldout", [
            "lab", "code-model-router", "--python", str(interpreter),
            "--", "--mode", "selftest"],
            "TRUSTED_CODE_MODEL_LOCAL_SELFTEST_NO_EXTERNAL_AUDIT")
        if (actual_code_models.get("model_routing_demonstrated") is not True or
                actual_code_models.get("external_independent_auditor_attested") is not False or
                any(report.get("exact_repair_rate") < .95 for report in
                    actual_code_models["reports"].values())):
            raise AssertionError("real trained code repair model quality gate missing")
        oci_capability = run("v025_reproducible_oci_layout_not_sandbox_claim", [
            "lab", "oci-layout", "--python", str(interpreter),
            "--", "--mode", "capabilities"],
            "OCI_LAYOUT_CANDIDATE_ADAPTER_AVAILABLE")
        if (oci_capability.get("image_built") is not False or
                oci_capability.get("container_executed") is not False or
                oci_capability.get("sandbox_isolation_verified") is not False or
                oci_capability.get("release_authorized") is not False):
            raise AssertionError("OCI capability probe claimed an untested runtime or release")
    return {"version": label, "checks": entries, "passed": len(entries)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--interpreter", action="append", required=True)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error("Rust release binary missing")
    outcomes = []
    for item in args.interpreter:
        label, separator, executable = item.partition("=")
        if not separator or label not in {"3." + str(x) for x in range(9, 16)}:
            parser.error("invalid interpreter specification")
        outcomes.append(check_version(label, Path(executable).resolve(), binary))
    if len(outcomes) != 7 or len({row["version"] for row in outcomes}) != 7:
        parser.error("all seven actual CPython minor versions required")
    report = {"schema_version": 1,
              "tested_at_utc": datetime.now(timezone.utc).isoformat(),
              "scope": "offline_embedded_rust_lab_adapters_only",
              "network_enabled_by_runner": False,
              "unknown_source_executed": False,
              "full_feature_matrix_qualified": False,
              "checks_pass": sum(row["passed"] for row in outcomes),
              "versions": outcomes,
              "status": "PASS"}
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    expected_count = len(outcomes[0]["checks"]) * len(outcomes)
    print("OFFLINE-LAB {}/{} PASS".format(report["checks_pass"], expected_count))


if __name__ == "__main__":
    sys.exit(main())
