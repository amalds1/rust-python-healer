"""Bounded persistent metrics: arithmetic is tested, billing claims are not."""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("experiment_metrics", ROOT / "python" / "experiment_metrics.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


def operator_policy():
    return {"schema_version": 1, "policy_id": "P-fixture", "minimum_repetitions": 10,
            "maximum_latency_p95_ms": 50, "maximum_wait_p95_ms": 20,
            "maximum_cloud_micro_usd": 10_000}


def evidence_fixture(count=10, statuses=None, engine="safe-ruff"):
    code_hash = hashlib.sha256((engine + " source").encode()).hexdigest()
    conf_hash = hashlib.sha256((engine + " config").encode()).hexdigest()
    ident = "V-" + hashlib.sha256((engine + ":" + code_hash + ":" +
                                     conf_hash).encode()).hexdigest()[:16]
    rows = []
    for i in range(count):
        status = statuses[i] if statuses else "PASS"
        start = i * 10 + 2
        duration = 4 if status != "NOT_RUN" else 0
        rows.append({"run_id": f"run-{i}", "runtime": "3.12", "status": status,
                     "retest": i != 0, "submitted_ms": i * 10,
                     "started_ms": start, "finished_ms": start + duration,
                     "input_tokens": 10 if status != "NOT_RUN" else 0,
                     "output_tokens": 5 if status != "NOT_RUN" else 0,
                     "cloud_micro_usd": 100 if status != "NOT_RUN" else 0,
                     "provider": "test-provider"})
    return {"schema_version": 1, "candidate": {
        "variant_id": ident, "engine": engine, "code_sha256": code_hash,
        "config_sha256": conf_hash}, "runs": rows}


class ExperimentMetricsTests(unittest.TestCase):
    def test_ten_distinct_retests_are_recorded_with_real_sqlite_aggregation(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "measurements.sqlite"
            policy, evidence = operator_policy(), evidence_fixture()
            recorded = module.ingest(db, policy, evidence)
            self.assertEqual(recorded["status"], "RECORDED_UNVERIFIED")
            self.assertEqual(recorded["events_added"], 10)
            self.assertFalse(recorded["usage_independently_verified"])
            report = module.report(db, policy, evidence["candidate"]["variant_id"])
            stats = report["statistics"]
            self.assertEqual(stats["state"], "TEN_OR_MORE_IDENTICAL_STATUS_RETESTS_RECORDED_NOT_PROVEN")
            self.assertEqual(stats["runs"], 10)
            self.assertEqual(stats["pass"], 10)
            self.assertEqual(stats["total_input_tokens_recorded"], 100)
            self.assertEqual(stats["total_output_tokens_recorded"], 50)
            self.assertEqual(stats["total_cloud_micro_usd_recorded"], 1000)
            self.assertEqual(stats["duration_median_ms"], 4)
            self.assertEqual(stats["duration_p95_ms"], 4)
            self.assertEqual(stats["queue_wait_p95_ms"], 2)
            self.assertEqual(stats["peak_queued_events"], 1)
            self.assertTrue(stats["all_numeric_gates_pass"])
            self.assertFalse(stats["observations_verified"])
            self.assertFalse(report["release_authorized"])

    def test_fewer_than_ten_repetitions_are_never_qualified(self):
        data = evidence_fixture(9)["runs"]
        stats = module.summarize(data, operator_policy())
        self.assertEqual(stats["state"], "INSUFFICIENT_REPETITIONS")
        self.assertFalse(stats["gate_results"]["min_repetitions"])

    def test_failed_and_not_run_rows_never_mark_reliability_as_pass(self):
        statuses = ["PASS"] * 8 + ["FAIL", "NOT_RUN"]
        data = evidence_fixture(10, statuses)["runs"]
        stats = module.summarize(data, operator_policy())
        self.assertEqual(stats["state"], "OBSERVED_FAIL_OR_MISSING")
        self.assertEqual(stats["fail"], 1)
        self.assertEqual(stats["not_run"], 1)
        self.assertFalse(stats["gate_results"]["min_repetitions"])

    def test_duplicate_run_ids_and_implicit_retests_are_rejected(self):
        policy = operator_policy()
        data = evidence_fixture()
        data["runs"][1]["run_id"] = data["runs"][0]["run_id"]
        with self.assertRaisesRegex(ValueError, "duplicate_run_id"):
            module.ingest("unused.sqlite", policy, data)
        data = evidence_fixture()
        data["runs"][1]["retest"] = False
        with self.assertRaisesRegex(ValueError, "explicit_retest"):
            module.validate_evidence(data)

    def test_policy_thresholds_are_independent_and_cannot_be_silently_weakened(self):
        policy = operator_policy()
        policy["minimum_repetitions"] = 9
        with self.assertRaisesRegex(ValueError, "at_least_ten"):
            module.validate_policy(policy)
        policy = operator_policy()
        policy["maximum_cloud_micro_usd"] = True
        with self.assertRaisesRegex(ValueError, "invalid_cloud"):
            module.validate_policy(policy)
        policy = operator_policy()
        policy["maximum_latency_p95_ms"] = float("nan")
        with self.assertRaisesRegex(ValueError, "invalid_latency"):
            module.validate_policy(policy)

    def test_tampering_an_immutable_record_is_rejected_by_hash_chain(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "ledger.sqlite"
            evidence, policy = evidence_fixture(), operator_policy()
            module.ingest(db, policy, evidence)
            connection = sqlite3.connect(str(db))
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE usage_events SET cloud_micro_usd = 0 WHERE seq = 1")
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("DELETE FROM usage_events WHERE seq = 1")
            connection.execute("DROP TRIGGER usage_no_update")
            connection.execute("UPDATE usage_events SET cloud_micro_usd = 0 WHERE seq = 1")
            connection.commit()
            connection.close()
            with self.assertRaisesRegex(ValueError, "usage_evidence_tampered"):
                module.report(db, policy, evidence["candidate"]["variant_id"])

    def test_failed_batch_is_atomic_and_never_partially_persisted(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "ledger.sqlite"
            policy, evidence = operator_policy(), evidence_fixture()
            module.ingest(db, policy, evidence)
            duplicate = evidence_fixture(2, engine="second")
            duplicate["runs"][1]["run_id"] = duplicate["runs"][0]["run_id"]
            with self.assertRaises(ValueError):
                module.ingest(db, policy, duplicate)
            connection = sqlite3.connect(str(db))
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM usage_events").fetchone()[0], 10)
            connection.close()

    def test_existing_candidate_can_append_only_with_new_explicit_retest(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "ledger.sqlite"
            policy, evidence = operator_policy(), evidence_fixture(2)
            module.ingest(db, policy, evidence)
            extension = evidence_fixture(2)
            extension["runs"][0]["run_id"] = "run-2"
            extension["runs"][1]["run_id"] = "run-3"
            with self.assertRaisesRegex(ValueError, "existing_candidate_requires_explicit_retest"):
                module.ingest(db, policy, extension)
            extension["runs"][0]["retest"] = True
            module.ingest(db, policy, extension)
            self.assertEqual(module.report(db, policy, evidence["candidate"]["variant_id"])[
                "statistics"]["runs"], 4)

    def test_reused_identifier_is_rejected_even_when_retest_requested(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "ledger.sqlite"
            policy = operator_policy()
            evidence = evidence_fixture(1)
            module.ingest(db, policy, evidence)
            evidence["runs"][0]["retest"] = True
            with self.assertRaises(sqlite3.IntegrityError):
                module.ingest(db, policy, evidence)

    def test_nearest_rank_p95_rejects_outlier_instead_of_using_mean(self):
        values = [4] * 19 + [100]
        self.assertEqual(module.percentile(values, 0.95), 4)
        self.assertEqual(module.percentile(values, 1.0), 100)
        self.assertIsNone(module.percentile([], 0.95))
        data = evidence_fixture(20)["runs"]
        data[18]["finished_ms"] += 100
        data[19]["finished_ms"] += 100
        stats = module.summarize(data, operator_policy())
        self.assertGreater(stats["duration_p95_ms"], 50)
        self.assertFalse(stats["gate_results"]["latency_p95_ms"])

    def test_impossible_timelines_nan_and_bools_are_rejected(self):
        evidence = evidence_fixture(2)
        evidence["runs"][0]["started_ms"] = -1
        with self.assertRaisesRegex(ValueError, "invalid_timestamp"):
            module.validate_evidence(evidence)
        evidence = evidence_fixture(2)
        evidence["runs"][0]["finished_ms"] = 0
        with self.assertRaisesRegex(ValueError, "impossible_timeline"):
            module.validate_evidence(evidence)
        evidence = evidence_fixture(2)
        evidence["runs"][0]["input_tokens"] = True
        with self.assertRaisesRegex(ValueError, "invalid_usage_metric"):
            module.validate_evidence(evidence)

    def test_symlinked_hardlinked_and_oversized_json_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "safe.json"
            path.write_text(json.dumps(operator_policy()))
            symbolic = root / "link.json"
            symbolic.symlink_to(path)
            with self.assertRaisesRegex(ValueError, "input_symlink_refused"):
                module.bounded_json(symbolic)
            hard = root / "hard.json"
            os.link(str(path), str(hard))
            with self.assertRaisesRegex(ValueError, "input_not_unique_regular"):
                module.bounded_json(path)
            hard.unlink()
            path.write_bytes(b"x" * (module.MAX_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "input_oversized"):
                module.bounded_json(path)

    def test_duplicate_json_keys_nonfinite_and_private_identity_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "duplicate.json"
            path.write_text('{"schema_version":1,"schema_version":1}')
            with self.assertRaisesRegex(ValueError, "duplicate_json_key"):
                module.bounded_json(path)
            path.write_text('{"unexpected":NaN}')
            with self.assertRaisesRegex(ValueError, "nonfinite_json_number"):
                module.bounded_json(path)
            evidence = evidence_fixture(1)
            evidence["runs"][0]["provider"] = "https://user:token@provider.invalid/secret"
            with self.assertRaisesRegex(ValueError, "invalid_run_identity"):
                module.validate_evidence(evidence)

    def test_cli_records_and_reports_without_claiming_audited_usage(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            policy_file, evidence_file = root / "policy.json", root / "evidence.json"
            db = root / "ledger.sqlite"
            policy_file.write_text(json.dumps(operator_policy()))
            evidence = evidence_fixture()
            evidence_file.write_text(json.dumps(evidence))
            base = [sys.executable, "-I", "-S", "-B", str(ROOT / "python/experiment_metrics.py"),
                    "--db", str(db), "--policy", str(policy_file)]
            done = subprocess.run(base + ["--evidence", str(evidence_file)],
                                  capture_output=True, text=True, check=False)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(json.loads(done.stdout)["events_added"], 10)
            report = subprocess.run(base + ["--candidate", evidence["candidate"]["variant_id"]],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(report.returncode, 0, report.stderr)
            payload = json.loads(report.stdout)
            self.assertFalse(payload["release_authorized"])
            self.assertFalse(payload["tests_independently_executed"])
            self.assertEqual(payload["statistics"]["total_cloud_micro_usd_recorded"], 1000)

    def test_missing_ledger_report_does_not_create_files(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "not_here.sqlite"
            with self.assertRaisesRegex(ValueError, "missing_ledger"):
                module.report(db, operator_policy(), evidence_fixture()["candidate"]["variant_id"])
            self.assertFalse(db.exists())


if __name__ == "__main__":
    unittest.main()
