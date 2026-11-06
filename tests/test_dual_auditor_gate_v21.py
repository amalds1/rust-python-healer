"""Real separate signed auditor subprocesses and all fail-closed six-axis gates."""

import copy
import importlib.util
import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("dual_auditor_gate_v21",
                                               ROOT / "python/dual_auditor_gate_v21.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
RUST = ROOT / "target" / "release" / ("rust-python-healer.exe" if sys.platform == "win32" else "rust-python-healer")
RUFF = ROOT.parent / ".uv-bin/ruff"
RUNTIMES = {minor: (Path("/usr/bin/python3.12") if minor == "3.12" else
                    ROOT.parent / ".python-bin" / ("python" + minor))
            for minor in module.MINORS}


class DualAuditorGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not RUST.is_file() or not RUFF.is_file() or any(not p.is_file() for p in RUNTIMES.values()):
            raise unittest.SkipTest("actual Rust, Ruff and all 7 CPython minors required")
        cls.live = module.run_actual_dual_auditors(RUST, RUFF, RUNTIMES)
        cls.keys = {"origin-a": b"A" * 32, "origin-b": b"B" * 32}
        cls.nonces = {"origin-a": "a" * 48, "origin-b": "b" * 48}
        with tempfile.TemporaryDirectory() as temporary:
            cls.artifacts = {}
            for origin in module.AUDITOR_ORIGINS:
                folder = Path(temporary) / origin
                folder.mkdir()
                cls.artifacts[origin] = module.audit_in_independent_origin(
                    origin, cls.keys[origin], cls.nonces[origin], RUST, RUFF, RUNTIMES, folder)

    def verified(self, artifacts=None, keys=None, nonces=None, now=None):
        return module.verify_and_rank(self.artifacts if artifacts is None else artifacts,
                                      self.keys if keys is None else keys,
                                      self.nonces if nonces is None else nonces, now)

    def _resign(self, reports, origin):
        reports[origin]["signature_hmac_sha256"] = module.sign(self.keys[origin], reports[origin]["report"])

    def _change_trusted_retest_to_fail(self, reports, origin, engine):
        body = reports[origin]["report"]
        record = next(row for row in body["candidates"] if row["engine"] == engine)
        record["retests"][0]["status"] = "FAIL"
        record["metrics"]["CORRECTNESS"] = 1
        record["metrics"]["RELIABILITY"] = 9
        record["gate_status"]["CORRECTNESS"] = "FAIL"
        record["gate_status"]["RELIABILITY"] = "FAIL"
        record["proof_sha256"] = module.digest(module.canonical({
            "source": record["source_sha256"], "candidate": record["candidate_sha256"],
            "rust_status": record["rust_repair_status"], "retests": record["retests"],
            "minors": record["minor_outcomes"], "nonce": self.nonces[origin],
            "origin": origin}))
        self._resign(reports, origin)

    def test_two_actual_independent_auditor_processes_produce_winner_and_reserve(self):
        report = self.live
        self.assertEqual(report["status"], "LOCAL_TWO_INDEPENDENT_SIGNED_AUDITORS", report)
        self.assertEqual(report["decision"], "TRUSTED_FIXTURE_PRIMARY")
        self.assertEqual(report["actual_local_auditor_processes"], 2)
        self.assertEqual(report["actual_trusted_probe_processes"], 68)
        self.assertEqual(report["distinct_local_origins"], ["origin-a", "origin-b"])
        self.assertTrue(report["independent_local_signatures_verified"])
        self.assertNotEqual(report["primary_variant"], report["reserve_variant"])
        self.assertEqual(report["maximum_reserves"], 1)
        self.assertFalse(report["external_independent_audit"])
        self.assertFalse(report["release_authorized"])

    def test_both_cryptographically_signed_observations_are_rechecked(self):
        report = self.verified()
        self.assertEqual(report["verified_candidate_count"], 2)
        self.assertTrue(report["all_six_axes_verified_by_both_local_origins"])
        self.assertTrue(report["ranked_only_after_both_signed_reports"])
        self.assertEqual(len(report["decisions"]), 2)

    def test_six_axes_each_actually_pass_on_both_repair_candidates(self):
        for origin in module.AUDITOR_ORIGINS:
            report = self.artifacts[origin]["report"]
            self.assertEqual(report["version_proofs"], {version: version for version in module.MINORS})
            for candidate in report["candidates"]:
                self.assertEqual(set(candidate["metrics"]), set(module.AXES))
                self.assertEqual(set(candidate["gate_status"].values()), {"PASS"})
                self.assertEqual(candidate["test_processes"], 17)
                self.assertEqual(len(candidate["retests"]), 10)
                self.assertEqual(set(candidate["minor_outcomes"]), set(module.MINORS))
                self.assertTrue(candidate["snapshot_intact"])
                self.assertEqual(candidate["rust_repair_status"], "PASS")

    def test_stable_sha256_variants_from_two_independent_rust_repair_runs(self):
        left, right = (self.artifacts[origin]["report"]["candidates"] for origin in module.AUDITOR_ORIGINS)
        self.assertEqual({row["candidate_sha256"] for row in left},
                         {row["candidate_sha256"] for row in right})
        self.assertEqual(len({row["proof_sha256"] for report in (left, right)
                              for row in report}), 4)

    def test_hmac_verification_rejects_mutated_measurement(self):
        reports = copy.deepcopy(self.artifacts)
        reports["origin-a"]["report"]["candidates"][0]["metrics"]["SPEED"] = 0
        result = self.verified(reports)
        self.assertEqual(result["decision"], "NO_WINNER")
        self.assertEqual(result["reason"], "independent_hmac_signature_invalid")

    def test_nan_poisoning_and_non_ascii_signature_fail_closed(self):
        reports = copy.deepcopy(self.artifacts)
        reports["origin-a"]["report"]["candidates"][0]["metrics"]["SPEED"] = float("nan")
        self.assertEqual(self.verified(reports)["decision"], "NO_WINNER")
        reports = copy.deepcopy(self.artifacts)
        reports["origin-a"]["signature_hmac_sha256"] = "☃" * 64
        self.assertEqual(self.verified(reports)["decision"], "NO_WINNER")

    def test_identical_signing_keys_collusion_is_blocked(self):
        fake_keys = dict(self.keys)
        fake_keys["origin-b"] = fake_keys["origin-a"]
        result = self.verified(keys=fake_keys)
        self.assertEqual(result["decision"], "NO_WINNER")
        self.assertEqual(result["reason"], "keys_not_independent_or_invalid")

    def test_replayed_or_wrong_session_nonce_rejected(self):
        fake = dict(self.nonces)
        fake["origin-b"] = "z" * 48
        result = self.verified(nonces=fake)
        self.assertEqual(result["decision"], "NO_WINNER")
        self.assertEqual(result["reason"], "replayed_or_mislabeled_local_auditor")

    def test_duplicate_nonce_rejected_before_signatures(self):
        fake = dict(self.nonces)
        fake["origin-b"] = fake["origin-a"]
        self.assertEqual(self.verified(nonces=fake)["decision"], "NO_WINNER")

    def test_expired_signed_auditor_evidence_fails_closed(self):
        reports = copy.deepcopy(self.artifacts)
        reports["origin-a"]["report"]["reported_at_unix"] = time.time() - 1000
        self._resign(reports, "origin-a")
        result = self.verified(reports)
        self.assertEqual(result["reason"], "stale_future_or_replayed_evidence")

    def test_signed_report_from_future_is_rejected(self):
        reports = copy.deepcopy(self.artifacts)
        reports["origin-a"]["report"]["reported_at_unix"] = time.time() + 30
        self._resign(reports, "origin-a")
        self.assertEqual(self.verified(reports)["reason"], "stale_future_or_replayed_evidence")

    def test_valid_hmac_wrong_real_version_proof_rejected(self):
        reports = copy.deepcopy(self.artifacts)
        reports["origin-b"]["report"]["version_proofs"]["3.15"] = "3.14"
        self._resign(reports, "origin-b")
        result = self.verified(reports)
        self.assertEqual(result["reason"], "version_mismatch_or_missing_minor")

    def test_missing_six_axis_metric_rejected_even_if_resigned(self):
        reports = copy.deepcopy(self.artifacts)
        del reports["origin-a"]["report"]["candidates"][0]["metrics"]["SAFETY"]
        self._resign(reports, "origin-a")
        result = self.verified(reports)
        self.assertEqual(result["reason"], "six_measured_axes_required")

    def test_changed_external_audit_claim_rejected_even_with_valid_hmac(self):
        reports = copy.deepcopy(self.artifacts)
        reports["origin-b"]["report"]["independent_external_auditor"] = True
        self._resign(reports, "origin-b")
        self.assertEqual(self.verified(reports)["decision"], "NO_WINNER")

    def test_false_hard_gate_cannot_be_signed_as_pass(self):
        reports = copy.deepcopy(self.artifacts)
        reports["origin-a"]["report"]["candidates"][0]["gate_status"]["SAFETY"] = "FAIL"
        self._resign(reports, "origin-a")
        self.assertEqual(self.verified(reports)["reason"], "signed_gate_disagrees_with_predeclared_threshold")

    def test_signed_evidence_same_proof_for_two_auditors_rejected(self):
        reports = copy.deepcopy(self.artifacts)
        reports["origin-b"]["report"]["candidates"][0]["proof_sha256"] = (
            reports["origin-a"]["report"]["candidates"][0]["proof_sha256"])
        self._resign(reports, "origin-b")
        self.assertEqual(self.verified(reports)["decision"], "NO_WINNER")

    def test_one_auditor_failing_one_candidate_leaves_only_primary_no_reserve(self):
        reports = copy.deepcopy(self.artifacts)
        self._change_trusted_retest_to_fail(reports, "origin-a", "ruff")
        result = self.verified(reports)
        self.assertEqual(result["decision"], "TRUSTED_FIXTURE_PRIMARY", result)
        self.assertEqual(result["verified_candidate_count"], 1)
        self.assertIsNone(result["reserve_variant"])

    def test_conflicts_across_both_candidates_produce_no_winner(self):
        reports = copy.deepcopy(self.artifacts)
        self._change_trusted_retest_to_fail(reports, "origin-a", "ruff")
        self._change_trusted_retest_to_fail(reports, "origin-b", "colon")
        result = self.verified(reports)
        self.assertEqual(result["decision"], "NO_WINNER", result)
        self.assertIsNone(result["primary_variant"])
        self.assertIsNone(result["reserve_variant"])

    def test_missing_auditor_origin_rejected(self):
        fake = {"origin-a": self.artifacts["origin-a"]}
        self.assertEqual(self.verified(fake)["reason"], "two_distinct_auditor_origins_required")

    def test_missing_selected_rust_binary_is_not_a_success(self):
        report = module.run_actual_dual_auditors("/nonexistent/rust", RUFF, RUNTIMES)
        self.assertEqual(report["status"], "NOT_RUN_MISSING_EXECUTABLE")
        self.assertEqual(report["decision"], "NO_WINNER")

    def test_public_cli_two_actual_auditor_origins_json_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtimes.json"
            path.write_text(json.dumps({minor: str(p) for minor, p in RUNTIMES.items()}),
                            encoding="utf-8")
            proc = subprocess.run([sys.executable, "-I", "-S", "-B",
                                   str(ROOT / "python/dual_auditor_gate_v21.py"),
                                   "--binary", str(RUST), "--ruff", str(RUFF),
                                   "--runtime-json", str(path)],
                                  capture_output=True, check=False, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["status"], "LOCAL_TWO_INDEPENDENT_SIGNED_AUDITORS")

    def test_hmac_signing_rejects_invalid_key_size(self):
        with self.assertRaisesRegex(ValueError, "invalid_auditor_key"):
            module.sign(b"short", {"x": 1})


if __name__ == "__main__":
    unittest.main()
