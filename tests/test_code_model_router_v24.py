"""F127 bounded actual code-model routing on every CPython 3.9–3.15."""

import hashlib
import copy
import hmac
from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "code_model_router_v24.py"
SPEC = spec_from_file_location("rph_code_model_router_v24", SCRIPT)
router = module_from_spec(SPEC)
SPEC.loader.exec_module(router)
INDEPENDENT_AUDITOR_KEY = b"independent-frozen-real-compiler-holdout-auditor-v24"


class RealCodeRepairModelsTests(unittest.TestCase):
    def test_constant_clocks_terminate_at_real_call_cap_without_epsilon(self):
        calls = [0]
        def plain_inference(model, features):
            calls[0] += 1
            return "COLON"
        with patch.object(router, "infer", plain_inference), \
                patch.object(router.time, "process_time_ns", return_value=0), \
                patch.object(router.time, "perf_counter_ns", return_value=0):
            result = router.measure_inference_batch({}, {})
        self.assertEqual(calls[0], 65536)
        self.assertEqual(result["repetitions"], 65536)
        self.assertEqual(result["status"], "NOT_RUN_TIMER_RESOLUTION")
        self.assertEqual((result["process_cpu_ns"], result["wall_ns"], result["mean_cpu_us"], result["mean_wall_us"]), (0, 0, 0, 0))

    def test_batch_means_are_derived_from_raw_measured_thresholds(self):
        with patch.object(router, "infer", return_value="COLON") as inference, \
                patch.object(router.time, "process_time_ns", side_effect=[0, 1_000_000]), \
                patch.object(router.time, "perf_counter_ns", side_effect=[0, 5_000_000]):
            result = router.measure_inference_batch({}, {})
        self.assertEqual(result["status"], "MEASURED")
        self.assertEqual(inference.call_count, 64)
        self.assertEqual(result["mean_cpu_us"], 1_000_000 / 64 / 1000)
        self.assertEqual(result["mean_wall_us"], 5_000_000 / 64 / 1000)

    def test_cpu_and_wall_thresholds_are_both_required_and_timeout_is_not_qualified(self):
        for cpu, wall, expected in ((999999, 500000000, "NOT_RUN_TIMER_RESOLUTION"),
                                    (1000000, 4999999, "NOT_RUN_TIMER_RESOLUTION"),
                                    (1000000, 500000001, "NOT_RUN_SAMPLE_BUDGET")):
            with self.subTest(cpu=cpu, wall=wall), \
                    patch.object(router, "infer", lambda model, features: "COLON"):
                # Give each clock a real zero start, then constant insufficient observations.
                cpu_counter = iter([0] + [cpu] * 1024)
                wall_counter = iter([0] + [wall] * 1024)
                with patch.object(router.time, "process_time_ns", side_effect=lambda: next(cpu_counter)), \
                        patch.object(router.time, "perf_counter_ns", side_effect=lambda: next(wall_counter)):
                    result = router.measure_inference_batch({}, {})
            self.assertEqual(result["status"], expected)

    def test_backwards_calibration_cpu_or_wall_clock_is_rejected(self):
        for cpu, wall in (([100, 99], [100, 101]), ([100, 101], [100, 99])):
            with self.subTest(cpu=cpu, wall=wall), patch.object(router, "infer", return_value="COLON"), \
                    patch.object(router.time, "process_time_ns", side_effect=cpu), \
                    patch.object(router.time, "perf_counter_ns", side_effect=wall):
                with self.assertRaisesRegex(ValueError, "calibration_monotonic_clock_went_backwards"):
                    router.measure_inference_batch({}, {})

    def test_valid_hmac_cannot_qualify_missing_zero_legacy_or_forged_timing(self):
        for variant in ("missing", "legacy", "zero", "repetitions", "mean", "p95", "method", "duplicate"):
            with self.subTest(variant=variant):
                receipt = json.loads(json.dumps(self.calibration))
                for report in receipt["reports"].values():
                    report["exact_repair_rate"] = 1
                    if variant == "missing": del report["timing"]
                    elif variant == "legacy":
                        report.pop("timing"); report["p95_wall_us"] = report["p95_cpu_us"] = .001
                    elif variant == "zero": report["timing"]["samples"][0]["process_cpu_ns"] = 0
                    elif variant == "repetitions": report["timing"]["samples"][0]["repetitions"] = 0
                    elif variant == "mean": report["timing"]["samples"][0]["mean_wall_us"] = .001
                    elif variant == "p95": report["p95_cpu_us"] = .001
                    elif variant == "method": report["timing"]["method"] = "SINGLE_CALL_FLOORED_LEGACY"
                    else: report["timing"]["samples"][1]["source_sha256"] = report["timing"]["samples"][0]["source_sha256"]
                receipt.pop("auditor_hmac_sha256")
                receipt["auditor_hmac_sha256"] = hmac.new(INDEPENDENT_AUDITOR_KEY, router.canonical(receipt), hashlib.sha256).hexdigest()
                result = router.route_task(self.models, receipt, self.oracle["cases"][0]["source"], INDEPENDENT_AUDITOR_KEY)
                self.assertEqual(result["status"], "NO_QUALIFIED_MODEL_FOR_BUDGET")

    def test_unresolved_timing_preserves_once_per_case_quality_and_source_identity(self):
        original_models, original_oracle = copy.deepcopy(self.models), copy.deepcopy(self.oracle)
        unresolved = {"status": "NOT_RUN_TIMER_RESOLUTION", "repetitions": 65536,
                      "process_cpu_ns": 0, "wall_ns": 0, "mean_cpu_us": 0, "mean_wall_us": 0}
        with patch.object(router, "measure_inference_batch", side_effect=lambda *args: dict(unresolved)), \
                patch.object(router, "infer", wraps=router.infer) as inference:
            receipt = router.calibrate(self.models, self.oracle, self.signature, INDEPENDENT_AUDITOR_KEY)
        self.assertEqual(inference.call_count, 64)
        self.assertEqual(receipt["status"], "NOT_RUN_CALIBRATION_TIMING_UNRESOLVED")
        for report in receipt["reports"].values():
            self.assertEqual(report["actual_oracle_runs"], 32)
            self.assertGreaterEqual(report["exact_repair_rate"], router.MIN_QUALITY)
            self.assertIsNone(report["p95_cpu_us"])
            self.assertIsNone(report["p95_wall_us"])
        self.assertEqual(self.models, original_models)
        self.assertEqual(self.oracle, original_oracle)
        result = router.route_task(self.models, receipt, self.oracle["cases"][0]["source"], INDEPENDENT_AUDITOR_KEY)
        self.assertEqual(result["status"], "NO_QUALIFIED_MODEL_FOR_BUDGET")

    def test_real_raw_case_batch_means_and_p95_contract_are_complete(self):
        for report in self.calibration["reports"].values():
            self.assertTrue(router.qualified_case_batch_timing(report))
            self.assertEqual(report["timing"]["p95_statistic"], "NEAREST_RANK_P95_OF_CASE_BATCH_MEANS_US")
            self.assertFalse(report["timing"]["single_call_p95_claimed"])
            self.assertEqual({row["source_sha256"] for row in report["timing"]["samples"]},
                {router.digest(row["source"].encode()) for row in self.oracle["cases"]})

    def test_zero_elapsed_sample_is_not_replaced_by_invented_duration(self):
        with patch.object(router.time, "perf_counter_ns", return_value=123):
            report = router.route_task(self.models, self.calibration,
                                       self.oracle["cases"][0]["source"], INDEPENDENT_AUDITOR_KEY)
        self.assertEqual(report["status"], "ACTUAL_TRAINED_CODE_MODEL_PROPOSED_COMPILE_ONLY")
        self.assertEqual(report["actual_inference_us"], 0)
        self.assertEqual(report["actual_inference_wall_ns"], 0)
        self.assertEqual(report["actual_inference_timing_status"], "NOT_RUN_TIMER_RESOLUTION")
        self.assertFalse(report["source_code_executed"])

    @classmethod
    def setUpClass(cls):
        cls.models = router.train_models()
        cls.oracle = {"schema": 1, "domain": router.TASK_DOMAIN,
                      "cases": router.frozen_sources(train=False)}
        cls.signature = hmac.new(INDEPENDENT_AUDITOR_KEY,
                                 router.canonical(cls.oracle),
                                 hashlib.sha256).hexdigest()
        cls.calibration = router.calibrate(cls.models, cls.oracle,
                                           cls.signature, INDEPENDENT_AUDITOR_KEY)

    def test_actually_two_independent_learned_models_and_no_duplicate_training(self):
        self.assertEqual(set(self.models), set(router.MODEL_FAMILIES))
        first, second = self.models.values()
        self.assertNotEqual(first["model_sha256"], second["model_sha256"])
        self.assertEqual(first["training_count"], 120)
        self.assertEqual(second["training_count"], 120)
        self.assertEqual(len(first["training_source_sha256"]), 120)
        self.assertEqual(first["training_source_sha256"],
                         second["training_source_sha256"])
        self.assertEqual(first["model_sha256"], router.fingerprint_model(first))
        self.assertEqual(second["model_sha256"], router.fingerprint_model(second))

    def test_all_32_real_heldout_compiler_diagnostics_are_disjoint(self):
        self.assertEqual(len(self.oracle["cases"]), 32)
        ids = set()
        for row in self.oracle["cases"]:
            report = router.compiler_diagnostic(row["source"])
            self.assertEqual(report["status"], "REAL_CPYTHON_SYNTAX_ERROR")
            self.assertFalse(report["source_executed"])
            source_sha = router.digest(row["source"].encode())
            self.assertNotIn(source_sha, ids)
            self.assertNotIn(source_sha, next(iter(self.models.values()))[
                "training_source_sha256"])
            ids.add(source_sha)

    def test_both_models_achieve_independent_exact_source_oracle(self):
        self.assertEqual(self.calibration["status"],
                         "TWO_ACTUALLY_TRAINED_CODE_MODELS_CALIBRATED")
        for family in router.MODEL_FAMILIES:
            report = self.calibration["reports"][family]
            self.assertEqual(report["actual_oracle_runs"], 32)
            self.assertGreaterEqual(report["exact_repair_rate"], router.MIN_QUALITY)
            self.assertTrue(all(v >= router.MIN_QUALITY for v in
                                report["per_kind_repair_rate"].values()))
            self.assertGreater(report["p95_wall_us"], 0)
            self.assertGreater(report["p95_cpu_us"], 0)
            self.assertEqual(report["compute_cost_unit"],
                             "actual_process_CPU_microseconds_not_money")

    def test_real_router_selects_model_for_each_approved_code_task(self):
        for case in self.oracle["cases"]:
            with self.subTest(kind=case["kind"], source=case["source"]):
                result = router.route_task(self.models, self.calibration,
                                           case["source"], INDEPENDENT_AUDITOR_KEY)
                self.assertEqual(result["status"],
                                 "ACTUAL_TRAINED_CODE_MODEL_PROPOSED_COMPILE_ONLY")
                self.assertIn(result["model_family"], router.MODEL_FAMILIES)
                self.assertEqual(result["candidate_sha256"], case["expected_sha256"])
                self.assertGreater(result["actual_inference_us"], 0)
                self.assertTrue(result["model_inference_executed"])
                self.assertFalse(result["source_code_executed"])
                self.assertFalse(result["source_file_modified"])
                self.assertFalse(result["candidate_auto_promoted"])
                self.assertFalse(result["arbitrary_project_correctness_attested"])

    def test_code_model_output_is_only_one_character_diff_not_source_dump(self):
        for row in self.oracle["cases"]:
            result = router.route_task(self.models, self.calibration, row["source"],
                                       INDEPENDENT_AUDITOR_KEY)
            self.assertIn(result["edit"]["insert"], ":)]}")
            self.assertEqual(result["edit"]["line"], 1)
            self.assertNotIn("candidate_source", result)
            self.assertNotIn(row["source"], json.dumps(result))

    def test_actual_compiler_only_never_executes_valid_hostile_source(self):
        with tempfile.TemporaryDirectory(prefix="rph-v24-noexec-") as folder:
            target = Path(folder) / "must-not-exist.txt"
            user_source = "__import__('pathlib').Path({!r}).write_text('BAD')\n".format(
                str(target))
            result = router.route_task(self.models, self.calibration,
                                       user_source, INDEPENDENT_AUDITOR_KEY)
            self.assertEqual(result["status"], "NO_SYNTAX_ERROR_NO_REPAIR")
            self.assertFalse(target.exists())
            self.assertFalse(result["source_code_executed"])

    def test_wrong_domain_is_not_silent_general_python_ai_execution(self):
        source = self.oracle["cases"][0]["source"]
        result = router.route_task(self.models, self.calibration, source,
                                   INDEPENDENT_AUDITOR_KEY,
                                   task_domain="arbitrary_python_bug_autofix")
        self.assertEqual(result["status"], "NO_QUALIFIED_MODEL_FOR_TASK_DOMAIN")
        self.assertFalse(result["source_code_executed"])

    def test_budget_limits_fail_closed_without_false_pass(self):
        source = self.oracle["cases"][0]["source"]
        for limit in (0.00001, 0.0001):
            result = router.route_task(self.models, self.calibration, source,
                                       INDEPENDENT_AUDITOR_KEY,
                                       max_p95_wall_us=limit,
                                       max_p95_cpu_us=limit)
            self.assertEqual(result["status"], "NO_QUALIFIED_MODEL_FOR_BUDGET")

    def test_insufficient_quality_gate_refuses_false_success(self):
        source = self.oracle["cases"][0]["source"]
        for quality in (-1, 0, 1.2, "good"):
            result = router.route_task(self.models, self.calibration,
                                       source, INDEPENDENT_AUDITOR_KEY,
                                       min_quality=quality)
            self.assertEqual(result["status"], "NO_QUALIFIED_MODEL_FOR_TASK_DOMAIN")

    def test_unsigned_oracle_and_modified_signed_oracle_rejected(self):
        with self.assertRaisesRegex(ValueError, "independent_signed_oracle_required"):
            router.calibrate(self.models, self.oracle, "0" * 64,
                             INDEPENDENT_AUDITOR_KEY)
        forged = dict(self.oracle)
        forged["cases"] = [dict(row) for row in self.oracle["cases"]]
        forged["cases"][0]["expected_sha256"] = "a" * 64
        with self.assertRaisesRegex(ValueError, "independent_signed_oracle_required"):
            router.calibrate(self.models, forged, self.signature,
                             INDEPENDENT_AUDITOR_KEY)

    def test_oracle_duplicate_and_train_overlap_rejected_even_if_resigned(self):
        forged = dict(self.oracle)
        forged["cases"] = [dict(row) for row in self.oracle["cases"]]
        forged["cases"][1]["source"] = forged["cases"][0]["source"]
        signature = hmac.new(INDEPENDENT_AUDITOR_KEY, router.canonical(forged),
                             hashlib.sha256).hexdigest()
        with self.assertRaisesRegex(ValueError, "heldout_train_overlap_or_duplicate"):
            router.calibrate(self.models, forged, signature, INDEPENDENT_AUDITOR_KEY)

    def test_calibration_quality_tamper_and_wrong_auditor_key_rejected(self):
        damaged = dict(self.calibration)
        damaged["reports"] = dict(self.calibration["reports"])
        damaged["reports"][router.MODEL_FAMILIES[0]] = dict(
            damaged["reports"][router.MODEL_FAMILIES[0]])
        damaged["reports"][router.MODEL_FAMILIES[0]]["exact_repair_rate"] = 0.5
        with self.assertRaisesRegex(ValueError, "model_calibration_tampered"):
            router.route_task(self.models, damaged, self.oracle["cases"][0]["source"],
                              INDEPENDENT_AUDITOR_KEY)
        with self.assertRaisesRegex(ValueError, "model_calibration_tampered"):
            router.route_task(self.models, self.calibration,
                              self.oracle["cases"][0]["source"], b"x" * 32)

    def test_learned_model_weights_tamper_detected_independently_of_receipt(self):
        model = self.models["multiclass_perceptron"]
        weights = model["weights"]["COLON"]
        feature = "one_unclosed:PAREN"
        existed = feature in weights
        original = weights[feature]
        weights[feature] = original + 100000
        try:
            with self.assertRaisesRegex(ValueError, "trained_model_parameters_tampered"):
                router.route_task(self.models, self.calibration,
                                  self.oracle["cases"][0]["source"],
                                  INDEPENDENT_AUDITOR_KEY)
        finally:
            if existed:
                weights[feature] = original
            else:
                del weights[feature]

    def test_no_silent_repair_for_unsupported_syntax_semantics(self):
        for source in ("return 1\n", "continue\n", "def f():\n    return 1 +\n"):
            result = router.route_task(self.models, self.calibration, source,
                                       INDEPENDENT_AUDITOR_KEY)
            self.assertEqual(result["status"], "NO_APPROVED_ONE_CHARACTER_REPAIR")

    def test_unbounded_binary_non_ascii_and_missing_source_refused(self):
        for source in ("", "x = 1\x00", "a = '😈'", "x = " + "1" * 3000, 7):
            with self.assertRaises((ValueError, UnicodeError, TypeError)):
                router.compiler_diagnostic(source)

    def test_cli_capabilities_never_claims_actual_model_execution(self):
        done = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT)],
                              capture_output=True, text=True, timeout=8, check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        value = json.loads(done.stdout)
        self.assertEqual(value["status"], "ACTUAL_CODE_MODEL_ROUTER_ADAPTER_AVAILABLE")
        self.assertFalse(value["training_or_model_inference_executed"])
        self.assertFalse(value["source_code_executed"])

    def test_cli_local_selftest_executes_real_models_but_no_operator_claim(self):
        done = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                               "--mode", "selftest"], capture_output=True,
                              text=True, timeout=15, check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        value = json.loads(done.stdout)
        self.assertEqual(value["status"],
                         "TRUSTED_CODE_MODEL_LOCAL_SELFTEST_NO_EXTERNAL_AUDIT")
        self.assertTrue(value["model_routing_demonstrated"])
        self.assertFalse(value["external_independent_auditor_attested"])
        self.assertFalse(value["source_code_executed"])

    def test_cli_route_without_signed_credentials_fails_closed(self):
        done = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                               "--mode", "route"], capture_output=True,
                              text=True, timeout=8, check=False)
        self.assertEqual(done.returncode, 2)
        self.assertEqual(json.loads(done.stdout)["status"],
                         "NOT_RUN_OR_UNQUALIFIED_CODE_MODEL")

    def test_cli_real_signed_operator_calibration_proposes_without_writing(self):
        with tempfile.TemporaryDirectory(prefix="rph-v24-signed-model-") as folder:
            base = Path(folder)
            source = base / "original.py"
            source.write_bytes(self.oracle["cases"][0]["source"].encode("ascii"))
            oracle = base / "oracle.json"
            oracle.write_bytes(router.canonical(self.oracle))
            key = base / "auditor.key"
            key.write_bytes(INDEPENDENT_AUDITOR_KEY)
            key.chmod(0o600)
            if os.name == "nt":
                import windows_privacy_fixtures
                windows_privacy_fixtures.set_private_acl(key)
            done = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                                   "--mode", "route", "--source-file", str(source),
                                   "--oracle-file", str(oracle), "--key-file", str(key),
                                   "--signature", self.signature], capture_output=True,
                                  text=True, timeout=15, check=False)
            self.assertEqual(done.returncode, 0, done.stderr)
            report = json.loads(done.stdout)
            self.assertEqual(report["status"],
                             "ACTUAL_TRAINED_CODE_MODEL_PROPOSED_COMPILE_ONLY")
            self.assertFalse(report["source_file_modified"])
            self.assertEqual(source.read_text(encoding="ascii"),
                             self.oracle["cases"][0]["source"])

    def test_private_key_symlink_and_public_mode_rejected(self):
        with tempfile.TemporaryDirectory(prefix="rph-v24-private-auditor-") as folder:
            base = Path(folder)
            key = base / "auditor.key"
            key.write_bytes(INDEPENDENT_AUDITOR_KEY)
            key.chmod(0o644)
            if os.name == "nt":
                import windows_privacy_fixtures
                windows_privacy_fixtures.set_public_read_acl(key)
            with self.assertRaisesRegex(ValueError, "unsafe_model_evidence_file"):
                router.read_regular(key, private=True)
            key.chmod(0o600)
            if os.name == "nt":
                import windows_privacy_fixtures
                windows_privacy_fixtures.set_private_acl(key)
            pointer = base / "symlink.key"
            pointer.symlink_to(key)
            with self.assertRaisesRegex(ValueError, "unsafe_model_evidence_file"):
                router.read_regular(pointer, private=True)


if __name__ == "__main__":
    unittest.main()
