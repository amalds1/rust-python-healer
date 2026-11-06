"""Real Rust/Ruff trusted variant workers and 7-minor six-axis regression suite."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("real_orchestrator_v21",
                                               ROOT / "python/real_orchestrator_v21.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
RUST = ROOT / "target" / "release" / ("rust-python-healer.exe" if sys.platform == "win32" else "rust-python-healer")
RUFF = ROOT.parent / ".uv-bin/ruff"
RUNTIMES = {minor: (Path("/usr/bin/python3.12") if minor == "3.12" else
                    ROOT.parent / ".python-bin" / ("python" + minor))
            for minor in module.EXPECTED_MINORS}


def rank_input(name, **kwargs):
    metrics = dict(module.LIMITS)
    metrics.update(kwargs)
    return {"variant_id": name, "trusted_measured": True,
            "gates": {axis: True for axis in module.SIX_AXES}, "metrics": metrics}


class RealOrchestratorV21Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not RUST.is_file() or not RUFF.is_file() or any(not p.is_file() for p in RUNTIMES.values()):
            raise unittest.SkipTest("real Rust binary, Ruff and all seven CPython minors are mandatory")
        cls.report = module.run_trusted_orchestrator(RUST, RUFF, RUNTIMES)

    def test_real_independently_spawned_rust_ruff_and_colon_workers(self):
        report = self.report
        self.assertEqual(report["status"], "TRUSTED_FIXTURE_ORCHESTRATED", report)
        self.assertEqual(report["repair_independent_processes"], 2)
        self.assertEqual({row["engine"] for row in report["variants"]}, {"ruff", "colon"})
        self.assertEqual(len({row["separate_workdir"] for row in report["variants"]}), 2)
        self.assertEqual(len({row["config_initialization_sha256"] for row in report["variants"]}), 2)
        self.assertTrue(all(row["snapshot_preserved"] for row in report["variants"]))
        self.assertFalse(report["workspace_snapshot_retained"])

    def test_real_seven_actual_python_minors_not_only_host_version(self):
        self.assertEqual(self.report["python_minor_proofs"], {v: v for v in module.EXPECTED_MINORS})
        self.assertEqual(self.report["actual_child_behavior_observations"], 160)
        self.assertEqual({item["metrics"]["COMPATIBILITY"] for item in self.report["candidate_gates"]}, {7})

    def test_real_ten_identical_behavioral_retests_each_minor_and_candidate(self):
        self.assertEqual({item["metrics"]["RELIABILITY"] for item in self.report["candidate_gates"]}, {10})
        self.assertEqual({item["metrics"]["CORRECTNESS"] for item in self.report["candidate_gates"]}, {0})
        self.assertTrue(all(row["gates"]["CORRECTNESS"] for row in self.report["candidate_gates"]))

    def test_real_six_axis_gates_precede_objective_ranking(self):
        decision = self.report["selection"]
        self.assertEqual(decision["decision"], "TRUSTED_FIXTURE_PRIMARY", decision)
        self.assertEqual(decision["qualified"], 2)
        self.assertEqual(len(decision["decisions"]), 2)
        self.assertTrue(decision["ranked_only_after_all_six_measured_gates"])
        self.assertTrue(all(len(row["gates"]) == 6 for row in self.report["candidate_gates"]))
        self.assertFalse(decision["external_independent_audit"])

    def test_real_one_primary_and_at_most_one_reserve(self):
        self.assertNotEqual(self.report["selection"]["primary_variant"],
                            self.report["selection"]["reserve_variant"])
        self.assertEqual(self.report["selection"]["maximum_reserves"], 1)
        self.assertEqual({self.report["selection"]["primary_variant"],
                          self.report["selection"]["reserve_variant"]},
                         {row["variant_id"] for row in self.report["variants"]})

    def test_actual_cpu_ram_elapsed_and_no_cloud_model_token_usage(self):
        for row in self.report["variants"]:
            self.assertGreater(row["cpu_ms"], 0)
            self.assertGreater(row["peak_rss_kb"], 0)
            self.assertGreater(row["worker_wall_ms"], 0)
            self.assertEqual(row["actual_tokens_used"], 0)
            self.assertEqual(row["cloud_cost_usd"], 0.0)
        self.assertGreater(self.report["measured_total_wall_ms"], 0)
        self.assertGreater(self.report["measured_critical_path_ms"], 0)
        self.assertGreater(self.report["resource_peak_cpu_ms"], 0)
        self.assertGreater(self.report["resource_peak_rss_kb"], 0)
        self.assertFalse(self.report["untrusted_project_code_executed"])

    def test_real_independent_repair_outputs_have_measured_outcome_phi(self):
        self.assertEqual(self.report["measured_probe_phi"], 1.0)
        self.assertEqual(len(self.report["per_variant_probe_outcomes"]), 2)
        for outcomes in self.report["per_variant_probe_outcomes"].values():
            self.assertEqual(set(outcomes), set(module.PROBES))
            self.assertEqual(set(outcomes.values()), {"PASS", "FAIL"})
        self.assertTrue(self.report["independent_initializations"])

    def test_router_feedback_measured_no_external_model_claim(self):
        self.assertEqual(set(self.report["model_router_feedback"]), {"ruff", "colon"})
        self.assertFalse(self.report["external_models_called"])
        self.assertFalse(self.report["independent_external_oracle"])
        self.assertFalse(self.report["release_authorized"])

    def test_resource_adaptive_cap_uses_real_worker_cpu_and_rss(self):
        self.assertGreater(self.report["resource_peak_rss_kb"], 0)
        self.assertGreater(self.report["resource_peak_cpu_ms"], 0)
        self.assertLessEqual(self.report["adaptive_worker_cap_after_real_measurement"],
                             self.report["adaptive_worker_cap_before"])
        self.assertEqual(self.report["declared_memory_budget_kb"], 150000)

    def test_real_measured_memory_pressure_reduces_validation_workers(self):
        # A preselected 25 MB budget accommodates a single measured Rust
        # worker but not two; the real 160-job verification pool becomes 1.
        report = module.run_trusted_orchestrator(RUST, RUFF, RUNTIMES, max_workers=4,
                                                  memory_budget_kb=25000)
        self.assertEqual(report["status"], "TRUSTED_FIXTURE_ORCHESTRATED", report)
        self.assertLess(report["adaptive_worker_cap_after_real_measurement"],
                        report["adaptive_worker_cap_before"])
        self.assertEqual(report["adaptive_worker_cap_after_real_measurement"], 1)
        self.assertFalse(report["resource_limit_prevented_dispatch"])
        self.assertEqual(report["decision"], "TRUSTED_FIXTURE_PRIMARY")

    def test_real_budget_below_measured_minimum_blocks_release_and_validation(self):
        report = module.run_trusted_orchestrator(RUST, RUFF, RUNTIMES,
                                                  memory_budget_kb=1, cpu_budget_ms=1)
        self.assertEqual(report["decision"], "NO_WINNER", report)
        self.assertEqual(report["actual_child_behavior_observations"], 0)
        self.assertTrue(report["resource_limit_prevented_dispatch"])
        self.assertEqual(report["adaptive_worker_cap_after_real_measurement"], 0)

    def test_six_axis_gate_rejects_one_axis_even_with_other_five_pass(self):
        for axis in module.SIX_AXES:
            with self.subTest(axis=axis):
                candidate = rank_input("v1")
                candidate["gates"][axis] = False
                result = module.rank_measured_gates([candidate])
                self.assertEqual(result["decision"], "NO_WINNER")
                self.assertIn(axis + "_NOT_PASS", result["decisions"][0]["failed_gates"])

    def test_six_actual_thresholds_fail_closed(self):
        cases = (("SAFETY", 1), ("CORRECTNESS", 1), ("SPEED", 301),
                 ("RELIABILITY", 9), ("COMPATIBILITY", 6), ("FUTURE_READINESS", 31))
        for axis, value in cases:
            with self.subTest(axis=axis):
                result = module.rank_measured_gates([rank_input("v1", **{axis: value})])
                self.assertEqual(result["decision"], "NO_WINNER")
                self.assertIn(axis + "_THRESHOLD_FAIL", result["decisions"][0]["failed_gates"])

    def test_rank_qualified_only_and_max_one_reserve(self):
        first = rank_input("a", SPEED=22)
        second = rank_input("b", SPEED=12)
        rejected = rank_input("c")
        rejected["gates"]["SAFETY"] = False
        with self.assertRaisesRegex(ValueError, "invalid_candidate_count"):
            module.rank_measured_gates([first, second, rejected])
        report = module.rank_measured_gates([first, second])
        self.assertEqual(report["primary_variant"], "b")
        self.assertEqual(report["reserve_variant"], "a")
        self.assertEqual(report["maximum_reserves"], 1)

    def test_unknown_or_self_claimed_axes_do_not_qualify(self):
        row = rank_input("x")
        row["trusted_measured"] = "true"
        self.assertEqual(module.rank_measured_gates([row])["decision"], "NO_WINNER")
        row["trusted_measured"] = True
        del row["metrics"]["SAFETY"]
        with self.assertRaisesRegex(ValueError, "all_six_axes_required"):
            module.rank_measured_gates([row])

    def test_invalid_version_mapping_no_winner_before_rust(self):
        fake = dict(RUNTIMES)
        fake["3.9"], fake["3.10"] = fake["3.10"], fake["3.9"]
        report = module.run_trusted_orchestrator(RUST, RUFF, fake)
        self.assertEqual(report["status"], "RUNTIME_MINOR_MISMATCH")
        self.assertEqual(report["decision"], "NO_WINNER")

    def test_missing_selected_rust_or_ruff_cannot_create_winner(self):
        report = module.run_trusted_orchestrator("/missing/rust", RUFF, RUNTIMES)
        self.assertEqual(report["status"], "NOT_RUN_MISSING_SELECTED_BINARY")
        self.assertEqual(report["decision"], "NO_WINNER")

    def test_invalid_resource_quotas_rejected(self):
        for kwargs in ({"max_workers": True}, {"max_workers": 5}, {"memory_budget_kb": 0},
                       {"cpu_budget_ms": 50000}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                module.run_trusted_orchestrator(RUST, RUFF, RUNTIMES, **kwargs)

    def test_candidate_hash_mismatch_never_executed(self):
        with tempfile.TemporaryDirectory() as folder:
            candidate = Path(folder) / "candidate.py"
            candidate.write_bytes(b"answer = 999\n")
            report = module._trusted_behavior_process(sys.executable, folder, candidate,
                                                       module.sha(b"answer = 42\n"), "eq42")
        self.assertEqual(report["status"], "NOT_RUN")

    def test_measured_correlations_require_both_variations(self):
        self.assertIsNone(module._measured_phi({"x": "PASS"}, {"x": "FAIL"}))
        same = {probe: "PASS" for probe in module.PROBES}
        self.assertIsNone(module._measured_phi(same, same))

    def test_cli_actual_json_selected_real_minor_matrix(self):
        with tempfile.TemporaryDirectory() as folder:
            runtimes = Path(folder) / "runtimes.json"
            runtimes.write_text(json.dumps({k: str(v) for k, v in RUNTIMES.items()}), encoding="utf-8")
            proc = subprocess.run([sys.executable, "-I", "-S", "-B",
                                   str(ROOT / "python/real_orchestrator_v21.py"),
                                   "--binary", str(RUST), "--ruff", str(RUFF),
                                   "--runtime-json", str(runtimes)],
                                  capture_output=True, check=False, text=True, timeout=40)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["decision"], "TRUSTED_FIXTURE_PRIMARY")


if __name__ == "__main__":
    unittest.main()
