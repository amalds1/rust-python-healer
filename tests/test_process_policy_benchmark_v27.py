"""Strict safety/compatibility gates and duplicate-proof F167 candidate registry."""

import copy
import importlib.util
import json
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "rph_process_policy_bench_v27", ROOT / "tools" / "process_policy_benchmark_v27.py")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def registry():
    return json.loads(module.CONFIG.read_text(encoding="utf-8"))


def row(status="PASS", elapsed=100.0):
    return [{"python_minor": "3.15", "samples": [
        {"status": status, "elapsed_ms": elapsed}]}]


class RegistryAndGatesTests(unittest.TestCase):
    def test_valid_registered_pinned_distinct_candidates(self):
        items = registry()
        thresholds = module.validate_registry(items)
        self.assertEqual(len(items["candidates"]), 2)
        self.assertEqual(thresholds["repeat_count_minimum"], 3)

    def test_duplicate_id_is_rejected(self):
        items = registry()
        items["candidates"][1]["variant_id"] = items["candidates"][0]["variant_id"]
        with self.assertRaisesRegex(ValueError, "duplicate_candidate_id"):
            module.validate_registry(items)

    def test_duplicate_code_and_configuration_is_rejected(self):
        items = registry()
        items["candidates"][1]["configuration"] = copy.deepcopy(items["candidates"][0]["configuration"])
        with self.assertRaisesRegex(ValueError, "duplicate_candidate_combination"):
            module.validate_registry(items)

    def test_modified_source_hash_never_passes(self):
        items = registry()
        items["candidates"][0]["source_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "unreviewed_source_change"):
            module.validate_registry(items)

    def test_no_source_injection_in_registry(self):
        items = registry()
        items["candidates"][0]["source"] = "../../tmp/untrusted.py"
        with self.assertRaisesRegex(ValueError, "untrusted_executable_source"):
            module.validate_registry(items)

    def test_safety_thresholds_cannot_be_turned_off(self):
        items = registry()
        for bad in (0, 1, 2, True):
            changed = copy.deepcopy(items)
            changed["thresholds"]["repeat_count_minimum"] = bad
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "unsafe_thresholds"):
                module.validate_registry(changed)

    def test_all_six_gates_and_no_external_pass(self):
        gates = module.gates_for_runs(row(), registry()["thresholds"], "Linux")
        self.assertEqual(set(gates), set(module.REQUIRED_GATES))
        for required in ("VEILIGHEID", "COMPATIBILITEIT", "TOEKOMSTBESTENDIGHEID"):
            self.assertEqual(gates[required]["status"], "NOT_RUN")
        self.assertEqual(gates["CORRECTHEID"]["status"], "PASS")

    def test_failed_worker_is_not_correctness_pass(self):
        gates = module.gates_for_runs(row("FAIL"), registry()["thresholds"], "Linux")
        self.assertEqual(gates["CORRECTHEID"]["status"], "FAIL")
        self.assertEqual(gates["BETROUWBAARHEID"]["status"], "FAIL")

    def test_socket_denial_is_not_a_success(self):
        gates = module.gates_for_runs(row("NOT_RUN"), registry()["thresholds"], "Linux")
        self.assertEqual(gates["CORRECTHEID"]["status"], "NOT_RUN")
        self.assertEqual(gates["BETROUWBAARHEID"]["status"], "NOT_RUN")

    def test_slow_worker_fails_speed_gate(self):
        threshold = registry()["thresholds"]["each_probe_wall_time_max_ms"]
        gates = module.gates_for_runs(row(elapsed=threshold + 1), registry()["thresholds"], "Linux")
        self.assertEqual(gates["SNELHEID"]["status"], "FAIL")

    def test_probing_no_exec_or_user_arguments(self):
        candidate = registry()["candidates"][1]
        response = json.dumps({"status": "EXPLICIT_SPAWN_FALLBACK_PASS",
                               "primary": {"status": "NOT_RUN"},
                               "requested_method": "forkserver", "effective_method": "spawn",
                               "fallback": {"status": "PASS"},
                               "untrusted_source_executed": False,
                               "implicit_security_sandbox": False,
                               "explicit_fallback_consent": True}).encode("utf-8")
        completed = mock.Mock(returncode=0, stdout=response, stderr=b"")
        with mock.patch.object(module.subprocess, "run", return_value=completed) as run:
            result = module.probe_one("/usr/bin/python3", candidate)
        self.assertEqual(result["status"], "PASS")
        cmd = run.call_args.args[0]
        self.assertIn("--allow-spawn-fallback", cmd)
        self.assertIn("-I", cmd)
        self.assertIn("-S", cmd)
        self.assertNotIn("-c", cmd)

    def test_forged_fallback_on_strict_variant_rejected(self):
        candidate = registry()["candidates"][0]
        response = json.dumps({"status": "EXPLICIT_SPAWN_FALLBACK_PASS",
                               "primary": {"status": "NOT_RUN"},
                               "requested_method": "forkserver", "effective_method": "spawn",
                               "fallback": {"status": "PASS"},
                               "untrusted_source_executed": False,
                               "implicit_security_sandbox": False,
                               "explicit_fallback_consent": False}).encode("utf-8")
        with mock.patch.object(module.subprocess, "run", return_value=mock.Mock(
                returncode=0, stdout=response, stderr=b"")):
            result = module.probe_one("/usr/bin/python3", candidate)
        self.assertEqual(result["status"], "FAIL")

    def test_forged_trust_contract_never_passes(self):
        candidate = registry()["candidates"][0]
        response = json.dumps({"status": "PRIMARY_PASS", "primary": {"status": "PASS"},
                               "requested_method": "spawn", "effective_method": "spawn",
                               "untrusted_source_executed": True,
                               "implicit_security_sandbox": False,
                               "explicit_fallback_consent": False}).encode("utf-8")
        with mock.patch.object(module.subprocess, "run", return_value=mock.Mock(
                returncode=0, stdout=response, stderr=b"")):
            result = module.probe_one("/usr/bin/python3", candidate)
        self.assertEqual(result["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
