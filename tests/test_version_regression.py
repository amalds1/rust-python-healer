"""Regression corpus for trusted static Python syntax, bytecode and traces."""

from importlib.util import module_from_spec, spec_from_file_location
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config" / "version_regression_cases.json"
spec = spec_from_file_location("version_regression", ROOT / "python" / "version_regression.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


def modified_manifest(folder, section=None):
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if section:
        selected = module.inspect(MANIFEST).get("runtime_reference_profile")
        if selected:
            next(row for row in data["runtime_profiles"] if row["id"] == selected)["reference"][section]["sha256"] = "0" * 64
        else:
            data["versions"][module.VERSION][section]["sha256"] = "0" * 64
    path = Path(folder) / "version_regressions.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


class VersionRegressionTests(unittest.TestCase):
    def test_seven_pinned_real_interpreter_baselines_are_checked(self):
        report = module.inspect(MANIFEST)
        self.assertEqual(report["status"], "BASELINE_MATCH")
        self.assertEqual(report["checks"], {
            "ast": True, "bytecode": True, "traceback": True})
        self.assertEqual(report["baselines_compared"], 3)
        self.assertEqual(report["baselines_matching"], 3)
        self.assertFalse(report["untrusted_source_executed"])
        self.assertFalse(report["project_code_loaded"])
        self.assertEqual(report["reference_authenticity"], "UNSIGNED_NOT_VERIFIED")
        self.assertEqual(report["full_python_compatibility"], "NOT_VERIFIED")

    def test_ast_syntax_support_tracks_minor_version_without_code_execution(self):
        data = module.ast_observation()
        minor = sys.version_info.minor
        self.assertEqual(data["syntax_acceptance"], {
            "pattern_matching": minor >= 10,
            "exception_groups": minor >= 11,
            "type_parameters": minor >= 12,
            "template_strings": minor >= 14,
        })

    def test_bytecode_function_ops_detect_known_version_families(self):
        data = module.bytecode_observation()
        branch = data["branch"]["function_ops"]
        self.assertIn("RETURN_VALUE", branch)
        self.assertEqual("RESUME" in branch, sys.version_info.minor >= 11)
        self.assertEqual("LOAD_FAST_BORROW" in branch, sys.version_info.minor >= 14)
        self.assertEqual(data["exception"]["co_exceptiontable_bytes"] > 0,
                         sys.version_info.minor >= 11)

    def test_traceback_fixture_captures_only_known_frames_and_notes(self):
        report = module.traceback_observation()
        self.assertEqual(report["exception"], "RuntimeError")
        self.assertEqual(report["frames"], [
            "regression_frame_outer", "regression_frame_inner"])
        self.assertEqual(report["exception_notes_supported"], sys.version_info.minor >= 11)
        self.assertNotIn("/home/", json.dumps(report))

    def test_ast_baseline_corruption_is_a_regression(self):
        with tempfile.TemporaryDirectory() as directory:
            report = module.inspect(modified_manifest(directory, "ast"))
        self.assertEqual(report["status"], "REGRESSION")
        self.assertFalse(report["checks"]["ast"])
        self.assertTrue(report["checks"]["bytecode"])
        self.assertTrue(report["checks"]["traceback"])

    def test_bytecode_baseline_corruption_is_a_regression(self):
        with tempfile.TemporaryDirectory() as directory:
            report = module.inspect(modified_manifest(directory, "bytecode"))
        self.assertEqual(report["status"], "REGRESSION")
        self.assertFalse(report["checks"]["bytecode"])

    def test_traceback_baseline_corruption_is_a_regression(self):
        with tempfile.TemporaryDirectory() as directory:
            report = module.inspect(modified_manifest(directory, "traceback"))
        self.assertEqual(report["status"], "REGRESSION")
        self.assertFalse(report["checks"]["traceback"])

    def test_missing_future_baseline_reports_not_run(self):
        saved = module.VERSION
        try:
            module.VERSION = "3.16"
            result = module.inspect(MANIFEST)
        finally:
            module.VERSION = saved
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertEqual(result["reason"], "missing_version_baseline")
        self.assertFalse(result["trusted_embedded_probes_executed"])

    def test_duplicate_manifest_key_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "duplicate.json"
            file.write_text('{"schema_version":1,"versions":{},"versions":{}}')
            result = module.inspect(file)
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertEqual(result["reason"], "invalid_manifest_json")

    def test_invalid_utf8_and_structure_cannot_get_false_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "invalid.json"
            file.write_bytes(b"\xff\xfe")
            self.assertEqual(module.inspect(file)["status"], "NOT_RUN")
            file.write_text(json.dumps({"schema_version": 1, "versions": {
                module.VERSION: {"ast": {}, "bytecode": {}}}}))
            self.assertEqual(module.inspect(file)["reason"], "invalid_manifest_schema")

    def test_deeply_nested_json_cannot_crash_or_receive_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "nested.json"
            file.write_text("[" * 1800 + "0" + "]" * 1800)
            result = module.inspect(file)
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertIn(result["reason"], ("invalid_manifest_json", "invalid_manifest_schema"))

    def test_oversized_manifest_refused_without_loading(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "oversized.json"
            file.write_bytes(b"x" * (module.MAX_MANIFEST_BYTES + 1))
            result = module.inspect(file)
        self.assertEqual(result["status"], "NOT_RUN")
        self.assertEqual(result["reason"], "manifest_size_limit")
        self.assertFalse(result["trusted_embedded_probes_executed"])

    def test_symlinked_and_hardlinked_manifest_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = modified_manifest(directory)
            symlink = root / "linked.json"
            symlink.symlink_to(original)
            self.assertEqual(module.inspect(symlink)["reason"], "manifest_symlink_refused")
            hardlink = root / "hardlink.json"
            os.link(str(original), str(hardlink))
            self.assertEqual(module.inspect(original)["reason"],
                             "manifest_not_unique_regular_file")

    def test_child_process_reports_candidate_without_silent_promotion(self):
        command = [sys.executable, "-I", "-S", "-B",
                   str(ROOT / "python" / "version_regression.py"), "--candidate"]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "CANDIDATE_UNVERIFIED")
        self.assertFalse(payload["untrusted_source_executed"])
        self.assertEqual(set(payload["reference"]), {"ast", "bytecode", "traceback"})

    def test_child_process_checks_pinned_manifest(self):
        command = [sys.executable, "-I", "-S", "-B",
                   str(ROOT / "python" / "version_regression.py"),
                   "--manifest", str(MANIFEST)]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "BASELINE_MATCH")
        self.assertTrue(all(payload["checks"].values()))


if __name__ == "__main__":
    unittest.main()
