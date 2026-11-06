"""Real 3.15 alpha/beta/RC and 3.16-alpha curated compatibility evidence."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import shutil
import tempfile
import unittest
import unittest.mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "prerelease_matrix_v23.py"
spec = importlib.util.spec_from_file_location("prerelease_matrix_v23", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PreviewRuntimeActualEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual = module.actual_release_identity()
        cls.preview = cls.actual["status"] == "ACTUAL_CPYTHON_PREVIEW_IDENTITY"

    def test_real_sys_version_info_not_filename_phase(self):
        self.assertEqual(self.actual["major"], sys.version_info.major)
        self.assertEqual(self.actual["minor"], sys.version_info.minor)
        self.assertEqual(self.actual["releaselevel"], sys.version_info.releaselevel)
        self.assertEqual(self.actual["serial"], sys.version_info.serial)

    def test_expected_phase_real_matching_only(self):
        if self.preview:
            report = module.checked_release_expectation(self.actual["version_label"])
            self.assertEqual(report["status"], "REAL_VERSION_PHASE_MATCH")
            self.assertTrue(report["phase_proof_from_sys_version_info"])
        else:
            report = module.checked_release_expectation("3.15.0rc1")
            self.assertFalse(report["matched"])

    def test_wrong_prerelease_phase_or_serial_rejected(self):
        wrong = "3.15.0a77" if self.actual["version_label"] != "3.15.0a77" else "3.15.0rc1"
        result = module.checked_release_expectation(wrong)
        self.assertEqual(result["status"], "WRONG_OR_MISSING_PREVIEW_INTERPRETER_REJECTED")
        self.assertFalse(result["matched"])

    def test_unrecognized_phase_input_not_accepted(self):
        for value in (None, "3.15.0", "3.15.0beta1", "3.16.0final",
                      "../../../evil", "3.15.0a1 --execute"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                module.checked_release_expectation(value)

    def test_actual_prerelease_selected_100_cases_no_full_release_claim(self):
        report = module.run_selected_preview_suite()
        if self.preview:
            self.assertEqual(report["status"], "PREVIEW_100_LANGUAGE_AND_8_GRAMMAR_PASS_NOT_FULL")
            self.assertEqual(report["actual_tests_total"], 100)
            self.assertEqual(report["actual_tests_pass"], 100)
            self.assertEqual(report["actual_tests_fail"], 0)
            self.assertTrue(report["selected_suite_passed"])
            self.assertFalse(report["future_stable_python_3_16_qualified"])
        else:
            self.assertEqual(report["status"], "NOT_RUN_NOT_ACTUAL_CPYTHON_PRERELEASE")

    def test_actual_grammar_compiler_not_executes_source(self):
        report = module.compile_extra_grammar_oracles()
        if self.actual["minor"] >= 15:
            self.assertEqual(report["status"], "SELECTED_PRERELEASE_GRAMMAR_ORACLES_PASS")
            self.assertEqual(report["passes"], 8)
            self.assertTrue(all(item["code_executed"] is False for item in report["checks"]))
        else:
            self.assertEqual(report["status"], "NOT_RUN_PREVIEW_ORACLES_REQUIRE_3_15_PLUS")

    def test_pinned_suite_sha256_rejects_mutated_project_source(self):
        if self.preview:
            with unittest.mock.patch.object(module, "TRUSTED_VERSION_SUITE_SHA256", "0" * 64):
                report = module.run_selected_preview_suite()
            self.assertEqual(report["status"], "NOT_RUN_CURATED_SUITE_SHA_MISMATCH")
            self.assertFalse(report["unknown_project_source_executed"])

    def test_curated_suite_exact_source_hash_static_reference(self):
        source = (ROOT / "python" / "version_suite.py").read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(),
                         module.TRUSTED_VERSION_SUITE_SHA256)

    def test_cli_identity_reports_current_real_interpreter(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                              "--mode", "identity"], capture_output=True, timeout=8)
        self.assertEqual(run.returncode, 0)
        self.assertEqual(json.loads(run.stdout)["version_label"], self.actual["version_label"])

    def test_cli_phase_without_expected_fails_closed(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                              "--mode", "phase"], capture_output=True, timeout=8)
        self.assertNotEqual(run.returncode, 0)
        self.assertEqual(json.loads(run.stdout)["status"], "NOT_RUN_OR_INVALID_PREVIEW_EVIDENCE")


class FourRealPreviewInterpreterMatrix(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = module.run_known_preview_matrix()

    def test_real_three_phase_3_15_processes_pass(self):
        self.assertEqual(self.matrix["status"], "REAL_ALPHA_BETA_RC_PREVIEW_MATRIX_QUALIFIED_LOCAL")
        self.assertTrue(self.matrix["alpha_beta_releasecandidate_verified"])
        self.assertEqual([item["actual_releaselevel"] for item in self.matrix["real_versions"][:3]],
                         ["alpha", "beta", "candidate"])

    def test_four_separate_real_executables_not_four_duplicate_reports(self):
        self.assertEqual(self.matrix["actual_subprocesses_executed"], 4)
        self.assertTrue(all(item["exact_real_executable"] for item in self.matrix["real_versions"]))
        self.assertEqual(len({item["binary_sha256"] for item in self.matrix["real_versions"]}), 4)

    def test_four_real_100_case_suites_and_eight_grammar_checks(self):
        self.assertEqual(sum(item["actual_tests_pass"] for item in self.matrix["real_versions"]), 400)
        self.assertEqual(sum(item["extra_grammar_pass"] for item in self.matrix["real_versions"]), 32)
        self.assertEqual(len({item["curated_suite_sha256"] for item in self.matrix["real_versions"]}), 1)

    def test_future_3_16_alpha_selected_not_fully_qualified(self):
        self.assertTrue(self.matrix["future_3_16_alpha_selected_tests_passed"])
        self.assertEqual(self.matrix["real_versions"][3]["expected"], "3.16.0a1")
        self.assertFalse(self.matrix["future_3_16_stable_fully_qualified"])
        self.assertFalse(self.matrix["external_publisher_and_binary_provenance_attested"])

    def test_missing_preview_binaries_do_not_generate_fake_pass(self):
        with unittest.mock.patch.object(module, "_known_preview_executable",
                                        side_effect=ValueError("missing_real_binary")):
            result = module.run_known_preview_matrix()
        self.assertEqual(result["status"], "PREVIEW_PHASE_MATRIX_UNVERIFIED")
        self.assertEqual(result["actual_subprocesses_executed"], 0)

    @unittest.skipUnless(sys.platform == "win32", "Windows source/process binding")
    def test_windows_false_child_flags_and_malformed_oracles_are_rejected(self):
        original = self.matrix["real_versions"][0]["child_report"]
        item = module.PREVIEW_BINARIES[0]
        paths = [
            (("probe_schema",), True), (("challenge",), "0" * 32),
            (("executable_sha256",), "0" * 64), (("pid",), -1),
            (("result", "selected_suite_passed"), False),
            (("result", "future_stable_python_3_16_qualified"), True),
            (("result", "unknown_project_code_executed"), True),
            (("result", "actual_tests_fail"), False),
            (("result", "actual", "micro"), False),
            (("result", "actual", "releaselevel"), "beta"),
            (("result", "additional_grammar_checks", "passes"), 7),
            (("result", "additional_grammar_checks", "checks", 0, "code_executed"), True),
            (("result", "additional_grammar_checks", "checks", 0, "name"), []),
        ]
        for path, value in paths:
            changed = json.loads(json.dumps(original))
            target = changed
            for key in path[:-1]: target = target[key]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError):
                module._validate_windows_preview_report(changed, item, original["challenge"],
                    original["source_graph"], original["executable_sha256"], original["pid"])

    @unittest.skipUnless(sys.platform == "win32", "Primary Windows archive pins")
    def test_windows_actual_archives_and_source_graphs_have_independent_pins(self):
        expected_graph = self.matrix["source_graph"]
        self.assertEqual(expected_graph["prerelease_matrix_v23.py"], hashlib.sha256(SCRIPT.read_bytes()).hexdigest())
        for row in self.matrix["real_versions"]:
            self.assertEqual(row["archive_sha256"], module.WINDOWS_PREVIEW_ARCHIVES[row["expected"]][1])
            self.assertEqual(row["source_graph"], expected_graph)
            self.assertTrue(row["challenge_matched"])
            self.assertGreater(row["verified_bundle_files"], 1000)
            self.assertFalse(row["independent_publisher_signature_verified"])

    def test_cli_matrix_json_contains_all_real_phases(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                              "--mode", "matrix"], capture_output=True,
                             timeout=240 if sys.platform == "win32" else 20)
        self.assertEqual(run.returncode, 0, run.stderr[-300:])
        report = json.loads(run.stdout)
        self.assertEqual(len(report["real_versions"]), 4)
        self.assertTrue(report["alpha_beta_releasecandidate_verified"])
        self.assertFalse(report["unknown_project_source_executed"])


@unittest.skipUnless(sys.platform == "win32", "Native Windows preview safety contracts")
class WindowsPreviewSafetyNegatives(unittest.TestCase):
    def test_duplicate_child_json_keys_refused(self):
        with self.assertRaisesRegex(ValueError, "duplicate_windows_preview_json_key"):
            json.loads('{"probe_schema":1,"probe_schema":1}', object_pairs_hook=module._preview_json_object)

    def test_caller_cannot_supply_an_archive_trust_pin(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT), "--mode", "matrix",
                              "--archive-sha256", "0" * 64], capture_output=True, timeout=8)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn(b"unrecognized arguments", run.stderr)

    def test_actual_bad_archive_pin_denies_before_child(self):
        import windows_privacy_fixtures as fixtures
        known_root = ROOT.parent / "python-preview-windows-v029"
        version = module.PREVIEW_BINARIES[0][0]
        with tempfile.TemporaryDirectory(prefix="rph-preview-bad-pin-") as temporary:
            root = fixtures.create_private_directory(Path(temporary) / "private")
            fixture = fixtures.create_private_directory(root / ("cpython-" + version + "-windows-amd64"))
            shutil.copyfile(known_root / fixture.name / "python.exe", fixture / "python.exe")
            archive = root / ("python-" + version + "-amd64.zip")
            shutil.copyfile(known_root / archive.name, archive)
            with archive.open("r+b") as stream:
                stream.write(b"XX")
            with unittest.mock.patch.object(module.subprocess, "Popen", side_effect=AssertionError("unverified_child_must_not_start")):
                result = module.run_known_preview_matrix(root)
            self.assertEqual(result["status"], "PREVIEW_PHASE_MATRIX_UNVERIFIED")
            self.assertEqual(result["actual_subprocesses_executed"], 0)

    def test_real_owned_child_timeout_and_false_json_refused(self):
        item = module.PREVIEW_BINARIES[0]
        folder = ROOT.parent / "python-preview-windows-v029" / ("cpython-" + item[0] + "-windows-amd64")
        binary = folder / "python.exe"
        source, suite, graph = module._windows_preview_sources()
        bundle = {"runtime_directory": folder, "executable_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
        actual_popen = subprocess.Popen
        children, environments = [], []

        def observed_real_popen(*args, **kwargs):
            child = actual_popen(*args, **kwargs)
            children.append(child); environments.append(kwargs.get("env"))
            return child

        for code, timeout in (("import time;time.sleep(30)", 0.15), ('print(\'{"selected_suite_passed":true}\')', 5)):
            with unittest.mock.patch.object(module, "_WINDOWS_PREVIEW_CHILD", code), \
                    unittest.mock.patch.object(module.subprocess, "Popen", side_effect=observed_real_popen), \
                    unittest.mock.patch.dict(os.environ, {"PYTHONPATH": "C:/rph_untrusted_missing", "RPH_SECRET": "fixed_test_secret"}):
                with self.assertRaises(ValueError):
                    module._run_windows_preview_child(binary, source, suite, graph, bundle, item, timeout=timeout)
        self.assertEqual(len(children), 2)
        self.assertTrue(all(child.poll() is not None for child in children))
        self.assertTrue(all("PYTHONPATH" not in env and "RPH_SECRET" not in env for env in environments))


if __name__ == "__main__":
    unittest.main()
