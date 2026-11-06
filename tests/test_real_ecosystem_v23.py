"""Real installed-framework evidence is distinct from static/absent mocks."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "real_ecosystem_v23.py"
spec = importlib.util.spec_from_file_location("real_ecosystem_v23", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class RealEcosystemEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rph-v23-framework-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def test_nine_required_fids_are_exact_and_ordered(self):
        self.assertEqual(list(mod.STAGING), ["F{}".format(n) for n in range(251, 260)])

    def test_all_nine_require_explicit_real_dependencies(self):
        self.assertEqual(set(mod.DEPENDENCIES), set(mod.STAGING))
        self.assertTrue(all(names and isinstance(names, tuple)
                            for names in mod.DEPENDENCIES.values()))

    def test_runtime_allowlist_has_only_three_locally_probeable_libraries(self):
        self.assertEqual(mod.RUNTIME_ALLOWLIST, {"numpy", "pandas", "cffi"})

    def test_absent_framework_never_receives_synthetic_runtime_pass(self):
        report = mod.probe_real_runtime("numpy")
        installed = mod.installed_distribution("numpy")["status"] == (
            "LOCAL_DISTRIBUTION_METADATA_FOUND_NOT_RUNTIME_PROOF")
        self.assertEqual(report["behavioral_evidence"], installed)
        if not installed:
            self.assertEqual(report["status"], "NOT_RUN_NO_TRUSTED_INSTALLED_RUNTIME")
            self.assertFalse(report["actual_runtime_imported"])

    def test_full_matrix_does_not_fake_any_green_fid(self):
        report = mod.inspect_matrix(run_installed_fixtures=False)
        self.assertEqual(report["status"],
                         "ACTUAL_INSTALLED_ECOSYSTEM_EVIDENCE_INCOMPLETE")
        self.assertEqual(set(report["features"]), set(mod.STAGING))
        for fid, data in report["features"].items():
            self.assertEqual(data["status"], "NOT_RUN_NO_REAL_RUNTIME_PROOF", fid)
            self.assertFalse(data["fully_qualified_all_python_minors"])
            self.assertFalse(data["framework_behavior_verified"])
            self.assertFalse(data["external_runtime_attested"])

    def test_full_matrix_real_mode_only_partial_or_not_run(self):
        report = mod.inspect_matrix(run_installed_fixtures=True)
        self.assertEqual(report["python"], "{}.{}".format(sys.version_info.major,
                                                        sys.version_info.minor))
        for fid, data in report["features"].items():
            self.assertIn(data["status"], ("PARTIAL_REAL_RUNTIME_SUBSET",
                                           "NOT_RUN_NO_REAL_RUNTIME_PROOF"), fid)
            self.assertFalse(data["fully_qualified_all_python_minors"])
        self.assertFalse(report["unknown_project_source_executed"])
        self.assertFalse(report["unavailable_framework_fixtures_replaced_with_stubs"])

    def test_installed_metadata_never_claims_real_framework_behavior(self):
        for package in ("numpy", "pandas", "cffi"):
            info = mod.installed_distribution(package)
            self.assertIn(info["status"], ("NOT_INSTALLED",
                       "NOT_TRUSTED_INSTALL_ROOT",
                       "LOCAL_DISTRIBUTION_METADATA_FOUND_NOT_RUNTIME_PROOF"))
            self.assertNotEqual(info["status"], "RUNTIME_VERIFIED")
            if info["status"] == "LOCAL_DISTRIBUTION_METADATA_FOUND_NOT_RUNTIME_PROOF":
                self.assertFalse(info["provenance_officially_authenticated"])
                self.assertTrue(info["metadata_root_within_current_interpreter"])

    def test_torch_tensorflow_jax_not_faked_into_3_12_environment(self):
        matrix = mod.inspect_matrix(run_installed_fixtures=False)
        for fid in ("F253", "F254"):
            self.assertEqual(matrix["features"][fid]["status"],
                             "NOT_RUN_NO_REAL_RUNTIME_PROOF")

    def test_web_orm_queues_arrow_are_not_counted_as_runtime(self):
        matrix = mod.inspect_matrix(run_installed_fixtures=False)
        for fid in ("F255", "F256", "F257", "F258"):
            self.assertEqual(matrix["features"][fid]["status"],
                             "NOT_RUN_NO_REAL_RUNTIME_PROOF")

    def test_real_numpy_reshape_broadcast_dtype_or_not_run(self):
        actual = mod.probe_real_runtime("numpy")
        if actual["behavioral_evidence"]:
            self.assertEqual(actual["status"], "REAL_INSTALLED_NUMPY_BEHAVIOR_VERIFIED")
            self.assertEqual(actual["failure_oracles"],
                             ["RESHAPE_COUNT_MISMATCH", "BROADCAST_SHAPE_MISMATCH",
                              "UNKNOWN_DTYPE_REJECTED"])
            self.assertEqual(actual["framework_version"],
                             mod.installed_distribution("numpy")["installed_version"])
        else:
            self.assertEqual(actual["status"], "NOT_RUN_NO_TRUSTED_INSTALLED_RUNTIME")

    def test_real_pandas_dtype_index_or_not_run(self):
        actual = mod.probe_real_runtime("pandas")
        if actual["behavioral_evidence"]:
            self.assertEqual(actual["status"], "REAL_INSTALLED_PANDAS_BEHAVIOR_VERIFIED")
            self.assertEqual(actual["failure_oracles"],
                             ["MISSING_COLUMN_KEYERROR", "INVALID_DTYPE_REJECTED"])
            self.assertEqual(actual["framework_version"],
                             mod.installed_distribution("pandas")["installed_version"])
        else:
            self.assertEqual(actual["status"], "NOT_RUN_NO_TRUSTED_INSTALLED_RUNTIME")

    def test_real_cffi_libc_abi_or_not_run_without_pyo3_claim(self):
        actual = mod.probe_real_runtime("cffi")
        if actual["behavioral_evidence"]:
            self.assertEqual(actual["status"], "REAL_INSTALLED_CFFI_LIBC_BEHAVIOR_VERIFIED")
            self.assertEqual(actual["failure_oracles"],
                             ["UNKNOWN_NATIVE_DECLARATION_REJECTED"])
            self.assertEqual(actual["framework_version"],
                             mod.installed_distribution("cffi")["installed_version"])
        else:
            self.assertEqual(actual["status"], "NOT_RUN_NO_TRUSTED_INSTALLED_RUNTIME")

    def test_unsupported_dynamic_import_refused_before_execution(self):
        for package in ("tensorflow", "torch", "jax", "django", "pyarrow", "pyo3", "os"):
            with self.assertRaisesRegex(ValueError, "not_allowlisted"):
                mod.probe_real_runtime(package)

    def test_unrecognized_distribution_name_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unapproved_distribution"):
            mod.installed_distribution("untrusted_local_project")

    def test_metadata_outside_prefix_is_untrusted(self):
        class FakeDistribution:
            version = "123"

            @staticmethod
            def locate_file(_path):
                return "/etc"

        with mock.patch.object(mod.importlib.metadata, "distribution",
                               return_value=FakeDistribution()):
            self.assertEqual(mod.installed_distribution("numpy")["status"],
                             "NOT_TRUSTED_INSTALL_ROOT")

    def test_untrusted_install_root_never_reaches_runtime_process(self):
        with mock.patch.object(mod, "installed_distribution", return_value={
                "status":"NOT_TRUSTED_INSTALL_ROOT", "distribution":"numpy"}), \
                mock.patch.object(mod.subprocess, "run", side_effect=AssertionError("must not execute")):
            report = mod.probe_real_runtime("numpy")
        self.assertEqual(report["status"], "NOT_RUN_NO_TRUSTED_INSTALLED_RUNTIME")
        self.assertEqual(report["metadata_status"], "NOT_TRUSTED_INSTALL_ROOT")
        self.assertFalse(report["actual_runtime_imported"])
        self.assertFalse(report["behavioral_evidence"])

    def test_forged_subprocess_version_does_not_count_as_real_runtime(self):
        fake = mock.Mock(returncode=0, stdout=json.dumps({
            "status": "REAL_INSTALLED_NUMPY_BEHAVIOR_VERIFIED",
            "framework_version": "999.999.999", "failure_oracles": ["FAKED"],
            "user_source_executed": False}).encode(), stderr=b"")
        with mock.patch.object(mod, "installed_distribution", return_value={
                "status":"LOCAL_DISTRIBUTION_METADATA_FOUND_NOT_RUNTIME_PROOF",
                "installed_version":"1.0-fixture"}), \
                mock.patch.object(mod.subprocess, "run", return_value=fake):
            report = mod.probe_real_runtime("numpy")
        self.assertEqual(report["status"], "NOT_RUN_LOCAL_RUNTIME_ORACLE_FAILED")
        self.assertFalse(report["behavioral_evidence"])

    def test_forged_user_source_execution_is_rejected(self):
        installed_version = "1.0-fixture"
        fake = mock.Mock(returncode=0, stdout=json.dumps({
            "status": "REAL_INSTALLED_NUMPY_BEHAVIOR_VERIFIED",
            "framework_version": installed_version, "failure_oracles": ["FAKED"],
            "user_source_executed": True}).encode(), stderr=b"")
        with mock.patch.object(mod, "installed_distribution", return_value={
                "status":"LOCAL_DISTRIBUTION_METADATA_FOUND_NOT_RUNTIME_PROOF",
                "installed_version":installed_version}), \
                mock.patch.object(mod.subprocess, "run", return_value=fake):
            report = mod.probe_real_runtime("numpy")
        self.assertFalse(report["behavioral_evidence"])

    def test_trace_classifier_recognizes_nine_ecosystems_without_runtime(self):
        messages = {
            "F251": b"ValueError: cannot reshape array of size 6 into shape (4,2)",
            "F252": b"KeyError: 'missing'",
            "F253": b"RuntimeError: CUDA out of memory",
            "F254": b"jax.errors.TracerArrayConversionError: array",
            "F255": b"django.core.exceptions.ImproperlyConfigured: setting",
            "F256": b"sqlalchemy.exc.MissingGreenlet: context",
            "F257": b"celery.exceptions.SoftTimeLimitExceeded: deadline",
            "F258": b"pyarrow.lib.ArrowInvalid: invalid data",
            "F259": b"ImportError: undefined symbol: foo",
        }
        for fid, record in messages.items():
            output = mod.classify_captured_error(record)
            self.assertTrue(any(item["feature"] == fid for item in output), fid)
            self.assertTrue(all(item["status"].startswith("STATIC_TRACE") for item in output))
            self.assertFalse(any(item["behavioral_cause_verified"] for item in output))

    def test_trace_only_final_exception_line_counts(self):
        before = b"private-path: CUDA out of memory\nRuntimeError: independent test passed"
        self.assertEqual(mod.classify_captured_error(before), [])

    def test_trace_classifier_never_reveals_private_material(self):
        classified = mod.classify_captured_error(
            b"/secret/customer.txt: token=private\nImportError: undefined symbol: abc")
        self.assertEqual(len(classified), 1)
        self.assertEqual(classified[0]["rule_id"], "NATIVE_ABI")
        self.assertNotIn("customer", json.dumps(classified))
        self.assertFalse(classified[0]["private_trace_content_exposed"])

    def test_empty_unknown_trace_has_no_fabricated_diagnosis(self):
        self.assertEqual(mod.classify_captured_error(b""), [])
        self.assertEqual(mod.classify_captured_error(b"zero unrelated evidence"), [])

    def test_oversized_trace_refused(self):
        with self.assertRaises(ValueError):
            mod.classify_captured_error(b"A" * (mod.MAX_TRACE + 1))

    def test_ast_import_inventory_only(self):
        report = mod.inspect_source_imports(
            b"import numpy as np\nfrom pandas import DataFrame\nimport fastapi\n")
        self.assertEqual(report["status"], "STATIC_IMPORT_CANDIDATE_ONLY")
        self.assertEqual(report["referenced_frameworks"],
                         ["fastapi", "numpy", "pandas"])
        self.assertFalse(report["frameworks_imported"])
        self.assertFalse(report["source_executed"])

    def test_ast_does_not_count_framework_name_inside_string(self):
        report = mod.inspect_source_imports(b"fake='import numpy'\nx=1\n")
        self.assertEqual(report["referenced_frameworks"], [])

    def test_ast_never_executes_malicious_call(self):
        marker = self.base / "unexpected-execution"
        source = ("import pandas\n"
                  "__import__('pathlib').Path({!r}).write_text('bad')\n".format(str(marker)))
        report = mod.inspect_source_imports(source.encode("utf-8"))
        self.assertEqual(report["referenced_frameworks"], ["pandas"])
        self.assertFalse(report["source_executed"])
        self.assertFalse(marker.exists())

    def test_ast_budget_rejects_untrusted_huge_input(self):
        with self.assertRaises(ValueError):
            mod.inspect_source_imports(b"x" * (mod.MAX_SOURCE + 1))

    def test_ast_syntax_error_does_not_claim_good_source(self):
        with self.assertRaises(SyntaxError):
            mod.inspect_source_imports(b"import numpy\nif:")

    def test_availability_cli_is_machine_readable_and_nonexecuting(self):
        p = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                            "--mode", "availability"],
                           capture_output=True, text=True, check=False, timeout=12)
        self.assertEqual(p.returncode, 0, p.stderr)
        report = json.loads(p.stdout)
        self.assertEqual(report["python"], "{}.{}".format(sys.version_info.major,
                                                        sys.version_info.minor))
        self.assertEqual(set(report["features"]), set(mod.STAGING))
        self.assertFalse(report["unknown_project_source_executed"])

    def test_full_cli_uses_real_installed_subprocess_or_explicit_not_run(self):
        p = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT),
                            "--mode", "full"],
                           capture_output=True, text=True, check=False, timeout=20)
        self.assertEqual(p.returncode, 0, p.stderr)
        report = json.loads(p.stdout)
        for fid, row in report["features"].items():
            self.assertIn(row["status"], ("PARTIAL_REAL_RUNTIME_SUBSET",
                                          "NOT_RUN_NO_REAL_RUNTIME_PROOF"), fid)
            self.assertFalse(row["fully_qualified_all_python_minors"])
        self.assertFalse(report["unknown_project_source_executed"])

    def test_runtime_cli_missing_package_stays_not_run_or_real(self):
        p = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT),
                            "--mode", "runtime", "--package", "numpy"],
                           capture_output=True, text=True, check=False, timeout=15)
        self.assertEqual(p.returncode, 0, p.stderr)
        report = json.loads(p.stdout)
        self.assertIn(report["status"], ("NOT_RUN_NO_TRUSTED_INSTALLED_RUNTIME",
                                           "REAL_INSTALLED_NUMPY_BEHAVIOR_VERIFIED"))

    def test_static_cli_parses_allowed_regular_file(self):
        source = self.base / "untrusted.py"
        source.write_text("import numpy\nimport pandas\n", encoding="utf-8")
        p = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                            "--mode", "static", "--source", str(source)],
                           capture_output=True, text=True, check=False, timeout=10)
        self.assertEqual(p.returncode, 0, p.stderr)
        report = json.loads(p.stdout)
        self.assertEqual(report["referenced_frameworks"], ["numpy", "pandas"])
        self.assertFalse(report["source_executed"])

    def test_static_cli_rejects_symlink(self):
        source = self.base / "real.py"
        link = self.base / "link.py"
        source.write_text("import numpy\n", encoding="utf-8")
        link.symlink_to(source)
        p = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                            "--mode", "static", "--source", str(link)],
                           capture_output=True, text=True, check=False, timeout=10)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(json.loads(p.stdout)["status"],
                         "NO_PASS_INVALID_OR_UNAVAILABLE_ECOSYSTEM_EVIDENCE")

    def test_static_cli_rejects_hardlink(self):
        source = self.base / "real.py"
        link = self.base / "link.py"
        source.write_text("import numpy\n", encoding="utf-8")
        os.link(source, link)
        p = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                            "--mode", "static", "--source", str(link)],
                           capture_output=True, text=True, check=False, timeout=10)
        self.assertNotEqual(p.returncode, 0)

    def test_static_reader_detects_inode_swap_before_open(self):
        source = self.base / "swap.py"
        source.write_text("import numpy\n", encoding="utf-8")
        genuine_open = mod.os.open

        def swap_target(path, flags, *args, **kwargs):
            source.unlink()
            source.write_text("private_token = 'hidden'\n", encoding="utf-8")
            return genuine_open(path, flags, *args, **kwargs)

        with mock.patch.object(mod.os, "open", side_effect=swap_target):
            with self.assertRaisesRegex(ValueError, "static_file_(?:changed_or_too_large|replaced_before_read)"):
                mod.read_static_regular_file(source)

    def test_cli_rejects_arbitrary_package_runtime(self):
        p = subprocess.run([sys.executable, "-I", "-B", str(SCRIPT),
                            "--mode", "runtime", "--package", "evil"],
                           capture_output=True, text=True, check=False, timeout=10)
        self.assertNotEqual(p.returncode, 0)


if __name__ == "__main__":
    unittest.main()
