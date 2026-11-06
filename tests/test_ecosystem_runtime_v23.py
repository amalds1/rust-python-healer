"""Real F255/F256 installed-wheel fixtures, seven CPython minors; no stubs."""

import json
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "python" / "ecosystem_runtime_v23.py"
SPEC = importlib.util.spec_from_file_location("ecosystem_runtime_v23", SOURCE)
RUNTIME = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNTIME)
MINOR = "{}.{}".format(sys.version_info.major, sys.version_info.minor)
TARGET = ROOT.parent / "healer-r6-ecosystem-staging" / MINOR / "packages"


def run_fixture(mode, target=TARGET, environment=None):
    return subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE),
                           "--mode", mode, "--target", str(target)],
                          capture_output=True, text=True, check=False,
                          timeout=20, env=environment)


class RealFrameworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TARGET.is_dir():
            raise unittest.SkipTest("NOT_RUN: pinned official wheel target missing for " + MINOR)
        cls.web = run_fixture("web")
        cls.orm = run_fixture("orm")
        if cls.web.returncode != 0 or cls.orm.returncode != 0:
            raise AssertionError("NOT_RUN: real framework or ORM import/fixture failed, not green")
        cls.web_data = json.loads(cls.web.stdout)
        cls.orm_data = json.loads(cls.orm.stdout)
        cls.numpy_probe = run_fixture("numpy")
        cls.pandas_probe = run_fixture("pandas")
        cls.numeric_available = (cls.numpy_probe.returncode == 0 and
                                 cls.pandas_probe.returncode == 0)
        if cls.numeric_available:
            cls.numpy_data = json.loads(cls.numpy_probe.stdout)
            cls.pandas_data = json.loads(cls.pandas_probe.stdout)

    def need_numeric_runtime(self):
        if not self.numeric_available:
            self.skipTest("NOT_RUN: real pinned NumPy/Pandas wheels absent for " + MINOR)

    def test_actual_python_minor_is_not_faked(self):
        self.assertEqual(self.web_data["python"], MINOR)
        self.assertEqual(self.orm_data["python"], MINOR)

    def test_wheels_pinned_django_fastapi_flask_sqlalchemy(self):
        for label, value in {"django": "4.2.27", "fastapi": "0.120.4",
                             "flask": "3.1.2", "sqlalchemy": "2.0.44"}.items():
            self.assertEqual(self.web_data["primary_pins"][label], value)
            self.assertEqual(self.orm_data["primary_pins"][label], value)

    def test_django_real_resolver_and_reverse(self):
        self.assertTrue(self.web_data["django_resolve_and_reverse"])
        self.assertEqual(self.web_data["django_version"], "4.2.27")

    def test_django_real_404_negative(self):
        self.assertTrue(self.web_data["django_negative_404"])

    def test_django_real_common_middleware(self):
        self.assertTrue(self.web_data["django_real_middleware_response"])

    def test_fastapi_real_dependency_injection_graph(self):
        self.assertTrue(self.web_data["fastapi_real_route_and_dependency_graph"])
        self.assertEqual(self.web_data["fastapi_version"], "0.120.4")

    def test_fastapi_real_middleware_registered(self):
        self.assertTrue(self.web_data["fastapi_real_middleware_registration"])

    def test_flask_real_test_client_200_and_404(self):
        self.assertTrue(self.web_data["flask_real_test_client_200_and_404"])

    def test_flask_real_before_after_middleware(self):
        self.assertTrue(self.web_data["flask_real_before_after_middleware"])

    def test_web_probe_never_claims_external_deployment_or_running_user_project(self):
        self.assertEqual(self.web_data["status"],
                         "REAL_DJANGO_FASTAPI_FLASK_FIXTURE_VERIFIED")
        self.assertFalse(self.web_data["unknown_project_code_executed"])
        self.assertFalse(self.web_data["production_web_deployment_qualified"])
        self.assertFalse(self.web_data["external_runtime_attested"])

    def test_web_probe_did_not_open_external_service(self):
        self.assertFalse(self.web_data["external_network_contacted"])

    def test_sqlalchemy_real_memory_sqlite_roundtrip(self):
        self.assertEqual(self.orm_data["status"],
                         "REAL_SQLALCHEMY_SQLITE_ASYNC_CONTEXT_VERIFIED")
        self.assertEqual(self.orm_data["sqlite_real_insert_select_count"], 1)

    def test_sqlalchemy_legacy_raw_string_sql_rejected(self):
        self.assertTrue(self.orm_data["legacy_raw_sql_rejected"])

    def test_sqlalchemy_actual_sqlite_duplicate_constraint_rejected(self):
        self.assertTrue(self.orm_data["sqlite_duplicate_constraint_rejected"])

    def test_sqlalchemy_actual_ddl_migration_committed(self):
        self.assertTrue(self.orm_data["actual_schema_migration_committed"])

    def test_sqlalchemy_migration_preserves_older_data(self):
        self.assertTrue(self.orm_data["actual_migration_preserved_original_row"])

    def test_sqlalchemy_duplicate_column_upgrade_is_rejected(self):
        self.assertTrue(self.orm_data["duplicate_column_migration_rejected"])

    def test_sqlalchemy_real_ddl_rollback_removes_temporary_column(self):
        self.assertTrue(self.orm_data["actual_sqlite_ddl_rollback_verified"])

    def test_sqlalchemy_actual_missing_greenlet_context_rejected(self):
        self.assertTrue(self.orm_data["async_without_greenlet_context_rejected"])

    def test_sqlalchemy_version_and_no_production_claim(self):
        self.assertEqual(self.orm_data["sqlalchemy_version"], "2.0.44")
        self.assertFalse(self.orm_data["production_orm_migrations_qualified"])

    def test_sqlalchemy_never_runs_external_database_or_user_program(self):
        self.assertFalse(self.orm_data["unknown_project_code_executed"])
        self.assertFalse(self.orm_data["external_database_contacted"])

    def test_invalid_public_directory_rejected(self):
        with tempfile.TemporaryDirectory(prefix="rph-f255-public-") as folder:
            if os.name == "nt":
                import windows_privacy_fixtures as acl
                acl.set_public_read_acl(Path(folder))
            else:
                Path(folder).chmod(0o755)
            outcome = run_fixture("web", folder)
            self.assertNotEqual(outcome.returncode, 0)
            self.assertEqual(json.loads(outcome.stdout)["status"],
                             "NO_PASS_UNVERIFIED_FRAMEWORK_RUNTIME")

    def test_symlink_target_rejected_before_any_framework_import(self):
        with tempfile.TemporaryDirectory(prefix="rph-f255-link-") as folder:
            parent = Path(folder)
            link = parent / "link"
            link.symlink_to(TARGET)
            outcome = run_fixture("web", link)
            self.assertNotEqual(outcome.returncode, 0)

    def test_empty_private_target_does_not_fake_imports(self):
        with tempfile.TemporaryDirectory(prefix="rph-f256-missing-") as folder:
            if os.name == "nt":
                import windows_privacy_fixtures as acl
                acl.set_private_acl(Path(folder))
            else:
                Path(folder).chmod(0o700)
            outcome = run_fixture("orm", folder)
            self.assertNotEqual(outcome.returncode, 0)
            self.assertEqual(json.loads(outcome.stdout)["reason_code"], "ValueError")

    def test_unknown_mode_rejected_by_cli(self):
        outcome = run_fixture("run-untrusted-code")
        self.assertNotEqual(outcome.returncode, 0)

    def test_capabilities_default_without_target_never_imports_frameworks(self):
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE)],
                                capture_output=True, text=True, check=False, timeout=8)
        self.assertEqual(result.returncode, 0, result.stderr)
        details = json.loads(result.stdout)
        self.assertEqual(details["status"],
                         "PINNED_REAL_FRAMEWORK_FIXTURE_ADAPTER_AVAILABLE")
        self.assertFalse(details["real_frameworks_executed"])
        self.assertFalse(details["unknown_project_code_executed"])

    def test_runtime_without_target_fails_closed(self):
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE),
                                 "--mode", "numpy"], capture_output=True,
                                text=True, check=False, timeout=8)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["status"],
                         "NO_PASS_UNVERIFIED_FRAMEWORK_RUNTIME")

    def test_pythonpath_injection_is_ignored_by_isolated_interpreter(self):
        with tempfile.TemporaryDirectory(prefix="rph-f255-inject-") as folder:
            source = Path(folder) / "django.py"
            marker = Path(folder) / "malicious-executed"
            source.write_text("from pathlib import Path\nPath({!r}).write_text('bad')\n".format(
                              str(marker)), encoding="utf-8")
            environment = dict(os.environ)
            environment["PYTHONPATH"] = folder
            outcome = run_fixture("web", environment=environment)
            self.assertEqual(outcome.returncode, 0, outcome.stderr)
            self.assertFalse(marker.exists())

    def test_returned_logs_contain_no_secret_source_or_credentials(self):
        for data in (self.web_data, self.orm_data):
            rendered = json.dumps(data)
            self.assertNotIn("SECRET_KEY", rendered)
            self.assertNotIn("DATABASE_URL", rendered)
            self.assertNotIn("127.0.0.1:", rendered)

    def test_numeric_pins_match_wheel_availability_per_minor(self):
        self.need_numeric_runtime()
        expected_numpy, expected_pandas = RUNTIME.NUMERIC_PINS[MINOR]
        self.assertEqual(self.numpy_data["installed_pin"], expected_numpy)
        self.assertEqual(self.pandas_data["installed_pin"], expected_pandas)

    def test_numpy_real_compiled_native_extension_import(self):
        self.need_numeric_runtime()
        self.assertEqual(self.numpy_data["status"], "REAL_NUMPY_NATIVE_SHAPE_DTYPE_VERIFIED")
        self.assertTrue(self.numpy_data["real_native_extension_imported"])

    def test_numpy_real_reshape_positive(self):
        self.need_numeric_runtime()
        self.assertEqual(self.numpy_data["shape_after_reshape"], [2, 3])

    def test_numpy_real_broadcast_positive(self):
        self.need_numeric_runtime()
        self.assertEqual(self.numpy_data["broadcast_output_shape"], [2, 3])

    def test_numpy_real_reshape_negative(self):
        self.need_numeric_runtime()
        self.assertIn("RESHAPE_COUNT_MISMATCH",
                      self.numpy_data["actual_negative_runtime_oracles"])

    def test_numpy_real_broadcast_negative(self):
        self.need_numeric_runtime()
        self.assertIn("BROADCAST_SHAPE_MISMATCH",
                      self.numpy_data["actual_negative_runtime_oracles"])

    def test_numpy_real_invalid_dtype_negative(self):
        self.need_numeric_runtime()
        self.assertIn("UNKNOWN_DTYPE_REJECTED",
                      self.numpy_data["actual_negative_runtime_oracles"])

    def test_numpy_native_abi_captured_error_not_executed(self):
        positive = RUNTIME.classify_numpy_native_abi_error(
            b"ImportError: numpy.dtype size changed, expected 96 from C header")
        self.assertEqual(positive[0]["rule_id"], "NUMPY_DTYPE_ABI_SIZE_MISMATCH")
        self.assertFalse(positive[0]["unknown_native_module_loaded"])
        self.assertTrue(self.numpy_data["incompatible_abi_binary_intentionally_not_executed"]
                        if self.numeric_available else True)

    def test_numpy_abi_classifier_ignores_untrusted_first_trace_line(self):
        malicious = (b"private-path: numpy.dtype size changed\n"
                     b"RuntimeError: isolated fixture completed")
        self.assertEqual(RUNTIME.classify_numpy_native_abi_error(malicious), [])

    def test_pandas_real_native_extension_and_dtype(self):
        self.need_numeric_runtime()
        self.assertEqual(self.pandas_data["status"],
                         "REAL_PANDAS_NATIVE_INDEX_DTYPE_SCHEMA_VERIFIED")
        self.assertTrue(self.pandas_data["real_native_extension_imported"])
        self.assertEqual(self.pandas_data["nullable_integer_dtype"], "Int64")

    def test_pandas_actual_schema_verified(self):
        self.need_numeric_runtime()
        self.assertTrue(self.pandas_data["real_dataframe_schema_verified"])

    def test_pandas_actual_label_index_positive(self):
        self.need_numeric_runtime()
        self.assertTrue(self.pandas_data["real_index_lookup_verified"])

    def test_pandas_actual_missing_column_negative(self):
        self.need_numeric_runtime()
        self.assertIn("MISSING_SCHEMA_COLUMN_REJECTED",
                      self.pandas_data["actual_negative_runtime_oracles"])

    def test_pandas_actual_missing_label_negative(self):
        self.need_numeric_runtime()
        self.assertIn("INVALID_LABEL_INDEX_REJECTED",
                      self.pandas_data["actual_negative_runtime_oracles"])

    def test_pandas_actual_dtype_conversion_negative(self):
        self.need_numeric_runtime()
        self.assertIn("INVALID_DTYPE_REJECTED",
                      self.pandas_data["actual_negative_runtime_oracles"])

    def test_numeric_modules_never_run_unknown_project(self):
        self.need_numeric_runtime()
        for report in (self.numpy_data, self.pandas_data):
            self.assertFalse(report["unknown_project_code_executed"])
            self.assertFalse(report["independent_external_audit"])


if __name__ == "__main__":
    unittest.main()
