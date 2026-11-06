"""Real PyArrow/protobuf and Cython/cffi/orjson native wheel fixtures (F258/F259)."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "native_serialization_v23.py"
MINOR = "{}.{}".format(sys.version_info.major, sys.version_info.minor)
TARGET = ROOT.parent / "healer-r6-ecosystem-staging" / MINOR / "packages"
SPEC = importlib.util.spec_from_file_location("native_serialization_v23", SCRIPT)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def run_mode(mode, target=TARGET, environment=None):
    return subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                           "--mode", mode, "--target", str(target)],
                          capture_output=True, text=True, check=False,
                          timeout=20, env=environment)


class RealNativeSerializationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TARGET.is_dir():
            raise unittest.SkipTest("NOT_RUN: pinned native wheel target missing for " + MINOR)
        cls.serialization = run_mode("serialization")
        cls.native = run_mode("native")
        if cls.serialization.returncode != 0 or cls.native.returncode != 0:
            raise AssertionError("NOT_RUN: real native wheel or serialization fixture failed")
        cls.serialization_data = json.loads(cls.serialization.stdout)
        cls.native_data = json.loads(cls.native.stdout)

    def test_real_minor_checked_not_inferred(self):
        self.assertEqual(self.serialization_data["python"], MINOR)
        self.assertEqual(self.native_data["python"], MINOR)

    def test_exact_per_minor_native_pins(self):
        pins = dict(zip(MOD.NAMES, MOD.PINS[MINOR]))
        self.assertEqual(self.serialization_data["pin_versions"], pins)
        self.assertEqual(self.native_data["pin_versions"], pins)

    def test_pyarrow_genuine_native_extension(self):
        self.assertEqual(self.serialization_data["status"],
                         "REAL_ARROW_PARQUET_PROTOBUF_SCHEMA_COMPAT_VERIFIED")
        self.assertTrue(self.serialization_data["real_native_pyarrow_runtime"])

    def test_arrow_real_zero_copy_pointer_shared_with_numpy(self):
        self.assertTrue(self.serialization_data["real_arrow_zero_copy_same_memory_pointer"])

    def test_parquet_actual_in_memory_roundtrip(self):
        self.assertTrue(self.serialization_data["real_parquet_in_memory_roundtrip"])

    def test_parquet_corrupt_file_rejected_by_real_native_decoder(self):
        self.assertIn("CORRUPT_PARQUET_REJECTED",
                      self.serialization_data["actual_negative_runtime_oracles"])

    def test_arrow_actual_schema_type_mismatch_rejected(self):
        self.assertIn("ARROW_SCHEMA_TYPE_MISMATCH_REJECTED",
                      self.serialization_data["actual_negative_runtime_oracles"])

    def test_protobuf_real_dynamic_descriptor_roundtrip(self):
        self.assertTrue(self.serialization_data["real_protobuf_dynamic_schema_roundtrip"])

    def test_protobuf_additive_schema_backward_readable(self):
        self.assertTrue(self.serialization_data["real_protobuf_additive_schema_compatibility"])

    def test_corrupt_protobuf_fails_real_decoder(self):
        self.assertIn("CORRUPT_PROTOBUF_REJECTED",
                      self.serialization_data["actual_negative_runtime_oracles"])

    def test_real_cython_compiled_scanning_extension_imported(self):
        self.assertEqual(self.native_data["status"],
                         "REAL_CYTHON_CFFI_RUST_NATIVE_FIXTURES_VERIFIED")
        self.assertTrue(self.native_data["compiled_cython_native_scanning_imported"])

    def test_cffi_actual_libc_function_abi(self):
        self.assertEqual(self.native_data["cffi_real_libc_strlen_bytes"], 16)

    def test_cffi_unapproved_type_is_rejected(self):
        self.assertIn("CFFI_INVALID_NATIVE_DECLARATION_REJECTED",
                      self.native_data["actual_negative_runtime_oracles"])

    def test_real_rust_native_orjson_extension_loaded(self):
        self.assertTrue(self.native_data["rust_orjson_native_extension_imported"])

    def test_rust_orjson_actual_json_roundtrip(self):
        self.assertTrue(self.native_data["rust_orjson_json_roundtrip_verified"])

    def test_orjson_unsupported_input_rejected(self):
        self.assertIn("PYO3_ORJSON_UNSUPPORTED_OBJECT_REJECTED",
                      self.native_data["actual_negative_runtime_oracles"])

    def test_orjson_malformed_json_rejected(self):
        self.assertIn("PYO3_ORJSON_CORRUPT_JSON_REJECTED",
                      self.native_data["actual_negative_runtime_oracles"])

    def test_invalid_non_elf_fixed_bytes_rejected_by_real_loader(self):
        self.assertTrue(self.native_data["fixed_non_elf_rejected_before_native_initialization"])

    def test_actual_native_loader_exception_was_classified(self):
        self.assertTrue(self.native_data["captured_native_loader_error_classified"])

    def test_native_crash_was_not_deliberately_executed(self):
        self.assertTrue(self.native_data["native_crash_test_intentionally_not_run"])
        self.assertFalse(self.native_data["unknown_native_machine_code_executed"])

    def test_native_runtime_unknown_project_code_never_executed(self):
        self.assertFalse(self.native_data["unknown_project_code_executed"])
        self.assertFalse(self.serialization_data["unknown_project_code_executed"])

    def test_no_external_datasets_or_network(self):
        self.assertFalse(self.serialization_data["external_dataset_or_network_used"])

    def test_no_universal_production_qualification_claims(self):
        self.assertFalse(self.serialization_data["all_serialization_formats_universally_qualified"])
        self.assertFalse(self.native_data["all_native_abi_variants_universally_qualified"])

    def test_native_trace_classifier_redacts_error_paths(self):
        result = MOD.classify_captured_native_error(
            b"/private/user/patient.txt contains token\nImportError: undefined symbol: PyArray_API")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["rule_id"], "NATIVE_MODULE_UNDEFINED_SYMBOL")
        self.assertNotIn("patient", json.dumps(result))

    def test_trace_classifier_does_not_trust_earlier_stack_frames(self):
        result = MOD.classify_captured_native_error(
            b"not-executed/source: undefined symbol: secret\nValueError: benign unrelated cause")
        self.assertEqual(result, [])

    def test_trace_classifier_no_fabricated_findings(self):
        self.assertEqual(MOD.classify_captured_native_error(b""), [])
        self.assertEqual(MOD.classify_captured_native_error(b"None: no native errors"), [])

    def test_native_trace_oversized_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid_or_excessive"):
            MOD.classify_captured_native_error(b"x" * 65537)

    def test_public_wheel_directory_rejected(self):
        with tempfile.TemporaryDirectory(prefix="rph-native-public-") as folder:
            if os.name == "nt":
                import windows_privacy_fixtures as acl
                acl.set_public_read_acl(Path(folder))
            else:
                Path(folder).chmod(0o755)
            process = run_mode("native", folder)
            self.assertNotEqual(process.returncode, 0)
            self.assertEqual(json.loads(process.stdout)["status"],
                             "NO_PASS_NATIVE_OR_SERIALIZATION_UNVERIFIED")

    def test_symlink_wheel_directory_rejected(self):
        with tempfile.TemporaryDirectory(prefix="rph-native-link-") as folder:
            link = Path(folder) / "private-link"
            link.symlink_to(TARGET)
            process = run_mode("serialization", link)
            self.assertNotEqual(process.returncode, 0)

    def test_empty_private_wheel_directory_rejected(self):
        with tempfile.TemporaryDirectory(prefix="rph-native-empty-") as folder:
            process = run_mode("native", folder)
            self.assertNotEqual(process.returncode, 0)

    def test_capabilities_default_has_no_framework_imports(self):
        process = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT)],
                                 capture_output=True, text=True, check=False, timeout=8)
        self.assertEqual(process.returncode, 0, process.stderr)
        report = json.loads(process.stdout)
        self.assertEqual(report["status"], "PINNED_NATIVE_SERIALIZATION_ADAPTER_AVAILABLE")
        self.assertFalse(report["real_packages_imported"])
        self.assertFalse(report["unknown_project_code_executed"])

    def test_real_runtime_requires_private_explicit_target(self):
        process = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                                  "--mode", "serialization"],
                                 capture_output=True, text=True, check=False, timeout=8)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(json.loads(process.stdout)["status"],
                         "NO_PASS_NATIVE_OR_SERIALIZATION_UNVERIFIED")

    def test_pythonpath_injection_is_not_imported(self):
        with tempfile.TemporaryDirectory(prefix="rph-native-injection-") as folder:
            marker = Path(folder) / "untrusted-source-was-executed"
            for package in ("pyarrow", "orjson"):
                Path(folder, package + ".py").write_text(
                    "from pathlib import Path\nPath({!r}).write_text('bad')\n".format(str(marker)),
                    encoding="utf-8")
            env = dict(os.environ)
            env["PYTHONPATH"] = folder
            process = run_mode("serialization", environment=env)
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
