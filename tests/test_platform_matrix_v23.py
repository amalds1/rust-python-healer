"""Honest real CPython native ABI and subinterpreter qualification fixtures."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "platform_matrix_v23.py"
spec = importlib.util.spec_from_file_location("platform_matrix_v23", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

spec_abi = importlib.util.spec_from_file_location("abi_tags_for_native_fixture",
                                                  ROOT / "python" / "abi_tags.py")
abi = importlib.util.module_from_spec(spec_abi)
spec_abi.loader.exec_module(abi)


class RealNativeWheelMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = module.qualify_local_native()

    def test_current_minor_real_native_build_import_and_subinterp(self):
        self.assertEqual(self.result["status"], "LOCAL_NATIVE_WHEEL_ABI_SUBINTERP_VERIFIED")
        self.assertTrue(self.result["trusted_compiler_invoked"])
        self.assertTrue(self.result["trusted_native_import_in_host_pass"])
        self.assertTrue(self.result["trusted_native_import_in_subinterp_pass"])

    def test_source_is_single_known_immutable_fixture(self):
        proofs = self.result["native_source_fixtures"]
        self.assertRegex(proofs["multiphase_fixture_sha256"], r"\A[0-9a-f]{64}\Z")
        self.assertFalse(proofs["submitted_source_compiled"])
        self.assertFalse(self.result["unknown_project_source_executed"])
        self.assertFalse(self.result["unknown_native_binary_loaded"])

    def test_actual_interpreter_abi_metadata_matches_sys(self):
        runtime = self.result["runtime"]
        self.assertEqual(runtime["implementation"], "cpython")
        self.assertEqual(runtime["minor"], sys.version_info.minor)
        self.assertEqual(runtime["version"], "{}.{}.{}".format(*sys.version_info[:3]))
        self.assertIn(runtime["extension_suffix"], runtime["extension_suffixes"])
        self.assertTrue(runtime["headers_present"])

    def test_platform_and_wheel_tag_are_actual_local_runtime(self):
        runtime = self.result["runtime"]
        self.assertEqual(runtime["linux_host"], sys.platform == "linux")
        self.assertEqual(runtime["windows_host"], sys.platform == "win32")
        self.assertTrue(runtime["platform_tag"].startswith("win_" if sys.platform == "win32" else "linux_"))
        self.assertEqual(self.result["wheel_tag"], "{}-{}-{}".format(
            runtime["python_tag"], runtime["abi_tag"], runtime["platform_tag"]))
        self.assertEqual(abi.compare_wheel(self.result["wheel_name"])["compatibility"],
                         "POSSIBLE_TAG_MATCH_NOT_INSTALLED")

    def test_negative_wrong_minor_tag_is_not_accepted(self):
        name = self.result["wheel_name"]
        current = self.result["runtime"]["python_tag"]
        foreign = "cp3{}".format(sys.version_info.minor + 1)
        forged = name.replace("-" + current + "-", "-" + foreign + "-", 1)
        self.assertNotEqual(abi.compare_wheel(forged)["compatibility"],
                            "POSSIBLE_TAG_MATCH_NOT_INSTALLED")

    def test_singlephase_legacy_policy_report_is_not_generalized(self):
        self.assertIn(self.result["legacy_subinterpreter_result"], (
            "LEGACY_SINGLE_PHASE_REFUSED", "LEGACY_SINGLE_PHASE_ACCEPTED_OLD_POLICY"))
        self.assertTrue(self.result["legacy_singlephase_policy_pass"])
        if sys.version_info[:2] >= (3, 12):
            self.assertTrue(self.result["singlephase_refused_in_subinterp"])
        else:
            self.assertEqual(self.result["legacy_subinterpreter_result"], "LEGACY_SINGLE_PHASE_ACCEPTED_OLD_POLICY")

    def test_report_explicitly_refuses_other_platform_attestation(self):
        self.assertFalse(self.result["windows_macos_musl_qualified"])
        self.assertFalse(self.result["other_python_minor_binaries_executed"])
        self.assertRegex(self.result["compiled_native_sha256"], r"\A[0-9a-f]{64}\Z")


class NativeWheelIntegrityNegatives(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="rph-v23-native-oracle-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.folder = Path(cls.temp.name)
        cls.runtime = module.actual_runtime()
        cls.binary = module._compile_fixture(cls.folder, module.MODULE, module._MULTIPHASE_C,
                                             cls.runtime["extension_suffix"],
                                             cls.runtime["include_dir"], module._compiler())
        cls.wheel = module.make_native_wheel_bytes(cls.binary, cls.runtime)
        cls.pin = hashlib.sha256(cls.wheel["bytes"]).hexdigest()

    def test_pinned_native_wheel_has_real_record_bytes(self):
        result = module.verify_native_wheel_bytes(self.wheel["bytes"], self.pin,
                                                  self.wheel["native_entry"])
        self.assertEqual(result["status"], "PINNED_NATIVE_WHEEL_RECORD_VERIFIED")
        self.assertEqual(result["record_entries"], 4)
        self.assertEqual(result["native_sha256"],
                         hashlib.sha256(self.binary.read_bytes()).hexdigest())

    def test_actual_subinterpreter_failure_cannot_emit_multiphase_pass(self):
        missing = self.folder / ("rph_absent" + self.runtime["extension_suffix"])
        result = module._checked_process([sys.executable, "-I", "-S", "-B", "-c",
                                          module._SUBINTERP_CODE, str(missing)], self.folder)
        self.assertNotEqual(result["returncode"], 0)
        self.assertNotIn("SUBINTERP_MULTIPHASE_NATIVE_VERIFIED", result["stdout"])

    @unittest.skipUnless(sys.platform == "win32", "Native Windows PE contract")
    def test_real_pe_machine_and_section_boundaries_are_checked(self):
        import struct
        original = self.binary.read_bytes()
        pe = struct.unpack_from("<I", original, 60)[0]
        wrong_machine = bytearray(original)
        struct.pack_into("<H", wrong_machine, pe + 4, 0x14c)
        with self.assertRaisesRegex(ValueError, "pe_architecture"):
            module._validate_native_payload(bytes(wrong_machine), self.runtime["extension_suffix"])
        wrong_sections = bytearray(original)
        section_table = pe + 24 + struct.unpack_from("<H", original, pe + 20)[0]
        struct.pack_into("<II", wrong_sections, section_table + 16, 100, len(original))
        with self.assertRaisesRegex(ValueError, "section_out_of_bounds"):
            module._validate_native_payload(bytes(wrong_sections), self.runtime["extension_suffix"])

    @unittest.skipUnless(sys.platform == "win32", "Native Windows compiler environment")
    def test_caller_cl_injection_is_not_forwarded_to_real_compiler(self):
        with tempfile.TemporaryDirectory(prefix="rph-msvc-env-") as directory:
            with unittest.mock.patch.dict(os.environ, {"CL": "/FIrph_absent_injected_header.h", "_CL_": "/FIrph_absent_other_header.h"}):
                built = module._compile_fixture(Path(directory), module.MODULE, module._MULTIPHASE_C,
                    self.runtime["extension_suffix"], self.runtime["include_dir"], module._compiler())
            self.assertEqual(module._validate_native_payload(built.read_bytes(), self.runtime["extension_suffix"]), "PE32+_AMD64_DLL")

    def test_missing_or_false_out_of_band_pin_fails_closed(self):
        for pin in ("", "f" * 64, "invalid", None):
            with self.subTest(pin=pin), self.assertRaises(ValueError):
                module.verify_native_wheel_bytes(self.wheel["bytes"], pin,
                                                 self.wheel["native_entry"])

    def test_tampered_native_extension_rejected_even_if_sha_pin_matches(self):
        with zipfile.ZipFile(io.BytesIO(self.wheel["bytes"])) as archive:
            rows = [(name, archive.read(name)) for name in archive.namelist()]
        modified = io.BytesIO()
        with zipfile.ZipFile(modified, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, content in rows:
                if name == self.wheel["native_entry"]:
                    content = content + b"CORRUPTED_AFTER_BUILD"
                archive.writestr(name, content)
        changed = modified.getvalue()
        changed_pin = hashlib.sha256(changed).hexdigest()
        with self.assertRaisesRegex(ValueError, "wheel_record_hash_or_size_mismatch"):
            module.verify_native_wheel_bytes(changed, changed_pin, self.wheel["native_entry"])

    def test_path_traversal_archive_with_valid_pin_rejected(self):
        modified = io.BytesIO()
        with zipfile.ZipFile(modified, "w", compression=zipfile.ZIP_STORED) as archive:
            for name in ("../outside.so", "a.dist-info/WHEEL", "a.dist-info/METADATA",
                         "a.dist-info/RECORD"):
                archive.writestr(name, b"TEST")
        data = modified.getvalue()
        with self.assertRaisesRegex(ValueError, "unsafe_native_wheel_entries"):
            module.verify_native_wheel_bytes(data, hashlib.sha256(data).hexdigest(),
                                             self.wheel["native_entry"])

    def test_unsafe_or_missing_native_entry_rejected(self):
        for name in ("../evil.so", "", "something.so", self.wheel["native_entry"] + "x"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                module.verify_native_wheel_bytes(self.wheel["bytes"], self.pin, name)

    def test_untrusted_source_cannot_be_passed_to_native_compiler(self):
        with self.assertRaisesRegex(ValueError, "only_curated_native_source"):
            module._compile_fixture(self.folder, "untrusted_extension", "/* malicious */",
                                    self.runtime["extension_suffix"],
                                    self.runtime["include_dir"], module._compiler())

    def test_reject_non_elf_payload_wheel(self):
        with tempfile.TemporaryDirectory(prefix="rph-v23-non-elf-") as folder:
            forged = Path(folder) / (module.MODULE + self.runtime["extension_suffix"])
            forged.write_bytes(b"\x00" * 100)
            with self.assertRaisesRegex(ValueError, "not_pe" if sys.platform == "win32" else "not_elf"):
                module.make_native_wheel_bytes(forged, self.runtime)

    def test_refuse_symlinked_compiled_native_binary(self):
        with tempfile.TemporaryDirectory(prefix="rph-v23-link-") as folder:
            link = Path(folder) / (module.MODULE + self.runtime["extension_suffix"])
            link.symlink_to(self.binary)
            with self.assertRaisesRegex(ValueError, "unsafe_compiled_native_payload"):
                module.make_native_wheel_bytes(link, self.runtime)

    def test_reject_zip_bomb_before_decompression(self):
        modified = io.BytesIO()
        with zipfile.ZipFile(modified, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name in (self.wheel["native_entry"], "a.dist-info/WHEEL",
                         "a.dist-info/METADATA", "a.dist-info/RECORD"):
                archive.writestr(name, b"A" * 400_000)
        payload = modified.getvalue()
        with self.assertRaisesRegex(ValueError, "native_wheel_entry_quota_or_encoding"):
            module.verify_native_wheel_bytes(payload, hashlib.sha256(payload).hexdigest(),
                                             self.wheel["native_entry"])

    def test_refuse_wheel_over_absolute_byte_limit(self):
        with self.assertRaisesRegex(ValueError, "invalid_native_wheel_size"):
            module.verify_native_wheel_bytes(b"X" * (module.LIMIT_WHEEL_BYTES + 1),
                                             self.pin, self.wheel["native_entry"])


class CapabilityAndCliEvidence(unittest.TestCase):
    def test_runtime_probe_does_not_expand_unknown_os_support(self):
        detail = module.actual_runtime()
        self.assertFalse(detail["other_os_or_implementation_tested"])
        self.assertTrue(detail["real_interpreter_queried"])

    def test_free_threaded_and_other_runtime_gaps_explicit(self):
        detail = module.environmental_gaps()
        self.assertEqual(detail["status"], "ENVIRONMENT_GAPS_RECORDED_NO_FALSE_PASS")
        self.assertFalse(detail["all_supported_microversions_tested"])
        self.assertFalse(detail["forkserver_qualified"])
        self.assertEqual(detail["f167_status"], "BLOCKED_OR_NOT_RUN")
        self.assertFalse(detail["other_os_abi_qualified"])

    def test_missing_real_compiler_never_claims_native_pass(self):
        with unittest.mock.patch.object(module, "_compiler", return_value=None):
            detail = module.qualify_local_native()
        self.assertEqual(detail["status"], "NOT_RUN_REQUIRED_NATIVE_FIXTURE_TOOLCHAIN_MISSING")

    def test_cli_probe_isolation_and_runtime_json(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                              "--mode", "runtime"], capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 0)
        self.assertEqual(json.loads(run.stdout)["status"],
                         "ACTUAL_RUNNING_CPYTHON_ABI_INSPECTED")

    def test_cli_actual_native_fixture_end_to_end(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                              "--mode", "native"], capture_output=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stderr[-300:])
        report = json.loads(run.stdout)
        self.assertEqual(report["status"], "LOCAL_NATIVE_WHEEL_ABI_SUBINTERP_VERIFIED")

    def test_cli_gaps_no_false_full_matrix_pass(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                              "--mode", "gaps"], capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 0)
        self.assertEqual(json.loads(run.stdout)["f050_status"], "NOT_RUN")


if __name__ == "__main__":
    unittest.main()
