"""Linux enforcement and lexical cross-platform proof, not unknown-code sandbox."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "platform_constraints_v22.py"
spec = importlib.util.spec_from_file_location("platform_constraints_v22", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ResourceControlsTests(unittest.TestCase):
    @unittest.skipIf(sys.platform == "linux", "Non-Linux rejection contract")
    def test_non_linux_resource_limits_explicitly_unsupported(self):
        for mode in ("safe", "cpu", "ram", "file", "fd", "stdout"):
            with self.subTest(mode=mode):
                report = mod.run_guarded_fixture(mode)
                self.assertEqual(report["status"], "NOT_SUPPORTED_NON_LINUX")
                self.assertFalse(report["unknown_source_executed"])

    @unittest.skipUnless(sys.platform == "linux", "Requires actual Linux RLIMIT/libc/ELF runtime; run on Linux/WSL")
    def test_real_safe_trusted_process_finishes(self):
        outcome = mod.run_guarded_fixture("safe")
        self.assertEqual(outcome["status"], "FIXED_LINUX_RESOURCE_GATE_VERIFIED")
        self.assertEqual(outcome["returncode"], 0)
        self.assertFalse(outcome["arbitrary_user_source_sandboxed"])

    @unittest.skipUnless(sys.platform == "linux", "Requires actual Linux RLIMIT/libc/ELF runtime; run on Linux/WSL")
    def test_real_cpu_rlimit_kills_spinning_trusted_child(self):
        outcome = mod.run_guarded_fixture("cpu")
        self.assertEqual(outcome["status"], "FIXED_LINUX_RESOURCE_GATE_VERIFIED")
        self.assertTrue(outcome["limit_tripped_or_safe_completed"])
        self.assertFalse(outcome["timeout_kill_used"])

    @unittest.skipUnless(sys.platform == "linux", "Requires actual Linux RLIMIT/libc/ELF runtime; run on Linux/WSL")
    def test_real_memory_rlimit_prevents_large_allocation(self):
        outcome = mod.run_guarded_fixture("ram")
        self.assertEqual(outcome["status"], "FIXED_LINUX_RESOURCE_GATE_VERIFIED")
        self.assertEqual(outcome["returncode"], 43)

    @unittest.skipUnless(sys.platform == "linux", "Requires actual Linux RLIMIT/libc/ELF runtime; run on Linux/WSL")
    def test_real_file_size_rlimit_prevents_large_disk_write(self):
        outcome = mod.run_guarded_fixture("file")
        self.assertEqual(outcome["status"], "FIXED_LINUX_RESOURCE_GATE_VERIFIED")
        self.assertTrue(outcome["returncode"] in (44, -25))
        self.assertLessEqual(outcome["fixture_disk_bytes_written"], 512)

    @unittest.skipUnless(sys.platform == "linux", "Requires actual Linux RLIMIT/libc/ELF runtime; run on Linux/WSL")
    def test_real_descriptor_limit_denies_too_many_open_files(self):
        outcome = mod.run_guarded_fixture("fd")
        self.assertEqual(outcome["status"], "FIXED_LINUX_RESOURCE_GATE_VERIFIED")
        self.assertEqual(outcome["returncode"], 45)
        self.assertEqual(outcome["rlimit_open_file_descriptors"], 32)

    @unittest.skipUnless(sys.platform == "linux", "Requires actual Linux RLIMIT/libc/ELF runtime; run on Linux/WSL")
    def test_real_stdout_quota_bounds_and_kills_streaming_child(self):
        outcome = mod.run_guarded_fixture("stdout", output_quota=512)
        self.assertEqual(outcome["status"], "FIXED_LINUX_RESOURCE_GATE_VERIFIED")
        self.assertTrue(outcome["output_quota_exceeded"])
        self.assertEqual(outcome["stdout_stderr_quota_bytes"], 512)
        self.assertFalse(outcome["full_disk_read_io_limit_proven"])

    def test_refuse_arbitrary_script_or_unknown_fixture(self):
        with self.assertRaisesRegex(ValueError, "unknown_trusted_fixture"):
            mod.run_guarded_fixture("source_from_user")

    def test_refuse_invalid_time_and_byte_quotas(self):
        for value in (0, True, 100, float("nan")):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    mod.run_guarded_fixture("safe", timeout_seconds=value)
        for value in (0, 32, 16384, True):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    mod.run_guarded_fixture("safe", output_quota=value)

    @unittest.skipUnless(sys.platform == "linux", "Requires actual Linux RLIMIT/libc/ELF runtime; run on Linux/WSL")
    def test_cli_fixed_trusted_subprocess_and_json(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                              "--mode", "limits", "--fixture", "safe"],
                             capture_output=True, timeout=8, check=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["status"], "FIXED_LINUX_RESOURCE_GATE_VERIFIED")
        self.assertFalse(report["unknown_source_executed"])


class WindowsLexicalChecksTests(unittest.TestCase):
    def test_absolute_drive_path_oracles_agree(self):
        result = mod.inspect_windows_path(r"C:\Program Files\Python\python.exe")
        self.assertEqual(result["kind"], "DRIVE")
        self.assertEqual(result["file_components"], 3)
        self.assertFalse(result["powershell_or_windows_executed"])

    def test_absolute_unc_share_and_file(self):
        result = mod.inspect_windows_path(r"\\server\share\app\data.json")
        self.assertEqual(result["kind"], "UNC")
        self.assertEqual(result["drive"], "\\\\server\\share")

    def test_reserved_windows_device_names_denied(self):
        for raw in (r"C:\safe\NUL.txt", r"C:\safe\CON", r"C:\PRN", r"C:\COM1.txt"):
            with self.subTest(path=raw), self.assertRaises(ValueError):
                mod.inspect_windows_path(raw)

    def test_traversal_and_ambiguous_components_denied(self):
        for raw in (r"C:\safe\..\private.txt", r"C:\safe\.\file", r"C:\file.",
                    r"C:\file ", r"C:\safe\\file", r"C:\safe\data:stream"):
            with self.subTest(path=raw), self.assertRaises(ValueError):
                mod.inspect_windows_path(raw)

    def test_nt_namespace_device_path_denied(self):
        for raw in (r"\\?\C:\foo", r"\\.\CON", r"\\?\UNC\server\share\file"):
            with self.subTest(path=raw), self.assertRaises(ValueError):
                mod.inspect_windows_path(raw)

    def test_relative_or_drive_relative_paths_denied(self):
        for raw in (r"foo\bar", r"C:relative\file", r"\foo\bar", "C:\\"):
            with self.subTest(path=raw), self.assertRaises(ValueError):
                mod.inspect_windows_path(raw)

    def test_alternative_separator_and_control_characters_denied(self):
        for raw in (r"C:/safe/file", "C:\\safe\nfile", "C:\\safe\x00file"):
            with self.subTest(path=repr(raw)), self.assertRaises(ValueError):
                mod.inspect_windows_path(raw)

    def test_powershell_metacharacters_remain_data_after_roundtrip(self):
        values = (r"$env:SECRET; Get-Process", r"$(whoami) | cat", "O'Brien's file",
                  r"`n ${meta} #comment")
        for raw in values:
            with self.subTest(value=raw):
                encoded = mod.quote_powershell_single_literal(raw)
                self.assertEqual(mod.decode_powershell_single_literal(encoded), raw)
                self.assertEqual(encoded[0], "'")

    def test_powershell_quote_decoder_rejects_injection(self):
        for token in ("'safe'; Get-Process", "'one'two'", "not quoted", "''bad"):
            with self.subTest(token=token), self.assertRaises(ValueError):
                mod.decode_powershell_single_literal(token)

    def test_long_or_control_quoting_denied(self):
        for token in ("x" * 1025, "'" * 1024, "a\nb", "a\x00b"):
            with self.subTest(length=len(token)), self.assertRaises(ValueError):
                mod.quote_powershell_single_literal(token)

    def test_cli_windows_static_no_powershell_execution(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                              "--mode", "windows", "--path", r"C:\safe\file.txt"],
                             capture_output=True, timeout=8, check=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["kind"], "DRIVE")
        self.assertEqual(mod.decode_powershell_single_literal(report["powershell_quoted_data"]),
                         r"C:\safe\file.txt")


class LinuxWheelAndElfChecksTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "win32", "Windows rejection contract")
    def test_windows_python_is_not_elf_and_libc_not_verified(self):
        self.assertEqual(mod.inspect_linux_libc(), {"status": "NOT_SUPPORTED_NON_LINUX", "libc_verified": False})
        with tempfile.TemporaryDirectory() as folder:
            item = Path(folder) / "windows-python.exe"
            shutil.copyfile(sys.executable, item)
            self.assertEqual(mod.inspect_local_elf(item)["status"], "NOT_ELF")

    @unittest.skipUnless(sys.platform == "linux", "Requires actual Linux RLIMIT/libc/ELF runtime; run on Linux/WSL")
    def test_actual_linux_libc_local_call(self):
        result = mod.inspect_linux_libc()
        self.assertIn(result["status"], ("LOCAL_LIBC_PROBED", "UNKNOWN_LIBC"))
        self.assertTrue(result["local_runtime_only"])
        self.assertFalse(result["foreign_musl_execution_proven"])

    @unittest.skipUnless(sys.platform == "linux", "Requires actual Linux RLIMIT/libc/ELF runtime; run on Linux/WSL")
    def test_local_supported_old_manylinux_policy(self):
        result = mod.compare_linux_wheel_policy("manylinux_2_5_x86_64")
        self.assertEqual(result["status"], "LOCAL_WHEEL_POLICY_COMPARED")
        if mod.inspect_linux_libc()["libc_family"] == "glibc" and \
                mod.inspect_linux_libc()["architecture"] == "x86_64":
            self.assertEqual(result["compatibility"], "MATCH_LOCAL_POLICY_ONLY")
        self.assertFalse(result["native_import_verified"])

    def test_local_manylinux_legacy_alias_still_validated(self):
        result = mod.compare_linux_wheel_policy("manylinux2014_x86_64")
        self.assertEqual(result["declared_min_libc"], "2.17")
        self.assertEqual(result["declared_family"], "glibc")

    @unittest.skipUnless(sys.platform == "linux", "Requires actual Linux RLIMIT/libc/ELF runtime; run on Linux/WSL")
    def test_musllinux_tag_mismatches_actual_glibc(self):
        result = mod.compare_linux_wheel_policy("musllinux_1_2_x86_64")
        if mod.inspect_linux_libc()["libc_family"] == "glibc":
            self.assertEqual(result["compatibility"], "MISMATCH")
        self.assertFalse(result["musl_runtime_actually_tested"])

    @unittest.skipUnless(sys.platform == "linux", "Requires actual Linux RLIMIT/libc/ELF runtime; run on Linux/WSL")
    def test_future_glibc_minimum_mismatches_actual_runtime(self):
        result = mod.compare_linux_wheel_policy("manylinux_99_0_x86_64")
        if mod.inspect_linux_libc()["libc_family"] == "glibc":
            self.assertEqual(result["compatibility"], "MISMATCH")

    @unittest.skipUnless(sys.platform == "linux", "Requires actual Linux RLIMIT/libc/ELF runtime; run on Linux/WSL")
    def test_foreign_arch_not_silently_accepted(self):
        local = mod.inspect_linux_libc()
        foreign = "aarch64" if local["architecture"] == "x86_64" else "x86_64"
        result = mod.compare_linux_wheel_policy("manylinux_2_5_" + foreign)
        self.assertNotEqual(result["compatibility"], "MATCH_LOCAL_POLICY_ONLY")

    def test_synthetic_musl_runtime_does_not_attest_real_musl_execution(self):
        fake = {"status": "LOCAL_LIBC_PROBED", "libc_family": "musl", "libc_version": "1.2",
                "architecture": "x86_64", "evidence": "CALLER_SUPPLIED"}
        report = mod.compare_linux_wheel_policy("musllinux_1_2_x86_64", fake)
        self.assertEqual(report["status"], "CALLER_SUPPLIED_POLICY_HYPOTHESIS_NOT_ATTESTED")
        self.assertFalse(report["musl_runtime_actually_tested"])

    def test_invalid_or_malicious_platform_tag_denied(self):
        for tag in ("../../etc/passwd", "manylinux_2_7_x86_64;rm", "manylinux_bad",
                    "MANYLINUX_2_17_x86_64"):
            with self.subTest(tag=tag):
                report = mod.compare_linux_wheel_policy(tag)
                self.assertEqual(report["compatibility"], "UNKNOWN")

    @unittest.skipUnless(sys.platform == "linux", "Requires actual Linux RLIMIT/libc/ELF runtime; run on Linux/WSL")
    def test_actual_interpreter_elf64_header_without_loading_binary(self):
        with tempfile.TemporaryDirectory(prefix="rph-v22-real-elf-") as folder:
            item = Path(folder) / "copied-interpreter-elf"
            shutil.copyfile(str(Path(sys.executable).resolve()), str(item))
            report = mod.inspect_local_elf(item)
            self.assertEqual(report["status"], "ELF64_HEADER_INSPECTED_NOT_LOADED")
            self.assertTrue(report["compatible_architecture"])
            self.assertFalse(report["binary_executed"])

    def test_non_elf_and_short_headers_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="rph-v22-fake-elf-") as folder:
            item = Path(folder) / "not-elf"
            item.write_bytes(b"MZ")
            self.assertEqual(mod.inspect_local_elf(item)["status"], "NOT_ELF")
            item.write_bytes(b"\x7fELF\x01\x01" + b"\x00" * 58)
            self.assertEqual(mod.inspect_local_elf(item)["status"], "UNSUPPORTED_ELF_FORMAT")

    def test_forged_other_cpu_elf_header_is_not_executed(self):
        with tempfile.TemporaryDirectory(prefix="rph-v22-other-elf-") as folder:
            item = Path(folder) / "other-elf"
            data = bytearray(b"\x7fELF\x02\x01\x01" + b"\x00" * 57)
            struct.pack_into("<H", data, 18, 183 if platform_machine() != "aarch64" else 62)
            item.write_bytes(data)
            report = mod.inspect_local_elf(item)
            self.assertEqual(report["status"], "ELF64_HEADER_INSPECTED_NOT_LOADED")
            self.assertFalse(report["compatible_architecture"])

    def test_symlink_to_external_elf_denied(self):
        with tempfile.TemporaryDirectory(prefix="rph-v22-elf-link-") as folder:
            file_path = Path(folder) / "elf.bin"
            file_path.write_bytes(b"\x7fELF" + b"\x00" * 60)
            (Path(folder) / "symlink").symlink_to(file_path)
            with self.assertRaisesRegex(ValueError, "unsafe_elf_input"):
                mod.inspect_local_elf(Path(folder) / "symlink")

    def test_hardlinked_elf_denied(self):
        with tempfile.TemporaryDirectory(prefix="rph-v22-elf-hardlink-") as folder:
            file_path = Path(folder) / "elf.bin"
            file_path.write_bytes(b"\x7fELF" + b"\x00" * 60)
            os.link(file_path, Path(folder) / "second-link")
            with self.assertRaisesRegex(ValueError, "unsafe_elf_input"):
                mod.inspect_local_elf(file_path)

    def test_cli_linux_platform_probe_no_native_package_import(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                              "--mode", "linux", "--platform-tag", "manylinux_2_5_x86_64"],
                             capture_output=True, timeout=8, check=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report["status"], "LOCAL_LINUX_PLATFORM_DIAGNOSTICS")
        self.assertFalse(report["wheel_policy"]["native_import_verified"])


def platform_machine():
    import platform
    return platform.machine().lower()


if __name__ == "__main__":
    unittest.main()
