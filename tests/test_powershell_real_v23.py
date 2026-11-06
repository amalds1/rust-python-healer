"""Official SHA-pinned PowerShell parser, live Windows/Linux fixtures.

These tests require a host where CoreCLR is permitted to start; restricted
containers may return NOT_RUN. Never count that failure as a functional PASS.
"""

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

if os.name == "nt":
    from windows_privacy_fixtures import set_private_acl, set_public_read_acl


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "powershell_real_v23.py"
spec = importlib.util.spec_from_file_location("powershell_real_v23", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class OfficialRuntimeAndFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = module.verify_official_pwsh(verify_archive=True)

    def test_official_archive_hash_and_runtime_files_exact(self):
        self.assertEqual(self.evidence["official_archive_sha256"],
                         module.WINDOWS_ARCHIVE_SHA256 if os.name == "nt" else module.OFFICIAL_ARCHIVE_SHA256)
        self.assertTrue(self.evidence["official_archive_rechecked"])
        self.assertTrue(self.evidence["trusted_official_binary_verified"])
        self.assertEqual(len(self.evidence["runtime_component_hashes"]), 4)

    def test_publishers_crypto_signature_not_falsely_claimed(self):
        self.assertFalse(self.evidence["publisher_signature_cryptographically_verified"])
        self.assertEqual(self.evidence["actual_windows_host"], os.name == "nt")
        if os.name == "nt":
            self.assertEqual(self.evidence["all_archive_members_verified_and_held"], 930)
            self.assertFalse(self.evidence["ancestor_sandbox_proven"])

    def test_real_powershell_noninteractive_engine_version(self):
        result = module.probe_real_pwsh_version()
        self.assertEqual(result["status"], "REAL_OFFICIAL_POWERSHELL_7_5_13_EXECUTED")
        self.assertEqual(result["actual_pwsh_version"], "7.5.13")
        self.assertFalse(result["profile_loaded"])
        self.assertFalse(result["interactive"])
        self.assertEqual(result["real_windows_host"], os.name == "nt")

    def test_real_quote_parsing_all_hardcoded_adversarial_literals(self):
        for name in module.TRUSTED_LITERAL_FIXTURES:
            with self.subTest(name=name):
                result = module.verify_real_literal(name)
                self.assertEqual(result["status"], "REAL_POWERSHELL_LITERAL_PARSER_PROVED")
                self.assertTrue(result["sha256_match"])
                self.assertTrue(result["power_shell_engine_executed"])

    def test_actual_drive_and_unc_lexical_oracles_plus_parser(self):
        for key, kind in (("drive_path", "DRIVE"), ("unc_path", "UNC")):
            with self.subTest(fixture=key):
                report = module.verify_real_windows_path_fixture(key)
                self.assertEqual(report["status"], "LOCAL_POWERSHELL_WINDOWS_LEXICAL_FIXTURE_PASS")
                self.assertEqual(report["windows_path_kind"], kind)
                self.assertFalse(report["actual_windows_filesystem_tested"])

    def test_real_powershell_parser_rejects_unterminated_quote(self):
        result = module.parser_negative_unterminated_quote()
        self.assertEqual(result["status"], "REAL_POWERSHELL_UNTERMINATED_QUOTE_REJECTED")
        self.assertTrue(result["actual_powershell_parser_invoked"])
        self.assertFalse(result["malicious_script_executed"])

    def test_fixed_fixture_digests_not_echoed(self):
        report = module.verify_real_literal("dollar_substitution")
        self.assertTrue(report["sha256_match"])
        self.assertFalse(report["original_data_echoed"])
        self.assertFalse(report["unknown_user_literal_or_script_executed"])

    def test_actual_wellformed_literal_innocuous_metacharacters(self):
        self.assertEqual(module.verify_real_literal("pipe_semicolon")["status"],
                         "REAL_POWERSHELL_LITERAL_PARSER_PROVED")
        self.assertEqual(module.verify_real_literal("nested_quotes")["status"],
                         "REAL_POWERSHELL_LITERAL_PARSER_PROVED")


class LocalWindowsLexicalSecurityTests(unittest.TestCase):
    def test_synthetic_dependency_tamper_alias_public_acl_and_extra_members_never_execute(self):
        if os.name != "nt":
            with self.assertRaises(ValueError):module._fixed_runtime_process("arbitrary")
            return
        # Tiny *test-only* authenticated fixture pins exercise all-member
        # enforcement. The process boundary MUST never run these dummy bytes.
        for mutation in ("tamper", "hardlink", "symlink", "public_acl", "extra", "archive"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(prefix="rph-v23-members-") as folder:
                root = Path(folder); set_private_acl(root); binary = root / "bin"; binary.mkdir()
                content = {name:b"fixed harmless fixture" for name in module.WINDOWS_RUNTIME_FILES}
                content["dependency.dll"] = b"fixed separate dependency"
                for name, raw in content.items():(binary / name).write_bytes(raw)
                archive = root / "PowerShell-7.5.13-win-x64.zip"
                with zipfile.ZipFile(archive, "w") as package:
                    for name, raw in content.items():package.writestr(name, raw)
                fixture_archive_pin = hashlib.sha256(archive.read_bytes()).hexdigest()
                fixture_component_pins = {name:hashlib.sha256(raw).hexdigest()
                    for name, raw in content.items() if name != "dependency.dll"}
                dependency = binary / "dependency.dll"
                if mutation == "tamper":dependency.write_bytes(b"changed separate module")
                elif mutation == "hardlink":os.link(dependency, root / "dependency-alias")
                elif mutation == "symlink":
                    dependency.rename(root / "backing"); dependency.symlink_to(root / "backing")
                elif mutation == "public_acl":set_public_read_acl(dependency)
                elif mutation == "extra":(binary / "unknown.dll").write_bytes(b"unknown")
                elif mutation == "archive":
                    with archive.open("ab") as output:output.write(b"changed")
                with mock.patch.dict(module.WINDOWS_RUNTIME_FILES, fixture_component_pins, clear=True), \
                        mock.patch.object(module, "WINDOWS_ARCHIVE_SHA256", fixture_archive_pin), \
                        mock.patch.object(module, "_execute_fixed", side_effect=AssertionError("dummy fixture must never execute")):
                    with self.assertRaises(ValueError):module.probe_real_pwsh_version(root)

    def test_drive_lexical_oracles_agree(self):
        detail = module.windows_lexical_oracles(r"C:\Program Files\Python\python.exe")
        self.assertEqual(detail["status"], "TWO_WINDOWS_LEXICAL_ORACLES_AGREE")
        self.assertEqual(detail["kind"], "DRIVE")
        self.assertFalse(detail["native_windows_path_executed"])

    def test_unc_lexical_oracles_agree(self):
        detail = module.windows_lexical_oracles(r"\\server\share\app\entry.py")
        self.assertEqual(detail["kind"], "UNC")
        self.assertTrue(detail["independent_ntpath_and_purewindows_agree"])

    def test_path_traversal_and_drive_relative_rejected(self):
        values = (r"C:\safe\..\secret.txt", r"C:relative\filename.txt",
                  r"\\?\C:\outside", r"\\.\CON", r"\relative\filename")
        for raw in values:
            with self.subTest(path=raw), self.assertRaises(ValueError):
                module.windows_lexical_oracles(raw)

    def test_windows_devices_ads_and_separator_rejected(self):
        values = (r"C:\safe\NUL.txt", r"C:\safe\file.txt:ads",
                  r"C:\safe\COM1", r"C:/mixed/separator")
        for raw in values:
            with self.subTest(path=raw), self.assertRaises(ValueError):
                module.windows_lexical_oracles(raw)

    def test_null_and_newline_literal_rejected_before_shell(self):
        for value in ("abc\x00def", "abc\ndef", "x" * 1025, "'" * 1024):
            with self.subTest(length=len(value)), self.assertRaises(ValueError):
                module.quote_ps_literal(value)

    def test_escaping_apostrophes_for_real_powershell_data(self):
        value = "O'Brien's data"
        self.assertEqual(module.quote_ps_literal(value), "'O''Brien''s data'")

    def test_unlisted_fixture_never_enters_real_powershell(self):
        with self.assertRaisesRegex(ValueError, "only_curated"):
            module.verify_real_literal("user-supplied-arbitrary-script")
        with self.assertRaisesRegex(ValueError, "only_curated"):
            module.verify_real_windows_path_fixture("unknown")

    def test_unlisted_shell_code_rejected_before_process(self):
        with self.assertRaisesRegex(ValueError, "unknown_powershell_script_never_executed"):
            module._fixed_runtime_process("Write-Host 'NOT_ALLOWED'")

    def test_tampered_runtime_file_does_not_count_as_official(self):
        with tempfile.TemporaryDirectory(prefix="rph-v23-fake-pwsh-") as folder:
            bin_dir = Path(folder) / "bin"
            bin_dir.mkdir()
            if os.name == "nt":set_private_acl(Path(folder))
            (bin_dir / ("pwsh.exe" if os.name == "nt" else "pwsh")).write_bytes(b"forged")
            with self.assertRaisesRegex(ValueError, "hash_mismatch"):
                module.verify_official_pwsh(folder)

    def test_symlink_to_real_powershell_binary_rejected(self):
        with tempfile.TemporaryDirectory(prefix="rph-v23-link-pwsh-") as folder:
            bin_dir = Path(folder) / "bin"
            bin_dir.mkdir()
            if os.name == "nt":set_private_acl(Path(folder))
            name = "pwsh.exe" if os.name == "nt" else "pwsh"
            target = module._runtime_root() / "bin" / name
            (bin_dir / name).symlink_to(target)
            with self.assertRaisesRegex(ValueError, "not_safe_regular"):
                module.verify_official_pwsh(folder)

    def test_hardlinked_runtime_file_is_not_official(self):
        with tempfile.TemporaryDirectory(prefix="rph-v23-hardlink-pwsh-") as folder:
            root = Path(folder); binary = root / "bin"; binary.mkdir()
            if os.name == "nt":set_private_acl(root)
            file = binary / ("pwsh.exe" if os.name == "nt" else "pwsh")
            file.write_bytes(b"fixed not executable fixture")
            os.link(file, binary / "alias")
            with self.assertRaisesRegex(ValueError, "not_safe_regular"):
                module.verify_official_pwsh(root)

    def test_runtime_root_symlink_never_executes(self):
        with tempfile.TemporaryDirectory(prefix="rph-v23-root-alias-") as folder:
            alias = Path(folder) / "runtime"
            alias.symlink_to(module._runtime_root(), target_is_directory=True)
            try:
                with mock.patch.object(module, "_execute_fixed", side_effect=AssertionError("must not execute")):
                    report = module.probe_real_pwsh_version(alias)
                    self.assertFalse(report["powershell_child_executed"])
            finally:alias.unlink()

    def test_public_windows_runtime_root_rejected_before_hash_or_process(self):
        # POSIX retains its existing extracted-runtime contract; this branch
        # exercises real DACLs on native Windows, with no skip added.
        if os.name == "nt":
            with tempfile.TemporaryDirectory(prefix="rph-v23-public-root-") as folder:
                root = Path(folder); (root / "bin").mkdir(); set_public_read_acl(root)
                with mock.patch.object(module, "_sha_regular", side_effect=AssertionError("must not hash")), \
                        mock.patch.object(module, "_execute_fixed", side_effect=AssertionError("must not execute")):
                    with self.assertRaises(ValueError):module.probe_real_pwsh_version(root)
        else:
            self.assertEqual(module.OFFICIAL_ARCHIVE_SHA256, "e9256bfc6ac98fcbec97270e8a986577a7346a587837cc80d30595eef3c2546b")

    def test_pinned_runtime_handles_close_after_process_failure(self):
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            kernel, _ = module._windows_privacy()._libraries()
            kernel.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
            def count():
                value = wintypes.DWORD()
                self.assertTrue(kernel.GetProcessHandleCount(wintypes.HANDLE(-1), ctypes.byref(value)))
                return value.value
            before = count()
            def fail(*args):
                self.assertGreaterEqual(count(), before + 930)
                with self.assertRaises(OSError):
                    (module._runtime_root() / "bin" / "pwsh.exe").open("ab")
                raise OSError("fixed process failure")
            with mock.patch.object(module, "_execute_fixed", side_effect=fail):
                with self.assertRaisesRegex(OSError, "fixed process failure"):
                    module.probe_real_pwsh_version()
            self.assertLessEqual(count(), before + 2)
        else:
            with mock.patch.object(module, "_execute_fixed", side_effect=OSError("fixed process failure")):
                with self.assertRaises(OSError):module.probe_real_pwsh_version()


class PinnedPowerShellCliTests(unittest.TestCase):
    def test_cli_capabilities_default_needs_no_powershell_runtime(self):
        with tempfile.TemporaryDirectory(prefix="rph-v23-absent-pwsh-") as folder:
            missing_pwsh = str(Path(folder) / "deliberately-not-installed")
            env = dict(os.environ, RPH_PINNED_POWERSHELL_ROOT=missing_pwsh)
            completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT)],
                                       capture_output=True, timeout=10, env=env)
        self.assertEqual(completed.returncode, 0, completed.stderr[-200:])
        report = json.loads(completed.stdout)
        self.assertEqual(report["status"], "REAL_POWERSHELL_OPTIONAL_PINNED_ADAPTER")
        self.assertFalse(report["actual_powershell_parser_invoked"])
        self.assertFalse(report["native_windows_host_verified"])
        self.assertFalse(report["pwsh_runtime_required_for_capabilities"])
        self.assertFalse(report["user_shell_script_executed"])

    def test_cli_capabilities_explicit_reports_bounded_functionality(self):
        completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                                    "--mode", "capabilities"], capture_output=True,
                                   timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr[-200:])
        report = json.loads(completed.stdout)
        self.assertEqual(report["supported_real_parser_modes"],
                         ["version", "literal", "windows", "negative"])
        self.assertTrue(report["separate_live_sha256_verification_available"])

    def test_cli_version_is_real_power_shell(self):
        completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                                    "--mode", "version"], capture_output=True, timeout=15)
        self.assertEqual(completed.returncode, 0, completed.stderr[-200:])
        self.assertEqual(json.loads(completed.stdout)["actual_pwsh_version"], "7.5.13")

    def test_cli_real_quoting_keeps_shell_metacharacters_inert(self):
        completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                                    "--mode", "literal", "--fixture", "dollar_substitution"],
                                   capture_output=True, timeout=15)
        self.assertEqual(completed.returncode, 0, completed.stderr[-200:])
        self.assertTrue(json.loads(completed.stdout)["sha256_match"])

    def test_cli_pinned_unc_and_drive(self):
        for name in ("drive_path", "unc_path"):
            with self.subTest(name=name):
                completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                                            "--mode", "windows", "--fixture", name],
                                           capture_output=True, timeout=15)
                self.assertEqual(completed.returncode, 0, completed.stderr[-200:])
                self.assertEqual(json.loads(completed.stdout)["status"],
                                 "LOCAL_POWERSHELL_WINDOWS_LEXICAL_FIXTURE_PASS")

    def test_cli_parser_negative(self):
        completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                                    "--mode", "negative"], capture_output=True, timeout=15)
        self.assertEqual(completed.returncode, 0, completed.stderr[-200:])
        self.assertEqual(json.loads(completed.stdout)["status"],
                         "REAL_POWERSHELL_UNTERMINATED_QUOTE_REJECTED")


if __name__ == "__main__":
    unittest.main()
