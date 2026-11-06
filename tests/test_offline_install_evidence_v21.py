"""Real trusted wheel RECORD and two offline pip installs on every CPython."""

import hashlib
import shutil
import stat
import sys
import tempfile
import unittest
import zipfile
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = spec_from_file_location("offline_install_evidence_v21",
                              ROOT / "python" / "offline_install_evidence_v21.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


class TrustedWheelEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="fixed-wheel-v21-")
        cls.root = Path(cls.tmp.name)
        cls.fixtures = cls.root / "wheel"
        cls.fixtures.mkdir()
        cls.wheel = module.build_trusted_fixture_wheel(cls.fixtures)
        cls.path = Path(cls.wheel["wheel_path"])
        cls.one, cls.two = cls.root / "one", cls.root / "two"
        cls.one.mkdir()
        cls.two.mkdir()
        cls.installs = module.reproducible_offline_install(
            cls.path, cls.wheel["sha256"], cls.one, cls.two)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_trusted_fixture_builder_generates_exact_filename(self):
        self.assertEqual(self.path.name, module.WHEEL_FILENAME)
        self.assertTrue(self.path.is_file())
        self.assertFalse(self.wheel["build_backend_executed"])

    def test_wheel_sha256_matches_independent_hashlib_oracle(self):
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(),
                         self.wheel["sha256"])

    def test_audit_wheel_sha256_and_exact_member_allowlist(self):
        audit = module.audit_trusted_wheel(self.path, self.wheel["sha256"])
        self.assertEqual(audit["status"], "VERIFIED_LOCAL_FIXTURE")
        self.assertEqual(audit["member_count"], 4)
        self.assertFalse(audit["publisher_authenticated"])

    def test_actual_offline_install_twice_reproducible(self):
        self.assertEqual(self.installs["status"], "PASS", self.installs)
        self.assertTrue(self.installs["identical_installed_file_hashes"])
        self.assertTrue(self.installs["two_independent_targets"])

    def test_installed_wheel_detected_by_importlib_metadata(self):
        first = self.installs["first"]
        self.assertEqual(first["status"], "PASS")
        self.assertTrue(first["installed_distribution_detected"])
        self.assertEqual(first["python_version"], "{}.{}".format(*sys.version_info[:2]))

    def test_two_record_audits_compare_actual_file_hashes(self):
        first, second = self.installs["first"], self.installs["second"]
        self.assertEqual(first["file_sha256"], second["file_sha256"])
        self.assertIn(module.MODULE_NAME, first["file_sha256"])
        actual = hashlib.sha256((self.one / module.MODULE_NAME).read_bytes()).hexdigest()
        self.assertEqual(first["file_sha256"][module.MODULE_NAME], actual)

    def test_exact_pip_offline_no_deps_flags_reported(self):
        flags = self.installs["used_flags"]
        self.assertIn("--no-index", flags)
        self.assertIn("--no-deps", flags)
        self.assertIn("--no-compile", flags)
        self.assertIn("--target", flags)

    def test_no_target_import_build_backend_or_system_install(self):
        self.assertFalse(self.installs["system_install_performed"])
        self.assertFalse(self.installs["untrusted_wheel_installed"])
        self.assertFalse(self.installs["network_used"])
        self.assertFalse(self.installs["first"]["target_modules_imported"])
        self.assertNotIn("rph_fixture_v21", sys.modules)

    def test_publishers_not_verified_despite_local_hashes(self):
        self.assertFalse(self.installs["publisher_authenticated"])
        self.assertFalse(self.installs["first"]["publisher_authenticated"])

    def test_mutated_installed_module_fails_record_hash_verification(self):
        with tempfile.TemporaryDirectory(prefix="tamper-test-") as dirname:
            target = Path(dirname)
            shutil.copytree(self.one, target / "copy")
            (target / "copy" / module.MODULE_NAME).write_bytes(b"VALUE = 'changed'\n")
            result = module.audit_installed_record(target / "copy")
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any("sha256_or_size_mismatch" in error for error in result["errors"]))

    def test_mutated_record_digest_fails(self):
        with tempfile.TemporaryDirectory(prefix="tamper-record-") as dirname:
            copied = Path(dirname) / "copy"
            shutil.copytree(self.one, copied)
            record_path = copied / module.RECORD_NAME
            original = record_path.read_text(encoding="utf-8")
            record_path.write_text(original.replace("sha256=", "sha256=corrupted", 1),
                                   encoding="utf-8")
            result = module.audit_installed_record(copied)
        self.assertEqual(result["status"], "FAIL")

    def test_mutated_record_size_fails_even_when_hash_matches(self):
        with tempfile.TemporaryDirectory(prefix="tamper-record-size-") as dirname:
            copied = Path(dirname) / "copy"
            shutil.copytree(self.one, copied)
            record_path = copied / module.RECORD_NAME
            raw = record_path.read_text(encoding="utf-8")
            digest = module._record_hash(module.MODULE_SOURCE)
            expected = f"{module.MODULE_NAME},{digest},{len(module.MODULE_SOURCE)}"
            mutated = f"{module.MODULE_NAME},{digest},{len(module.MODULE_SOURCE) + 1}"
            self.assertIn(expected, raw)
            record_path.write_text(raw.replace(expected, mutated), encoding="utf-8")
            result = module.audit_installed_record(copied)
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any("sha256_or_size_mismatch" in item for item in result["errors"]))

    def test_record_path_traversal_detected_without_touching_outside(self):
        with tempfile.TemporaryDirectory(prefix="bad-record-path-") as dirname:
            copied = Path(dirname) / "copy"
            shutil.copytree(self.one, copied)
            record_path = copied / module.RECORD_NAME
            with record_path.open("a", encoding="utf-8") as record_file:
                record_file.write("../../../unrelated.txt,sha256=invalid,1\n")
            result = module.audit_installed_record(copied)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("invalid_record_entry", result["errors"])

    def test_missing_record_is_never_pass(self):
        with tempfile.TemporaryDirectory(prefix="missing-record-") as dirname:
            copied = Path(dirname) / "copy"
            shutil.copytree(self.one, copied)
            (copied / module.RECORD_NAME).unlink()
            result = module.audit_installed_record(copied)
        self.assertEqual(result["status"], "MISSING_OR_UNSAFE_RECORD")

    def test_installed_unrecorded_file_is_failure(self):
        with tempfile.TemporaryDirectory(prefix="unrecorded-") as dirname:
            copied = Path(dirname) / "copy"
            shutil.copytree(self.one, copied)
            (copied / "injected.py").write_text("not executed\n", encoding="utf-8")
            result = module.audit_installed_record(copied)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("unrecorded_installed_files", result["errors"])

    def test_installed_symlink_payload_refused_without_import(self):
        with tempfile.TemporaryDirectory(prefix="symlink-") as dirname:
            copied = Path(dirname) / "copy"
            shutil.copytree(self.one, copied)
            payload = copied / module.MODULE_NAME
            payload.unlink()
            try:
                payload.symlink_to(self.one / module.MODULE_NAME)
            except (OSError, NotImplementedError):
                self.skipTest("OS forbids symlinks in private test directory")
            result = module.audit_installed_record(copied)
        self.assertEqual(result["status"], "FAIL")
        self.assertIn("unsafe_symlink_in_install", result["errors"])

    def test_wrong_expected_hash_rejected_before_any_pip_execution(self):
        with tempfile.TemporaryDirectory(prefix="rejected-") as dirname:
            first = Path(dirname) / "one"
            second = Path(dirname) / "two"
            first.mkdir()
            second.mkdir()
            report = module.reproducible_offline_install(self.path, "0" * 64,
                                                         first, second)
            self.assertEqual(report["status"], "REJECTED_BEFORE_INSTALL")
            self.assertEqual(list(first.iterdir()), [])
            self.assertEqual(list(second.iterdir()), [])

    def test_arbitrary_filename_and_untrusted_wheel_rejected(self):
        with tempfile.TemporaryDirectory(prefix="arbitrary-wheel-") as dirname:
            arbitrary = Path(dirname) / "arbitrary-1.0-py3-none-any.whl"
            arbitrary.write_bytes(self.path.read_bytes())
            report = module.audit_trusted_wheel(arbitrary, self.wheel["sha256"])
        self.assertEqual(report["status"], "REJECTED")

    def test_corrupted_zip_archive_rejected_even_if_hash_is_attested(self):
        with tempfile.TemporaryDirectory(prefix="corrupt-zip-") as dirname:
            path = Path(dirname) / module.WHEEL_FILENAME
            path.write_bytes(b"not a ZIP archive")
            report = module.audit_trusted_wheel(path,
                hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(report["status"], "REJECTED")
        self.assertEqual(report["reason"], "invalid_zip_archive")

    def test_modified_record_in_wheel_rejected_with_new_correct_archive_digest(self):
        with tempfile.TemporaryDirectory(prefix="bad-record-wheel-") as dirname:
            path = Path(dirname) / module.WHEEL_FILENAME
            with zipfile.ZipFile(self.path, "r") as source, zipfile.ZipFile(path, "w") as out:
                for info in source.infolist():
                    data = source.read(info)
                    if info.filename == module.RECORD_NAME:
                        data += b"invalid,sha256=bad,1\n"
                    out.writestr(info, data)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            report = module.audit_trusted_wheel(path, digest)
        self.assertEqual(report["status"], "REJECTED")
        self.assertEqual(report["reason"], "wheel_record_or_content_invalid")

    def test_wheel_symlink_member_refused_before_install(self):
        with tempfile.TemporaryDirectory(prefix="symlink-member-") as dirname:
            path = Path(dirname) / module.WHEEL_FILENAME
            with zipfile.ZipFile(self.path, "r") as source, zipfile.ZipFile(path, "w") as out:
                for info in source.infolist():
                    data = source.read(info)
                    if info.filename == module.MODULE_NAME:
                        info.external_attr = (stat.S_IFLNK | 0o777) << 16
                    out.writestr(info, data)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            report = module.audit_trusted_wheel(path, digest)
        self.assertEqual(report["status"], "REJECTED")
        self.assertEqual(report["reason"], "unsafe_wheel_member")

    def test_archive_wheel_duplicate_member_denied(self):
        with tempfile.TemporaryDirectory(prefix="duplicate-member-") as dirname:
            path = Path(dirname) / module.WHEEL_FILENAME
            with zipfile.ZipFile(self.path, "r") as source, zipfile.ZipFile(path, "w") as out:
                for info in source.infolist():
                    out.writestr(info, source.read(info))
                with __import__("warnings").catch_warnings():
                    __import__("warnings").simplefilter("ignore", UserWarning)
                    out.writestr(module.MODULE_NAME, module.MODULE_SOURCE)
            report = module.audit_trusted_wheel(path, hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(report["status"], "REJECTED")
        self.assertEqual(report["reason"], "unexpected_wheel_members")

    def test_nonempty_or_same_targets_rejected_before_reinstall(self):
        with tempfile.TemporaryDirectory(prefix="invalid-target-") as dirname:
            first = Path(dirname) / "one"
            second = Path(dirname) / "two"
            first.mkdir()
            second.mkdir()
            with self.assertRaisesRegex(ValueError, "two_distinct_empty_private_targets_required"):
                module.reproducible_offline_install(self.path, self.wheel["sha256"],
                                                     first, first)
            (first / "user-data.txt").write_text("retain", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "two_distinct_empty_private_targets_required"):
                module.reproducible_offline_install(self.path, self.wheel["sha256"],
                                                     first, second)
            self.assertEqual((first / "user-data.txt").read_text(encoding="utf-8"), "retain")

    def test_two_deterministic_built_wheels_have_same_hash(self):
        with tempfile.TemporaryDirectory(prefix="second-fixture-") as dirname:
            second = module.build_trusted_fixture_wheel(dirname)
        self.assertEqual(second["sha256"], self.wheel["sha256"])

    def test_fixture_refuses_existing_wheel_overwrite(self):
        with self.assertRaisesRegex(ValueError, "fixture_wheel_cannot_overwrite_existing_file"):
            module.build_trusted_fixture_wheel(self.fixtures)


if __name__ == "__main__":
    unittest.main()
