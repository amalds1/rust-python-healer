"""F253: real file-structure checks; mocks do not count as runtime evidence."""

import importlib.util
import json
import pickle
import stat
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

MODULE_PATH = Path(__file__).resolve().parent.parent / "python" / "pytorch_runtime_v27.py"
spec = importlib.util.spec_from_file_location("pytorch_runtime_v27", MODULE_PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def synthetic_zip(path, pickle_data=None, extras=None, archive_root="archive"):
    """A synthetic PyTorch-*style* archive, NOT a real torch checkpoint."""
    if pickle_data is None:
        pickle_data = pickle.dumps({"device": "cuda:1", "values": [1, 2, 3]}, protocol=4)
    with zipfile.ZipFile(path, "w") as container:
        container.writestr(archive_root + "/data.pkl", pickle_data)
        container.writestr(archive_root + "/version", b"3\n")
        for name, value in (extras or []):
            container.writestr(name, value)


class PyTorchStaticCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix="rph-torch-v27-")
        self.addCleanup(self.tempdir.cleanup)
        self.path = Path(self.tempdir.name) / "fixture.pt"

    def test_static_fixture_does_not_invoke_pickle_or_torch(self):
        synthetic_zip(self.path)
        with mock.patch.object(pickle, "loads", side_effect=AssertionError("unpickle!")), \
             mock.patch.object(subprocess, "run", side_effect=AssertionError("execute!")):
            observed = module.inspect_checkpoint(self.path)
        self.assertEqual(observed["status"], "PASS_BOUNDED_STATIC_TORCH_ZIP_INSPECTION_ONLY")
        self.assertTrue(observed["format_heuristic"].endswith("UNVERIFIED"))
        self.assertEqual(observed["archive_file_count"], 2)
        self.assertEqual(observed["pickle_opcode_analysis"]["device_hints_unverified"], ["cuda:1"])
        self.assertFalse(observed["pickle_unpickled"])
        self.assertFalse(observed["checkpoint_compatibility_verified"])
        self.assertFalse(observed["archive_all_member_crcs_verified"])
        self.assertFalse(observed["gpu_verified"])

    def test_pickle_opcode_dynamic_global_warns_and_never_executes(self):
        synthetic_zip(self.path, b"\x8c\x02os\x8c\x06system\x93.")
        result = module.inspect_checkpoint(self.path)
        self.assertEqual(result["status"], "PASS_BOUNDED_STATIC_TORCH_ZIP_INSPECTION_ONLY")
        self.assertTrue(result["pickle_opcode_analysis"]["dynamic_global_references"])
        self.assertFalse(result["pickle_unpickled"])

    def test_pickle_opcode_unknown_module_warns_without_loading(self):
        synthetic_zip(self.path, b"cos\nsystem\n.")
        result = module.inspect_checkpoint(self.path)
        self.assertEqual(result["pickle_opcode_analysis"]["nonframework_global_modules"], ["os"])

    def test_bad_pickle_opcode_rejected(self):
        synthetic_zip(self.path, b"\xff.")
        self.assertEqual(module.inspect_checkpoint(self.path)["status"], "REJECTED_INVALID_PICKLE_OPCODES")

    def test_symlink_as_source_rejected(self):
        synthetic_zip(self.path)
        link = Path(self.tempdir.name) / "symlink.pt"
        try:
            link.symlink_to(self.path)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation denied by OS")
        self.assertEqual(module.inspect_checkpoint(link)["status"], "REJECTED_NOT_REGULAR_FILE_OR_SYMLINK")

    def test_directory_rejected(self):
        self.assertEqual(module.inspect_checkpoint(self.tempdir.name)["status"],
                         "REJECTED_NOT_REGULAR_FILE_OR_SYMLINK")

    def test_missing_file_not_a_pass_or_data_leak(self):
        report = module.inspect_checkpoint(self.path)
        self.assertEqual(report["status"], "NOT_RUN_CHECKPOINT_IO_FAILURE")
        self.assertNotIn(self.path.name, json.dumps(report))

    def test_excess_file_size_rejected(self):
        synthetic_zip(self.path)
        self.assertEqual(module.inspect_checkpoint(self.path, max_checkpoint_bytes=1024)["status"],
                         "PASS_BOUNDED_STATIC_TORCH_ZIP_INSPECTION_ONLY")
        with self.assertRaisesRegex(ValueError, "invalid_checkpoint_limit"):
            module.inspect_checkpoint(self.path, 1)
        with self.assertRaisesRegex(ValueError, "invalid_checkpoint_limit"):
            module.inspect_checkpoint(self.path, True)
        with self.path.open("ab") as handle:
            handle.write(b"X" * 2048)
        self.assertEqual(module.inspect_checkpoint(self.path, max_checkpoint_bytes=1024)["status"],
                         "REJECTED_ARCHIVE_SIZE")

    def test_archive_root_collision_rejected(self):
        synthetic_zip(self.path, extras=[("other/file.bin", b"x")])
        self.assertEqual(module.inspect_checkpoint(self.path)["status"], "REJECTED_ARCHIVE_ROOTS")

    def test_dotdot_path_rejected(self):
        synthetic_zip(self.path, extras=[("archive/../escape", b"x")])
        self.assertEqual(module.inspect_checkpoint(self.path)["status"], "REJECTED_ARCHIVE_PATH")

    def test_archive_absolute_path_rejected(self):
        synthetic_zip(self.path, extras=[("/tmp/unsafe", b"x")])
        self.assertEqual(module.inspect_checkpoint(self.path)["status"], "REJECTED_ARCHIVE_ROOTS")

    def test_archive_nested_symlink_rejected(self):
        entry = zipfile.ZipInfo("archive/links")
        entry.create_system = 3
        entry.external_attr = ((stat.S_IFLNK | 0o777) << 16)
        synthetic_zip(self.path, extras=[(entry, b"target")])
        self.assertEqual(module.inspect_checkpoint(self.path)["status"], "REJECTED_ARCHIVE_SYMLINK")

    def test_zip_bomb_compression_ratio_rejected(self):
        with zipfile.ZipFile(self.path, "w", compression=zipfile.ZIP_DEFLATED) as container:
            container.writestr("archive/data.pkl", pickle.dumps({"a": 1}, protocol=4))
            container.writestr("archive/bomb.bin", b"0" * 1_000_000)
        self.assertEqual(module.inspect_checkpoint(self.path)["status"], "REJECTED_COMPRESSION_RATIO")

    def test_large_pickle_entry_rejected(self):
        with zipfile.ZipFile(self.path, "w") as container:
            container.writestr("archive/data.pkl", b"." * (module.MAX_PICKLE_BYTES + 1))
        self.assertEqual(module.inspect_checkpoint(self.path)["status"], "REJECTED_PICKLE_SIZE")

    def test_bad_zip_rejected(self):
        self.path.write_bytes(b"not a real torch zip file")
        self.assertEqual(module.inspect_checkpoint(self.path)["status"], "NOT_RUN_CORRUPT_OR_UNSUPPORTED_ZIP")

    def test_legacy_pickle_without_zip_never_loaded(self):
        self.path.write_bytes(pickle.dumps({"device": "cpu"}))
        self.assertEqual(module.inspect_checkpoint(self.path)["status"], "NOT_RUN_CORRUPT_OR_UNSUPPORTED_ZIP")

    def test_no_data_pickle_is_not_recognized(self):
        with zipfile.ZipFile(self.path, "w") as container:
            container.writestr("archive/version", b"3")
        self.assertEqual(module.inspect_checkpoint(self.path)["status"], "NOT_RECOGNIZED_TORCH_ZIP_LAYOUT")

    def test_duplicate_data_pickle_rejected(self):
        with zipfile.ZipFile(self.path, "w") as container:
            container.writestr("archive/data.pkl", b"}.")
            with __import__("warnings").catch_warnings():
                __import__("warnings").simplefilter("ignore", UserWarning)
                container.writestr("archive/data.pkl", b"}.")
        self.assertEqual(module.inspect_checkpoint(self.path)["status"], "NOT_RECOGNIZED_TORCH_ZIP_LAYOUT")

    def test_wrong_argument_type_rejected(self):
        with self.assertRaises(TypeError):
            module.inspect_checkpoint(123)


class PyTorchRealRuntimeEvidenceTests(unittest.TestCase):
    def test_absent_distribution_does_not_run_cpu(self):
        with mock.patch.object(module, "installed_torch_metadata", return_value={
                "status": "NOT_RUN_TORCH_NOT_INSTALLED", "torch_imported": False}), \
             mock.patch.object(module.subprocess, "run", side_effect=AssertionError("run!")):
            observed = module.probe_installed_torch_cpu()
        self.assertEqual(observed["status"], "NOT_RUN_TORCH_NOT_INSTALLED")
        self.assertFalse(observed["cpu_runtime_verified"])

    def test_invalid_torch_runtime_timeout_rejected(self):
        for timeout in (0, 31, True, 10.5):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                module.probe_installed_torch_cpu(timeout)

    def test_cpu_runtime_rejects_fake_success_from_subprocess(self):
        fake_metadata = {"status": "LOCAL_TORCH_METADATA_ONLY", "distribution_version": "9.0"}
        fake_process = subprocess.CompletedProcess([], 0, stdout=json.dumps({
            "status": "REAL_INSTALLED_TORCH_CPU_FIXED_FIXTURE_PASS",
            "cpu_sum": [5, 7, 8], "checkpoint_from_user_loaded": False,
            "gpu_verified": False, "torch_version": "9.0",
            "fixed_negative_oracles": ["INVALID_DEVICE_REJECTED"]}).encode(), stderr=b"")
        with mock.patch.object(module, "installed_torch_metadata", return_value=fake_metadata), \
             mock.patch.object(module.subprocess, "run", return_value=fake_process):
            observed = module.probe_installed_torch_cpu()
        self.assertEqual(observed["status"], "NOT_RUN_TORCH_CPU_FIXTURE_ORACLE_MISMATCH")
        self.assertFalse(observed["cpu_runtime_verified"])

    def test_cpu_runtime_child_failure_not_pass(self):
        fake_metadata = {"status": "LOCAL_TORCH_METADATA_ONLY", "distribution_version": "2.5.0"}
        fake_process = subprocess.CompletedProcess([], 1, stdout=b"", stderr=b"secret-key=LEAK")
        with mock.patch.object(module, "installed_torch_metadata", return_value=fake_metadata), \
             mock.patch.object(module.subprocess, "run", return_value=fake_process):
            observed = module.probe_installed_torch_cpu()
        self.assertEqual(observed["status"], "NOT_RUN_TORCH_CPU_FIXTURE_FAILED")
        self.assertNotIn("secret", json.dumps(observed))

    def test_actual_local_runtime_only_if_really_installed(self):
        metadata = module.installed_torch_metadata()
        observed = module.probe_installed_torch_cpu()
        if metadata["status"] == "LOCAL_TORCH_METADATA_ONLY":
            # No mock, and NO PASS unless the real fixed CPU fixture succeeds.
            self.assertIn(observed["status"], (
                "PASS_REAL_INSTALLED_TORCH_CPU_FIXED_FIXTURE_ONLY",
                "NOT_RUN_TORCH_CPU_FIXTURE_FAILED", "NOT_RUN_TORCH_CPU_FIXTURE_ORACLE_MISMATCH"))
        else:
            self.assertEqual(observed["status"], metadata["status"])
            self.assertFalse(observed["cpu_runtime_verified"])
        self.assertFalse(observed.get("gpu_runtime_verified", False))

    def test_top_level_report_never_claims_complete_f253(self):
        observed = module.report()
        self.assertFalse(observed["complete_F253_qualification"])
        self.assertFalse(observed["untrusted_python_executed"])
        self.assertFalse(observed["gpu_tested"])


if __name__ == "__main__":
    unittest.main()
