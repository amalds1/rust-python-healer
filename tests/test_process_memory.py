"""Native peak-memory measurement and unit conversion are evidence, never zero fallbacks."""

import importlib.util
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("measured_process_memory", ROOT / "python/process_memory.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProcessMemoryTests(unittest.TestCase):
    def test_native_measurement_is_positive_and_peak_does_not_decrease(self):
        before = module.peak_rss_kib()
        self.assertGreater(before, 0)
        allocation = bytearray(8 * 1024 * 1024)
        for offset in range(0, len(allocation), 4096):
            allocation[offset] = 1
        after = module.peak_rss_kib()
        self.assertGreaterEqual(after, before)
        self.assertEqual(allocation[4096], 1)

    def test_windows_peak_bytes_are_converted_to_kib(self):
        with mock.patch.object(module.os, "name", "nt"), \
                mock.patch.object(module, "_windows_peak_working_set_bytes", return_value=123456):
            self.assertEqual(module.peak_rss_kib(), 123456 / 1024.0)
            self.assertEqual(module.rss_basis(), "windows_peak_working_set_process_high_water")

    def test_windows_api_failure_is_not_converted_to_zero(self):
        with mock.patch.object(module.os, "name", "nt"), \
                mock.patch.object(module, "_windows_peak_working_set_bytes", side_effect=OSError("api failed")):
            with self.assertRaises(OSError):
                module.peak_rss_kib()

    def test_linux_resource_kib_value_is_preserved(self):
        resource = SimpleNamespace(RUSAGE_SELF=0, getrusage=lambda _: SimpleNamespace(ru_maxrss=12345))
        with mock.patch.object(module.os, "name", "posix"), \
                mock.patch.object(module.sys, "platform", "linux"), \
                mock.patch.dict(sys.modules, {"resource": resource}):
            self.assertEqual(module.peak_rss_kib(), 12345)
            self.assertEqual(module.rss_basis(), "linux_ru_maxrss_process_high_water")

    def test_macos_resource_bytes_are_converted_to_kib(self):
        resource = SimpleNamespace(RUSAGE_SELF=0, getrusage=lambda _: SimpleNamespace(ru_maxrss=4096))
        with mock.patch.object(module.os, "name", "posix"), \
                mock.patch.object(module.sys, "platform", "darwin"), \
                mock.patch.dict(sys.modules, {"resource": resource}):
            self.assertEqual(module.peak_rss_kib(), 4.0)


if __name__ == "__main__":
    unittest.main()
