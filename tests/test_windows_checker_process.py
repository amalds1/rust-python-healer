"""Actual own checker-launcher HANDLE metrics, not fabricated resource zeros."""
import ctypes
from ctypes import wintypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('r5_checker_process',ROOT/'python/windows_checker_process_v028.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


@unittest.skipUnless(os.name=='nt','native Windows owned-HANDLE metrics required')
class WindowsCheckerProcessTests(unittest.TestCase):
    def test_real_retained_child_handle_peak_survives_process_exit(self):
        with tempfile.TemporaryDirectory(prefix='rph-checker-metric-') as folder:
            fixed="x=bytearray(16*1024*1024);print(len(x))"
            result,metrics=module.run_trusted_checker([sys.executable,'-I','-B','-c',fixed],Path(folder),dict(os.environ))
        self.assertEqual(result.returncode,0)
        self.assertEqual(result.stdout.strip(),b'16777216')
        self.assertGreater(metrics['peak_child_rss_kib'],16*1024)
        self.assertGreater(metrics['process_pid'],0)
        self.assertGreater(metrics['process_creation_time_100ns'],0)
        self.assertIsNone(metrics['delta_peak_rss_kib'])
        self.assertEqual(metrics['delta_peak_rss_status'],'NOT_RUN_NO_SAME_CHILD_STARTUP_BASELINE')
        self.assertFalse(metrics['descendant_memory_measured'])
        self.assertFalse(metrics['os_sandbox_proven'])

    def test_mismatched_pid_cannot_be_accepted_as_own_metrics(self):
        child=subprocess.Popen([sys.executable,'-I','-B','-c','pass'])
        child.wait(timeout=3)
        actual=child.pid
        try:
            child.pid=actual+1
            with self.assertRaisesRegex(ValueError,'handle_pid_mismatch'):
                module.process_usage(child)
        finally:
            child.pid=actual

    def test_real_timeout_closes_owned_job_and_descendant(self):
        with tempfile.TemporaryDirectory(prefix='rph-checker-timeout-') as folder:
            marker=Path(folder)/'own-child.json'
            fixed=("import subprocess,sys,pathlib,json,time,ctypes;from ctypes import wintypes;"
                   "p=subprocess.Popen([sys.executable,'-I','-B','-c','import time;time.sleep(30)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
                   "k=ctypes.WinDLL('kernel32',use_last_error=True);k.GetProcessTimes.argtypes=[wintypes.HANDLE]+[ctypes.POINTER(wintypes.FILETIME)]*4;"
                   "ts=[wintypes.FILETIME() for _ in range(4)];assert k.GetProcessTimes(int(p._handle),*[ctypes.byref(x) for x in ts]);"
                   "pathlib.Path(sys.argv[1]).write_text(json.dumps({'pid':p.pid,'creation':ts[0].dwLowDateTime+(ts[0].dwHighDateTime<<32)}));"
                   "print('ready',flush=True);time.sleep(30)")
            start=time.monotonic()
            with self.assertRaisesRegex(ValueError,'external_checker_failed_to_run'):
                module.run_trusted_checker([sys.executable,'-I','-B','-c',fixed,str(marker)],Path(folder),dict(os.environ),timeout=1)
            self.assertLess(time.monotonic()-start,5)
            owned=json.loads(marker.read_text())
            kernel=ctypes.WinDLL('kernel32',use_last_error=True)
            kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];kernel.OpenProcess.restype=wintypes.HANDLE
            kernel.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD];kernel.WaitForSingleObject.restype=wintypes.DWORD
            kernel.CloseHandle.argtypes=[wintypes.HANDLE]
            handle=kernel.OpenProcess(0x100000|0x1000,False,owned['pid'])
            if handle:
                try:
                    # Read-only identity/liveness check of our recorded child;
                    # never terminate a PID found through a global lookup.
                    kernel.GetProcessTimes.argtypes=[wintypes.HANDLE]+[ctypes.POINTER(wintypes.FILETIME)]*4
                    times=[wintypes.FILETIME() for _ in range(4)]
                    self.assertTrue(kernel.GetProcessTimes(handle,*[ctypes.byref(x) for x in times]))
                    self.assertEqual(times[0].dwLowDateTime+(times[0].dwHighDateTime<<32),owned['creation'])
                    self.assertEqual(kernel.WaitForSingleObject(handle,2000),0)
                finally:kernel.CloseHandle(handle)
