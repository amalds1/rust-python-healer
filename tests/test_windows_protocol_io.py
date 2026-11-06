"""Real Windows anonymous-pipe deadlines and native path preflight oracles."""
import ctypes
from ctypes import wintypes
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('r5_native_dap_client', ROOT/'python/dap_client_conformance_v26.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


@unittest.skipUnless(os.name == 'nt', 'actual Windows pipe HANDLE API required')
class WindowsProtocolPipeTests(unittest.TestCase):
    def test_actual_fixed_adapter_does_not_use_socket_select_for_stdio(self):
        with mock.patch.object(client.selectors, 'DefaultSelector', side_effect=AssertionError('socket selector on pipe')):
            with client.FixedFixtureClient() as session:
                child = session._proc
                initialized, events = session.request('initialize', {'adapterID':'rph-r5'}, ('initialized',))
                self.assertTrue(initialized['success'])
                self.assertEqual(events[0]['event'], 'initialized')
        self.assertIsNotNone(child.returncode)
        self.assertTrue(child.stdin.closed)
        self.assertTrue(child.stdout.closed)

    def test_actual_fragmented_pipe_output_is_read_in_bounded_chunks(self):
        fixed = "import os,time;os.write(1,b'Content-Len');time.sleep(0.04);os.write(1,b'gth: 2\\r\\n\\r\\n{}')"
        child = subprocess.Popen([sys.executable,'-I','-S','-B','-c',fixed], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        data = bytearray()
        deadline = time.monotonic()+3
        try:
            while time.monotonic()<deadline:
                block = client._windows_pipe_bytes(child.stdout, 5)
                if block is None:
                    time.sleep(.005)
                    continue
                if not block:
                    break
                self.assertLessEqual(len(block),5)
                data.extend(block)
            child.wait(timeout=2)
            self.assertEqual(child.returncode,0)
            self.assertEqual(bytes(data),b'Content-Length: 2\r\n\r\n{}')
        finally:
            if child.poll() is None:
                child.kill();child.wait(timeout=2)
            child.stdout.close()

    def test_idle_adapter_has_real_deadline_and_owned_process_cleanup(self):
        with client.FixedFixtureClient() as session:
            child = session._proc
            start = time.monotonic()
            with self.assertRaisesRegex(client.ClientProtocolError,'adapter_response_deadline'):
                session._read()
            elapsed = time.monotonic()-start
            self.assertGreaterEqual(elapsed,client.MAX_RESPONSE_SECONDS-.05)
            self.assertLess(elapsed,client.MAX_RESPONSE_SECONDS+1.5)
        self.assertIsNotNone(child.returncode)
        self.assertTrue(child.stdout.closed)


if __name__ == '__main__':
    unittest.main()
