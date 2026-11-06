"""Real mutual-TLS fixed-DAP transport and adversarial path-map evidence."""

import hashlib
import hmac
import importlib.util
import io
import json
import os
import shutil
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "remote_dap_v23.py"
SPEC = importlib.util.spec_from_file_location("remote_dap_v23", SCRIPT)
remote = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(remote)
dap = remote.dap
OPENSSL = shutil.which("openssl")
if OPENSSL is None and os.name == "nt":
    installed_git_openssl = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/usr/bin/openssl.exe"
    if installed_git_openssl.is_file():
        OPENSSL = str(installed_git_openssl)


class TLSFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory(prefix="rph-v23-remote-tls-")
        cls.base = Path(cls.folder.name)
        cls.base.chmod(0o700)
        cls.ca = cls.base / "ca.pem"
        cls.ca_key = cls.base / "ca.key"
        cls.other_ca = cls.base / "otherca.pem"
        cls.other_ca_key = cls.base / "otherca.key"
        cls.server_cert = cls.base / "server.pem"
        cls.server_key = cls.base / "server.key"
        cls.client_cert = cls.base / "client.pem"
        cls.client_key = cls.base / "client.key"
        cls.other_client_cert = cls.base / "other-client.pem"
        cls.other_client_key = cls.base / "other-client.key"

        def openssl(*args):
            if OPENSSL is None:
                raise RuntimeError("installed_openssl_required_for_real_tls_fixture")
            result = subprocess.run([OPENSSL] + [str(arg) for arg in args],
                                    cwd=str(cls.base), capture_output=True,
                                    check=False, timeout=12)
            if result.returncode != 0:
                raise RuntimeError("trusted_openssl_fixture_generation_failed")

        for name in ("ca", "otherca"):
            openssl("req", "-x509", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:prime256v1", "-nodes", "-sha256",
                    "-keyout", cls.base / (name + ".key"), "-out",
                    cls.base / (name + ".pem"), "-subj",
                    "/CN=RPH-{}-fixture-CA".format(name), "-days", "1")
        for name, extension in (
                ("server", "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
                           "extendedKeyUsage=serverAuth\n"),
                ("client", "extendedKeyUsage=clientAuth\n"),
                ("other-client", "extendedKeyUsage=clientAuth\n")):
            cert = cls.base / (name + ".pem")
            key = cls.base / (name + ".key")
            csr = cls.base / (name + ".csr")
            extensions = cls.base / (name + ".ext")
            extensions.write_text(extension, encoding="ascii")
            openssl("req", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:prime256v1", "-nodes", "-sha256",
                    "-keyout", key, "-out", csr, "-subj", "/CN={}".format(
                        "localhost" if name == "server" else name))
            openssl("x509", "-req", "-in", csr, "-CA", cls.ca,
                    "-CAkey", cls.ca_key, "-CAcreateserial", "-out", cert,
                    "-days", "1", "-sha256", "-extfile", extensions)
            key.chmod(0o600)
        cls.server_pin = remote.leaf_pin_from_pem(cls.server_cert)
        cls.client_pin = remote.leaf_pin_from_pem(cls.client_cert)
        cls.other_client_pin = remote.leaf_pin_from_pem(cls.other_client_cert)
        cls.key = b"remote-dap-operator-approval-not-released-to-client"

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def setUp(self):
        self.listener = None
        self.client = None
        self.addCleanup(self._clean)

    def _clean(self):
        if self.client is not None:
            self.client.close()
        if self.listener is not None:
            self.listener.close()

    def start(self, expected_client_pin=None):
        self.listener = remote.PinnedRemoteDAPServer(
            self.ca, self.server_cert, self.server_key,
            expected_client_pin or self.client_pin, self.key)
        return self.listener.start()

    def connect(self, port, pin=None, cert=None, key=None, ca=None):
        self.client = remote.PinnedRemoteDAPClient(
            ca or self.ca, cert or self.client_cert,
            key or self.client_key, pin or self.server_pin)
        self.client.connect("127.0.0.1", port)
        return self.client

    def init_and_launch(self):
        initialized = self.client.request({"seq": 1, "type": "request", "command": "initialize",
                          "arguments": {"adapterID": "rph-mtls-test"}}, response_count=2)
        self.assertTrue(initialized[0]["success"])
        nonce = "remotenonce001"
        digest = hmac.new(self.key, ("launch:" + nonce).encode("ascii"),
                          hashlib.sha256).hexdigest()
        result = self.client.request({"seq": 2, "type": "request", "command": "launch",
                       "arguments": {"fixture": "rph-trusted-v22", "nonce": nonce,
                                     "approval": digest}}, response_count=3)
        self.assertTrue(result[0]["success"])
        self.assertEqual(result[-1]["event"], "stopped")
        return result[0]["body"]["sessionId"]

    def test_real_mutual_tls_with_two_pinned_leaf_keys_and_real_dap_trace(self):
        host, port = self.start()
        self.assertEqual(host, "127.0.0.1")
        self.connect(port)
        session = self.init_and_launch()
        self.assertTrue(self.client.peer_leaf_verified)
        self.assertTrue(self.listener.peer_leaf_verified)
        self.assertIn(self.client.actual_tls_version, ("TLSv1.2", "TLSv1.3"))
        self.assertEqual(self.client.actual_tls_version, self.listener.actual_tls_version)
        paused = self.client.request({"seq": 3, "type": "request", "command": "stackTrace"})
        self.assertTrue(paused[0]["success"])
        self.assertTrue(paused[0]["body"]["stackFrames"])
        completed = self.client.request({"seq": 4, "type": "request", "command": "continue",
                                         "arguments": {"sessionId": session}}, response_count=4)
        self.assertEqual([x["event"] for x in completed[1:]],
                         ["continued", "output", "terminated"])
        self.assertEqual(completed[-2]["body"]["output"], "trusted fixture completed: 9")
        self.assertNotIn("PRIVATE", json.dumps(completed))

    def test_wrong_out_of_band_server_pin_is_rejected_after_genuine_tls(self):
        _, port = self.start()
        with self.assertRaisesRegex(ValueError, "wrong_operator_pinned_server_leaf"):
            self.connect(port, pin="f" * 64)
        self.assertIsNone(self.client.stream)
        self.assertFalse(self.client.peer_leaf_verified)

    def test_wrong_client_leaf_signed_by_same_ca_is_rejected_by_server_pin(self):
        _, port = self.start(expected_client_pin=self.client_pin)
        self.connect(port, cert=self.other_client_cert, key=self.other_client_key)
        # A TLS1.3 client handshake may finish before the server has processed
        # the final flight. Do not abort it before its actual pin oracle runs.
        self.assertTrue(self.listener.completed.wait(3))
        self.client.close()
        self.listener.close()
        self.assertFalse(self.listener.peer_leaf_verified)
        self.assertTrue(self.listener.peer_chain_verified)
        self.assertTrue(self.listener.peer_leaf_pin_mismatch)
        self.assertEqual(self.listener.error_class, "ValueError")

    def test_ca_mismatch_refuses_server_certificate_chain(self):
        _, port = self.start()
        with self.assertRaises(ssl.SSLError):
            self.connect(port, ca=self.other_ca)
        self.assertFalse(self.client.peer_leaf_verified)

    def test_hostname_verification_rejects_wrong_server_identity(self):
        _, port = self.start()
        context = remote._tls_context(self.ca, self.client_cert, self.client_key, False)
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            with self.assertRaises(ssl.SSLError):
                context.wrap_socket(sock, server_hostname="other.invalid")

    def test_plaintext_cannot_be_mistaken_for_dap_tls_connection(self):
        _, port = self.start()
        payload = io.BytesIO()
        dap.write_frame(payload, {"seq": 1, "type": "request", "command": "initialize",
                                  "arguments": {"adapterID": "attacker"}})
        with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
            raw.sendall(payload.getvalue())
        self.listener.close()
        self.assertFalse(self.listener.peer_leaf_verified)
        self.assertIsNotNone(self.listener.error_class)

    def test_operator_refuses_remote_wan_destination_before_connect(self):
        self.client = remote.PinnedRemoteDAPClient(
            self.ca, self.client_cert, self.client_key, self.server_pin)
        with self.assertRaisesRegex(ValueError, "only_loopback_fixture_enabled"):
            self.client.connect("example.com", 443)
        self.assertIsNone(self.client.connection)

    def test_server_refuses_world_readable_private_key(self):
        self.server_key.chmod(0o644)
        if os.name == "nt":
            sys.path.insert(0, str(ROOT / "tests"))
            import windows_privacy_fixtures
            windows_privacy_fixtures.set_public_read_acl(self.server_key)
        try:
            with self.assertRaisesRegex(ValueError, "private_key_file_required"):
                remote.PinnedRemoteDAPServer(self.ca, self.server_cert, self.server_key,
                                             self.client_pin, self.key)
        finally:
            self.server_key.chmod(0o600)
            if os.name == "nt":
                windows_privacy_fixtures.set_private_acl(self.server_key)

    def test_invalid_leaf_pins_never_create_an_unpinned_listener(self):
        for pin in ("", "f" * 63, "G" * 64, "f" * 65, None):
            with self.assertRaises(ValueError):
                remote.PinnedRemoteDAPServer(self.ca, self.server_cert,
                                             self.server_key, pin, self.key)

    def test_network_dap_wrong_hmac_launch_never_runs_fixture(self):
        _, port = self.start()
        self.connect(port)
        self.client.request({"seq": 1, "type": "request", "command": "initialize",
                             "arguments": {"adapterID": "rph-mtls"}}, response_count=2)
        denied = self.client.request({"seq": 2, "type": "request", "command": "launch",
                             "arguments": {"fixture": "rph-trusted-v22",
                                           "nonce": "remotenonce001", "approval": "f" * 64}})
        self.assertFalse(denied[0]["success"])
        self.assertTrue(self.listener.peer_leaf_verified)

    def test_network_dap_unknown_program_refused_even_with_valid_hmac(self):
        _, port = self.start()
        self.connect(port)
        self.client.request({"seq": 1, "type": "request", "command": "initialize",
                             "arguments": {"adapterID": "rph-mtls"}}, response_count=2)
        nonce = "remotenonce001"
        digest = hmac.new(self.key, ("launch:" + nonce).encode(), hashlib.sha256).hexdigest()
        denied = self.client.request({"seq": 2, "type": "request", "command": "launch",
                             "arguments": {"fixture": "rph-trusted-v22", "nonce": nonce,
                                           "approval": digest, "program": "/private/user.py"}})
        self.assertFalse(denied[0]["success"])


class PathMappingTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="rph-v23-pathmap-")
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.host = self.root / "project"
        self.host.mkdir(mode=0o700)
        (self.host / "app").mkdir()
        (self.host / "app" / "main.py").write_text("VALUE=1\n", encoding="utf-8")
        self.roots = {
            "host": {"root": str(self.host), "flavor": "windows" if os.name == "nt" else "posix"},
            "container": {"root": "/app/project", "flavor": "posix"},
            "wsl": {"root": "/mnt/c/myproject", "flavor": "posix"},
            "remote": {"root": "C:\\remote\\project", "flavor": "windows"}}
        self.mapper = remote.SourcePathMapper(self.roots, verify_host=True)

    def test_real_host_to_container_wsl_and_windows_remote(self):
        source = str(self.host / "app" / "main.py")
        expected = {"container": "/app/project/app/main.py",
                    "wsl": "/mnt/c/myproject/app/main.py",
                    "remote": "C:\\remote\\project\\app\\main.py"}
        for environment, target in expected.items():
            translated = self.mapper.translate(source, "host", environment)
            self.assertEqual(translated["translated_path"], target)
            self.assertTrue(translated["existing_host_symlinks_checked"])
            self.assertFalse(translated["remote_filesystem_verified"])
            self.assertFalse(translated["arbitrary_files_opened"])

    def test_reverse_container_wsl_and_windows_to_host(self):
        host_target = str(self.host / "app" / "main.py")
        for value, environment in (
                ("/app/project/app/main.py", "container"),
                ("/mnt/c/myproject/app/main.py", "wsl"),
                ("C:\\remote\\project\\app\\main.py", "remote")):
            mapped = self.mapper.translate(value, environment, "host")
            self.assertEqual(mapped["translated_path"], host_target)
            self.assertTrue(mapped["existing_host_symlinks_checked"])

    def test_windows_casefold_is_root_only_and_preserves_relative_path_case(self):
        result = self.mapper.translate("c:\\REMOTE\\PROJECT\\App\\File.PY",
                                       "remote", "container")
        self.assertEqual(result["translated_path"], "/app/project/App/File.PY")

    def test_native_windows_host_casefold_preserves_requested_relative_case(self):
        if os.name != 'nt':
            self.skipTest('actual Windows host casefold contract')
        value = str(self.host).swapcase() + '\\App\\MAIN.PY'
        result = self.mapper.translate(value,'host','remote')
        self.assertEqual(result['translated_path'],'C:\\remote\\project\\App\\MAIN.PY')

    def test_windows_unc_paths_can_be_allowlisted_without_drive_aliasing(self):
        roots = dict(self.roots)
        roots["remote"] = {"root": "\\\\fileserver\\buildshare\\project",
                           "flavor": "windows"}
        mapper = remote.SourcePathMapper(roots)
        self.assertEqual(mapper.translate("\\\\fileserver\\buildshare\\project\\src\\a.py",
                                          "remote", "container")["translated_path"],
                         "/app/project/src/a.py")

    def test_posix_dotdot_traversal_refused_before_mapping(self):
        for path in (str(self.host / "app" / ".." / "secret.py"),
                     str(self.host) + "/../secret.py",
                     str(self.host) + "//app/main.py"):
            with self.assertRaises(ValueError):
                self.mapper.translate(path, "host", "container")

    def test_windows_drive_relative_traversal_and_alternate_stream_refused(self):
        for path in ("C:remote\\project\\a.py", "C:\\remote\\project\\..\\secret.py",
                     "C:\\remote\\project\\main.py:secret",
                     "\\\\?\\C:\\remote\\project\\main.py"):
            with self.assertRaises(ValueError):
                self.mapper.translate(path, "remote", "host")

    def test_sibling_prefix_is_not_a_valid_path_root(self):
        path = str(self.host.parent / (self.host.name + "-other") / "main.py")
        with self.assertRaisesRegex(ValueError, "outside_allowlisted_root"):
            self.mapper.translate(path, "host", "remote")

    def test_cross_environment_identical_roots_rejected_as_collision(self):
        roots = dict(self.roots)
        roots["wsl"] = {"root": "/app/project", "flavor": "posix"}
        with self.assertRaisesRegex(ValueError, "cross_environment_root_collision"):
            remote.SourcePathMapper(roots)

    def test_existing_host_symlink_to_external_file_rejected(self):
        external = self.root / "external-private.py"
        external.write_text("SECRET=1\n", encoding="utf-8")
        (self.host / "app" / "linked.py").symlink_to(external)
        with self.assertRaisesRegex(ValueError, "linked_host_path_component"):
            self.mapper.translate(str(self.host / "app" / "linked.py"), "host", "remote")

    def test_reverse_mapping_refuses_host_symlink_to_external_file(self):
        external = self.root / "secret.py"
        external.write_text("PRIVATE=1\n", encoding="utf-8")
        (self.host / "app" / "linked.py").symlink_to(external)
        with self.assertRaisesRegex(ValueError, "linked_host_path_component"):
            self.mapper.translate("/app/project/app/linked.py", "container", "host")

    def test_host_symlink_root_is_rejected(self):
        link = self.root / "project-link"
        link.symlink_to(self.host, target_is_directory=True)
        roots = dict(self.roots)
        roots["host"] = {"root": str(link), "flavor": "windows" if os.name == "nt" else "posix"}
        with self.assertRaisesRegex(ValueError, "linked_host_root"):
            remote.SourcePathMapper(roots, verify_host=True)

    def test_encoded_traversal_sequences_rejected_before_consumer_uri_decoding(self):
        for source, environment in ((str(self.host) + "/%2e%2e/secret.py", "host"),
                                    ("C:\\remote\\project\\%2e%2e\\secret.py", "remote")):
            with self.assertRaises(ValueError):
                self.mapper.translate(source, environment, "container")

    def test_nul_unbounded_long_source_and_empty_input_rejected(self):
        for value in (str(self.host) + "/\x00bad.py", "", "x" * 5000):
            with self.assertRaises(ValueError):
                self.mapper.translate(value, "host", "remote")

    def test_unsupported_source_environment_and_self_mapping_rejected(self):
        for source, target in (("unknown", "host"), ("host", "host"),
                               ("host", "external")):
            with self.assertRaisesRegex(ValueError, "unknown_or_duplicate_environment"):
                self.mapper.translate(str(self.host), source, target)

    def test_actual_cli_path_mapping_returns_json_with_no_remote_read_claim(self):
        completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                                    "--fixture-pathmap-selftest"], capture_output=True,
                                   check=False, timeout=5)
        self.assertEqual(completed.returncode, 0, completed.stderr[:100])
        report = json.loads(completed.stdout)
        self.assertEqual(report["translated_path"], "C:\\remote\\project\\app\\main.py")
        self.assertFalse(report["remote_filesystem_verified"])
        self.assertFalse(report["arbitrary_files_opened"])

    def test_windows_ambiguous_components_and_device_names_refused(self):
        for part in ('.. ', 'name.', 'name ', 'NUL', 'CON.py', 'LPT1.txt', 'file?name.py'):
            with self.subTest(part=part), self.assertRaises(ValueError):
                self.mapper.translate('C:\\remote\\project\\' + part, 'remote', 'host')

    def test_host_flavor_mismatch_rejected_before_filesystem_access(self):
        roots = dict(self.roots)
        roots['host'] = {'root': '/trusted/project' if os.name == 'nt' else 'C:\\trusted\\project',
                         'flavor': 'posix' if os.name == 'nt' else 'windows'}
        with self.assertRaisesRegex(ValueError, 'flavor_must_match_actual_platform'):
            remote.SourcePathMapper(roots, verify_host=True)

    def test_windows_host_unc_is_not_opened_as_local_filesystem(self):
        if os.name != 'nt':
            self.skipTest('native Windows host path contract')
        roots = dict(self.roots)
        roots['host'] = {'root': '\\\\nonexistent-server\\share\\project', 'flavor': 'windows'}
        with self.assertRaisesRegex(ValueError, 'real_local_windows_directory'):
            remote.SourcePathMapper(roots, verify_host=True)

    def test_host_hardlink_leaf_is_refused_without_reading_contents(self):
        outside = self.root / 'outside.py'
        outside.write_text('PRIVATE=1\n', encoding='utf-8')
        alias = self.host / 'app' / 'hardlink.py'
        os.link(outside, alias)
        with self.assertRaisesRegex(ValueError, 'linked_host_path_component'):
            self.mapper.translate(str(alias), 'host', 'remote')

    def test_windows_junction_components_and_root_are_rejected(self):
        if os.name != 'nt':
            self.skipTest('actual NTFS junction requires Windows')
        outside = self.root / 'junction-outside'
        outside.mkdir()
        (outside / 'private.py').write_text('PRIVATE=1\n', encoding='utf-8')
        junction = self.host / 'junction'
        environment = dict(os.environ, RPH_TEST_JUNCTION_PATH=str(junction), RPH_TEST_JUNCTION_TARGET=str(outside))
        completed = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
            'New-Item -ItemType Junction -Path $env:RPH_TEST_JUNCTION_PATH -Target $env:RPH_TEST_JUNCTION_TARGET -ErrorAction Stop | Out-Null'],
            env=environment, capture_output=True, timeout=10, check=False)
        self.assertEqual(completed.returncode,0,completed.stderr)
        try:
            self.assertTrue(junction.lstat().st_file_attributes & 0x400)
            with self.assertRaisesRegex(ValueError,'linked_host_path_component'):
                self.mapper.translate(str(junction/'private.py'),'host','remote')
            roots = dict(self.roots)
            roots['host'] = {'root':str(junction),'flavor':'windows'}
            with self.assertRaisesRegex(ValueError,'linked_host_root'):
                remote.SourcePathMapper(roots,verify_host=True)
        finally:
            junction.rmdir()  # Remove our junction itself, never the target tree.


if __name__ == "__main__":
    unittest.main()
