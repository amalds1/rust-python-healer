"""Real loopback HTTP role, audit, escaped HTML and signed webhook regressions."""

from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "localhost_dashboard_v21", ROOT / "python" / "localhost_dashboard_v21.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SECRET = b"trusted-local-fixture-secret-key-0123456789"


def http_get(port, path, token=None, method="GET"):
    connection = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        headers = {"Authorization": "Bearer " + token} if token else {}
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.state = module.DashboardState([
            {"id": "<script>alert(1)</script>", "status": "PASS", "python_minor": "3.9"},
            {"id": "F107", "status": "BLOCKED", "python_minor": "3.15"}], SECRET)
        self.server = module.open_local_dashboard(self.state)
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.viewer = self.state.issue_session("viewer", actor="reader")
        self.admin = self.state.issue_session("admin", actor="editor")

    def test_real_local_dashboard_renders_escaped_diagnoses(self):
        status, headers, body = http_get(self.port, "/", self.viewer)
        self.assertEqual(status, 200)
        self.assertIn(b"&lt;script&gt;", body)
        self.assertNotIn(b"<script>", body)
        self.assertIn(b"Diagnoses", body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["Content-Security-Policy"], "default-src 'none'")

    def test_real_diagnosis_json_contains_only_data(self):
        status, _, body = http_get(self.port, "/api/diagnoses", self.viewer)
        self.assertEqual(status, 200)
        result = json.loads(body)
        self.assertEqual(len(result["records"]), 2)
        self.assertFalse(result["source_executed"])

    def test_unauthenticated_and_random_tokens_are_denied(self):
        self.assertEqual(http_get(self.port, "/")[0], 403)
        self.assertEqual(http_get(self.port, "/api/diagnoses", "invalid")[0], 403)
        self.assertGreater(len(self.state.audit), 0)

    def test_viewer_cannot_export_admin_audit(self):
        self.assertEqual(http_get(self.port, "/api/audit", self.viewer)[0], 403)
        status, _, body = http_get(self.port, "/api/audit", self.admin)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "LOCAL_HASH_CHAIN_VERIFIED_NOT_EXTERNAL_WORM")

    def test_web_post_mutation_never_supported(self):
        self.assertEqual(http_get(self.port, "/api/diagnoses", self.admin, "POST")[0], 405)
        self.assertFalse(any("source" in str(item) for item in self.state.audit))

    def test_unknown_route_returns_404_without_raw_path_leak(self):
        self.assertEqual(http_get(self.port, "/private-token-shall-not-appear", self.admin)[0],
                         404)
        self.assertNotIn("private-token", json.dumps(self.state.export_audit()))

    def test_sessions_expire_and_request_quota_enforced(self):
        now = [100.0]
        state = module.DashboardState([], SECRET, clock=lambda: now[0])
        token = state.issue_session("admin", lifetime_seconds=1)
        self.assertIsNotNone(state.authenticate("Bearer " + token, "admin"))
        now[0] += 1
        self.assertIsNone(state.authenticate("Bearer " + token))
        now[0] -= 1
        for _ in range(199):
            state.authenticate("Bearer " + token)
        self.assertIsNone(state.authenticate("Bearer " + token))

    def test_audit_chain_detects_mutations(self):
        http_get(self.port, "/", self.viewer)
        deadline = time.monotonic() + 1
        while not self.state.export_audit()["events"] and time.monotonic() < deadline:
            # HTTP body reception may race the server's final audit append.
            time.sleep(0.005)
        self.assertTrue(self.state.export_audit()["events"])
        self.state.audit[0]["status"] = "FAIL"
        with self.assertRaisesRegex(ValueError, "tampered"):
            self.state.export_audit()

    def test_diagnostic_record_quotas_and_bad_statuses(self):
        with self.assertRaisesRegex(ValueError, "diagnostic_record"):
            module.permitted_records([{"id": "x", "status": "SECRET", "python_minor": "3.9"}])
        with self.assertRaisesRegex(ValueError, "record_count"):
            module.permitted_records([{"id": "x", "status": "PASS", "python_minor": "3.9"}] * 251)

    def test_session_token_not_in_audit_or_response(self):
        http_get(self.port, "/", self.admin)
        _, _, output = http_get(self.port, "/api/audit", self.admin)
        self.assertNotIn(self.admin.encode(), output)
        self.assertNotIn(SECRET, output)


class WebhookTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        own = self.events

        class Receiver(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if length > 512 or self.path != "/hook":
                    self.send_response(400)
                    self.end_headers()
                    return
                payload = self.rfile.read(length)
                signature = self.headers.get("X-RPH-HMAC-SHA256", "")
                expected = hmac.new(SECRET, payload, hashlib.sha256).hexdigest()
                if hmac.compare_digest(expected, signature):
                    own.append(json.loads(payload))
                    self.send_response(202)
                else:
                    self.send_response(403)
                self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.state = module.DashboardState([], SECRET)
        self.admin = self.state.issue_session("admin")
        self.viewer = self.state.issue_session("viewer")
        self.url = "http://127.0.0.1:{}/hook".format(self.server.server_address[1])

    def test_real_hmac_signed_webhook_and_audit(self):
        result = module.signed_notification(self.state, self.admin, "TEST_PASS", self.url)
        self.assertTrue(result["success"])
        self.assertEqual(result["status"], "SIGNED_LOOPBACK_WEBHOOK_DELIVERED")
        self.assertEqual(self.events, [{"event_code": "TEST_PASS", "schema": 1,
                                       "source_executed": False}])
        self.assertEqual(self.state.export_audit()["events"][-1]["event_code"], "WEBHOOK_SENT")

    def test_webhook_user_role_and_event_allowlist(self):
        with self.assertRaisesRegex(ValueError, "administrator_session"):
            module.signed_notification(self.state, self.viewer, "TEST_PASS", self.url)
        with self.assertRaisesRegex(ValueError, "notification_code"):
            module.signed_notification(self.state, self.admin, "RUN_SHELL", self.url)
        self.assertEqual(self.events, [])

    def test_webhook_rejects_nonlocal_scheme_and_credential_url(self):
        for address in ("https://example.org/hook", "http://127.0.0.2:1234/hook",
                        "http://user:secret@127.0.0.1:2345/hook",
                        "http://127.0.0.1:1234/anything", "http://127.0.0.1:1234/hook?x=1"):
            with self.assertRaisesRegex(ValueError, "nonlocal"):
                module.signed_notification(self.state, self.admin, "TEST_FAIL", address)

    def test_real_connection_refused_never_reported_as_delivered(self):
        url = "http://127.0.0.1:{}/hook".format(self.server.server_address[1])
        self.server.shutdown()
        self.server.server_close()
        result = module.signed_notification(self.state, self.admin, "TEST_FAIL", url)
        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "WEBHOOK_FAILED_NOT_PASS")
        self.assertEqual(self.state.export_audit()["events"][-1]["event_code"], "WEBHOOK_FAILED")


if __name__ == "__main__":
    unittest.main()
