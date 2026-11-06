"""Real loopback-only HTTP dashboard, private sessions and signed webhooks.

Only caller-supplied *data* is displayed. No user code or plugins are run.
This is not a remotely hosted, independently hardened production service.
"""

import hashlib
import hmac
from html import escape
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import threading
import time


MAX_RECORDS = 250
MAX_BODY = 2048
MAX_SESSIONS = 20
MAX_AUDIT_EVENTS = 1000
EVENT_CODES = frozenset(("TEST_PASS", "TEST_FAIL", "VERSION_DISCOVERED", "RELEASE_DENIED"))


def digest(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True,
                     separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def permitted_records(records):
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError("invalid_dashboard_record_count")
    output = []
    for row in records:
        if (not isinstance(row, dict) or set(row) != {"id", "status", "python_minor"} or
                any(not isinstance(row[k], str) or len(row[k]) > 64 for k in row) or
                row["status"] not in ("PASS", "FAIL", "PARTIAL", "NOT_RUN", "BLOCKED") or
                row["python_minor"] not in {"3." + str(k) for k in range(9, 16)}):
            raise ValueError("invalid_data_only_diagnostic_record")
        output.append(dict(row))
    return output


class DashboardState:
    def __init__(self, records, secret, clock=time.monotonic):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("private_dashboard_key_required")
        self.records = permitted_records(records)
        self.secret = secret
        self.clock = clock
        self.sessions = {}
        self.audit = []
        self.lock = threading.RLock()
        self.previous = "0" * 64

    def issue_session(self, role="viewer", lifetime_seconds=120, actor="trusted"):
        if role not in ("viewer", "admin") or not isinstance(actor, str) or \
                len(actor) > 60 or not actor or not 1 <= lifetime_seconds <= 3600:
            raise ValueError("invalid_session_role_or_lifetime")
        with self.lock:
            if len(self.sessions) >= MAX_SESSIONS:
                raise ValueError("session_quota")
            token = secrets.token_urlsafe(32)
            self.sessions[hashlib.sha256(token.encode()).hexdigest()] = {
                "role": role, "actor_hash": hashlib.sha256(actor.encode()).hexdigest(),
                "expires": self.clock() + lifetime_seconds, "requests": 0}
        return token

    def authenticate(self, authorization, required="viewer"):
        if not isinstance(authorization, str) or not authorization.startswith("Bearer "):
            return None
        token = authorization[len("Bearer "):]
        if len(token) < 30 or len(token) > 130:
            return None
        key = hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            row = self.sessions.get(key)
            if row is None or self.clock() >= row["expires"] or row["requests"] >= 200:
                return None
            if required == "admin" and row["role"] != "admin":
                return None
            row["requests"] += 1
            return dict(row)

    def append_audit(self, actor, event_code, status):
        if not isinstance(actor, str) or len(actor) != 64 or event_code not in (
                "HTTP_VIEW", "HTTP_AUDIT_EXPORT", "HTTP_DENIED", "WEBHOOK_SENT", "WEBHOOK_FAILED") or \
                status not in ("PASS", "FAIL"):
            raise ValueError("invalid_audit_record")
        with self.lock:
            if len(self.audit) >= MAX_AUDIT_EVENTS:
                raise ValueError("audit_quota")
            row = {"sequence": len(self.audit) + 1, "actor_sha256": actor,
                   "event_code": event_code, "status": status, "previous": self.previous}
            row["sha256"] = digest(row)
            self.previous = row["sha256"]
            self.audit.append(row)

    def export_audit(self):
        with self.lock:
            observed = [dict(row) for row in self.audit]
        previous = "0" * 64
        for index, row in enumerate(observed):
            if row["previous"] != previous or row["sequence"] != index + 1 or \
                    digest({k: v for k, v in row.items() if k != "sha256"}) != row["sha256"]:
                raise ValueError("audit_hash_chain_tampered")
            previous = row["sha256"]
        return {"status": "LOCAL_HASH_CHAIN_VERIFIED_NOT_EXTERNAL_WORM",
                "events": observed, "source_executed": False}

    def html(self):
        entries = "".join("<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            escape(row["id"], quote=True), escape(row["status"], quote=True),
            escape(row["python_minor"], quote=True)) for row in self.records)
        return ("<!doctype html><html lang='nl'><meta charset='utf-8'>"
                "<title>Rust Python Healer — lokaal dashboard</title>"
                "<h1>Diagnoses en herstelstatus</h1><table><thead><tr>"
                "<th>ID</th><th>Status</th><th>Python</th></tr></thead><tbody>"
                + entries + "</tbody></table><p>Alleen lokale, niet-uitgevoerde bewijsdata.</p></html>")


def make_dashboard_handler(state):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            # Deliberately suppress HTTP authorization headers and raw paths.
            return

        def do_GET(self):
            route = self.path
            authorized = state.authenticate(self.headers.get("Authorization"),
                                            "admin" if route == "/api/audit" else "viewer")
            if authorized is None:
                state.append_audit("0" * 64, "HTTP_DENIED", "FAIL")
                self.send_error(403, "not_authorized")
                return
            if route == "/":
                output = state.html().encode("utf-8")
                media = "text/html; charset=utf-8"
                event = "HTTP_VIEW"
            elif route == "/api/diagnoses":
                output = json.dumps({"records": state.records, "source_executed": False},
                                    sort_keys=True).encode()
                media = "application/json"
                event = "HTTP_VIEW"
            elif route == "/api/audit":
                output = json.dumps(state.export_audit(), sort_keys=True).encode()
                media = "application/json"
                event = "HTTP_AUDIT_EXPORT"
            else:
                state.append_audit(authorized["actor_hash"], "HTTP_DENIED", "FAIL")
                self.send_error(404, "unknown_endpoint")
                return
            self.send_response(200)
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(output)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'")
            self.end_headers()
            self.wfile.write(output)
            state.append_audit(authorized["actor_hash"], event, "PASS")

        def do_POST(self):
            # The data-only dashboard deliberately has NO remote mutation API.
            state.append_audit("0" * 64, "HTTP_DENIED", "FAIL")
            self.send_error(405, "read_only_dashboard")

    return Handler


def open_local_dashboard(state):
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_dashboard_handler(state))
    server.daemon_threads = True
    return server


def signed_notification(state, actor_token, event_code, callback_url):
    """Actually POST HMAC-authenticated allowlisted event to loopback only."""
    from urllib.parse import urlsplit
    info = state.authenticate("Bearer " + actor_token, "admin")
    if info is None:
        raise ValueError("administrator_session_required")
    parsed = urlsplit(callback_url)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or
            parsed.username is not None or parsed.password is not None or
            parsed.query or parsed.fragment or parsed.port is None or
            not 1024 <= parsed.port <= 65535 or parsed.path not in ("/hook", "/events")):
        raise ValueError("nonlocal_or_unapproved_webhook_destination")
    if event_code not in EVENT_CODES:
        raise ValueError("unknown_notification_code")
    payload = json.dumps({"schema": 1, "event_code": event_code,
                          "source_executed": False}, sort_keys=True).encode()
    signature = hmac.new(state.secret, payload, hashlib.sha256).hexdigest()
    connection = HTTPConnection("127.0.0.1", parsed.port, timeout=3)
    try:
        connection.request("POST", parsed.path, body=payload,
                           headers={"Content-Type": "application/json",
                                    "X-RPH-HMAC-SHA256": signature})
        answer = connection.getresponse()
        ok = answer.status in (200, 202, 204)
        answer.read(4096)
    except (TimeoutError, OSError):
        ok = False
    finally:
        connection.close()
    state.append_audit(info["actor_hash"], "WEBHOOK_SENT" if ok else "WEBHOOK_FAILED",
                       "PASS" if ok else "FAIL")
    return {"status": "SIGNED_LOOPBACK_WEBHOOK_DELIVERED" if ok else "WEBHOOK_FAILED_NOT_PASS",
            "authenticated": True, "success": ok, "unknown_source_executed": False,
            "external_network_used": False, "publisher_authenticated": False}
