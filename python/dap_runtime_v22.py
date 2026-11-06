"""Bounded live Debug Adapter Protocol for a hardcoded trusted Python fixture.

This is intentionally NOT an arbitrary-program debugger or production DAP
implementation.  It runs one immutable fixture in a controllable real thread,
observes real trace events and refuses user-supplied programs or evaluation
code.  All mutation/session operations need scoped HMAC permission.
"""

import argparse
import ast
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import threading


TRUSTED_FILE = "<rph-v22-trusted-dap-fixture>"
TRUSTED_SOURCE = ("SECRET = 'PRIVATE_NEVER_EXPOSE'\n"
                  "STATE = {'count': 1}\n"
                  "def compute():\n"
                  "    a = STATE['count']\n"
                  "    STATE['count'] = a + 2\n"
                  "    b = STATE['count'] * 3\n"
                  "    return b\n"
                  "RESULT = compute()\n"
                  "OUTPUT = 'completed'\n")
EXCEPTION_SOURCE = ("SECRET = 'PRIVATE_NEVER_EXPOSE'\n"
                    "STATE = {'count': 1}\n"
                    "def compute():\n"
                    "    raise ValueError('PRIVATE_EXCEPTION_MESSAGE')\n"
                    "RESULT = compute()\n")
MAX_MESSAGE_BYTES = 65536
MAX_HEADER_BYTES = 4096
MAX_REQUESTS = 256
MAX_STACK = 16
READ_SCOPES = frozenset(("count", "a", "b", "RESULT"))
TRACE_FILE = TRUSTED_FILE
SAFE_NONCE = re.compile(r"[A-Za-z0-9_-]{8,96}\Z", re.ASCII)
SAFE_TOKEN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class ProtocolError(ValueError):
    pass


class _StopFixture(BaseException):
    pass


def read_frame(stream):
    header = bytearray()
    while not header.endswith(b"\r\n\r\n"):
        if len(header) >= MAX_HEADER_BYTES:
            raise ProtocolError("header_limit")
        part = stream.read(1)
        if not part:
            if not header:
                return None
            raise ProtocolError("short_header")
        header += part
    try:
        lines = header[:-4].decode("ascii").split("\r\n")
    except UnicodeError:
        raise ProtocolError("non_ascii_header") from None
    length = None
    for line in lines:
        if ": " not in line:
            raise ProtocolError("invalid_header")
        name, value = line.split(": ", 1)
        if name.lower() == "content-length":
            if length is not None or not value.isascii() or not value.isdigit():
                raise ProtocolError("duplicate_or_invalid_length")
            length = int(value)
    if length is None or not 0 < length <= MAX_MESSAGE_BYTES:
        raise ProtocolError("body_limit_or_missing_length")
    blocks = []
    remaining = length
    while remaining:
        block = stream.read(remaining)
        if not block:
            raise ProtocolError("short_body")
        blocks.append(block)
        remaining -= len(block)
    payload = b"".join(blocks)
    try:
        packet = json.loads(payload.decode("utf-8"),
                            object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeError, ValueError):
        raise ProtocolError("invalid_json") from None
    if not isinstance(packet, dict):
        raise ProtocolError("invalid_packet")
    return packet


def _reject_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ProtocolError("duplicate_json_key")
        obj[key] = value
    return obj


def write_frame(stream, packet):
    data = json.dumps(packet, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")
    if len(data) > MAX_MESSAGE_BYTES:
        raise ProtocolError("outgoing_body_limit")
    stream.write(("Content-Length: {}\r\n\r\n".format(len(data))).encode("ascii"))
    stream.write(data)
    stream.flush()


def _safe_scalar(value):
    if type(value) is bool:
        return value
    if type(value) is int and -1000000 <= value <= 1000000:
        return value
    if type(value) is float and -1000000 <= value <= 1000000:
        return value
    if type(value) is str and len(value) < 64 and "PRIVATE" not in value:
        return value
    return "[REDACTED]"


def _trusted_eval(expression, names):
    if not isinstance(expression, str) or len(expression) > 70:
        raise ValueError("evaluation_input_limit")
    tree = ast.parse(expression, mode="eval")
    nodes = list(ast.walk(tree))
    if len(nodes) > 14 or any(not isinstance(node, (
            ast.Expression, ast.Constant, ast.Name, ast.Load, ast.BinOp,
            ast.Add, ast.Sub, ast.Mult, ast.USub, ast.UnaryOp)) for node in nodes):
        raise ValueError("evaluation_ast_forbidden")

    def visit(node):
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and type(node.value) is int:
            if abs(node.value) <= 1000:
                return node.value
        if isinstance(node, ast.Name) and node.id in names and type(names[node.id]) is int:
            return names[node.id]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            return -visit(node.operand)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult)):
            left, right = visit(node.left), visit(node.right)
            result = (left + right if isinstance(node.op, ast.Add)
                      else left - right if isinstance(node.op, ast.Sub) else left * right)
            if abs(result) <= 1000000:
                return result
        raise ValueError("evaluation_rejected")

    return visit(tree)


class TrustedDAP:
    """Real local trace-controlled worker with strictly limited DAP requests."""

    def __init__(self, key):
        if not isinstance(key, bytes) or len(key) < 16:
            raise ValueError("private_hmac_key_required")
        self._key = key
        self._used_nonces = set()
        self._seq = 1
        self._initialize = False
        self._condition = threading.Condition()
        self._worker = None
        self._child = None
        self._paused = False
        self._finished = False
        self._terminate = False
        self._frame = None
        self._reason = None
        self._exception_type = None
        self._last_value = None
        self._step_mode = "entry"
        self._step_depth = 0
        self._started = False
        self._session_id = None
        self._fixture_mode = "normal"
        self._completed_result = None
        self._line_breakpoints = set()
        self._function_breakpoints = set()
        self._data_breakpoints = set()
        self._exception_breakpoints = set()
        self._scope_refs = {}
        self._variables_in_session = {}

    @property
    def session_id(self):
        return self._session_id

    def approval(self, action, nonce):
        """Operator-side expected token; secret is never sent to the DAP peer."""
        scope = "{}:{}".format(action, nonce)
        return hmac.new(self._key, scope.encode("ascii"), hashlib.sha256).hexdigest()

    def _authorized(self, args, action):
        nonce = args.get("nonce")
        token = args.get("approval")
        if (not isinstance(nonce, str) or SAFE_NONCE.fullmatch(nonce) is None
                or not isinstance(token, str) or SAFE_TOKEN.fullmatch(token) is None):
            return False
        if nonce in self._used_nonces:
            return False
        expected = self.approval(action, nonce)
        if not hmac.compare_digest(expected, token):
            return False
        self._used_nonces.add(nonce)
        return True

    def _reply(self, seq, command, success, body=None):
        answer = {"seq": self._seq, "type": "response", "request_seq": seq,
                  "command": command, "success": bool(success),
                  "body": body if success and body is not None else {}}
        self._seq += 1
        return answer

    def _event(self, name, body=None):
        answer = {"seq": self._seq, "type": "event", "event": name,
                  "body": body or {}}
        self._seq += 1
        return answer

    def _frames(self):
        current = self._frame
        frames = []
        while current is not None and len(frames) < MAX_STACK:
            if current.f_code.co_filename == TRUSTED_FILE:
                frames.append(current)
            current = current.f_back
        return frames

    def _variables(self, frame=None):
        result = {}
        if frame is None:
            frame = self._frame
        if frame is not None:
            for name in sorted(READ_SCOPES):
                if name in frame.f_locals:
                    result[name] = _safe_scalar(frame.f_locals[name])
            state = frame.f_globals.get("STATE")
            if isinstance(state, dict) and type(state.get("count")) is int:
                result["count"] = _safe_scalar(state["count"])
        return result

    def _depth(self, frame):
        depth = 0
        while frame is not None:
            if frame.f_code.co_filename == TRUSTED_FILE:
                depth += 1
            frame = frame.f_back
        return depth

    def _trace(self, frame, event, argument):
        if frame.f_code.co_filename != TRUSTED_FILE:
            return self._trace
        with self._condition:
            if self._terminate:
                raise _StopFixture()
            reason = None
            if event == "call" and frame.f_code.co_name in self._function_breakpoints:
                reason = "function breakpoint"
            if event == "exception" and "raised" in self._exception_breakpoints:
                reason = "exception"
                self._exception_type = type(argument[1]).__name__
            if event == "line":
                depth = self._depth(frame)
                if self._step_mode == "entry":
                    reason = "entry"
                elif frame.f_lineno in self._line_breakpoints:
                    reason = "breakpoint"
                elif self._step_mode == "stepIn":
                    reason = "step"
                elif self._step_mode == "next" and depth <= self._step_depth:
                    reason = "step"
                elif self._step_mode == "stepOut" and depth < self._step_depth:
                    reason = "step"
                state = frame.f_globals.get("STATE")
                if isinstance(state, dict) and type(state.get("count")) is int:
                    observed = state["count"]
                    if (self._last_value is not None and observed != self._last_value
                            and "count" in self._data_breakpoints):
                        reason = "data breakpoint"
                    self._last_value = observed
            if reason:
                self._frame = frame
                self._reason = reason
                self._paused = True
                self._step_mode = "continue"
                self._condition.notify_all()
                while self._paused and not self._terminate:
                    self._condition.wait(timeout=0.5)
                if self._terminate:
                    raise _StopFixture()
        return self._trace

    def _worker_main(self):
        try:
            source = TRUSTED_SOURCE if self._fixture_mode == "normal" else EXCEPTION_SOURCE
            scope = {"__name__": "__trusted_dap_fixture__"}
            sys.settrace(self._trace)
            exec(compile(source, TRUSTED_FILE, "exec", dont_inherit=True), scope)
            self._completed_result = scope.get("RESULT")
        except (_StopFixture, ValueError):
            pass
        finally:
            sys.settrace(None)
            with self._condition:
                self._finished = True
                self._paused = False
                self._frame = None
                self._condition.notify_all()

    def _start(self, mode, spawn_child=False):
        self._stop()
        with self._condition:
            self._finished = False
            self._terminate = False
            self._paused = False
            self._frame = None
            self._reason = None
            self._exception_type = None
            self._last_value = None
            self._completed_result = None
            self._step_mode = "entry"
            self._scope_refs.clear()
            self._variables_in_session.clear()
            self._fixture_mode = mode
            self._session_id = secrets.token_hex(12)
        if spawn_child:
            self._child = subprocess.Popen([
                sys.executable, "-I", "-S", "-B", "-c",
                "import threading; threading.Event().wait(4)"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
        self._worker = threading.Thread(target=self._worker_main,
                                        name="rph-trusted-dap-worker", daemon=True)
        self._worker.start()
        with self._condition:
            if not self._condition.wait_for(lambda: self._paused or self._finished,
                                            timeout=2):
                self._stop()
                raise RuntimeError("trusted_worker_no_pause")
            if not self._paused:
                raise RuntimeError("trusted_worker_exited_before_pause")

    def _stop(self):
        with self._condition:
            self._terminate = True
            self._paused = False
            self._condition.notify_all()
        if self._worker is not None:
            self._worker.join(timeout=2)
            self._worker = None
        if self._child is not None:
            if self._child.poll() is None:
                self._child.terminate()
            try:
                self._child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._child.kill()
                self._child.wait(timeout=2)
            self._child = None
        self._session_id = None

    def close(self):
        self._stop()

    def _stop_event(self):
        return self._event("stopped", {"reason": self._reason or "pause",
                                       "threadId": 1, "allThreadsStopped": True})

    def _resume(self, mode):
        with self._condition:
            if not self._paused or self._frame is None:
                return False
            self._step_depth = self._depth(self._frame)
            self._step_mode = mode
            self._paused = False
            self._condition.notify_all()
            if not self._condition.wait_for(lambda: self._paused or self._finished,
                                            timeout=2):
                self._terminate = True
                self._condition.notify_all()
                raise RuntimeError("trusted_worker_timeout")
        return True

    def _valid_session(self, args):
        return bool(self._session_id and args.get("sessionId") == self._session_id)

    def request(self, packet):
        """Process one real DAP request and return response plus possible events."""
        if (not isinstance(packet, dict) or packet.get("type") != "request"
                or type(packet.get("seq")) is not int
                or not 0 < packet["seq"] <= 0x7fffffff
                or not isinstance(packet.get("command"), str)
                or not 0 < len(packet["command"]) <= 64):
            raise ProtocolError("invalid_dap_request")
        command = packet["command"]
        seq = packet["seq"]
        args = packet.get("arguments", {})
        if not isinstance(args, dict):
            return [self._reply(seq, command, False)]
        if command == "initialize" and not self._initialize:
            if not isinstance(args.get("adapterID"), str) or not args["adapterID"]:
                return [self._reply(seq, command, False)]
            self._initialize = True
            cap = {"supportsConfigurationDoneRequest": True,
                   "supportsFunctionBreakpoints": True,
                   "supportsConditionalBreakpoints": False,
                   "supportsDataBreakpoints": True,
                   "supportsExceptionFilterOptions": False,
                   "supportsSetVariable": True,
                   "supportsRestartRequest": True,
                   "supportsTerminateRequest": True,
                   "supportsEvaluateForHovers": True,
                   "supportsStepBack": False}
            return [self._reply(seq, command, True, cap), self._event("initialized")]
        if not self._initialize:
            return [self._reply(seq, command, False)]
        if command in ("setBreakpoints", "setFunctionBreakpoints", "setDataBreakpoints",
                       "setExceptionBreakpoints"):
            if command == "setBreakpoints":
                source = args.get("source", {})
                if not isinstance(source, dict) or source.get("path") != TRUSTED_FILE:
                    return [self._reply(seq, command, False)]
                points = args.get("breakpoints", [])
                if (not isinstance(points, list) or len(points) > 30
                        or any(not isinstance(x, dict) or type(x.get("line")) is not int
                               for x in points)):
                    return [self._reply(seq, command, False)]
                valid = {x["line"] for x in points if 1 <= x["line"] <= len(TRUSTED_SOURCE.splitlines())}
                self._line_breakpoints = valid
                return [self._reply(seq, command, True, {"breakpoints": [
                    {"verified": x["line"] in valid, "line": x["line"]} for x in points]})]
            if command == "setFunctionBreakpoints":
                points = args.get("breakpoints", [])
                if not isinstance(points, list) or len(points) > 8:
                    return [self._reply(seq, command, False)]
                names = [x.get("name") for x in points if isinstance(x, dict)]
                if len(names) != len(points) or any(not isinstance(x, str) for x in names):
                    return [self._reply(seq, command, False)]
                self._function_breakpoints = {x for x in names if x == "compute"}
                return [self._reply(seq, command, True, {"breakpoints": [
                    {"verified": x == "compute"} for x in names]})]
            if command == "setDataBreakpoints":
                points = args.get("breakpoints", [])
                if not isinstance(points, list) or len(points) > 8:
                    return [self._reply(seq, command, False)]
                names = [x.get("dataId") for x in points if isinstance(x, dict)]
                if len(names) != len(points):
                    return [self._reply(seq, command, False)]
                self._data_breakpoints = {x for x in names if x == "count"}
                return [self._reply(seq, command, True, {"breakpoints": [
                    {"verified": x == "count"} for x in names]})]
            filters = args.get("filters", [])
            if not isinstance(filters, list) or any(x != "raised" for x in filters):
                return [self._reply(seq, command, False)]
            self._exception_breakpoints = set(filters)
            return [self._reply(seq, command, True)]
        if command == "dataBreakpointInfo":
            if args.get("name") != "count":
                return [self._reply(seq, command, False)]
            return [self._reply(seq, command, True,
                                {"dataId": "count", "accessTypes": ["write"],
                                 "canPersist": False})]
        if command == "launch":
            if self._session_id is not None or args.get("fixture") != "rph-trusted-v22":
                return [self._reply(seq, command, False)]
            if set(args) - {"fixture", "nonce", "approval", "mode", "spawnChild"}:
                return [self._reply(seq, command, False)]
            if args.get("mode", "normal") not in ("normal", "exception"):
                return [self._reply(seq, command, False)]
            if type(args.get("spawnChild", False)) is not bool:
                return [self._reply(seq, command, False)]
            if not self._authorized(args, "launch"):
                return [self._reply(seq, command, False)]
            self._start(args.get("mode", "normal"), args.get("spawnChild", False))
            return [self._reply(seq, command, True,
                                {"sessionId": self._session_id,
                                 "trustedFixtureOnly": True}),
                    self._event("output", {"category": "console",
                                           "output": "trusted fixture started"}),
                    self._stop_event()]
        if command == "attach":
            if not self._valid_session(args) or not self._authorized(
                    args, "attach:" + self._session_id):
                return [self._reply(seq, command, False)]
            return [self._reply(seq, command, True,
                                {"attachedToOwnTrustedWorker": True}),
                    self._stop_event()] if self._paused else [self._reply(seq, command, True)]
        if command in ("disconnect", "terminate"):
            if not self._valid_session(args) or not self._authorized(
                    args, command + ":" + self._session_id):
                return [self._reply(seq, command, False)]
            self._stop()
            return [self._reply(seq, command, True), self._event("terminated")]
        if command == "restart":
            if not self._valid_session(args) or not self._authorized(
                    args, "restart:" + self._session_id):
                return [self._reply(seq, command, False)]
            mode = self._fixture_mode
            self._start(mode)
            return [self._reply(seq, command, True,
                                {"sessionId": self._session_id}),
                    self._event("terminated"), self._stop_event()]
        if command == "threads":
            if self._session_id is None:
                return [self._reply(seq, command, False)]
            return [self._reply(seq, command, True, {"threads": [
                {"id": 1, "name": "real trusted worker"}]
                if self._worker and self._worker.is_alive() else []})]
        if command == "processes":
            if self._session_id is None:
                return [self._reply(seq, command, False)]
            procs = [{"id": os.getpid(), "name": "trusted DAP host", "kind": "host"}]
            if self._child is not None and self._child.poll() is None:
                procs.append({"id": self._child.pid, "name": "fixed trusted child",
                              "kind": "child"})
            return [self._reply(seq, command, True, {"processes": procs})]
        if command == "stackTrace":
            if not self._paused:
                return [self._reply(seq, command, False)]
            frames = [{"id": 100 + n, "name": f.f_code.co_name,
                       "line": f.f_lineno,
                       "source": {"name": "trusted DAP fixture", "path": TRUSTED_FILE}}
                      for n, f in enumerate(self._frames())]
            return [self._reply(seq, command, True, {"stackFrames": frames,
                                                     "totalFrames": len(frames)})]
        if command == "scopes":
            if (not self._paused or type(args.get("frameId")) is not int
                    or not 100 <= args["frameId"] < 100 + len(self._frames())):
                return [self._reply(seq, command, False)]
            return [self._reply(seq, command, True, {"scopes": [
                {"name": "allowlisted scalars", "variablesReference": args["frameId"] - 99,
                 "expensive": False}]})]
        if command == "variables":
            reference = args.get("variablesReference")
            frames = self._frames()
            if (not self._paused or type(reference) is not int
                    or not 1 <= reference <= len(frames)):
                return [self._reply(seq, command, False)]
            return [self._reply(seq, command, True, {"variables": [
                {"name": name, "value": str(value), "type": type(value).__name__,
                 "variablesReference": 0} for name, value in self._variables(
                     frames[reference - 1]).items()]})]
        if command == "evaluate":
            if not self._paused or not self._valid_session(args) or not self._authorized(
                    args, "evaluate:" + self._session_id):
                return [self._reply(seq, command, False)]
            try:
                result = _trusted_eval(args.get("expression"), self._variables())
            except (ValueError, SyntaxError, TypeError, OverflowError):
                return [self._reply(seq, command, False)]
            return [self._reply(seq, command, True,
                                {"result": str(result), "variablesReference": 0})]
        if command == "setVariable":
            if not self._paused or not self._valid_session(args) or not self._authorized(
                    args, "mutate:" + self._session_id):
                return [self._reply(seq, command, False)]
            value = args.get("value")
            frame = self._frame
            state = frame.f_globals.get("STATE") if frame else None
            if (args.get("variablesReference") != 1 or args.get("name") != "count"
                    or not isinstance(value, str) or re.fullmatch(r"\d{1,2}", value) is None
                    or not isinstance(state, dict)):
                return [self._reply(seq, command, False)]
            state["count"] = int(value)
            self._last_value = int(value)
            return [self._reply(seq, command, True, {"value": value,
                                                     "variablesReference": 0})]
        if command in ("continue", "stepIn", "next", "stepOut"):
            if not self._valid_session(args):
                return [self._reply(seq, command, False)]
            if not self._resume(command):
                return [self._reply(seq, command, False)]
            outputs = [self._reply(seq, command, True),
                       self._event("continued", {"threadId": 1,
                                                  "allThreadsContinued": True})]
            if self._paused:
                outputs.append(self._stop_event())
            else:
                output = "trusted fixture completed"
                if type(self._completed_result) is int:
                    output += ": {}".format(self._completed_result)
                outputs.append(self._event("output", {"category": "console",
                                                       "output": output}))
                outputs.append(self._event("terminated"))
            return outputs
        if command == "configurationDone":
            return [self._reply(seq, command, True)]
        return [self._reply(seq, command, False)]


def serve(reader, writer, secret_key):
    server = TrustedDAP(secret_key)
    try:
        for _ in range(MAX_REQUESTS):
            packet = read_frame(reader)
            if packet is None:
                return
            for reply in server.request(packet):
                write_frame(writer, reply)
        raise ProtocolError("request_limit")
    finally:
        server.close()


def trusted_selftest():
    """JSON smoke contract for Rust `lab`; it has NO external DAP authority."""
    server = TrustedDAP(b"TEST_ONLY_PUBLIC_FIXED_FIXTURE_KEY_0001")
    try:
        initialized = server.request({"seq": 1, "type": "request", "command": "initialize",
                                      "arguments": {"adapterID": "rph-local-selftest"}})
        if len(initialized) != 2 or not initialized[0]["success"]:
            raise ValueError("trusted_dap_initialization_failed")
        configured = server.request({"seq": 2, "type": "request", "command": "setBreakpoints",
                                     "arguments": {"source": {"path": TRUSTED_FILE},
                                                   "breakpoints": [{"line": 5}]}})
        if not configured[0]["success"]:
            raise ValueError("trusted_breakpoint_setup_failed")
        nonce = "trustedselftest001"
        launch = server.request({"seq": 3, "type": "request", "command": "launch",
                                 "arguments": {"fixture": "rph-trusted-v22", "nonce": nonce,
                                               "approval": server.approval("launch", nonce)}})
        if not launch[0]["success"] or launch[-1].get("event") != "stopped":
            raise ValueError("trusted_launch_failed")
        session = launch[0]["body"]["sessionId"]
        stack = server.request({"seq": 4, "type": "request", "command": "stackTrace"})
        if not stack[0]["body"].get("stackFrames"):
            raise ValueError("trusted_stack_missing")
        stopped = server.request({"seq": 5, "type": "request", "command": "continue",
                                  "arguments": {"sessionId": session}})
        if stopped[-1].get("event") != "stopped" or server._frame.f_lineno != 5:
            raise ValueError("trusted_breakpoint_not_observed")
        final = server.request({"seq": 6, "type": "request", "command": "continue",
                                "arguments": {"sessionId": session}})
        if final[-1].get("event") != "terminated" or server._completed_result != 9:
            raise ValueError("trusted_result_not_observed")
        return {"status": "TRUSTED_DAP_REAL_FRAMED_FIXTURE_PASS",
                "fixed_fixture_only": True,
                "observed_real_trace_line": 5,
                "result_from_actual_trusted_execution": 9,
                "dap_events": ["initialized", "stopped", "continued", "output", "terminated"],
                "unknown_source_executed": False,
                "external_dap_client_conformance_verified": False,
                "external_attach_authorized": False}
    finally:
        server.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-file", type=Path)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.selftest:
            if args.key_file is not None:
                raise ValueError("no_operator_key_in_fixed_fixture_selftest")
            print(json.dumps(trusted_selftest(), sort_keys=True))
            return 0
        if args.key_file is None:
            raise ValueError("private_key_file_required")
        info = args.key_file.lstat()
        if not stat.S_ISREG(info.st_mode) or (os.name != "nt" and info.st_mode & 0o077) or info.st_nlink != 1:
            raise ValueError("private_key_file_required")
        if os.name == "nt":
            privacy = _windows_key_privacy()
            fd = privacy.open_private_readonly(args.key_file)
        else:
            fd = os.open(str(args.key_file), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (info.st_dev, info.st_ino, info.st_size) != (opened.st_dev, opened.st_ino, opened.st_size):
                raise ValueError("private_key_changed_before_read")
            key = stream.read(65)
            after = os.fstat(stream.fileno())
            if os.name == "nt":
                privacy.assert_private_file_descriptor(stream.fileno())
            if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise ValueError("private_key_changed_during_read")
        if len(key) < 16 or len(key) > 64:
            raise ValueError("invalid_key_length")
        serve(sys.stdin.buffer, sys.stdout.buffer, key)
    except (OSError, ValueError, ProtocolError):
        return 2
    return 0


def _windows_key_privacy():
    embedded = globals().get("_RPH_WINDOWS_PRIVACY")
    if embedded is not None:
        return embedded
    import importlib.util
    module_path = Path(__file__).resolve().with_name("windows_private_paths.py")
    spec = importlib.util.spec_from_file_location("rph_dap_windows_privacy", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    globals()["_RPH_WINDOWS_PRIVACY"] = module
    return module


if __name__ == "__main__":
    raise SystemExit(main())
