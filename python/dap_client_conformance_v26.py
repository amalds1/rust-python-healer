"""Independent, bounded DAP *client* exercising only the trusted local adapter.

This is NOT a VS Code/PyCharm test or a production DAP certification. It
launches the repository's fixed trusted fixture, never arbitrary project code.
Every socket-free stdio request, response, event and HMAC gate is real.
"""

import argparse
import hashlib
import hmac
import json
import os
import secrets
import selectors
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TRUSTED_ADAPTER = ROOT / "python" / "dap_runtime_v22.py"
MAX_HEADER = 4096
MAX_BODY = 65536
MAX_RESPONSE_SECONDS = 4.0
MAX_FRAMES_PER_REQUEST = 6


class ClientProtocolError(ValueError):
    """Untrusted or invalid adapter output; never interpreted as success."""


def _unique_object(pairs):
    obj = {}
    for name, value in pairs:
        if name in obj:
            raise ClientProtocolError("duplicate_adapter_json_key")
        obj[name] = value
    return obj


def decode_framed_packet(raw):
    """Consume at most one bounded DAP frame, return packet and byte count."""
    if not isinstance(raw, (bytes, bytearray)):
        raise ClientProtocolError("binary_frame_required")
    divider = raw.find(b"\r\n\r\n")
    if divider < 0:
        if len(raw) > MAX_HEADER:
            raise ClientProtocolError("adapter_header_quota")
        return None
    if divider > MAX_HEADER:
        raise ClientProtocolError("adapter_header_quota")
    length = None
    for line in raw[:divider].split(b"\r\n"):
        if b": " not in line:
            raise ClientProtocolError("malformed_adapter_header")
        name, value = line.split(b": ", 1)
        if name.lower() == b"content-length":
            if length is not None or not value or any(c not in b"0123456789" for c in value):
                raise ClientProtocolError("duplicate_or_invalid_adapter_length")
            length = int(value)
        elif name.lower() == b"content-type":
            if value.lower().replace(b" ", b"") not in (
                    b"application/vscode-jsonrpc",
                    b"application/vscode-jsonrpc;charset=utf-8"):
                raise ClientProtocolError("unsupported_adapter_content_type")
        else:
            raise ClientProtocolError("unexpected_adapter_header")
    if length is None or not 0 < length <= MAX_BODY:
        raise ClientProtocolError("missing_or_oversized_adapter_body")
    offset = divider + 4
    if len(raw) < offset + length:
        return None
    try:
        packet = json.loads(bytes(raw[offset:offset + length]).decode("utf-8"),
                            object_pairs_hook=_unique_object,
                            parse_constant=lambda _: (_ for _ in ()).throw(
                                ClientProtocolError("non_json_adapter_number")))
    except (UnicodeError, ValueError) as exc:
        raise ClientProtocolError("untrusted_adapter_json") from exc
    if not isinstance(packet, dict) or type(packet.get("seq")) is not int or \
            packet.get("type") not in ("response", "event"):
        raise ClientProtocolError("invalid_adapter_packet_shape")
    return packet, offset + length


def frame_request(packet):
    if not isinstance(packet, dict):
        raise ClientProtocolError("request_object_required")
    payload = json.dumps(packet, sort_keys=True, separators=(",", ":"),
                         allow_nan=False, ensure_ascii=True).encode("ascii")
    if not 0 < len(payload) <= MAX_BODY:
        raise ClientProtocolError("request_body_quota")
    return b"Content-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload


def _windows_pipe_bytes(stream, maximum):
    """Read only currently available bytes from our own anonymous pipe HANDLE.

    select() supports sockets on Windows, not subprocess pipes. PeekNamedPipe
    avoids an unbounded blocking read and does not create reader threads.
    Only this client owns and consumes this stdout pipe.
    """
    import ctypes
    from ctypes import wintypes
    import msvcrt
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.PeekNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                    ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
                                    ctypes.c_void_p]
    kernel.PeekNamedPipe.restype = wintypes.BOOL
    available = wintypes.DWORD()
    handle = msvcrt.get_osfhandle(stream.fileno())
    if not kernel.PeekNamedPipe(handle, None, 0, None, ctypes.byref(available), None):
        if ctypes.get_last_error() in (109, 233):
            return b""
        raise ClientProtocolError("adapter_windows_pipe_probe_failed")
    if not available.value:
        return None
    try:
        return os.read(stream.fileno(), min(maximum, available.value))
    except OSError as exc:
        raise ClientProtocolError("adapter_windows_pipe_read_failed") from exc


class FixedFixtureClient:
    """Independent wire client: no library functions imported from adapter."""

    def __init__(self):
        self._temp = None
        self._proc = None
        self._selector = None
        self._key = None
        self._buffer = bytearray()
        self._request_number = 0
        self._last_adapter_seq = 0
        self.events = []
        self.request_count = 0

    def __enter__(self):
        self._temp = tempfile.TemporaryDirectory(prefix="rph-dap-client-")
        self._key = secrets.token_bytes(32)
        keypath = Path(self._temp.name) / "approval.key"
        fd = os.open(str(keypath), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(self._key)
        self._proc = subprocess.Popen([
            sys.executable, "-I", "-S", "-B", str(TRUSTED_ADAPTER),
            "--key-file", str(keypath)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        if os.name != "nt":
            self._selector = selectors.DefaultSelector()
            self._selector.register(self._proc.stdout, selectors.EVENT_READ)
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        if self._selector is not None:
            self._selector.close()
        if self._proc is not None:
            if self._proc.stdin is not None:
                self._proc.stdin.close()
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    self._proc.wait(timeout=2)
            if self._proc.stdout is not None:
                self._proc.stdout.close()
        if self._temp is not None:
            self._temp.cleanup()
        self._key = None

    def approval(self, scope, nonce):
        if not isinstance(scope, str) or not isinstance(nonce, str):
            raise ValueError("approval_scope_required")
        return hmac.new(self._key, (scope + ":" + nonce).encode("ascii"),
                        hashlib.sha256).hexdigest()

    def _read(self):
        deadline = time.monotonic() + MAX_RESPONSE_SECONDS
        while time.monotonic() < deadline:
            decoded = decode_framed_packet(self._buffer)
            if decoded is not None:
                packet, consumed = decoded
                del self._buffer[:consumed]
                if packet["seq"] <= self._last_adapter_seq:
                    raise ClientProtocolError("non_monotonic_adapter_sequence")
                self._last_adapter_seq = packet["seq"]
                if any(token in json.dumps(packet) for token in (
                        "PRIVATE_NEVER_EXPOSE", "PRIVATE_EXCEPTION_MESSAGE")):
                    raise ClientProtocolError("adapter_exposed_private_fixture_data")
                return packet
            if os.name == "nt":
                data = _windows_pipe_bytes(self._proc.stdout, 4096)
                if data is None:
                    if self._proc.poll() is not None:
                        raise ClientProtocolError("adapter_closed_before_response")
                    time.sleep(min(0.01, max(0, deadline - time.monotonic())))
                    continue
            else:
                ready = self._selector.select(timeout=max(0, deadline - time.monotonic()))
                if not ready:
                    continue
                data = os.read(self._proc.stdout.fileno(), 4096)
            if not data:
                raise ClientProtocolError("adapter_closed_before_response")
            self._buffer.extend(data)
            if len(self._buffer) > MAX_HEADER + MAX_BODY * MAX_FRAMES_PER_REQUEST:
                raise ClientProtocolError("adapter_output_buffer_quota")
        raise ClientProtocolError("adapter_response_deadline")

    def request(self, command, arguments=None, event_names=()):
        if type(command) is not str or len(command) > 64:
            raise ClientProtocolError("invalid_client_command")
        self._request_number += 1
        number = self._request_number
        self._proc.stdin.write(frame_request({"seq": number, "type": "request",
                                             "command": command,
                                             "arguments": arguments or {}}))
        self._proc.stdin.flush()
        answer = self._read()
        if (answer.get("type") != "response" or answer.get("request_seq") != number
                or answer.get("command") != command or type(answer.get("success")) is not bool):
            raise ClientProtocolError("request_response_correlation_failed")
        observations = []
        for name in event_names:
            event = self._read()
            if event.get("type") != "event" or event.get("event") != name:
                raise ClientProtocolError("unexpected_adapter_event_order")
            observations.append(event)
            self.events.append(name)
        self.request_count += 1
        return answer, observations


def run_trusted_wire_oracle():
    """Operate a real subprocess, check a fixed DAP transcript and hard gates."""
    with FixedFixtureClient() as client:
        init, initialized = client.request("initialize", {
            "adapterID": "rust-python-healer-v26-local-conformance"}, ("initialized",))
        caps = init["body"]
        if not init["success"] or not caps.get("supportsDataBreakpoints") or \
                caps.get("supportsStepBack") is not False:
            raise ClientProtocolError("invalid_initialized_capabilities")
        points, _ = client.request("setBreakpoints", {
            "source": {"path": "<rph-v22-trusted-dap-fixture>"},
            "breakpoints": [{"line": 5}]})
        if not points["success"] or points["body"]["breakpoints"][0]["verified"] is not True:
            raise ClientProtocolError("trusted_breakpoint_not_verified")
        denied, _ = client.request("launch", {"fixture": "rph-trusted-v22",
                                              "nonce": "clientinvalid0001",
                                              "approval": "0" * 64})
        if denied["success"]:
            raise ClientProtocolError("unauthorized_launch_accepted")
        nonce = "clientlaunch0001"
        launched, launch_events = client.request("launch", {
            "fixture": "rph-trusted-v22", "nonce": nonce,
            "approval": client.approval("launch", nonce)}, ("output", "stopped"))
        if not launched["success"] or launch_events[-1]["body"].get("reason") != "entry":
            raise ClientProtocolError("trusted_launch_or_entry_not_observed")
        session_id = launched["body"]["sessionId"]
        stack, _ = client.request("stackTrace")
        if not stack["success"] or not stack["body"].get("stackFrames"):
            raise ClientProtocolError("stack_trace_missing")
        frame_id = stack["body"]["stackFrames"][0]["id"]
        scopes, _ = client.request("scopes", {"frameId": frame_id})
        if not scopes["success"] or not scopes["body"].get("scopes"):
            raise ClientProtocolError("scopes_missing")
        variables, _ = client.request("variables", {"variablesReference": 1})
        if not variables["success"]:
            raise ClientProtocolError("variables_missing")
        unauthorized_eval, _ = client.request("evaluate", {
            "sessionId": session_id, "expression": "count + 1"})
        if unauthorized_eval["success"]:
            raise ClientProtocolError("unauthorized_evaluation_accepted")
        unauthorized_set, _ = client.request("setVariable", {
            "sessionId": session_id, "variablesReference": 1,
            "name": "count", "value": "5"})
        if unauthorized_set["success"]:
            raise ClientProtocolError("unauthorized_mutation_accepted")
        stepped, observed = client.request("continue", {"sessionId": session_id},
                                          ("continued", "stopped"))
        if not stepped["success"] or observed[-1]["body"].get("reason") != "breakpoint":
            raise ClientProtocolError("actual_line_breakpoint_not_observed")
        if stack["body"]["stackFrames"][0]["source"]["path"] != \
                "<rph-v22-trusted-dap-fixture>":
            raise ClientProtocolError("untrusted_source_returned")
        finished, finish_events = client.request("continue", {"sessionId": session_id},
                                                ("continued", "output", "terminated"))
        if not finished["success"] or \
                "trusted fixture completed: 9" not in finish_events[1]["body"]["output"]:
            raise ClientProtocolError("trusted_runtime_outcome_mismatch")
        return {"status": "LOCAL_TRUSTED_DAP_FRAMED_CLIENT_PASS",
                "python_minor": "{}.{}".format(*sys.version_info[:2]),
                "local_client_requests": client.request_count,
                "actual_stdio_frames": client.request_count + len(client.events),
                "actual_event_names": list(client.events),
                "real_trusted_runtime_result": 9,
                "operator_hmac_enforced": True,
                "unknown_project_code_executed": False,
                "external_vscode_client_executed": False,
                "external_pycharm_client_executed": False,
                "external_client_conformance_verified": False}


def run_negative_frames():
    """Three fresh subprocesses prove malformed requests exit nonzero."""
    variants = {
        "duplicate_length": b"Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
        "invalid_json_duplicates": (
            b"Content-Length: 13\r\n\r\n" + b'{"x":1,"x":2}'),
        "oversized_length": b"Content-Length: 999999\r\n\r\n",
    }
    outcomes = {}
    for name, raw in variants.items():
        with tempfile.TemporaryDirectory(prefix="rph-dap-negative-") as dirname:
            keypath = Path(dirname) / "key"
            fd = os.open(str(keypath), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(secrets.token_bytes(32))
            completed = subprocess.run([sys.executable, "-I", "-S", "-B",
                                        str(TRUSTED_ADAPTER), "--key-file", str(keypath)],
                                       input=raw, capture_output=True, timeout=6,
                                       check=False)
        if completed.returncode != 2 or completed.stdout:
            raise ClientProtocolError("malformed_adapter_input_not_fail_closed")
        outcomes[name] = "PASS"
    return {"status": "LOCAL_TRUSTED_DAP_NEGATIVE_FRAMES_PASS",
            "negative_frame_outcomes": outcomes,
            "unknown_project_code_executed": False,
            "external_client_conformance_verified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("selftest", "negatives", "capabilities"),
                        default="capabilities")
    args = parser.parse_args(argv)
    try:
        if args.mode == "selftest":
            result = run_trusted_wire_oracle()
        elif args.mode == "negatives":
            result = run_negative_frames()
        else:
            result = {"status": "LOCAL_TRUSTED_DAP_CLIENT_PROBE_AVAILABLE",
                      "local_v22_adapter_only": True,
                      "external_client_conformance_verified": False}
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result = {"status": "NOT_RUN_OR_FAILED_DAP_CLIENT_PROBE",
                  "error_type": type(exc).__name__,
                  "external_client_conformance_verified": False}
        print(json.dumps(result, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
