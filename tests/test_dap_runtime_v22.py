"""Cross-minor real trusted trace/DAP test protocol, positive and adversarial."""

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "dap_runtime_v22.py"
SPEC = importlib.util.spec_from_file_location("dap_runtime_v22", SCRIPT)
dap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dap)


class DAPTests(unittest.TestCase):
    def setUp(self):
        self.key = b"trusted-dap-only-operator-approval-key-123"
        self.server = dap.TrustedDAP(self.key)
        self.addCleanup(self.server.close)
        self.sequence = 0
        self.nonce_count = 0

    def call(self, command, arguments=None):
        self.sequence += 1
        return self.server.request({"seq": self.sequence, "type": "request",
                                    "command": command,
                                    "arguments": arguments or {}})

    def nonce(self):
        self.nonce_count += 1
        return "testnonce{:06d}".format(self.nonce_count)

    def permitted(self, action, **kwargs):
        nonce = self.nonce()
        return dict(kwargs, nonce=nonce, approval=self.server.approval(action, nonce))

    def initialize(self):
        result = self.call("initialize", {"adapterID": "rust-python-healer"})
        self.assertEqual([x["type"] for x in result], ["response", "event"])
        self.assertTrue(result[0]["success"])
        self.assertEqual(result[1]["event"], "initialized")
        return result

    def launch(self, **kwargs):
        self.initialize()
        results = self.call("launch", self.permitted("launch", fixture="rph-trusted-v22",
                                                       **kwargs))
        self.assertTrue(results[0]["success"], results)
        self.assertEqual(results[-1]["event"], "stopped")
        self.assertEqual(results[-1]["body"]["reason"], "entry")
        return results[0]["body"]["sessionId"]

    def test_really_paused_trace_execution_at_entry(self):
        self.launch()
        self.assertTrue(self.server._paused)
        self.assertTrue(self.server._worker.is_alive())
        self.assertEqual(self.server._frame.f_code.co_filename, dap.TRUSTED_FILE)
        self.assertIsNone(self.server._completed_result)

    def test_initialize_claims_only_implemented_capabilities(self):
        capabilities = self.initialize()[0]["body"]
        self.assertTrue(capabilities["supportsFunctionBreakpoints"])
        self.assertTrue(capabilities["supportsDataBreakpoints"])
        self.assertTrue(capabilities["supportsSetVariable"])
        self.assertFalse(capabilities["supportsStepBack"])
        self.assertFalse(capabilities["supportsConditionalBreakpoints"])

    def test_denies_launch_before_init_and_wrong_operator_hmac(self):
        denied = self.call("launch", {"fixture": "rph-trusted-v22"})
        self.assertFalse(denied[0]["success"])
        self.initialize()
        denied = self.call("launch", {"fixture": "rph-trusted-v22",
                                      "nonce": "secret0001", "approval": "0" * 64})
        self.assertFalse(denied[0]["success"])
        self.assertIsNone(self.server._worker)

    def test_denies_unknown_project_program_source_and_env(self):
        self.initialize()
        for key in ("program", "source", "cwd", "env", "args"):
            args = self.permitted("launch", fixture="rph-trusted-v22",
                                  **{key: "/tmp/private_unknown_project.py"})
            self.assertFalse(self.call("launch", args)[0]["success"])
        self.assertIsNone(self.server._worker)

    def test_nonreplayable_hmac_launch_nonce(self):
        self.initialize()
        auth = self.permitted("launch", fixture="rph-trusted-v22")
        self.assertTrue(self.call("launch", auth)[0]["success"])
        self.server.close()
        self.assertFalse(self.call("launch", auth)[0]["success"])

    def test_attach_requires_owned_session_and_scope(self):
        session = self.launch()
        bad = self.permitted("attach:some-other", sessionId=session)
        self.assertFalse(self.call("attach", bad)[0]["success"])
        ok = self.permitted("attach:" + session, sessionId=session)
        result = self.call("attach", ok)
        self.assertTrue(result[0]["success"])
        self.assertEqual(result[-1]["event"], "stopped")
        self.assertFalse(self.call("attach", ok)[0]["success"])

    def test_detach_is_scoped_and_terminates_worker(self):
        session = self.launch()
        self.assertFalse(self.call("disconnect", self.permitted("disconnect:wrong",
                                            sessionId=session))[0]["success"])
        result = self.call("disconnect", self.permitted("disconnect:" + session,
                                            sessionId=session))
        self.assertTrue(result[0]["success"])
        self.assertEqual(result[-1]["event"], "terminated")
        self.assertIsNone(self.server._worker)

    def test_terminate_requires_capability_and_closes_trusted_processes(self):
        session = self.launch(spawnChild=True)
        child = self.server._child
        self.assertIsNotNone(child)
        self.assertIsNone(child.poll())
        self.assertFalse(self.call("terminate", {"sessionId": session})[0]["success"])
        result = self.call("terminate", self.permitted("terminate:" + session,
                                                        sessionId=session))
        self.assertTrue(result[0]["success"])
        self.assertEqual(result[1]["event"], "terminated")
        self.assertIsNotNone(child.poll())

    def test_real_host_process_child_process_and_thread_enumeration(self):
        self.launch(spawnChild=True)
        threads = self.call("threads")[0]["body"]["threads"]
        self.assertEqual(len(threads), 1)
        self.assertEqual(threads[0]["id"], 1)
        self.assertTrue(self.server._worker.is_alive())
        processes = self.call("processes")[0]["body"]["processes"]
        self.assertEqual(processes[0]["id"], os.getpid())
        self.assertEqual(processes[1]["id"], self.server._child.pid)
        self.assertEqual(processes[1]["kind"], "child")

    def test_real_line_breakpoint_pauses_at_compiled_line(self):
        self.initialize()
        self.assertTrue(self.call("setBreakpoints", {"source": {"path": dap.TRUSTED_FILE},
                                  "breakpoints": [{"line": 5}]})[0]["success"])
        launched = self.call("launch", self.permitted("launch", fixture="rph-trusted-v22"))
        session = launched[0]["body"]["sessionId"]
        resumed = self.call("continue", {"sessionId": session})
        self.assertEqual([x["event"] for x in resumed[1:]], ["continued", "stopped"])
        self.assertEqual(resumed[-1]["body"]["reason"], "breakpoint")
        self.assertEqual(self.server._frame.f_lineno, 5)

    def test_function_breakpoints_are_real_trace_call_events(self):
        self.initialize()
        result = self.call("setFunctionBreakpoints", {"breakpoints": [
            {"name": "compute"}, {"name": "unknown"}]})
        self.assertEqual([x["verified"] for x in result[0]["body"]["breakpoints"]],
                         [True, False])
        launched = self.call("launch", self.permitted("launch", fixture="rph-trusted-v22"))
        session = launched[0]["body"]["sessionId"]
        next_event = self.call("continue", {"sessionId": session})[-1]
        self.assertEqual(next_event["body"]["reason"], "function breakpoint")
        self.assertEqual(self.server._frame.f_code.co_name, "compute")

    def test_real_data_breakpoint_observes_scalar_write(self):
        self.initialize()
        self.assertEqual(self.call("dataBreakpointInfo", {"name": "count"})[0]["body"]["dataId"],
                         "count")
        self.assertTrue(self.call("setDataBreakpoints", {"breakpoints": [
            {"dataId": "count"}]})[0]["success"])
        launched = self.call("launch", self.permitted("launch", fixture="rph-trusted-v22"))
        session = launched[0]["body"]["sessionId"]
        next_event = self.call("continue", {"sessionId": session})[-1]
        self.assertEqual(next_event["body"]["reason"], "data breakpoint")
        self.assertEqual(self.server._variables()["count"], 3)

    def test_exception_breakpoint_stops_on_actual_exception(self):
        self.initialize()
        self.assertTrue(self.call("setExceptionBreakpoints", {"filters": ["raised"]})[0]["success"])
        launched = self.call("launch", self.permitted("launch", fixture="rph-trusted-v22",
                                                    mode="exception"))
        session = launched[0]["body"]["sessionId"]
        next_event = self.call("continue", {"sessionId": session})[-1]
        self.assertEqual(next_event["body"]["reason"], "exception")
        self.assertEqual(self.server._exception_type, "ValueError")
        self.assertNotIn("PRIVATE", json.dumps(next_event))

    def test_stacktrace_scopes_and_variables_redact_private_data(self):
        session = self.launch()
        self.assertTrue(session)
        self.assertFalse(self.call("scopes", {"frameId": 999})[0]["success"])
        stack = self.call("stackTrace")[0]["body"]["stackFrames"]
        self.assertTrue(stack)
        self.assertEqual(stack[0]["source"]["path"], dap.TRUSTED_FILE)
        scopes = self.call("scopes", {"frameId": stack[0]["id"]})[0]["body"]["scopes"]
        self.assertEqual(scopes[0]["variablesReference"], 1)
        variables = self.call("variables", {"variablesReference": 1})[0]["body"]["variables"]
        self.assertNotIn("PRIVATE", json.dumps([stack, scopes, variables]))
        self.assertNotIn("SECRET", json.dumps([stack, scopes, variables]))

    def test_frame_specific_scopes_read_real_distinct_locals(self):
        self.initialize()
        self.call("setBreakpoints", {"source": {"path": dap.TRUSTED_FILE},
                                     "breakpoints": [{"line": 5}]})
        launched = self.call("launch", self.permitted("launch", fixture="rph-trusted-v22"))
        session = launched[0]["body"]["sessionId"]
        self.call("continue", {"sessionId": session})
        frames = self.call("stackTrace")[0]["body"]["stackFrames"]
        self.assertEqual([f["name"] for f in frames[:2]], ["compute", "<module>"])
        references = [self.call("scopes", {"frameId": f["id"]})[0]["body"]
                      ["scopes"][0]["variablesReference"] for f in frames[:2]]
        self.assertEqual(references, [1, 2])
        inside = {x["name"] for x in self.call("variables", {
            "variablesReference": references[0]})[0]["body"]["variables"]}
        module = {x["name"] for x in self.call("variables", {
            "variablesReference": references[1]})[0]["body"]["variables"]}
        self.assertIn("a", inside)
        self.assertNotIn("a", module)
        self.assertIn("count", inside)
        self.assertIn("count", module)

    def test_read_evaluate_and_write_variable_require_separate_capabilities(self):
        self.initialize()
        self.call("setBreakpoints", {"source": {"path": dap.TRUSTED_FILE},
                                     "breakpoints": [{"line": 4}]})
        launched = self.call("launch", self.permitted("launch", fixture="rph-trusted-v22"))
        session = launched[0]["body"]["sessionId"]
        self.assertEqual(self.call("continue", {"sessionId": session})[-1]["event"], "stopped")
        args = {"sessionId": session, "expression": "count + 1"}
        self.assertFalse(self.call("evaluate", args)[0]["success"])
        self.assertFalse(self.call("setVariable", {"sessionId": session,
                          "variablesReference": 1, "name": "count", "value": "5"})[0]["success"])
        self.assertEqual(self.call("evaluate", self.permitted("evaluate:" + session,
                         **args))[0]["body"]["result"], "2")
        changed = self.call("setVariable", self.permitted("mutate:" + session,
                       sessionId=session, variablesReference=1,
                       name="count", value="5"))
        self.assertTrue(changed[0]["success"])
        self.assertEqual(self.server._variables()["count"], 5)

    def test_authorized_scalar_mutation_changes_actual_fixture_result(self):
        self.initialize()
        self.call("setBreakpoints", {"source": {"path": dap.TRUSTED_FILE},
                                     "breakpoints": [{"line": 4}]})
        launched = self.call("launch", self.permitted("launch", fixture="rph-trusted-v22"))
        session = launched[0]["body"]["sessionId"]
        self.call("continue", {"sessionId": session})
        args = self.permitted("mutate:" + session, sessionId=session,
                              variablesReference=1, name="count", value="6")
        self.assertTrue(self.call("setVariable", args)[0]["success"])
        result = self.call("continue", {"sessionId": session})
        self.assertEqual(result[-1]["event"], "terminated")
        self.assertEqual(self.server._completed_result, 24)

    def test_malicious_evaluate_never_calls_python_eval(self):
        session = self.launch()
        for expression in ("__import__('os').system('whoami')", "count.__class__",
                           "[x for x in range(100)]", "count ** 1000"):
            args = self.permitted("evaluate:" + session,
                                  sessionId=session, expression=expression)
            result = self.call("evaluate", args)
            self.assertFalse(result[0]["success"])
            self.assertNotIn(expression, json.dumps(result))

    def test_step_in_over_out_and_continue_follow_actual_events(self):
        self.initialize()
        self.call("setBreakpoints", {"source": {"path": dap.TRUSTED_FILE},
                                     "breakpoints": [{"line": 8}]})
        launched = self.call("launch", self.permitted("launch", fixture="rph-trusted-v22"))
        session = launched[0]["body"]["sessionId"]
        self.assertEqual(self.call("continue", {"sessionId": session})[-1]["event"], "stopped")
        self.assertEqual(self.server._frame.f_lineno, 8)
        self.assertEqual(self.call("stepIn", {"sessionId": session})[-1]["event"], "stopped")
        self.assertEqual(self.server._frame.f_code.co_name, "compute")
        self.assertEqual(self.call("next", {"sessionId": session})[-1]["event"], "stopped")
        self.assertEqual(self.server._frame.f_code.co_name, "compute")
        self.assertEqual(self.call("stepOut", {"sessionId": session})[-1]["event"], "stopped")
        self.assertEqual(self.server._frame.f_code.co_name, "<module>")

    def test_restart_requires_approval_and_starts_new_actual_worker(self):
        session = self.launch()
        self.assertFalse(self.call("restart", {"sessionId": session})[0]["success"])
        result = self.call("restart", self.permitted("restart:" + session,
                                                    sessionId=session))
        self.assertTrue(result[0]["success"])
        self.assertEqual([x["event"] for x in result[1:]], ["terminated", "stopped"])
        self.assertNotEqual(session, result[0]["body"]["sessionId"])
        self.assertTrue(self.server._worker.is_alive())

    def test_dap_continued_output_and_terminated_events(self):
        session = self.launch()
        result = self.call("continue", {"sessionId": session})
        self.assertEqual([x["event"] for x in result[1:]],
                         ["continued", "output", "terminated"])
        self.assertIn("trusted fixture completed", result[-2]["body"]["output"])
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_event_and_response_sequences_are_monotone(self):
        initialized = self.initialize()
        launched = self.call("launch", self.permitted("launch", fixture="rph-trusted-v22"))
        session = launched[0]["body"]["sessionId"]
        finished = self.call("continue", {"sessionId": session})
        sequence = [x["seq"] for x in initialized + launched + finished]
        self.assertEqual(sequence, sorted(sequence))
        self.assertEqual(len(sequence), len(set(sequence)))

    def test_protocol_frame_roundtrip_and_rejects_duplicate_json_keys(self):
        buffer = io.BytesIO()
        packet = {"seq": 1, "type": "request", "command": "initialize",
                  "arguments": {"adapterID": "rust-python-healer"}}
        dap.write_frame(buffer, packet)
        buffer.seek(0)
        self.assertEqual(dap.read_frame(buffer), packet)
        self.assertIsNone(dap.read_frame(buffer))
        invalid = b'{"seq":1,"seq":2}'
        frame = (b"Content-Length: " + str(len(invalid)).encode() + b"\r\n\r\n" + invalid)
        with self.assertRaisesRegex(dap.ProtocolError, "invalid_json"):
            dap.read_frame(io.BytesIO(frame))

    def test_fragmented_transport_body_is_reassembled_exactly(self):
        class ChunkedReader(io.BytesIO):
            def read(self, count=-1):
                return super().read(min(2, count))

        frame = io.BytesIO()
        packet = {"seq": 37, "type": "request", "command": "initialize",
                  "arguments": {"adapterID": "trusted-fixture"}}
        dap.write_frame(frame, packet)
        self.assertEqual(dap.read_frame(ChunkedReader(frame.getvalue())), packet)

    def test_protocol_rejects_header_body_and_framing_limits(self):
        for payload in (b"Content-Length: -1\r\n\r\n",
                        b"Content-Length: 5\r\n\r\n{}",
                        b"Content-Length: 1\r\nContent-Length: 1\r\n\r\nx",
                        b"Content-Length: 65537\r\n\r\n",
                        b"A" * 4100,
                        b"Content-Length: 4\r\n\r\nnull"):
            with self.assertRaises(dap.ProtocolError):
                dap.read_frame(io.BytesIO(payload))

    def test_missing_key_and_world_readable_key_are_rejected_by_cli(self):
        with tempfile.TemporaryDirectory(prefix="rph-v22-dap-key-") as folder:
            keyfile = Path(folder) / "key"
            keyfile.write_bytes(self.key)
            keyfile.chmod(0o644)
            if os.name == "nt":
                sys.path.insert(0, str(ROOT / "tests"))
                import windows_privacy_fixtures
                windows_privacy_fixtures.set_public_read_acl(keyfile)
            denied = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                                     "--key-file", str(keyfile)], capture_output=True,
                                    check=False, timeout=5)
            self.assertEqual(denied.returncode, 2)
            self.assertEqual(denied.stdout, b"")

    def test_actual_dap_stdio_server_handshake_and_launch(self):
        with tempfile.TemporaryDirectory(prefix="rph-v22-dap-stdio-") as folder:
            keyfile = Path(folder) / "key"
            keyfile.write_bytes(self.key)
            keyfile.chmod(0o600)
            nonce = "stdinmode0001"
            launch = {"seq": 2, "type": "request", "command": "launch",
                      "arguments": {"fixture": "rph-trusted-v22", "nonce": nonce,
                                    "approval": self.server.approval("launch", nonce)}}
            input_bytes = io.BytesIO()
            dap.write_frame(input_bytes, {"seq": 1, "type": "request", "command": "initialize",
                                          "arguments": {"adapterID": "rust-python-healer"}})
            dap.write_frame(input_bytes, launch)
            run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                                  "--key-file", str(keyfile)], input=input_bytes.getvalue(),
                                 capture_output=True, check=False, timeout=8)
            self.assertEqual(run.returncode, 0, run.stderr[:100])
            stream = io.BytesIO(run.stdout)
            frames = []
            while True:
                next_packet = dap.read_frame(stream)
                if next_packet is None:
                    break
                frames.append(next_packet)
            self.assertEqual([x["type"] for x in frames],
                             ["response", "event", "response", "event", "event"])
            self.assertTrue(frames[2]["success"])
            self.assertEqual(frames[-1]["event"], "stopped")
            self.assertNotIn("PRIVATE", run.stdout.decode("utf-8"))

    def test_executable_fixture_selftest_for_rust_lab_has_real_trace(self):
        run = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT), "--selftest"],
                             capture_output=True, check=False, timeout=8)
        self.assertEqual(run.returncode, 0, run.stderr[:100])
        report = json.loads(run.stdout)
        self.assertEqual(report["status"], "TRUSTED_DAP_REAL_FRAMED_FIXTURE_PASS")
        self.assertEqual(report["observed_real_trace_line"], 5)
        self.assertEqual(report["result_from_actual_trusted_execution"], 9)
        self.assertFalse(report["unknown_source_executed"])


if __name__ == "__main__":
    unittest.main()
