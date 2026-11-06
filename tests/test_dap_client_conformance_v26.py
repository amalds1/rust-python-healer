"""Actual local DAP client framing; no VS Code or PyCharm assertions."""

import importlib.util
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "python" / "dap_client_conformance_v26.py"
SPEC = importlib.util.spec_from_file_location("dap_client_conformance_v26", SOURCE)
CLIENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLIENT)


def packet(seq=1):
    return {"seq": seq, "type": "response", "request_seq": seq,
            "command": "initialize", "success": True, "body": {}}


def framed(data):
    return CLIENT.frame_request(data)


class DAPClientConformanceTests(unittest.TestCase):
    def test_real_local_adapter_with_observed_trace(self):
        result = CLIENT.run_trusted_wire_oracle()
        self.assertEqual(result["status"], "LOCAL_TRUSTED_DAP_FRAMED_CLIENT_PASS")
        self.assertEqual(result["real_trusted_runtime_result"], 9)
        self.assertEqual(result["local_client_requests"], 11)
        self.assertEqual(result["actual_stdio_frames"], 19)

    def test_actual_event_order(self):
        result = CLIENT.run_trusted_wire_oracle()
        self.assertEqual(result["actual_event_names"], [
            "initialized", "output", "stopped", "continued", "stopped",
            "continued", "output", "terminated"])

    def test_no_external_client_ever_claimed(self):
        result = CLIENT.run_trusted_wire_oracle()
        self.assertFalse(result["external_vscode_client_executed"])
        self.assertFalse(result["external_pycharm_client_executed"])
        self.assertFalse(result["external_client_conformance_verified"])
        self.assertFalse(result["unknown_project_code_executed"])

    def test_launch_rejects_unapproved_mutation_and_evaluation(self):
        # The real framed selftest includes separate rejected launch,
        # evaluate, and setVariable requests before ordinary completion.
        result = CLIENT.run_trusted_wire_oracle()
        self.assertTrue(result["operator_hmac_enforced"])
        self.assertEqual(result["real_trusted_runtime_result"], 9)

    def test_real_binary_stdio_cli_selftest(self):
        done = subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE),
                               "--mode", "selftest"], capture_output=True,
                              timeout=10, check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stderr, b"")
        report = json.loads(done.stdout)
        self.assertEqual(report["status"], "LOCAL_TRUSTED_DAP_FRAMED_CLIENT_PASS")
        self.assertNotIn(b"PRIVATE_NEVER_EXPOSE", done.stdout)

    def test_all_negative_wire_input_frames_rejected(self):
        results = CLIENT.run_negative_frames()
        self.assertEqual(results["negative_frame_outcomes"], {
            "duplicate_length": "PASS", "invalid_json_duplicates": "PASS",
            "oversized_length": "PASS"})

    def test_real_binary_stdio_cli_negatives(self):
        done = subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE),
                               "--mode", "negatives"], capture_output=True,
                              timeout=10, check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout)["status"],
                         "LOCAL_TRUSTED_DAP_NEGATIVE_FRAMES_PASS")

    def test_capabilities_mode_never_claims_external_clients(self):
        done = subprocess.run([sys.executable, "-I", "-S", "-B", str(SOURCE),
                               "--mode", "capabilities"], capture_output=True,
                              timeout=10, check=False)
        self.assertEqual(done.returncode, 0)
        result = json.loads(done.stdout)
        self.assertTrue(result["local_v22_adapter_only"])
        self.assertFalse(result["external_client_conformance_verified"])

    def test_roundtrip_independent_client_decoder(self):
        original = packet()
        decoded, consumed = CLIENT.decode_framed_packet(framed(original))
        self.assertEqual(decoded, original)
        self.assertEqual(consumed, len(framed(original)))

    def test_partial_header_or_body_never_means_pass(self):
        content = framed(packet())
        self.assertIsNone(CLIENT.decode_framed_packet(content[:5]))
        self.assertIsNone(CLIENT.decode_framed_packet(content[:-1]))

    def test_bad_header_rejected(self):
        bad = b"Content-Length 3\r\n\r\nabc"
        with self.assertRaisesRegex(CLIENT.ClientProtocolError, "header"):
            CLIENT.decode_framed_packet(bad)

    def test_repeated_length_rejected(self):
        bad = (b"Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}")
        with self.assertRaisesRegex(CLIENT.ClientProtocolError, "length"):
            CLIENT.decode_framed_packet(bad)

    def test_oversized_length_rejected(self):
        with self.assertRaisesRegex(CLIENT.ClientProtocolError, "oversized"):
            CLIENT.decode_framed_packet(b"Content-Length: 65537\r\n\r\n")

    def test_duplicate_json_keys_rejected(self):
        body = b'{"seq":1,"seq":2,"type":"response"}'
        frame = b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        with self.assertRaisesRegex(CLIENT.ClientProtocolError, "json"):
            CLIENT.decode_framed_packet(frame)

    def test_non_finite_json_numbers_rejected(self):
        body = b'{"seq":1,"type":"response","value":NaN}'
        frame = b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        with self.assertRaisesRegex(CLIENT.ClientProtocolError, "json"):
            CLIENT.decode_framed_packet(frame)

    def test_boolean_sequence_is_not_integer_sequence(self):
        bad = packet()
        bad["seq"] = True
        with self.assertRaisesRegex(CLIENT.ClientProtocolError, "packet_shape"):
            CLIENT.decode_framed_packet(framed(bad))

    def test_unknown_adapter_header_is_not_silently_ignored(self):
        bad = b"Content-Length: 2\r\nX-Tunnel: token\r\n\r\n{}"
        with self.assertRaisesRegex(CLIENT.ClientProtocolError, "header"):
            CLIENT.decode_framed_packet(bad)

    def test_client_request_non_json_payload_rejected(self):
        with self.assertRaises(ValueError):
            CLIENT.frame_request({"any": float("nan")})
        with self.assertRaises(CLIENT.ClientProtocolError):
            CLIENT.frame_request("not-a-request-object")

    def test_client_request_body_limit_rejected(self):
        with self.assertRaisesRegex(CLIENT.ClientProtocolError, "quota"):
            CLIENT.frame_request({"command": "x" * (CLIENT.MAX_BODY + 5)})

    def test_independent_hmac_approval_not_reusable_as_plain_token(self):
        with CLIENT.FixedFixtureClient() as client:
            token = client.approval("launch", "trustnonce00001")
            self.assertEqual(len(token), 64)
            self.assertNotEqual(token, "0" * 64)
            initialized, _ = client.request("initialize", {"adapterID": "rph"},
                                             ("initialized",))
            self.assertTrue(initialized["success"])
            denied, _ = client.request("launch", {"fixture": "rph-trusted-v22",
                                                   "nonce": "trustnonce00001",
                                                   "approval": "0" * 64})
            self.assertFalse(denied["success"])
            allowed, events = client.request("launch", {"fixture": "rph-trusted-v22",
                "nonce": "trustnonce00001", "approval": token},
                ("output", "stopped"))
            self.assertTrue(allowed["success"])
            self.assertEqual(events[-1]["body"]["reason"], "entry")


if __name__ == "__main__":
    unittest.main()
