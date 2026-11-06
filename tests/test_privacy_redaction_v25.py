"""v0.25 F207 scope: local bounded redaction, not full log-system proof."""

import hashlib
import importlib.util
import json
import unittest
from pathlib import Path

FILE = Path(__file__).resolve().parents[1] / "python" / "privacy_redaction_v25.py"
SPEC = importlib.util.spec_from_file_location("privacy_redaction_v25", FILE)
privacy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(privacy)


class PrivacyEvidenceTests(unittest.TestCase):
    def valid(self, raw=b"sk-PRIVATE_SECRET_123456789", context=b"/private/path.py"):
        return privacy.redact_event("TRACE", "FAIL", raw, context=context)

    def test_event_returns_digest_only(self):
        event = self.valid()
        self.assertEqual(event["status"], "PRIVATE_DIGEST_ONLY")
        self.assertEqual(event["raw_sha256"], hashlib.sha256(
            b"sk-PRIVATE_SECRET_123456789").hexdigest())
        self.assertEqual(event["raw_bytes"], 27)
        self.assertFalse(event["independent_privacy_audit_attested"])
        self.assertFalse(event["all_application_log_paths_covered"])

    def test_source_tokens_email_path_traceback_not_returned(self):
        content = ("sk-SECRET_123456789 token alice@example.invalid "
                   "C:\\Users\\alice\\AppData\\secret.py /home/alice/private.py "
                   "Traceback (most recent call last): print(very_secret)\n")
        result = self.valid(content, "sensitive-context")
        visible = json.dumps(result, sort_keys=True)
        for value in ("SECRET", "alice", "AppData", "private.py",
                      "Traceback", "sensitive-context", "very_secret"):
            self.assertNotIn(value, visible)

    def test_unicode_source_digest_bytes(self):
        event = self.valid("private-ключ-🔑", "persoonsgegevens")
        self.assertEqual(event["raw_bytes"], len("private-ключ-🔑".encode()))
        self.assertEqual(event["context_bytes"], len(b"persoonsgegevens"))

    def test_raw_bytes_not_modified_before_hash(self):
        raw = b"\x00\xff\xfe\x80secret\n"
        event = self.valid(raw)
        self.assertEqual(event["raw_sha256"], hashlib.sha256(raw).hexdigest())

    def test_empty_private_values_allowed(self):
        event = privacy.redact_event("UPDATER", "NOT_RUN", "")
        self.assertEqual(event["raw_bytes"], 0)
        self.assertEqual(event["context_bytes"], 0)

    def test_all_channels_and_outcomes_are_bounded(self):
        for channel in privacy.CHANNELS:
            for outcome in privacy.OUTCOMES:
                event = privacy.redact_event(channel, outcome, b"fixture")
                self.assertEqual(privacy.verify_redaction(event)["status"],
                                 "LOCAL_METADATA_INTEGRITY_VERIFIED_ONLY")

    def test_unknown_channel_rejected(self):
        for channel in ("NETWORK", "audit\nPII", "RUST_CLI ", ""):
            with self.assertRaises(privacy.PrivacyRedactionRejected):
                privacy.redact_event(channel, "PASS", "test")

    def test_unknown_outcome_rejected(self):
        for outcome in ("SUCCESS", "pass", "ALMOST_PASS", ""):
            with self.assertRaises(privacy.PrivacyRedactionRejected):
                privacy.redact_event("AUDIT", outcome, "test")

    def test_bools_not_accepted_as_labels(self):
        with self.assertRaises(privacy.PrivacyRedactionRejected):
            privacy.redact_event(True, "PASS", "fixture")
        with self.assertRaises(privacy.PrivacyRedactionRejected):
            privacy.redact_event("AUDIT", True, "fixture")

    def test_untrusted_object_is_never_stringified_or_iterated(self):
        class Trap:
            def __str__(self):
                raise AssertionError("unsafe __str__ executed")

            def __iter__(self):
                raise AssertionError("unsafe __iter__ executed")

            def __bytes__(self):
                raise AssertionError("unsafe __bytes__ executed")

        for raw, context in ((Trap(), None), (b"safe", Trap())):
            with self.assertRaises(privacy.PrivacyRedactionRejected):
                privacy.redact_event("AUDIT", "FAIL", raw, context=context)

    def test_caller_str_and_bytes_subclasses_fail_closed(self):
        class EvilText(str):
            def encode(self, *_args, **_kwargs):
                raise AssertionError("subclass code executed")

        class EvilBytes(bytes):
            def __len__(self):
                raise AssertionError("subclass length executed")

        with self.assertRaises(privacy.PrivacyRedactionRejected):
            self.valid(EvilText("secret"))
        with self.assertRaises(privacy.PrivacyRedactionRejected):
            self.valid(EvilBytes(b"secret"))

    def test_oversized_bytes_rejected(self):
        with self.assertRaises(privacy.PrivacyRedactionRejected):
            self.valid(b"X" * (privacy.MAX_LOG_BYTES + 1))

    def test_oversized_context_rejected(self):
        with self.assertRaises(privacy.PrivacyRedactionRejected):
            self.valid(b"hello", b"X" * (privacy.MAX_CONTEXT_BYTES + 1))

    def test_utf8_expansion_also_limited(self):
        with self.assertRaises(privacy.PrivacyRedactionRejected):
            self.valid("🌍" * (privacy.MAX_LOG_BYTES // 4 + 1))

    def test_unpaired_surrogate_never_raises_or_echoes_system_detail(self):
        with self.assertRaises(privacy.PrivacyRedactionRejected):
            self.valid("private-\ud800")

    def test_deterministic_evidence_hash(self):
        self.assertEqual(self.valid(), self.valid())
        self.assertNotEqual(self.valid(b"secret1")["evidence_sha256"],
                            self.valid(b"secret2")["evidence_sha256"])

    def test_byte_count_tamper_rejected(self):
        event = self.valid()
        event["raw_bytes"] = event["raw_bytes"] + 1
        with self.assertRaises(privacy.PrivacyRedactionRejected):
            privacy.verify_redaction(event)

    def test_unregistered_fields_are_fail_closed(self):
        event = self.valid()
        event["source_text"] = "secret"
        with self.assertRaises(privacy.PrivacyRedactionRejected):
            privacy.verify_redaction(event)

    def test_forged_success_flag_and_bool_as_int_rejected(self):
        event = self.valid()
        event["all_application_log_paths_covered"] = True
        with self.assertRaises(privacy.PrivacyRedactionRejected):
            privacy.verify_redaction(event)
        event = self.valid()
        event["raw_bytes"] = False
        with self.assertRaises(privacy.PrivacyRedactionRejected):
            privacy.verify_redaction(event)

    def test_wrong_schema_and_digest_rejected(self):
        for key, fake in (("schema_version", 2),
                          ("raw_sha256", "FF" * 32),
                          ("evidence_sha256", "a" * 64)):
            event = self.valid()
            event[key] = fake
            with self.subTest(key=key), self.assertRaises(
                    privacy.PrivacyRedactionRejected):
                privacy.verify_redaction(event)

    def test_status_object_never_calls_comparison(self):
        class Trap:
            def __ne__(self, _other):
                raise AssertionError("unsafe operator")
        event = self.valid()
        event["status"] = Trap()
        with self.assertRaises(privacy.PrivacyRedactionRejected):
            privacy.verify_redaction(event)

    def test_closed_schema_only_primitive_values(self):
        event = self.valid()
        self.assertTrue(all(type(key) is str for key in event))
        self.assertTrue(all(type(value) in (bool, str, int) for value in event.values()))
        self.assertTrue(privacy.verify_redaction(event)["status"].startswith("LOCAL_"))

    def test_real_v23_cli_redactor_is_integrated_without_raw_leak(self):
        output = privacy.redact_verified_cli_process(
            b"API_KEY=sk-VALUE_SECRET_123456789", b"/private/root/dev.py\n", 0, "scan")
        self.assertEqual(output["adapter_status"], "REDACTED_CLI_RESULT")
        self.assertTrue(output["privacy_event"]["raw_values_returned"] is False)
        self.assertFalse(output["all_rust_cli_log_paths_covered"])
        self.assertEqual(privacy.verify_redaction(output["privacy_event"])["status"],
                         "LOCAL_METADATA_INTEGRITY_VERIFIED_ONLY")
        self.assertNotIn("SECRET", json.dumps(output))
        self.assertNotIn("/private/root", json.dumps(output))

    def test_real_adapter_rejects_unrecognized_cli_commands(self):
        with self.assertRaises(ValueError):
            privacy.redact_verified_cli_process(b"SECRET", b"", 0, "unknown-rust-command")

    def test_real_adapter_rejects_oversized_process_output(self):
        with self.assertRaises(ValueError):
            privacy.redact_verified_cli_process(b"A" * (privacy.MAX_LOG_BYTES + 1),
                                               b"", 0, "scan")

    def test_integrated_cli_nonzero_is_failure(self):
        event = privacy.redact_verified_cli_process(b"", b"SECRET", 9, "update")
        self.assertEqual(event["privacy_event"]["outcome"], "FAIL")


if __name__ == "__main__":
    unittest.main()
