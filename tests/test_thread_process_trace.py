"""Trusted real local child/thread probes and offline service/queue/job traces."""

import copy
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from python import thread_process_trace as traces

TRACE_ID = "a" * 32
ROOT_ID = "1" * 16
QUEUE_ID = "2" * 16
JOB_ID = "3" * 16


def record(identity, stage, span, parent=None, trace_id=TRACE_ID):
    return {"event_id": identity, "stage": stage, "service": "trusted-local-service",
            "traceparent": traces.traceparent(trace_id, span),
            "parent_span_id": parent}


class TraceContextTests(unittest.TestCase):
    def test_traceparent_v00_roundtrip_and_child_fresh_span(self):
        root = traces.traceparent(TRACE_ID, ROOT_ID)
        self.assertEqual(traces.parse_traceparent(root),
                         {"trace_id": TRACE_ID, "span_id": ROOT_ID, "flags": "01"})
        child = traces.child_context(root)
        self.assertEqual(traces.parse_traceparent(child)["trace_id"], TRACE_ID)
        self.assertNotEqual(traces.parse_traceparent(child)["span_id"], ROOT_ID)
        self.assertEqual(traces.parse_traceparent(child)["flags"], "01")

    def test_new_root_has_valid_nonzero_random_trace_and_span(self):
        root = traces.new_root()
        self.assertEqual(len(root), 55)
        self.assertTrue(int(traces.parse_traceparent(root)["span_id"], 16))
        self.assertNotEqual(root, traces.new_root())

    def test_malformed_and_unsupported_context_rejected(self):
        valid = traces.traceparent(TRACE_ID, ROOT_ID)
        for candidate in (None, "", "00", valid.upper(), valid + "-bad",
                          valid.replace("00-", "01-", 1),
                          "00-" + "0" * 32 + "-" + ROOT_ID + "-01",
                          "00-" + TRACE_ID + "-" + "0" * 16 + "-01",
                          valid[:-2] + "ff"):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                traces.parse_traceparent(candidate)

    def test_actual_child_subprocess_receives_context_under_current_python(self):
        parent = traces.new_root()
        result = traces.probe_trusted_child(parent, sys.executable)
        self.assertEqual(result["status"], "TRUSTED_CHILD_CONTEXT_PROPAGATED")
        self.assertEqual(result["trace_id"], traces.parse_traceparent(parent)["trace_id"])
        self.assertEqual(result["parent_span_id"], traces.parse_traceparent(parent)["span_id"])
        self.assertNotEqual(result["child_span_id"], result["parent_span_id"])
        self.assertEqual(result["child_python_version"],
                         f"{sys.version_info.major}.{sys.version_info.minor}")
        self.assertFalse(result["source_executed"])
        self.assertTrue(result["trusted_probe_executed"])
        self.assertFalse(result["external_services_contacted"])
        self.assertFalse(result["remote_span_authenticated"])

    def test_child_isolation_does_not_forward_other_environment_values(self):
        marker = "TRUSTED_LOCAL_NEVER_FORWARD_SECRET"
        previous = os.environ.get(marker)
        os.environ[marker] = "PRIVATE_ENV_VALUE"
        try:
            report = traces.probe_trusted_child(traces.new_root())
        finally:
            if previous is None:
                os.environ.pop(marker, None)
            else:
                os.environ[marker] = previous
        self.assertFalse(report["environment_secrets_forwarded"])
        self.assertNotIn("PRIVATE_ENV_VALUE", json.dumps(report))

    def test_actual_thread_contextvars_copy_through_executor(self):
        parent = traces.new_root()
        report = traces.probe_trusted_thread(parent)
        self.assertEqual(report["status"], "TRUSTED_THREAD_CONTEXT_PROPAGATED")
        self.assertEqual(report["trace_id"], traces.parse_traceparent(parent)["trace_id"])
        self.assertTrue(report["context_propagated"])
        self.assertFalse(report["untrusted_callback_executed"])

    def test_thread_context_does_not_leak_to_caller_after_probe(self):
        self.assertIsNone(traces.CURRENT_CONTEXT.get())
        traces.probe_trusted_thread(traces.new_root())
        self.assertIsNone(traces.CURRENT_CONTEXT.get())

    def test_missing_child_interpreter_fails_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            missing = Path(folder) / "does-not-exist"
            with self.assertRaisesRegex(ValueError, "trusted_child_unavailable_or_timed_out"):
                traces.probe_trusted_child(traces.new_root(), missing)

    def test_invalid_context_rejected_before_running_child(self):
        with self.assertRaisesRegex(ValueError, "invalid_traceparent_format"):
            traces.probe_trusted_child("INVALID", "/definitely/nonexistent")

    def test_actual_offline_service_queue_job_parent_child_correlation(self):
        ledger = traces.OfflineCorrelationLedger()
        ledger.add(record("service-1", "service", ROOT_ID))
        ledger.add(record("queue-1", "queue", QUEUE_ID, ROOT_ID))
        ledger.add(record("job-1", "job", JOB_ID, QUEUE_ID))
        result = ledger.correlate()
        self.assertEqual(result["status"], "PARTIAL_OFFLINE_CORRELATION")
        self.assertEqual(result["events"], 3)
        self.assertEqual(result["trace_ids"], 1)
        self.assertEqual(result["stage_counts"], {"service": 1, "queue": 1, "job": 1})
        self.assertEqual(result["linked_parent_child_events"], [
            {"parent_event": "queue-1", "child_event": "job-1"},
            {"parent_event": "service-1", "child_event": "queue-1"}])
        self.assertEqual(result["orphan_events"], [])
        self.assertFalse(result["cross_service_runtime_verified"])
        self.assertFalse(result["queue_delivery_verified"])
        self.assertFalse(result["job_execution_verified"])
        self.assertFalse(result["remote_span_authenticated"])
        self.assertFalse(result["network_used"])

    def test_empty_offline_ledger_never_claims_correlation(self):
        report = traces.OfflineCorrelationLedger().correlate()
        self.assertEqual(report["status"], "NO_TRACE_EVENTS")
        self.assertEqual(report["events"], 0)
        self.assertFalse(report["cross_service_runtime_verified"])

    def test_different_trace_ids_cannot_be_cross_correlated(self):
        ledger = traces.OfflineCorrelationLedger()
        ledger.add(record("service", "service", ROOT_ID))
        ledger.add(record("foreign-queue", "queue", QUEUE_ID, ROOT_ID,
                          trace_id="b" * 32))
        report = ledger.correlate()
        self.assertEqual(report["status"], "INCOMPLETE_OR_INVALID_OFFLINE_CORRELATION")
        self.assertEqual(report["orphan_events"], ["foreign-queue"])
        self.assertEqual(report["trace_ids"], 2)

    def test_explicit_parent_cycle_detected_not_accepted_as_valid_chain(self):
        ledger = traces.OfflineCorrelationLedger()
        ledger.add(record("a", "service", ROOT_ID, QUEUE_ID))
        ledger.add(record("b", "queue", QUEUE_ID, ROOT_ID))
        report = ledger.correlate()
        self.assertEqual(report["status"], "INCOMPLETE_OR_INVALID_OFFLINE_CORRELATION")
        self.assertEqual(report["cycle_events"], ["a", "b"])

    def test_out_of_order_parent_event_can_resolve_when_later_added(self):
        ledger = traces.OfflineCorrelationLedger()
        ledger.add(record("queue", "queue", QUEUE_ID, ROOT_ID))
        self.assertEqual(ledger.correlate()["orphan_events"], ["queue"])
        ledger.add(record("root", "service", ROOT_ID))
        self.assertEqual(ledger.correlate()["orphan_events"], [])

    def test_duplicate_event_or_duplicate_span_denied(self):
        ledger = traces.OfflineCorrelationLedger()
        entry = record("event", "service", ROOT_ID)
        ledger.add(entry)
        with self.assertRaisesRegex(ValueError, "duplicate_trace_event_or_span"):
            ledger.add(copy.deepcopy(entry))
        other = record("new-event", "queue", ROOT_ID)
        with self.assertRaisesRegex(ValueError, "duplicate_trace_event_or_span"):
            ledger.add(other)

    def test_malformed_stage_event_parent_and_schema_rejected(self):
        ledger = traces.OfflineCorrelationLedger()
        for key, bad in (("stage", "unknown"), ("event_id", "PRIVATE\nVALUE"),
                         ("service", 123), ("parent_span_id", "f" * 15),
                         ("parent_span_id", ROOT_ID)):
            with self.subTest(key=key):
                row = record("example", "service", ROOT_ID)
                row[key] = bad
                with self.assertRaises(ValueError):
                    ledger.add(row)
        other = record("example", "service", ROOT_ID)
        other["unrecognized_private_metadata"] = "DO_NOT_DISCLOSE"
        with self.assertRaisesRegex(ValueError, "invalid_trace_event_schema"):
            ledger.add(other)

    def test_correlation_max_event_bound_enforced(self):
        ledger = traces.OfflineCorrelationLedger()
        for number in range(traces.MAX_EVENTS):
            span = f"{number + 1:016x}"
            ledger.add(record(f"event-{number}", "job", span))
        with self.assertRaisesRegex(ValueError, "trace_event_limit"):
            ledger.add(record("too-many", "job", "f" * 16))


if __name__ == "__main__":
    unittest.main()
