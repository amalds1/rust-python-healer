"""Actual debugger event tests on one fixed trusted fixture across CPython."""

import hashlib
import json
import sys
import unittest

from python import trusted_runtime_debugger_v21 as debugger


class RealBreakpointAndSteppingTests(unittest.TestCase):
    def test_enabled_line_breakpoint_pauses_on_actual_execution(self):
        result = debugger.TrustedRuntimeSession([{"line": 8}]).run()
        self.assertEqual(result["status"], "TRUSTED_RUNTIME_TRACE")
        self.assertEqual(result["result"], 16)
        self.assertEqual([(event["line"], event["reason"]) for event in result["stops"]],
                         [(8, "BREAKPOINT")])
        self.assertTrue(result["sys_settrace_actually_active"])
        self.assertGreater(result["trace_events"], result["line_events"])

    def test_disabled_breakpoint_does_not_pause(self):
        result = debugger.TrustedRuntimeSession([{"line": 8, "enabled": False}]).run()
        self.assertEqual(result["stops"], [])
        self.assertGreater(result["line_events"], 0)

    def test_enable_and_disable_registered_breakpoints_before_real_run(self):
        session = debugger.TrustedRuntimeSession([{"line": 8}, {"line": 9}])
        session.set_breakpoint_enabled(8, False)
        self.assertEqual([event["line"] for event in session.run()["stops"]], [9])
        session.set_breakpoint_enabled(8, True)
        session.set_breakpoint_enabled(9, False)
        self.assertEqual([event["line"] for event in session.run()["stops"]], [8])

    def test_real_condition_observes_second_invocation_only(self):
        session = debugger.TrustedRuntimeSession([{"line": 3,
                                                   "condition": "left == 4 and right >= 5"}])
        result = session.run()
        self.assertEqual(len(result["stops"]), 1)
        self.assertEqual(result["stops"][0]["line"], 3)
        self.assertEqual(result["stops"][0]["stack"][0]["locals"]["left"], 4)

    def test_false_breakpoint_condition_never_pauses(self):
        result = debugger.TrustedRuntimeSession([{"line": 3,
                                                  "condition": "left < 0"}]).run()
        self.assertEqual(result["stops"], [])

    def test_actual_hit_count_breakpoint_on_second_execution(self):
        session = debugger.TrustedRuntimeSession([{"line": 3, "hit_count": 2}])
        result = session.run()
        self.assertEqual(len(result["stops"]), 1)
        self.assertEqual(result["stops"][0]["stack"][0]["locals"]["left"], 4)
        self.assertEqual(session.breakpoints[0].visits, 2)

    def test_hit_count_is_reset_on_each_actual_runtime_session(self):
        session = debugger.TrustedRuntimeSession([{"line": 3, "hit_count": 2}])
        for _ in range(2):
            report = session.run()
            self.assertEqual(len(report["stops"]), 1)
            self.assertEqual(report["stops"][0]["stack"][0]["locals"]["left"], 4)
            self.assertEqual(session.breakpoints[0].visits, 2)

    def test_hit_count_beyond_real_execution_does_not_fabricate_hit(self):
        result = debugger.TrustedRuntimeSession([{"line": 3, "hit_count": 3}]).run()
        self.assertEqual(result["stops"], [])

    def test_real_step_in_over_out_and_continue_sequence(self):
        result = debugger.TrustedRuntimeSession(
            [{"line": 8}], ["step_in", "step_over", "step_out", "continue"]).run()
        self.assertEqual([(event["function"], event["line"], event["reason"])
                          for event in result["stops"]],
                         [("outer", 8, "BREAKPOINT"), ("add", 3, "STEP"),
                          ("add", 4, "STEP"), ("outer", 9, "STEP")])
        self.assertEqual(result["result"], 16)

    def test_real_step_over_skips_called_function_frames(self):
        result = debugger.TrustedRuntimeSession([{"line": 8}],
                                                ["step_over", "continue"]).run()
        self.assertEqual([(event["function"], event["line"])
                          for event in result["stops"]],
                         [("outer", 8), ("outer", 9)])

    def test_real_step_out_from_inner_function(self):
        result = debugger.TrustedRuntimeSession([{"line": 3}],
                                                ["step_out", "continue"]).run()
        self.assertEqual([(event["function"], event["line"])
                          for event in result["stops"]],
                         [("add", 3), ("outer", 9), ("add", 3)])

    def test_continue_does_not_stop_without_additional_breakpoints(self):
        result = debugger.TrustedRuntimeSession([{"line": 8}], ["continue"]).run()
        self.assertEqual(len(result["stops"]), 1)

    def test_unregistered_breakpoint_toggle_refused(self):
        session = debugger.TrustedRuntimeSession([{"line": 8}])
        with self.assertRaisesRegex(ValueError, "breakpoint_not_registered"):
            session.set_breakpoint_enabled(10, True)
        with self.assertRaisesRegex(ValueError, "invalid_breakpoint_enabled"):
            session.set_breakpoint_enabled(8, 1)


class SafeWatchAndFrameTests(unittest.TestCase):
    def test_scalar_watch_uses_runtime_frame_values_without_eval(self):
        result = debugger.TrustedRuntimeSession(
            [{"line": 4}], watches=["left + right", "partial == 3", "left * right"]).run()
        watches = result["stops"][0]["watches"]
        self.assertEqual(watches, {"left + right": 5, "partial == 3": True,
                                  "left * right": 6})

    def test_watch_without_bound_variable_is_redacted_not_evaluated(self):
        result = debugger.TrustedRuntimeSession([{"line": 8}],
                                                watches=["left + right"]).run()
        self.assertEqual(result["stops"][0]["watches"]["left + right"],
                         "[UNAVAILABLE_OR_UNSAFE]")

    def test_safe_expression_refuses_calls_eval_import_attribute_indexing(self):
        for unsafe in ("__import__('os')", "eval('1')", "left.__class__",
                       "left[0]", "[x for x in range(1)]", "(lambda: 3)()",
                       "SECRET", "globals()", "open('file')", "(x := 1)"):
            with self.subTest(expression=unsafe), self.assertRaises(ValueError):
                debugger.safe_expression(unsafe)

    def test_safe_expression_refuses_unsafe_type_and_arithmetic(self):
        for unsafe in ("'a' + 'b'", "left ** right", "left / right", "left @ right"):
            with self.subTest(expression=unsafe):
                try:
                    parsed = debugger.safe_expression(unsafe)
                except ValueError:
                    continue
                with self.assertRaises(ValueError):
                    debugger.evaluate_scalar(parsed, {"left": 2, "right": 3})

    def test_safe_scalar_watch_comparison_boolean_and_negative(self):
        parsed = debugger.safe_expression("left > 1 and right < 9")
        self.assertTrue(debugger.evaluate_scalar(parsed, {"left": 2, "right": 3}))
        self.assertFalse(debugger.evaluate_scalar(parsed, {"left": 0, "right": 3}))

    def test_snapshot_locals_globals_never_include_fixture_secret(self):
        result = debugger.TrustedRuntimeSession([{"line": 3}],
                                                watches=["left + 1"]).run()
        first = result["stops"][0]
        self.assertEqual(first["stack"][0]["locals"], {"left": 2, "right": 3})
        rendered = json.dumps(result)
        self.assertNotIn("PRIVATE_MUST_NEVER_BE_EXPOSED", rendered)
        self.assertNotIn("SECRET", rendered)
        self.assertNotIn("__builtins__", rendered)
        self.assertEqual(first["thread_id"], "T1")

    def test_stack_is_real_nested_fixture_frames_not_host_paths(self):
        report = debugger.TrustedRuntimeSession([{"line": 3}]).run()
        frames = report["stops"][0]["stack"]
        self.assertEqual([entry["function"] for entry in frames],
                         ["add", "outer", "<module>"])
        self.assertNotIn("/workspace", json.dumps(report))

    def test_watch_expression_count_and_complexity_bounded(self):
        with self.assertRaisesRegex(ValueError, "invalid_watch_count"):
            debugger.TrustedRuntimeSession(watches=["left"] * 17)
        for bad in ("", "x" * 1000, "left + " * 30 + "right"):
            with self.subTest(expression=bad[:10]), self.assertRaises(ValueError):
                debugger.safe_expression(bad)


class RealTraceAndPostmortemTests(unittest.TestCase):
    def test_sys_settrace_is_actually_installed_and_original_restored(self):
        before = sys.gettrace()
        report = debugger.TrustedRuntimeSession([{"line": 8}]).run()
        self.assertIs(sys.gettrace(), before)
        self.assertTrue(report["sys_settrace_actually_active"])
        self.assertGreaterEqual(report["line_events"], 10)

    def test_real_bdb_breakpoint_is_hit_and_cleared(self):
        result = debugger.trusted_bdb_probe()
        self.assertEqual(result["status"], "TRUSTED_BDB_BREAKPOINT_OBSERVED")
        self.assertIn(8, result["observed_lines"])
        self.assertEqual(result["breakpoints_after_clear"], 0)
        self.assertTrue(result["trusted_fixture_executed"])

    def test_real_postmortem_traceback_retains_original_exception_cause(self):
        report = debugger.trusted_postmortem()
        self.assertEqual(report["status"], "TRUSTED_POSTMORTEM_TRACEBACK")
        self.assertEqual(report["exception_class"], "RuntimeError")
        self.assertEqual(report["original_cause_class"], "KeyError")
        self.assertEqual([frame["function"] for frame in report["frames"]],
                         ["<module>", "fail"])
        self.assertFalse(report["private_message_disclosed"])
        self.assertNotIn("PRIVATE", json.dumps(report))

    def test_actual_trace_exception_event_pauses_with_redacted_class(self):
        result = debugger.TrustedRuntimeSession(pause_on_exception=True).run(
            exception_fixture=True)
        stops = [stop for stop in result["stops"] if stop["reason"] == "EXCEPTION"]
        self.assertGreaterEqual(len(stops), 2)
        self.assertEqual(result["exception_class"], "RuntimeError")
        self.assertIn("KeyError", [stop["exception_class"] for stop in stops])
        self.assertIn("RuntimeError", [stop["exception_class"] for stop in stops])
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_real_asyncio_task_and_thread_snapshot(self):
        report = debugger.trusted_thread_task_snapshot()
        self.assertEqual(report["status"], "TRUSTED_TASK_THREAD_INVENTORY")
        self.assertGreaterEqual(report["thread_count_at_snapshot"], 1)
        self.assertGreaterEqual(report["asyncio_tasks_at_snapshot"], 2)
        self.assertTrue(report["real_asyncio_all_tasks_called"])
        self.assertFalse(report["arbitrary_project_task_coverage"])

    def test_real_sys_monitoring_version_gating_and_line_callbacks(self):
        report = debugger.trusted_monitoring_probe()
        if sys.version_info < (3, 12):
            self.assertEqual(report["status"], "NOT_SUPPORTED")
        else:
            self.assertEqual(report["status"], "TRUSTED_SYS_MONITORING_OBSERVED")
            self.assertTrue(report["observed_fixture_breakpoint_line"])
            self.assertGreater(report["observed_line_events"], 0)
            self.assertEqual(report["trusted_result"], 16)
        self.assertFalse(report["source_executed"])

    def test_capabilities_explicitly_disclaim_general_debugging_and_dap(self):
        capabilities = debugger.debugger_capabilities()
        self.assertEqual(capabilities["source_scope"],
                         "FIXED_IMMUTABLE_TRUSTED_FIXTURE_ONLY")
        self.assertFalse(capabilities["full_dap_protocol"])
        self.assertFalse(capabilities["arbitrary_project_code_execution"])
        self.assertEqual(capabilities["compiled_trusted_fixture_sha256"],
                         hashlib.sha256(debugger.TRUSTED_SOURCE.encode()).hexdigest())

    def test_invalid_breakpoint_hitcounts_lines_commands_and_fixture_selection(self):
        for spec in ({"line": 0}, {"line": 999}, {"line": True},
                     {"line": 8, "hit_count": 0}, {"line": 8, "hit_count": True},
                     {"line": 8, "enabled": 1}):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                debugger.TrustedRuntimeSession([spec])
        with self.assertRaisesRegex(ValueError, "unknown_debug_command"):
            debugger.TrustedRuntimeSession(commands=["run-user-source"])
        with self.assertRaisesRegex(ValueError, "invalid_breakpoint_registration"):
            debugger.TrustedRuntimeSession(breakpoints=[object()])
        with self.assertRaisesRegex(ValueError, "unknown_trusted_fixture_selector"):
            debugger.TrustedRuntimeSession().run(exception_fixture="/tmp/unknown.py")


if __name__ == "__main__":
    unittest.main()
