"""Actual fixed trusted asyncio workloads under CPython 3.9 through 3.15."""

import asyncio
import gc
import hashlib
import json
import tempfile
import time
import unittest
import warnings
from pathlib import Path

from python import async_runtime_diagnostics as diagnostics


class RuntimeObservationTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_never_awaited_coroutine_runtime_warning_observed(self):
        diag = diagnostics.AsyncRuntimeDiagnostics()

        async def fixed_coroutine():
            return "not reached"

        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always", RuntimeWarning)
            unawaited = fixed_coroutine()
            del unawaited
            gc.collect()
        count = diag.observe_warnings(captured)
        self.assertEqual(count, 1)
        self.assertEqual(diag.events[0]["kind"],
                         "COROUTINE_NEVER_AWAITED_RUNTIME_WARNING")
        self.assertNotIn("fixed_coroutine", json.dumps(diag.report()))

    async def test_non_runtime_warning_is_not_false_unawaited_result(self):
        diag = diagnostics.AsyncRuntimeDiagnostics()
        with warnings.catch_warnings(record=True) as captured:
            warnings.simplefilter("always")
            warnings.warn("coroutine 'fake' was never awaited", UserWarning)
        self.assertEqual(diag.observe_warnings(captured), 0)
        self.assertEqual(diag.events, [])

    async def test_true_unretrieved_task_exception_preserves_cause_class(self):
        loop = asyncio.get_running_loop()
        diag = diagnostics.AsyncRuntimeDiagnostics().attach(loop)

        async def trusted_failure():
            try:
                raise KeyError("PRIVATE_ORIGINAL_CAUSE")
            except KeyError as root:
                raise RuntimeError("PRIVATE_UNHANDLED_MESSAGE") from root

        task = loop.create_task(trusted_failure())
        await asyncio.sleep(0)
        self.assertTrue(task.done())
        del task
        gc.collect()
        await asyncio.sleep(0)
        diag.detach()
        report = diag.report()
        matching = [event for event in report["events"]
                    if event["kind"] == "UNHANDLED_TASK_EXCEPTION"]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0]["exception_class"], "RuntimeError")
        self.assertEqual(matching[0]["explicit_cause_class"], "KeyError")
        self.assertTrue(matching[0]["original_exception_object_observed"])
        self.assertNotIn("PRIVATE", json.dumps(report))

    async def test_watching_failed_task_does_not_retrieve_or_suppress_exception(self):
        loop = asyncio.get_running_loop()
        diag = diagnostics.AsyncRuntimeDiagnostics().attach(loop)

        async def trusted_failure():
            raise LookupError("PRIVATE_NOT_RETRIEVED")

        task = asyncio.create_task(trusted_failure())
        diag.watch_task(task)
        await asyncio.sleep(0)
        del task
        gc.collect()
        await asyncio.sleep(0)
        diag.detach()
        kinds = [item["kind"] for item in diag.events]
        self.assertIn("UNHANDLED_TASK_EXCEPTION", kinds)
        self.assertNotIn("PRIVATE", json.dumps(diag.report()))

    async def test_explicit_task_cancellation_observed(self):
        diag = diagnostics.AsyncRuntimeDiagnostics()
        task = asyncio.create_task(asyncio.sleep(60))
        diag.watch_task(task)
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0)
        self.assertIn("TASK_CANCELLED", [item["kind"] for item in diag.events])

    async def test_actual_wait_timeout_observed_without_deadlock_claim(self):
        diag = diagnostics.AsyncRuntimeDiagnostics()
        with self.assertRaises(asyncio.TimeoutError):
            await diag.wait_for(asyncio.sleep(1), 0.002)
        timeout = diag.events[0]
        self.assertEqual(timeout["kind"], "AWAIT_TIMEOUT_OBSERVED")
        self.assertEqual(timeout["timeout_seconds"], 0.002)
        self.assertFalse(timeout["deadlock_proven"])

    async def test_wait_cancelled_observed_and_reraised(self):
        diag = diagnostics.AsyncRuntimeDiagnostics()

        async def trusted_waiter():
            await diag.wait_for(asyncio.sleep(60))

        task = asyncio.create_task(trusted_waiter())
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(diag.events[0]["kind"], "AWAIT_CANCELLED_OBSERVED")

    async def test_normal_wait_finishes_without_timeout_false_positive(self):
        diag = diagnostics.AsyncRuntimeDiagnostics()
        answer = await diag.wait_for(asyncio.sleep(0, result=42), timeout_seconds=1)
        self.assertEqual(answer, 42)
        self.assertEqual(diag.events, [])

    async def test_real_slow_synchronous_loop_callback_observed(self):
        diag = diagnostics.AsyncRuntimeDiagnostics(slow_callback_seconds=0.001)
        loop = asyncio.get_running_loop()
        finished = loop.create_future()

        def trusted_slow_callback():
            time.sleep(0.008)
            finished.set_result(True)

        loop.call_soon(diag.wrap_callback(trusted_slow_callback))
        await finished
        self.assertEqual(diag.events[0]["kind"], "SLOW_SYNCHRONOUS_CALLBACK")
        self.assertGreater(diag.events[0]["observed_milliseconds"], 1)
        self.assertFalse(diag.events[0]["cause_of_slowness_verified"])

    async def test_fast_loop_callback_no_false_slow_alarm(self):
        diag = diagnostics.AsyncRuntimeDiagnostics(slow_callback_seconds=1.0)
        loop = asyncio.get_running_loop()
        done = loop.create_future()
        loop.call_soon(diag.wrap_callback(done.set_result), True)
        await done
        self.assertEqual(diag.events, [])

    async def test_real_two_task_cycle_in_explicitly_tracked_locks(self):
        diag = diagnostics.AsyncRuntimeDiagnostics()
        first, second = diag.lock("PRIVATE_LOCK_A"), diag.lock("PRIVATE_LOCK_B")
        first_ready, second_ready = asyncio.Event(), asyncio.Event()

        async def trusted_worker(own, other, ready, peer_ready):
            await own.acquire()
            try:
                ready.set()
                await peer_ready.wait()
                await other.acquire()
                try:
                    return "not-reached-while-deadlocked"
                finally:
                    other.release()
            finally:
                own.release()

        left = asyncio.create_task(trusted_worker(first, second, first_ready, second_ready))
        right = asyncio.create_task(trusted_worker(second, first, second_ready, first_ready))
        try:
            await asyncio.wait_for(asyncio.gather(first_ready.wait(),
                                                  second_ready.wait()), 1)
            await asyncio.sleep(0.02)
            edges = diag.wait_graph()
            self.assertEqual(len(edges), 2, edges)
            detected = [item for item in diag.events
                        if item["kind"] == "TRACKED_LOCK_WAIT_CYCLE"]
            self.assertEqual(len(detected), 1)
            self.assertEqual(len(detected[0]["tasks"]), 2)
            self.assertFalse(detected[0]["global_deadlock_proven"])
            self.assertFalse(detected[0]["race_condition_verified"])
            self.assertNotIn("PRIVATE_LOCK", json.dumps(diag.report()))
        finally:
            left.cancel()
            right.cancel()
            await asyncio.gather(left, right, return_exceptions=True)
        self.assertEqual(diag.wait_graph(), [])

    async def test_one_wait_edge_does_not_create_false_cycle(self):
        diag = diagnostics.AsyncRuntimeDiagnostics()
        lock = diag.lock("single")
        async with lock:
            waiter = asyncio.create_task(lock.acquire())
            await asyncio.sleep(0)
            self.assertEqual(len(diag.wait_graph()), 1)
            self.assertEqual(diag.detect_lock_cycles(), [])
            waiter.cancel()
            await asyncio.gather(waiter, return_exceptions=True)
        self.assertEqual(diag.wait_graph(), [])

    async def test_non_owner_cannot_release_tracked_lock(self):
        diag = diagnostics.AsyncRuntimeDiagnostics()
        lock = diag.lock("owned")
        await lock.acquire()

        async def other_task():
            with self.assertRaisesRegex(RuntimeError, "tracked_lock_release_not_owner"):
                lock.release()

        try:
            await asyncio.create_task(other_task())
        finally:
            lock.release()

    async def test_reports_explicit_partial_scope_and_no_untracked_claims(self):
        report = diagnostics.AsyncRuntimeDiagnostics().report()
        self.assertEqual(report["status"], "PARTIAL_RUNTIME_DIAGNOSTICS")
        self.assertFalse(report["untracked_tasks_covered"])
        self.assertFalse(report["global_deadlock_proven"])
        self.assertFalse(report["race_condition_verified"])
        self.assertFalse(report["untrusted_source_files_imported_or_evaled_by_detector"])
        self.assertTrue(report["supplied_callbacks_and_awaitables_run_by_application"])

    async def test_invalid_inputs_refused_before_instrumentation(self):
        for bad in (0, -1, True, 120, "0.1"):
            with self.assertRaises(ValueError):
                diagnostics.AsyncRuntimeDiagnostics(bad)
        diag = diagnostics.AsyncRuntimeDiagnostics()
        for bad in (0, True, -1, "1"):
            unused_coroutine = asyncio.sleep(0)
            try:
                with self.assertRaises(ValueError):
                    await diag.wait_for(unused_coroutine, bad)
            finally:
                unused_coroutine.close()
        with self.assertRaisesRegex(TypeError, "watch_requires_asyncio_task"):
            diag.watch_task(object())
        with self.assertRaisesRegex(TypeError, "callback_must_be_callable"):
            diag.wrap_callback(None)


class StaticSchedulingTests(unittest.TestCase):
    def test_same_source_bare_async_calls_detected_without_execution(self):
        source = "async def work():\n    return 1\nwork()\nwork()\n"
        report = diagnostics.inspect_forgotten_scheduling(source)
        self.assertEqual(report["status"], "STATIC_CANDIDATES_FOUND")
        self.assertEqual(report["potential_forgotten_scheduling_count"], 2)
        self.assertEqual([item["call_line"] for item in report["findings"]], [3, 4])
        self.assertEqual([item["definition_line"] for item in report["findings"]], [1, 1])
        self.assertEqual(report["source_sha256"], hashlib.sha256(source.encode()).hexdigest())
        self.assertFalse(report["runtime_path_proven"])
        self.assertFalse(report["project_source_imported_or_executed"])
        self.assertFalse(report["private_function_names_exposed"])
        self.assertNotIn("work", json.dumps(report))

    def test_nested_sync_function_local_async_call_detected(self):
        source = ("def entry():\n"
                  "    async def nested():\n"
                  "        return 1\n"
                  "    nested()\n")
        report = diagnostics.inspect_forgotten_scheduling(source)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["lexical_depth"], 1)
        self.assertEqual(report["findings"][0]["call_line"], 4)

    def test_await_and_create_task_and_result_assignment_not_false_positives(self):
        source = ("async def coro():\n    return 7\n"
                  "async def main():\n"
                  "    async def nested():\n        pass\n"
                  "    await nested()\n"
                  "    asyncio.create_task(nested())\n"
                  "    pending = nested()\n")
        report = diagnostics.inspect_forgotten_scheduling(source)
        self.assertEqual(report["status"], "NO_STATIC_CANDIDATE")
        self.assertEqual(report["findings"], [])

    def test_shadowed_definitions_assignments_parameters_and_imports_not_reported(self):
        sources = (
            "async def job(): pass\njob = lambda: None\njob()\n",
            "async def job(): pass\ndef job(): pass\njob()\n",
            "async def job(): pass\nfrom unknown_package import job\njob()\n",
            "async def job(): pass\ndef worker(job):\n    job()\n",
            "def outer():\n    async def job(): pass\n    job = None\n    job()\n",
        )
        for source in sources:
            with self.subTest(source=source.splitlines()[0]):
                report = diagnostics.inspect_forgotten_scheduling(source)
                self.assertEqual(report["potential_forgotten_scheduling_count"], 0)

    def test_dynamic_branches_and_exit_do_not_get_falsely_classified(self):
        sources = (
            "async def job(): pass\nif flag: job = lambda: None\njob()\n",
            "def function():\n    async def job(): pass\n    if flag: return\n    job()\n",
            "def function():\n    async def job(): pass\n    return\n    job()\n",
            "def function():\n    async def job(): pass\n    raise RuntimeError()\n    job()\n",
            "async def job(): pass\ntry: pass\nfinally: pass\njob()\n",
            "async def job(): pass\nexec('job = lambda: 0')\njob()\n",
            "async def job(): pass\nvalue: mutate_global_job()\njob()\n",
            "async def job(): pass\nvalue = suspicious + overloaded\njob()\n",
        )
        for source in sources:
            with self.subTest(source=source.splitlines()[0]):
                report = diagnostics.inspect_forgotten_scheduling(source)
                self.assertEqual(report["findings"], [])

    def test_decorators_and_dynamic_arguments_not_trusted(self):
        source = ("@some_decorator\nasync def decorated(): pass\n"
                  "decorated()\n"
                  "async def plain(): pass\n"
                  "plain(rebind_globals())\n"
                  "plain()\n")
        report = diagnostics.inspect_forgotten_scheduling(source)
        # Decorators might turn async functions into arbitrary callables.
        self.assertNotIn(3, [item["call_line"] for item in report["findings"]])
        self.assertEqual([item["call_line"] for item in report["findings"]], [5])

    def test_inline_malicious_source_is_only_parsed_never_executed(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "MUST_NOT_EXIST"
            source = (f"from pathlib import Path\n"
                      f"Path({str(marker)!r}).write_text('SECRET_NOT_TO_RUN')\n"
                      "async def job(): pass\njob()\n")
            report = diagnostics.inspect_forgotten_scheduling(source)
            self.assertEqual(report["potential_forgotten_scheduling_count"], 1)
            self.assertFalse(marker.exists())
            self.assertNotIn("SECRET_NOT_TO_RUN", json.dumps(report))

    def test_invalid_or_large_static_sources_rejected(self):
        for source in (None, "", "a = 1\x00", "async def bad(:\n",
                       "x = 1\n" * 4000, "x = 1\n" + "#" * 132000,
                       "bad = '\ud800'"):
            with self.subTest(type=type(source).__name__), self.assertRaises(
                    (ValueError, TypeError)):
                diagnostics.inspect_forgotten_scheduling(source)

    def test_runtime_and_static_evidence_remain_distinct_and_honest(self):
        report = diagnostics.inspect_forgotten_scheduling("async def job(): pass\njob()\n")
        self.assertEqual(report["potential_forgotten_scheduling_count"], 1)
        self.assertFalse(report["runtime_path_proven"])
        self.assertFalse(report["dynamic_control_flow_exhaustively_analyzed"])
        self.assertEqual(diagnostics.AsyncRuntimeDiagnostics().events, [])


class ControlledThreadRaceTests(unittest.TestCase):
    def test_real_unlocked_threads_deterministically_lose_updates(self):
        for _ in range(3):
            report = diagnostics.run_trusted_counter_probe(workers=2, rounds=8,
                                                           protected=False)
            self.assertEqual(report["status"], "OBSERVED_EXPECTED_CONTROLLED_RESULT")
            self.assertEqual(report["thread_count"], 2)
            self.assertEqual(report["expected_increments"], 16)
            self.assertEqual(report["observed_increments"], 8)
            self.assertEqual(report["lost_updates"], 8)
            self.assertTrue(report["instrumented_lost_update_observed"])
            self.assertFalse(report["generic_race_detection_proven"])

    def test_real_locked_threads_are_negative_control(self):
        report = diagnostics.run_trusted_counter_probe(workers=4, rounds=10,
                                                       protected=True)
        self.assertEqual(report["status"], "OBSERVED_EXPECTED_CONTROLLED_RESULT")
        self.assertEqual(report["thread_count"], 4)
        self.assertEqual(report["observed_increments"], 40)
        self.assertEqual(report["lost_updates"], 0)
        self.assertFalse(report["instrumented_lost_update_observed"])

    def test_race_probe_integrates_with_runtime_events_honestly(self):
        diagnostic = diagnostics.AsyncRuntimeDiagnostics()
        evidence = diagnostic.probe_thread_race(workers=3, rounds=6)
        self.assertEqual(evidence["status"], "CONTROLLED_RACE_DETECTED")
        self.assertEqual(evidence["unsafe"]["lost_updates"], 12)
        self.assertEqual(evidence["locked_control"]["lost_updates"], 0)
        event = diagnostic.report()["events"][0]
        self.assertEqual(event["kind"], "INSTRUMENTED_THREAD_COUNTER_RACE_OBSERVED")
        self.assertFalse(event["arbitrary_shared_state_verified"])
        self.assertTrue(diagnostic.report()["instrumented_counter_race_verified"])
        self.assertFalse(diagnostic.report()["race_condition_verified"])

    def test_race_probe_bounded_inputs_and_absence_of_untrusted_code(self):
        for kwargs in ({"workers": 1}, {"workers": 9}, {"workers": True},
                       {"rounds": 0}, {"rounds": 65}, {"rounds": True},
                       {"protected": 1}):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(
                    ValueError, "invalid_bounded_counter_probe"):
                diagnostics.run_trusted_counter_probe(**kwargs)
        result = diagnostics.run_trusted_counter_probe()
        self.assertFalse(result["untrusted_source_executed"])


if __name__ == "__main__":
    unittest.main()
