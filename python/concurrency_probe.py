"""Trusted, bounded CPython process-method and subinterpreter regression probe.

Only fixed, reviewed probe code is executed.  Never accepts a Python source
file, code expression, package import or arbitrary function to execute.
Multiprocessing/subinterpreters are not OS sandbox boundaries.
"""

import argparse
import json
import multiprocessing
import os
import platform
import sys
import time

METHODS = ("fork", "spawn", "forkserver")
TIMEOUT_SECONDS = 5
EXPLICIT_SPAWN_FALLBACK_INTENT = "ALLOW_TRUSTED_SPAWN_FALLBACK"
FIXED_PROCESS_FIXTURES = ("pong", "timeout", "invalid_identity", "worker_error")


def trusted_process(conn, fixture="pong"):
    """Top-level fixed worker: import-safe under 'spawn' and 'forkserver'."""
    try:
        if fixture not in FIXED_PROCESS_FIXTURES:
            raise ValueError("unknown_fixed_process_fixture")
        if fixture == "worker_error":
            raise RuntimeError("fixed_worker_error_fixture")
        if fixture == "timeout":
            conn.send({"pid": os.getpid(), "parent": os.getppid(),
                       "fixed_probe": "READY"})
            time.sleep(60)  # Fixed negative fixture; parent must terminate/reap it.
            return
        conn.send({"pid": os.getpid() if fixture == "pong" else -1,
                   "parent": os.getppid(), "fixed_probe": "PONG"})
    finally:
        conn.close()


def inspect_method(method, *, fixture="pong", timeout_seconds=TIMEOUT_SECONDS):
    """Actual CPython multiprocessing start, message, join, termination."""
    if method not in METHODS:
        raise ValueError("unknown_start_method")
    if type(fixture) is not str or fixture not in FIXED_PROCESS_FIXTURES:
        raise ValueError("unknown_fixed_process_fixture")
    if (type(timeout_seconds) not in (int, float)
            or not 0.05 <= timeout_seconds <= TIMEOUT_SECONDS):
        raise ValueError("invalid_process_timeout")
    if method not in multiprocessing.get_all_start_methods():
        return {"method": method, "status": "UNSUPPORTED_ON_PLATFORM",
                "child_executed_fixed_fixture": False,
                "untrusted_source_executed": False,
                "child_started": False,
                "cleanup": {"owned_process_created": False,
                            "process_handle_closed": True,
                            "channels_closed": True,
                            "alive_after_cleanup": False}}
    start = time.monotonic()
    sender = receiver = process = None
    report = {"method": method, "fixture": fixture, "status": "NOT_RUN",
              "child_executed_fixed_fixture": False,
              "untrusted_source_executed": False, "child_started": False}
    cleanup = {"owned_process_created": False, "terminate_used": False,
               "kill_used": False, "child_reaped": False,
               "process_handle_closed": False, "channels_closed": False,
               "alive_after_cleanup": None}
    try:
        context = multiprocessing.get_context(method)
        receiver, sender = context.Pipe(duplex=False)
        process = context.Process(target=trusted_process, args=(sender, fixture))
        cleanup["owned_process_created"] = True
        process.daemon = True
        process.start()
        report["child_started"] = True
        report["owned_child_pid"] = process.pid
        sender.close()
        sender = None
        if not receiver.poll(timeout_seconds):
            report["reason"] = "worker_result_timeout"
            return report
        result = receiver.recv()
        if fixture == "timeout":
            ready = (type(result) is dict and result.get("fixed_probe") == "READY"
                     and type(result.get("pid")) is int and result["pid"] == process.pid
                     and type(result.get("parent")) is int and result["parent"] == os.getpid())
            if not ready:
                report.update(status="FAIL", reason="worker_ready_identity_invalid")
                return report
            report["child_executed_fixed_fixture"] = True
            report["ready_identity_verified"] = True
            if receiver.poll(timeout_seconds):
                report.update(status="FAIL", reason="timeout_fixture_unexpected_response")
            else:
                report["reason"] = "worker_result_timeout"
            return report
        process.join(timeout_seconds)
        if (process.is_alive() or process.exitcode != 0 or
                type(result) is not dict or result.get("fixed_probe") != "PONG" or
                type(result.get("pid")) is not int or
                result["pid"] != process.pid or result["pid"] == os.getpid() or
                type(result.get("parent")) is not int or result["parent"] != os.getpid()):
            report.update(status="FAIL", reason="worker_exit_or_identity_invalid")
            return report
        report.update(status="PASS", child_executed_fixed_fixture=True,
                      child_pid_different=True, parent_identity_verified=True)
        return report
    except EOFError:
        report.update(status="FAIL", reason="worker_pipe_eof")
        return report
    except (OSError, RuntimeError) as error:
        # Do not print error text: system exceptions can include sensitive paths.
        report.update(status="NOT_RUN", reason="os_or_environment_denied",
                      error_type=type(error).__name__)
        return report
    finally:
        # Own only this exact Process object and its Pipe endpoints. Never
        # terminate an unrelated PID or infer ownership from a process name.
        try:
            if process is not None:
                if process.pid is not None:
                    if process.is_alive():
                        cleanup["terminate_used"] = True
                        process.terminate()
                        process.join(TIMEOUT_SECONDS)
                    if process.is_alive():
                        cleanup["kill_used"] = True
                        process.kill()
                        process.join(TIMEOUT_SECONDS)
                    cleanup["alive_after_cleanup"] = process.is_alive()
                    cleanup["child_reaped"] = process.exitcode is not None
                    cleanup["child_exitcode"] = process.exitcode
                else:
                    cleanup["alive_after_cleanup"] = False
                if cleanup["alive_after_cleanup"] is False:
                    process.close()
                    cleanup["process_handle_closed"] = True
            else:
                cleanup["alive_after_cleanup"] = False
                cleanup["process_handle_closed"] = True
        except (OSError, RuntimeError, ValueError, AssertionError) as error:
            cleanup["error_type"] = type(error).__name__
        finally:
            channels_closed = True
            for channel in (receiver, sender):
                if channel is not None:
                    try:
                        channel.close()
                    except OSError:
                        channels_closed = False
            cleanup["channels_closed"] = channels_closed
        report["cleanup"] = cleanup
        report["cleanup_verified"] = (
            report["child_started"] and cleanup["child_reaped"]
            and cleanup["alive_after_cleanup"] is False
            and cleanup["process_handle_closed"] and cleanup["channels_closed"])
        report["elapsed_ms"] = round((time.monotonic() - start) * 1000, 3)
        if (cleanup["alive_after_cleanup"] is not False
                or not cleanup["process_handle_closed"] or not cleanup["channels_closed"]):
            report.update(status="FAIL", reason="owned_process_cleanup_failed")


def qualify_start_method(requested=None, fallback_intent=None):
    """Actually start trusted workers; an unavailable method never silently passes.

    Explicitly consenting to a *spawn-only* fallback is a compatibility
    decision, not a claim that forkserver was tested or that it is sandboxed.
    Neither user Python source nor arbitrary targets are accepted.
    """
    if requested is not None and (type(requested) is not str or
                                  requested not in METHODS):
        raise ValueError("invalid_requested_start_method")
    if fallback_intent not in (None, EXPLICIT_SPAWN_FALLBACK_INTENT):
        raise ValueError("unknown_fallback_intent")
    selected = requested if requested is not None else multiprocessing.get_start_method()
    if selected not in METHODS:
        raise ValueError("unsupported_default_start_method")
    primary = inspect_method(selected)
    report = {"schema_version": 1, "requested_method": selected,
              "default_was_requested": requested is None,
              "primary": primary,
              "explicit_fallback_consent": fallback_intent is not None,
              "untrusted_source_executed": False,
              "implicit_security_sandbox": False}
    if primary["status"] == "PASS":
        return dict(report, status="PRIMARY_PASS", effective_method=selected,
                    fallback=None)
    if fallback_intent is None or selected == "spawn":
        return dict(report, status="NOT_RUN", effective_method=None,
                    fallback=None)
    # Only an explicitly authorized, separately probed *spawn* may substitute
    # for a denied forkserver/fork; no substitution with thread-unsafe fork.
    alternative = inspect_method("spawn")
    if alternative["status"] == "PASS":
        return dict(report, status="EXPLICIT_SPAWN_FALLBACK_PASS",
                    effective_method="spawn", fallback=alternative)
    return dict(report, status="NOT_RUN", effective_method=None,
                fallback=alternative)


def inspect_subinterpreters():
    """Check builtin namespaces in two fixed CPython 3.14+ interpreters."""
    base = {"module": "concurrent.interpreters",
            "untrusted_source_executed": False,
            "security_boundary": False,
            "external_packages_tested": False,
            "independent_memory_isolation_verified": False}
    if sys.version_info[:2] < (3, 14):
        return dict(base, status="NOT_AVAILABLE_BEFORE_3_14")
    try:
        from concurrent import interpreters
    except ImportError:
        return dict(base, status="NOT_AVAILABLE_ON_BUILD")
    first = second = None
    marker = "RPH_FIXED_INTERPRETER_PROBE_12345"
    try:
        # Only compile/execute these trusted literal statements, never input.
        first = interpreters.create()
        second = interpreters.create()
        first.exec("import builtins\nbuiltins.RPH_FIXED_INTERPRETER_PROBE_12345 = 42")
        second.exec("import builtins\nassert not hasattr(builtins, 'RPH_FIXED_INTERPRETER_PROBE_12345')")
        first.exec("import builtins\nassert builtins.RPH_FIXED_INTERPRETER_PROBE_12345 == 42")
        import builtins
        if hasattr(builtins, marker):
            return dict(base, status="FAIL", reason="shared_python_builtins_namespace")
        if first.id == second.id:
            return dict(base, status="FAIL", reason="duplicate_interpreter_identity")
        return dict(base, status="PASS",
                    fixed_code_executed_in_subinterpreter=True,
                    two_distinct_interpreters=True,
                    builtin_namespace_separate=True)
    except (OSError, RuntimeError, interpreters.InterpreterError) as error:
        return dict(base, status="NOT_RUN", reason="subinterpreter_creation_refused",
                    error_type=type(error).__name__)
    finally:
        for interp in (first, second):
            if interp is not None:
                try:
                    interp.close()
                except (OSError, RuntimeError, ValueError):
                    # Interpreter cleanup is best-effort; never mask the
                    # original, already recorded probe outcome.
                    continue


def probe(methods=METHODS):
    """Version- and OS-bound evidence; never conflate unsupported with PASS."""
    if tuple(dict.fromkeys(methods)) != tuple(methods) or any(
            method not in METHODS for method in methods):
        raise ValueError("invalid_requested_methods")
    result = [inspect_method(method) for method in methods]
    minor = sys.version_info.minor
    actual_default = multiprocessing.get_start_method(allow_none=False)
    expected_default = None
    if platform.system() == "Linux":
        expected_default = "forkserver" if minor >= 14 else "fork"
    default_matches = actual_default == expected_default if expected_default else None
    sub = inspect_subinterpreters()
    return {
        "status": "PASS" if all(row["status"] == "PASS" for row in result) and
                  sub["status"] in ("PASS", "NOT_AVAILABLE_BEFORE_3_14") and
                  default_matches is not False else "PARTIAL_OR_NOT_RUN",
        "schema_version": 1,
        "python_minor": f"{sys.version_info.major}.{minor}",
        "implementation": sys.implementation.name,
        "os": platform.system(),
        "platform_expected_default": expected_default,
        "actual_default_start_method": actual_default,
        "default_matches_platform_version_expectation": default_matches,
        "available_start_methods": sorted(multiprocessing.get_all_start_methods()),
        "method_results": result,
        "subinterpreter": sub,
        "untrusted_source_executed": False,
        "no_implicit_security_sandbox": True,
        "process_count_limit": len(methods),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--method", choices=METHODS, action="append", default=[])
    parser.add_argument("--qualify-default", action="store_true",
                        help="check actual default method using only a fixed child")
    parser.add_argument("--allow-spawn-fallback", action="store_true",
                        help="explicitly allow a separately proven spawn fallback")
    args = parser.parse_args()
    if args.allow_spawn_fallback and not args.qualify_default:
        parser.error("--allow-spawn-fallback requires --qualify-default")
    if args.qualify_default:
        if args.method:
            parser.error("--qualify-default does not accept --method")
        intent = EXPLICIT_SPAWN_FALLBACK_INTENT if args.allow_spawn_fallback else None
        result = qualify_start_method(fallback_intent=intent)
    else:
        result = probe(tuple(args.method) if args.method else METHODS)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
