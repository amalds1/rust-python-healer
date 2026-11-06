"""Actual event-driven Python debugger on ONE immutable trusted fixture.

The fixture is hardcoded below.  No arbitrary Python files, expressions,
notebooks, CLI commands or modules are imported or executed.  Conditions and
watches use a tiny typed AST interpreter (never eval).  Runtime stop events,
postmortem tracebacks and monitoring are real; this is not a general debugger,
an arbitrary-program sandbox, or a full Debug Adapter Protocol server.
"""

import ast
import argparse
import asyncio
import bdb
import hashlib
import json
import linecache
import operator
import sys
import threading
import traceback

TRUSTED_FILENAME = "<rust-python-healer-trusted-runtime-fixture>"
TRUSTED_SOURCE = ("SECRET = 'PRIVATE_MUST_NEVER_BE_EXPOSED'\n"
                  "def add(left, right):\n"
                  "    partial = left + 1\n"
                  "    answer = partial + right\n"
                  "    return answer\n"
                  "\n"
                  "def outer():\n"
                  "    first = add(2, 3)\n"
                  "    second = add(4, 5)\n"
                  "    return first + second\n"
                  "\n"
                  "RESULT = outer()\n")
TRUSTED_EXCEPTION_SOURCE = ("def fail():\n"
                            "    try:\n"
                            "        raise KeyError('PRIVATE_ORIGINAL_EXCEPTION')\n"
                            "    except KeyError as cause:\n"
                            "        raise RuntimeError('PRIVATE_FINAL_EXCEPTION') from cause\n"
                            "fail()\n")
TRUSTED_ASYNC_SOURCE = ("async def task():\n"
                        "    await asyncio.sleep(0)\n"
                        "    return 3\n")
SAFE_NAMES = frozenset(("left", "right", "partial", "answer", "first", "second", "RESULT"))
SAFE_BINARY = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul}
SAFE_COMPARISONS = {ast.Eq: operator.eq, ast.NotEq: operator.ne,
                    ast.Lt: operator.lt, ast.LtE: operator.le,
                    ast.Gt: operator.gt, ast.GtE: operator.ge}
MAX_STOPS = 64
MAX_WATCHES = 16
MAX_TRACE_EVENTS = 4096


def safe_expression(text):
    """Parse a scalar-only, name-allowlisted expression with explicit quotas."""
    if not isinstance(text, str) or not 0 < len(text) <= 96:
        raise ValueError("unsafe_watch_expression")
    try:
        tree = ast.parse(text, filename="<trusted-watch>", mode="eval")
    except (ValueError, SyntaxError, RecursionError, MemoryError):
        raise ValueError("unsafe_watch_expression") from None
    if sum(1 for _ in ast.walk(tree)) > 32:
        raise ValueError("watch_expression_too_complex")
    for node in ast.walk(tree):
        if isinstance(node, (ast.Expression, ast.Load, ast.BoolOp, ast.BinOp,
                             ast.UnaryOp, ast.Compare, ast.Constant)):
            continue
        if isinstance(node, ast.Name):
            if node.id not in SAFE_NAMES:
                raise ValueError("watch_variable_not_allowlisted")
            continue
        if isinstance(node, (ast.And, ast.Or, ast.Not, ast.UAdd, ast.USub,
                             ast.Add, ast.Sub, ast.Mult, ast.Eq, ast.NotEq,
                             ast.Lt, ast.LtE, ast.Gt, ast.GtE)):
            continue
        raise ValueError("unsafe_watch_ast_node")
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and type(node.value) not in (
                int, float, bool, str, type(None)):
            raise ValueError("unsafe_watch_constant")
        if isinstance(node, ast.BinOp) and type(node.op) not in SAFE_BINARY:
            raise ValueError("unsafe_binary_operation")
        if isinstance(node, ast.Compare) and any(
                type(op) not in SAFE_COMPARISONS for op in node.ops):
            raise ValueError("unsafe_comparison_operation")
        if isinstance(node, ast.UnaryOp) and type(node.op) not in (
                ast.Not, ast.UAdd, ast.USub):
            raise ValueError("unsafe_unary_operation")
    return tree.body


def evaluate_scalar(tree, values):
    """Interpret primitive values; no Python eval/exec, calls or attrs."""
    def calculate(node, depth):
        if depth > 16:
            raise ValueError("watch_calculation_depth_limit")
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id not in values:
                raise ValueError("watch_variable_not_in_frame")
            value = values[node.id]
            if type(value) not in (int, float, bool, str, type(None)):
                raise ValueError("watch_variable_not_scalar")
            return value
        if isinstance(node, ast.UnaryOp):
            value = calculate(node.operand, depth + 1)
            if isinstance(node.op, ast.Not):
                return not value
            if type(value) not in (int, float):
                raise ValueError("watch_numeric_operand_required")
            return value if isinstance(node.op, ast.UAdd) else -value
        if isinstance(node, ast.BinOp):
            left, right = calculate(node.left, depth + 1), calculate(node.right, depth + 1)
            if type(left) not in (int, float) or type(right) not in (int, float):
                raise ValueError("watch_numeric_operand_required")
            answer = SAFE_BINARY[type(node.op)](left, right)
            if type(answer) not in (int, float) or abs(answer) > 1_000_000_000:
                raise ValueError("watch_numeric_result_limit")
            return answer
        if isinstance(node, ast.Compare):
            left = calculate(node.left, depth + 1)
            for comparator, right_node in zip(node.ops, node.comparators):
                right = calculate(right_node, depth + 1)
                if (type(left) not in (int, float, bool, str, type(None)) or
                        type(right) not in (int, float, bool, str, type(None))):
                    raise ValueError("watch_comparison_requires_scalars")
                if not SAFE_COMPARISONS[type(comparator)](left, right):
                    return False
                left = right
            return True
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                for item in node.values:
                    if not bool(calculate(item, depth + 1)):
                        return False
                return True
            for item in node.values:
                if bool(calculate(item, depth + 1)):
                    return True
            return False
        raise ValueError("watch_unknown_ast_node")

    return calculate(tree, 0)


def safe_frame_values(frame):
    """Only hardcoded scalar names; globals and secret locals never leak."""
    merged = {}
    for space in (frame.f_globals, frame.f_locals):
        for name, value in space.items():
            if name in SAFE_NAMES and type(value) in (int, float, bool, type(None)):
                merged[name] = value
    return dict(sorted(merged.items()))


def safe_stack(frame):
    """Only frames from the immutable fixture; no system/user source paths."""
    frames = []
    current = frame
    while current is not None and len(frames) < 12:
        if current.f_code.co_filename == TRUSTED_FILENAME:
            frames.append({"function": current.f_code.co_name,
                           "line": current.f_lineno,
                           "locals": safe_frame_values(current)})
        current = current.f_back
    return frames


class TrustedBreakpoint:
    """Validated fixture-only line/condition/hit-count rule."""

    def __init__(self, line, enabled=True, condition=None, hit_count=1):
        if type(line) is not int or not 1 <= line <= len(TRUSTED_SOURCE.splitlines()):
            raise ValueError("invalid_fixture_breakpoint_line")
        if type(enabled) is not bool or type(hit_count) is not int or not 1 <= hit_count <= 100:
            raise ValueError("invalid_breakpoint_properties")
        self.line = line
        self.enabled = enabled
        self.condition = safe_expression(condition) if condition is not None else None
        self.hit_count = hit_count
        self.visits = 0

    def matches(self, frame):
        if not self.enabled or frame.f_lineno != self.line:
            return False
        self.visits += 1
        if self.visits < self.hit_count:
            return False
        if self.condition is not None:
            try:
                return bool(evaluate_scalar(self.condition, safe_frame_values(frame)))
            except (ValueError, TypeError, OverflowError):
                return False
        return True


class TrustedRuntimeSession:
    """sys.settrace drives real stops, steps and sanitized frame snapshots."""

    def __init__(self, breakpoints=(), commands=(), watches=(), pause_on_exception=False):
        if not isinstance(breakpoints, (tuple, list)) or len(breakpoints) > 24:
            raise ValueError("invalid_breakpoint_count")
        if not isinstance(commands, (tuple, list)) or len(commands) > MAX_STOPS:
            raise ValueError("invalid_debug_commands")
        if any(command not in ("step_in", "step_over", "step_out", "continue")
               for command in commands):
            raise ValueError("unknown_debug_command")
        if not isinstance(watches, (tuple, list)) or len(watches) > MAX_WATCHES:
            raise ValueError("invalid_watch_count")
        self.breakpoints = []
        for item in breakpoints:
            if type(item) is TrustedBreakpoint:
                self.breakpoints.append(item)
            elif type(item) is dict and set(item) <= {
                    "line", "enabled", "condition", "hit_count"} and "line" in item:
                self.breakpoints.append(TrustedBreakpoint(**item))
            else:
                raise ValueError("invalid_breakpoint_registration")
        self.commands = list(commands)
        self.watches = [(text, safe_expression(text)) for text in watches]
        self.pause_on_exception = pause_on_exception is True
        self.stops = []
        self.all_line_events = 0
        self.trace_event_count = 0
        self._mode = "continue"
        self._mode_depth = 0
        self._thread_ids = {}

    def set_breakpoint_enabled(self, line, enabled):
        if type(enabled) is not bool:
            raise ValueError("invalid_breakpoint_enabled")
        matched = [item for item in self.breakpoints if item.line == line]
        if not matched:
            raise ValueError("breakpoint_not_registered")
        for item in matched:
            item.enabled = enabled

    @staticmethod
    def _depth(frame):
        count = 0
        while frame is not None:
            if frame.f_code.co_filename == TRUSTED_FILENAME:
                count += 1
            frame = frame.f_back
        return count

    def _snapshot(self, frame, reason, exception=None):
        values = safe_frame_values(frame)
        watches = {}
        for expression, tree in self.watches:
            try:
                watched = evaluate_scalar(tree, values)
            except (ValueError, TypeError, OverflowError):
                watches[expression] = "[UNAVAILABLE_OR_UNSAFE]"
            else:
                watches[expression] = watched if type(watched) in (
                    int, float, str, bool, type(None)) else "[UNSAFE]"
        thread = threading.get_ident()
        if thread not in self._thread_ids:
            self._thread_ids[thread] = "T" + str(len(self._thread_ids) + 1)
        result = {"line": frame.f_lineno, "function": frame.f_code.co_name,
                  "reason": reason, "thread_id": self._thread_ids[thread],
                  "depth": self._depth(frame), "stack": safe_stack(frame),
                  "watches": watches}
        if exception is not None:
            result["exception_class"] = exception.__name__
        self.stops.append(result)
        position = len(self.stops) - 1
        self._mode = self.commands[position] if position < len(self.commands) else "continue"
        self._mode_depth = self._depth(frame)

    def _trace(self, frame, event, argument):
        if frame.f_code.co_filename != TRUSTED_FILENAME:
            return None
        self.trace_event_count += 1
        if self.trace_event_count > MAX_TRACE_EVENTS:
            raise RuntimeError("trusted_trace_event_limit")
        if event == "exception" and self.pause_on_exception:
            if len(self.stops) < MAX_STOPS:
                self._snapshot(frame, "EXCEPTION", argument[0])
            return self._trace
        if event != "line":
            return self._trace
        self.all_line_events += 1
        depth = self._depth(frame)
        breakpoint_hit = any(item.matches(frame) for item in self.breakpoints)
        step_triggered = ((self._mode == "step_in") or
                          (self._mode == "step_over" and depth <= self._mode_depth) or
                          (self._mode == "step_out" and depth < self._mode_depth))
        if (breakpoint_hit or step_triggered) and len(self.stops) < MAX_STOPS:
            self._snapshot(frame, "BREAKPOINT" if breakpoint_hit else "STEP")
        return self._trace

    def run(self, exception_fixture=False):
        """The argument selects ONE of two hardcoded programs, never source."""
        if type(exception_fixture) is not bool:
            raise ValueError("unknown_trusted_fixture_selector")
        source = TRUSTED_EXCEPTION_SOURCE if exception_fixture else TRUSTED_SOURCE
        self.trace_event_count = 0
        self.all_line_events = 0
        self.stops.clear()
        self._mode = "continue"
        for breakpoint in self.breakpoints:
            breakpoint.visits = 0
        scope = {"__name__": "trusted_debug_fixture"}
        before = sys.gettrace()
        exception_type = None
        try:
            sys.settrace(self._trace)
            exec(compile(source, TRUSTED_FILENAME, "exec", dont_inherit=True), scope)  # noqa: S102 - immutable trusted fixture only
        except (RuntimeError, KeyError) as error:
            if not exception_fixture:
                raise
            exception_type = type(error).__name__
        finally:
            sys.settrace(before)
        return {"status": "TRUSTED_RUNTIME_TRACE",
                "line_events": self.all_line_events,
                "trace_events": self.trace_event_count,
                "stops": list(self.stops),
                "result": None if exception_fixture else scope["RESULT"],
                "exception_class": exception_type if exception_fixture else None,
                "sys_settrace_actually_active": self.trace_event_count > 0,
                "project_source_executed": False,
                "trusted_fixture_executed": True,
                "arbitrary_python_debugging_proven": False}


def trusted_postmortem():
    """Inspect real caught exception traceback; never leak messages/paths."""
    try:
        exec(  # noqa: S102 - source is one immutable hardcoded trusted fixture
            compile(TRUSTED_EXCEPTION_SOURCE, TRUSTED_FILENAME, "exec",
                    dont_inherit=True), {"__name__": "trusted_postmortem"})
    except RuntimeError as problem:
        frames = [{"function": frame.f_code.co_name, "line": line}
                  for frame, line in traceback.walk_tb(problem.__traceback__)
                  if frame.f_code.co_filename == TRUSTED_FILENAME]
        cause = problem.__cause__
        return {"status": "TRUSTED_POSTMORTEM_TRACEBACK",
                "exception_class": type(problem).__name__,
                "original_cause_class": type(cause).__name__ if cause else None,
                "frames": frames, "private_message_disclosed": False,
                "project_source_executed": False}
    raise RuntimeError("trusted_fixture_did_not_raise")


def trusted_bdb_probe():
    """Bdb actually sets/clears a breakpoint in an in-memory trusted fixture."""
    class ObservedBdb(bdb.Bdb):
        def __init__(self):
            super().__init__()
            self.observed_lines = []

        def user_line(self, frame):
            if frame.f_code.co_filename == TRUSTED_FILENAME:
                self.observed_lines.append(frame.f_lineno)
            self.set_continue()

    source_lines = TRUSTED_SOURCE.splitlines(keepends=True)
    old_cache = linecache.cache.get(TRUSTED_FILENAME)
    linecache.cache[TRUSTED_FILENAME] = (len(TRUSTED_SOURCE), None, source_lines,
                                        TRUSTED_FILENAME)
    debugger = ObservedBdb()
    try:
        error = debugger.set_break(TRUSTED_FILENAME, 8)
        if error is not None:
            raise ValueError("trusted_bdb_breakpoint_invalid")
        scope = {"__name__": "trusted_bdb_fixture"}
        debugger.run(compile(TRUSTED_SOURCE, TRUSTED_FILENAME, "exec"), scope)
        debugger.clear_all_breaks()
        return {"status": "TRUSTED_BDB_BREAKPOINT_OBSERVED" if 8 in debugger.observed_lines
                else "NOT_OBSERVED",
                "breakpoint_line": 8, "observed_lines": debugger.observed_lines[:64],
                "breakpoints_after_clear": sum(len(rows) for rows in debugger.breaks.values()),
                "source_executed": False, "trusted_fixture_executed": True}
    finally:
        if old_cache is None:
            linecache.cache.pop(TRUSTED_FILENAME, None)
        else:
            linecache.cache[TRUSTED_FILENAME] = old_cache


def trusted_thread_task_snapshot():
    """Real thread and asyncio Task inventory from fixed curated workload."""
    thread_count = len(threading.enumerate())

    async def sample():
        worker = asyncio.create_task(asyncio.sleep(0.01))
        await asyncio.sleep(0)
        tasks = asyncio.all_tasks()
        observed = len(tasks)
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)
        return observed

    task_count = asyncio.run(sample())
    return {"status": "TRUSTED_TASK_THREAD_INVENTORY",
            "thread_count_at_snapshot": thread_count,
            "asyncio_tasks_at_snapshot": task_count,
            "real_asyncio_all_tasks_called": True,
            "real_threading_enumerate_called": True,
            "private_thread_names_exposed": False,
            "arbitrary_project_task_coverage": False}


def trusted_monitoring_probe():
    """Real sys.monitoring.LINE callbacks on >=3.12, gracefully gated."""
    if sys.version_info < (3, 12) or not hasattr(sys, "monitoring"):
        return {"status": "NOT_SUPPORTED", "reason": "sys_monitoring_requires_3_12",
                "source_executed": False}
    monitoring = sys.monitoring
    tool_id = 5
    events = []

    def observe(code, line):
        if code.co_filename == TRUSTED_FILENAME and len(events) < MAX_TRACE_EVENTS:
            events.append(line)

    try:
        monitoring.use_tool_id(tool_id, "trusted-fixture-monitoring")
    except (ValueError, RuntimeError):
        return {"status": "NOT_RUN", "reason": "monitoring_tool_id_unavailable",
                "source_executed": False}
    try:
        monitoring.register_callback(tool_id, monitoring.events.LINE, observe)
        monitoring.set_events(tool_id, monitoring.events.LINE)
        scope = {"__name__": "trusted_monitoring_fixture"}
        exec(compile(TRUSTED_SOURCE, TRUSTED_FILENAME, "exec"), scope)  # noqa: S102 - hardcoded fixture
    finally:
        monitoring.set_events(tool_id, 0)
        monitoring.register_callback(tool_id, monitoring.events.LINE, None)
        monitoring.free_tool_id(tool_id)
    return {"status": "TRUSTED_SYS_MONITORING_OBSERVED" if events and
            8 in events and scope.get("RESULT") == 16 else "NOT_OBSERVED",
            "observed_line_events": len(events),
            "observed_fixture_breakpoint_line": 8 in events,
            "trusted_result": scope.get("RESULT"),
            "source_executed": False, "trusted_fixture_executed": True}


def debugger_capabilities():
    return {"source_scope": "FIXED_IMMUTABLE_TRUSTED_FIXTURE_ONLY",
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
            "sys_settrace_available": hasattr(sys, "settrace"),
            "bdb_available": True,
            "sys_monitoring_available": hasattr(sys, "monitoring"),
            "full_dap_protocol": False,
            "arbitrary_project_code_execution": False,
            "compiled_trusted_fixture_sha256": hashlib.sha256(
                TRUSTED_SOURCE.encode()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "trace", "postmortem", "bdb",
                                          "threads", "monitoring"), default="capabilities")
    parser.add_argument("--breakpoints-json", default="[]")
    parser.add_argument("--commands-json", default="[]")
    parser.add_argument("--watches-json", default="[]")
    parser.add_argument("--exception-fixture", action="store_true")
    args = parser.parse_args()
    if args.mode == "trace":
        if any(len(value) > 8192 for value in (
                args.breakpoints_json, args.commands_json, args.watches_json)):
            parser.error("trusted_debug_inputs_exceed_quota")
        session = TrustedRuntimeSession(
            breakpoints=json.loads(args.breakpoints_json),
            commands=json.loads(args.commands_json),
            watches=json.loads(args.watches_json),
            pause_on_exception=args.exception_fixture)
        report = session.run(exception_fixture=args.exception_fixture)
    elif args.mode == "postmortem":
        report = trusted_postmortem()
    elif args.mode == "bdb":
        report = trusted_bdb_probe()
    elif args.mode == "threads":
        report = trusted_thread_task_snapshot()
    elif args.mode == "monitoring":
        report = trusted_monitoring_probe()
    else:
        report = debugger_capabilities()
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()

