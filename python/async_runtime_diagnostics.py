"""Bounded asyncio runtime observations for explicitly instrumented workloads.

This module never loads or executes source files.  Consumers choose tasks,
coroutines, locks and callbacks to instrument in their *existing* event loop.
Only observable failures are reported; timing stalls are not deadlock proof,
and lock cycles are meaningful ONLY for instances of TrackedAsyncLock.
"""

import ast
import asyncio
import hashlib
import re
import threading
import time
import warnings
import weakref
from concurrent.futures import ThreadPoolExecutor

MAX_EVENTS = 256
MAX_INSTRUMENTED_LOCKS = 128
MAX_STATIC_SOURCE_BYTES = 131_072
MAX_STATIC_SOURCE_LINES = 3000
MAX_STATIC_AST_NODES = 16_384
MAX_STATIC_FINDINGS = 256
MAX_COUNTER_WORKERS = 8
MAX_COUNTER_ROUNDS = 64
SAFE_EXCEPTION_MODULES = frozenset(("builtins", "asyncio.exceptions"))
NEVER_AWAITED = re.compile(r"^coroutine ['\"].{1,200}['\"] was never awaited$")


def inspect_forgotten_scheduling(source):
    """Conservative parse-only detection of bare calls to local async defs.

    Only sequential statements in the SAME lexical body are considered.
    Anything with dynamic control flow, decorators, argument defaults,
    shadowing, imports or uncertain side effects invalidates observations.
    The tool neither imports nor runs the untrusted source.  A reported call
    is a *static possibility*, not proof that a given path executed.
    """
    if not isinstance(source, str):
        raise TypeError("static_source_must_be_text")
    try:
        raw = source.encode("utf-8")
    except UnicodeError:
        raise ValueError("invalid_static_source_unicode") from None
    if (not raw or len(raw) > MAX_STATIC_SOURCE_BYTES or b"\x00" in raw or
            source.count("\n") > MAX_STATIC_SOURCE_LINES):
        raise ValueError("invalid_static_source_bounds")
    try:
        tree = ast.parse(source, filename="<offline-static-async-source>", mode="exec")
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        raise ValueError("static_source_syntax_invalid_or_unsupported") from None
    for index, _node in enumerate(ast.walk(tree)):
        if index >= MAX_STATIC_AST_NODES:
            raise ValueError("static_ast_node_limit")
    findings = []

    def risky_definition(node):
        if node.decorator_list or node.args.defaults or any(
                item is not None for item in node.args.kw_defaults):
            return True
        for arg in (node.args.posonlyargs + node.args.args +
                    node.args.kwonlyargs + [argument for argument in
                                           (node.args.vararg, node.args.kwarg)
                                           if argument is not None]):
            # Even T[U] may execute user-defined __class_getitem__ at function
            # definition time.  Restrict confident detection to safe names.
            if arg.annotation is not None and not isinstance(
                    arg.annotation, (ast.Name, ast.Constant)):
                return True
        return (node.returns is not None and not isinstance(
            node.returns, (ast.Name, ast.Constant)))

    def scan(body, depth):
        if depth > 24:
            return
        if any(isinstance(stmt, (ast.Global, ast.Nonlocal)) for stmt in body):
            # Python's global/nonlocal directives change binding of a name
            # throughout this lexical body, including statements before them.
            return
        known_async_definitions = {}
        for statement in body:
            if isinstance(statement, (ast.AsyncFunctionDef, ast.FunctionDef)):
                if risky_definition(statement):
                    known_async_definitions.clear()
                elif isinstance(statement, ast.AsyncFunctionDef):
                    known_async_definitions[statement.name] = statement.lineno
                else:
                    known_async_definitions.pop(statement.name, None)
                scan(statement.body, depth + 1)
                continue
            if isinstance(statement, ast.ClassDef):
                scan(statement.body, depth + 1)
                # Class body, metaclass and decorators may have side effects.
                known_async_definitions.clear()
                continue
            if isinstance(statement, ast.Expr):
                value = statement.value
                if isinstance(value, ast.Call) and isinstance(value.func, ast.Name):
                    target = value.func.id
                    definition_line = known_async_definitions.get(target)
                    if definition_line is not None:
                        if len(findings) >= MAX_STATIC_FINDINGS:
                            raise ValueError("static_async_findings_limit")
                        findings.append({"call_line": statement.lineno,
                                         "definition_line": definition_line,
                                         "lexical_depth": depth,
                                         "status": "LIKELY_BARE_COROUTINE_CALL"})
                        # Argument expression evaluation might rebind the
                        # function before any following bare calls.
                        if any(not isinstance(arg, (ast.Constant, ast.Name))
                               for arg in value.args) or any(
                                   arg.arg is None or
                                   not isinstance(arg.value, (ast.Constant, ast.Name))
                                   for arg in value.keywords):
                            known_async_definitions.clear()
                        # Creating a coroutine doesn't execute its async body.
                        continue
                if isinstance(value, ast.Constant):
                    continue
                known_async_definitions.clear()
                continue
            if isinstance(statement, ast.Assign):
                # No attempt to trace aliases or calls on RHS; those may
                # dynamically rebind known names via globals()/side effects.
                if (any(not isinstance(target, ast.Name) for target in statement.targets)
                        or not isinstance(statement.value, (ast.Constant, ast.Name))):
                    known_async_definitions.clear()
                else:
                    for target in statement.targets:
                        known_async_definitions.pop(target.id, None)
                continue
            if isinstance(statement, ast.AnnAssign):
                if (isinstance(statement.target, ast.Name) and
                        isinstance(statement.annotation, (ast.Constant, ast.Name)) and
                        (statement.value is None or isinstance(
                            statement.value, (ast.Constant, ast.Name)))):
                    known_async_definitions.pop(statement.target.id, None)
                else:
                    known_async_definitions.clear()
                continue
            if isinstance(statement, ast.Pass):
                continue
            # Includes return/raise/exit, conditional branches, imports,
            # try/except*, loops, with, match, deletes and dynamic rebinding.
            known_async_definitions.clear()
            if isinstance(statement, (ast.Return, ast.Raise, ast.Break,
                                      ast.Continue)):
                break

    scan(tree.body, 0)
    return {"status": "STATIC_CANDIDATES_FOUND" if findings else "NO_STATIC_CANDIDATE",
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "potential_forgotten_scheduling_count": len(findings),
            "findings": findings,
            "inspection_scope": "SAME_LEXICAL_BODY_STRAIGHT_LINE_UNSHADOWED_ASYNC_DEFS",
            "runtime_path_proven": False,
            "dynamic_control_flow_exhaustively_analyzed": False,
            "project_source_imported_or_executed": False,
            "private_function_names_exposed": False}


def run_trusted_counter_probe(workers=2, rounds=8, protected=False):
    """Fixed real-thread lost-update probe, NOT arbitrary shared-state tracing.

    Each unlocked round forces every worker to read the same old value before
    any write via a barrier.  The locked control performs increments inside a
    real threading.Lock.  There is no dynamic source, callback or import.
    """
    if (type(workers) is not int or not 2 <= workers <= MAX_COUNTER_WORKERS or
            type(rounds) is not int or not 1 <= rounds <= MAX_COUNTER_ROUNDS or
            type(protected) is not bool):
        raise ValueError("invalid_bounded_counter_probe")
    counter = [0]
    counter_lock = threading.Lock()
    read_barrier = threading.Barrier(workers)
    write_barrier = threading.Barrier(workers)
    identities = set()

    def fixed_worker():
        with counter_lock:
            identities.add(threading.get_ident())
        for _ in range(rounds):
            if protected:
                with counter_lock:
                    counter[0] += 1
            else:
                # No mutex surrounds this read/write pair: two true threads
                # must read stale values before either can write.
                observed = counter[0]
                read_barrier.wait(timeout=3)
                counter[0] = observed + 1
            write_barrier.wait(timeout=3)

    try:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            jobs = [executor.submit(fixed_worker) for _ in range(workers)]
            for job in jobs:
                job.result(timeout=5)
    except (threading.BrokenBarrierError, TimeoutError, RuntimeError):
        raise ValueError("trusted_thread_counter_probe_failed") from None
    expected = workers * rounds
    observed = counter[0]
    lost = expected - observed
    distinct_threads = len(identities)
    valid = distinct_threads == workers and observed <= expected
    if protected:
        valid = valid and lost == 0
    else:
        valid = valid and lost > 0
    return {"status": "OBSERVED_EXPECTED_CONTROLLED_RESULT" if valid else "INCONCLUSIVE",
            "thread_count": distinct_threads,
            "workers": workers,
            "rounds": rounds,
            "expected_increments": expected,
            "observed_increments": observed,
            "lost_updates": lost,
            "protected_by_lock": protected,
            "instrumented_lost_update_observed": valid and not protected,
            "untrusted_source_executed": False,
            "generic_race_detection_proven": False}


def exception_class(value):
    """Avoid returning private custom class names or exception messages."""
    kind = type(value)
    if kind.__module__ not in SAFE_EXCEPTION_MODULES:
        return "[CUSTOM_EXCEPTION]"
    return kind.__name__[:64]


class AsyncRuntimeDiagnostics:
    """Attach to an active loop and instrument explicitly selected operations."""

    def __init__(self, slow_callback_seconds=0.004):
        if (isinstance(slow_callback_seconds, bool) or
                not isinstance(slow_callback_seconds, (int, float)) or
                not 0 < slow_callback_seconds <= 60):
            raise ValueError("invalid_slow_callback_threshold")
        self.slow_callback_seconds = slow_callback_seconds
        self.events = []
        self.overflow_events = 0
        self.loop = None
        self.previous_handler = None
        self._identities = weakref.WeakKeyDictionary()
        self._next_identity = 0
        self._waits = weakref.WeakKeyDictionary()
        self._locks = []
        self._cycles = set()

    def _record(self, kind, **fields):
        if len(self.events) >= MAX_EVENTS:
            self.overflow_events += 1
            return
        self.events.append({"kind": kind, **fields})

    def task_id(self, task):
        if task is None:
            return None
        if task not in self._identities:
            self._next_identity += 1
            self._identities[task] = "T" + str(self._next_identity)
        return self._identities[task]

    def attach(self, loop=None):
        loop = loop or asyncio.get_running_loop()
        if self.loop is not None:
            raise ValueError("diagnostics_already_attached")
        self.previous_handler = loop.get_exception_handler()
        self.loop = loop
        loop.set_exception_handler(self._handle_loop_exception)
        return self

    def detach(self):
        if self.loop is not None:
            self.loop.set_exception_handler(self.previous_handler)
            self.loop = None
            self.previous_handler = None

    def _handle_loop_exception(self, loop, context):
        """Capture actual loop exception context without logging raw messages."""
        message = context.get("message", "")
        problem = context.get("exception")
        if not isinstance(message, str):
            message = ""
        task = context.get("task") or context.get("future")
        if "exception was never retrieved" in message.lower() and problem is not None:
            cause = problem.__cause__
            self._record("UNHANDLED_TASK_EXCEPTION",
                         task_id=self.task_id(task),
                         exception_class=exception_class(problem),
                         explicit_cause_class=exception_class(cause)
                         if cause is not None else None,
                         original_exception_object_observed=True,
                         traceback_or_message_disclosed=False)
        elif "destroyed but it is pending" in message.lower():
            self._record("PENDING_TASK_DESTROYED_WARNING",
                         task_id=self.task_id(task),
                         scheduling_omission_proven=False)
        else:
            self._record("OTHER_ASYNCIO_LOOP_EXCEPTION",
                         exception_class=exception_class(problem)
                         if problem is not None else None)

    def observe_warnings(self, records):
        """Classify actual warnings.WarningMessage instances; no raw text."""
        count = 0
        for inspected, record in enumerate(records):
            if inspected >= MAX_EVENTS:
                self.overflow_events += 1
                break
            if (not isinstance(record, warnings.WarningMessage) or
                    not issubclass(record.category, RuntimeWarning)):
                continue
            message = str(record.message)
            # AsyncIO debug mode appends a multi-line coroutine origin traceback.
            # Inspect only the first warning line and never expose those paths.
            if NEVER_AWAITED.fullmatch(message.splitlines()[0][:512] if message else ""):
                self._record("COROUTINE_NEVER_AWAITED_RUNTIME_WARNING",
                             coroutine_source_identified=False,
                             no_import_or_execution_by_detector=True)
                count += 1
        return count

    def watch_task(self, task):
        """A done callback only inspects cancellation, NEVER consumes exceptions."""
        if not isinstance(task, asyncio.Task):
            raise TypeError("watch_requires_asyncio_task")
        identity = self.task_id(task)

        def finished(observed):
            if observed.cancelled():
                self._record("TASK_CANCELLED", task_id=identity,
                             cancelled_at_runtime=True)

        task.add_done_callback(finished)
        return identity

    async def wait_for(self, awaitable, timeout_seconds=None):
        """Observe real timeout/cancellation on an explicit caller's awaitable."""
        if timeout_seconds is not None and (
                isinstance(timeout_seconds, bool) or
                not isinstance(timeout_seconds, (float, int)) or
                not 0 < timeout_seconds <= 3600):
            raise ValueError("invalid_wait_timeout")
        current = asyncio.current_task()
        identity = self.task_id(current)
        try:
            if timeout_seconds is None:
                return await awaitable
            return await asyncio.wait_for(awaitable, timeout_seconds)
        except asyncio.TimeoutError:  # noqa: UP041 - distinct from TimeoutError in CPython 3.9
            self._record("AWAIT_TIMEOUT_OBSERVED", task_id=identity,
                         timeout_seconds=timeout_seconds,
                         deadlock_proven=False)
            raise
        except asyncio.CancelledError:
            self._record("AWAIT_CANCELLED_OBSERVED", task_id=identity)
            raise

    def wrap_callback(self, callback):
        """Time only explicitly wrapped synchronous callbacks."""
        if not callable(callback):
            raise TypeError("callback_must_be_callable")

        def measured(*args, **kwargs):
            started = time.perf_counter()
            try:
                return callback(*args, **kwargs)
            finally:
                elapsed = time.perf_counter() - started
                if elapsed >= self.slow_callback_seconds:
                    self._record("SLOW_SYNCHRONOUS_CALLBACK",
                                 observed_milliseconds=round(elapsed * 1000, 3),
                                 callback_source_disclosed=False,
                                 cause_of_slowness_verified=False)

        return measured

    def lock(self, label):
        """Allocate an explicitly instrumented lock; labels are never exposed."""
        if len(self._locks) >= MAX_INSTRUMENTED_LOCKS:
            raise ValueError("instrumented_lock_limit")
        if not isinstance(label, str) or not 0 < len(label) <= 64:
            raise ValueError("invalid_lock_label")
        lock = TrackedAsyncLock(self, len(self._locks) + 1)
        self._locks.append(lock)
        return lock

    def probe_thread_race(self, workers=2, rounds=8):
        """Integrate both real-thread race evidence and lock-protected control."""
        unsafe = run_trusted_counter_probe(workers, rounds, protected=False)
        protected = run_trusted_counter_probe(workers, rounds, protected=True)
        verified = (unsafe["status"] == "OBSERVED_EXPECTED_CONTROLLED_RESULT" and
                    protected["status"] == "OBSERVED_EXPECTED_CONTROLLED_RESULT")
        if verified:
            self._record("INSTRUMENTED_THREAD_COUNTER_RACE_OBSERVED",
                         workers=workers, rounds=rounds,
                         unsafe_lost_updates=unsafe["lost_updates"],
                         locked_lost_updates=protected["lost_updates"],
                         arbitrary_shared_state_verified=False)
        return {"status": "CONTROLLED_RACE_DETECTED" if verified else "INCONCLUSIVE",
                "unsafe": unsafe, "locked_control": protected,
                "arbitrary_shared_state_verified": False}

    def wait_graph(self):
        """Observed task->owner wait edges; never infer untracked dependencies."""
        edges = []
        for waiter, lock in list(self._waits.items()):
            if lock.owner is not None:
                edges.append({"waiter": self.task_id(waiter),
                              "owner": self.task_id(lock.owner),
                              "lock": lock.public_id})
        return sorted(edges, key=lambda item: (item["waiter"], item["lock"]))

    def detect_lock_cycles(self):
        """Find actual wait-for cycles among tracked locks, not all Python locks."""
        relationships = {}
        for waiter, lock in list(self._waits.items()):
            if lock.owner is not None:
                relationships[self.task_id(waiter)] = self.task_id(lock.owner)
        new_cycles = []
        for start in relationships:
            path, seen = [], {}
            current = start
            while current in relationships and current not in seen:
                seen[current] = len(path)
                path.append(current)
                current = relationships[current]
            if current in seen:
                cycle = tuple(sorted(path[seen[current]:]))
                if cycle not in self._cycles:
                    self._cycles.add(cycle)
                    new_cycles.append(cycle)
                    self._record("TRACKED_LOCK_WAIT_CYCLE", tasks=list(cycle),
                                 all_python_locks_observed=False,
                                 global_deadlock_proven=False,
                                 race_condition_verified=False)
        return new_cycles

    def report(self):
        return {"status": "PARTIAL_RUNTIME_DIAGNOSTICS",
                "events": list(self.events), "event_count": len(self.events),
                "overflow_events": self.overflow_events,
                "wait_graph": self.wait_graph(),
                "tracked_locks": len(self._locks),
                "untracked_tasks_covered": False,
                "global_deadlock_proven": False,
                "race_condition_verified": False,
                "instrumented_counter_race_verified": any(
                    row["kind"] == "INSTRUMENTED_THREAD_COUNTER_RACE_OBSERVED"
                    for row in self.events),
                "untrusted_source_files_imported_or_evaled_by_detector": False,
                "supplied_callbacks_and_awaitables_run_by_application": True,
                "private_exception_messages_exposed": False}


class TrackedAsyncLock:
    """Owner and wait-for edges for a lock explicitly opted into diagnostics."""

    def __init__(self, diagnostics, number):
        self.diagnostics = diagnostics
        self.public_id = "L" + str(number)
        self._lock = asyncio.Lock()
        self.owner = None

    async def acquire(self):
        task = asyncio.current_task()
        if task is None:
            raise RuntimeError("tracked_lock_requires_task")
        if self._lock.locked():
            self.diagnostics._waits[task] = self
            self.diagnostics.detect_lock_cycles()
        try:
            acquired = await self._lock.acquire()
        finally:
            self.diagnostics._waits.pop(task, None)
        if acquired:
            self.owner = task
        return acquired

    def release(self):
        if self.owner is not asyncio.current_task():
            raise RuntimeError("tracked_lock_release_not_owner")
        self.owner = None
        self._lock.release()

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, _kind, _value, _traceback):
        self.release()

