"""Real CPython 3.13t--3.15t GIL and curated native thread-safety evidence.

Only this interpreter's actual no-GIL build and one hardcoded C fixture are
tested. The module never builds, imports, or executes submitted native code.
It does not assert that arbitrary third-party wheels are thread-safe.
"""

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time


NATIVE_MODULE = "rph_v23_ft_native"
MAX_THREADS = 8
MAX_OPERATIONS_PER_THREAD = 10000
_COMPILER_PATHS = (Path("/usr/bin/cc"), Path("/usr/bin/gcc"))

_NATIVE_ATOMIC_AND_LOCKED = r'''
#include <Python.h>
#include <pythread.h>
#include <stdatomic.h>

typedef struct {
    atomic_ullong atomic_counter;
    unsigned long long locked_counter;
    PyThread_type_lock lock;
} CounterState;

static PyObject* bump_atomic(PyObject *self, PyObject *unused) {
    CounterState *state = (CounterState *)PyModule_GetState(self);
    if (state == NULL) return NULL;
    Py_BEGIN_ALLOW_THREADS
    atomic_fetch_add_explicit(&state->atomic_counter, 1, memory_order_relaxed);
    Py_END_ALLOW_THREADS
    Py_RETURN_NONE;
}

static PyObject* bump_locked(PyObject *self, PyObject *unused) {
    CounterState *state = (CounterState *)PyModule_GetState(self);
    if (state == NULL || state->lock == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "fixture lock missing");
        return NULL;
    }
    Py_BEGIN_ALLOW_THREADS
    PyThread_acquire_lock(state->lock, WAIT_LOCK);
    state->locked_counter += 1;
    PyThread_release_lock(state->lock);
    Py_END_ALLOW_THREADS
    Py_RETURN_NONE;
}

static PyObject* snapshot(PyObject *self, PyObject *unused) {
    CounterState *state = (CounterState *)PyModule_GetState(self);
    unsigned long long locked;
    unsigned long long atomic_count;
    if (state == NULL || state->lock == NULL) return NULL;
    Py_BEGIN_ALLOW_THREADS
    PyThread_acquire_lock(state->lock, WAIT_LOCK);
    locked = state->locked_counter;
    PyThread_release_lock(state->lock);
    atomic_count = atomic_load_explicit(&state->atomic_counter, memory_order_relaxed);
    Py_END_ALLOW_THREADS
    return Py_BuildValue("KK", atomic_count, locked);
}

static int mod_exec(PyObject *module) {
    CounterState *state = (CounterState *)PyModule_GetState(module);
    if (state == NULL) return -1;
    atomic_init(&state->atomic_counter, 0);
    state->locked_counter = 0;
    state->lock = PyThread_allocate_lock();
    if (state->lock == NULL) {
        PyErr_SetString(PyExc_MemoryError, "fixture lock allocation failed");
        return -1;
    }
    return PyModule_AddStringConstant(module, "fixture_kind", "ATOMIC_AND_LOCKED_CURATED");
}

static void mod_free(void *module) {
    CounterState *state = (CounterState *)PyModule_GetState((PyObject *)module);
    if (state != NULL && state->lock != NULL) {
        PyThread_free_lock(state->lock);
        state->lock = NULL;
    }
}

static PyMethodDef methods[] = {
    {"bump_atomic", bump_atomic, METH_NOARGS, "C11 atomic increment, GIL detached"},
    {"bump_locked", bump_locked, METH_NOARGS, "Native lock increment, GIL detached"},
    {"snapshot", snapshot, METH_NOARGS, "Read both counters safely"},
    {NULL, NULL, 0, NULL}
};

static PyModuleDef_Slot slots[] = {
    {Py_mod_exec, mod_exec},
#ifdef Py_mod_multiple_interpreters
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
#endif
#ifdef Py_mod_gil
    {Py_mod_gil, Py_MOD_GIL_NOT_USED},
#endif
    {0, NULL}
};

static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT,
    "rph_v23_ft_native", NULL, sizeof(CounterState), methods, slots,
    NULL, NULL, mod_free
};

PyMODINIT_FUNC PyInit_rph_v23_ft_native(void) {
    return PyModuleDef_Init(&module_def);
}
'''


def actual_free_threaded_runtime():
    """Triangulate actual CPython sysconfig, SOABI and live GIL status."""
    soabi = sysconfig.get_config_var("SOABI")
    free_abi = isinstance(soabi, str) and bool(re.search(r"cpython-3\d{2}t(?:-|$)", soabi))
    compile_flag = bool(sysconfig.get_config_var("Py_GIL_DISABLED"))
    inspect_gil = getattr(sys, "_is_gil_enabled", None)
    gil_enabled = inspect_gil() if callable(inspect_gil) else None
    actual_supported = (sys.implementation.name == "cpython" and
                        sys.platform == "linux" and
                        sys.version_info[:2] in ((3, 13), (3, 14), (3, 15)) and
                        compile_flag and free_abi and gil_enabled is False)
    return {"status": "ACTUAL_FREE_THREADED_NO_GIL_RUNNING" if actual_supported else
            "NOT_RUNNING_SUPPORTED_FREE_THREADED_BUILD",
            "python": "{}.{}.{}".format(*sys.version_info[:3]),
            "implementation": sys.implementation.name,
            "platform": sys.platform,
            "soabi": soabi, "py_gil_disabled_compile_flag": compile_flag,
            "soabi_has_free_threaded_suffix": free_abi,
            "actual_gil_enabled": gil_enabled,
            "python_minor": "{}.{}".format(*sys.version_info[:2]),
            "free_threaded_build_verified": actual_supported,
            "unknown_package_threadsafety_proven": False}


def _compiler():
    for candidate in _COMPILER_PATHS:
        try:
            st = candidate.stat()
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and os.access(str(candidate), os.X_OK):
            return str(candidate)
    return None


def _compile_curated_native(folder, compiler):
    if compiler not in (str(item) for item in _COMPILER_PATHS):
        raise ValueError("untrusted_compiler_path_refused")
    include = sysconfig.get_path("include")
    suffix = sysconfig.get_config_var("EXT_SUFFIX")
    if (not isinstance(include, str) or not Path(include, "Python.h").is_file() or
            not isinstance(suffix, str) or not suffix.endswith(".so") or
            "t" not in suffix):
        raise ValueError("free_threaded_headers_or_suffix_missing")
    source = Path(folder) / "rph_v23_ft_native.c"
    binary = Path(folder) / (NATIVE_MODULE + suffix)
    source.write_text(_NATIVE_ATOMIC_AND_LOCKED, encoding="utf-8")
    done = subprocess.run([compiler, "-shared", "-fPIC", "-O2", "-std=c11", "-pthread",
                           "-I", include, "-o", str(binary), str(source)],
                          cwd=str(folder), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          stdin=subprocess.DEVNULL, timeout=20, check=False)
    if (done.returncode != 0 or not binary.is_file() or
            binary.stat().st_size > 8_000_000 or not
            binary.read_bytes().startswith(b"\x7fELF")):
        raise RuntimeError("curated_native_compile_failed")
    return binary


def verify_native_counts(expected, atomic_count, locked_count):
    """Fail closed on independently different counts or invalid evidence."""
    values = (expected, atomic_count, locked_count)
    if any(type(value) is not int or value < 0 or value > 1_000_000 for value in values):
        return {"status": "NO_EVIDENCE_NO_PASS", "matched": False}
    matched = expected == atomic_count == locked_count
    return {"status": "TWO_INDEPENDENT_NATIVE_COUNTERS_MATCH" if matched else
            "NATIVE_CONCURRENCY_MISMATCH_REJECTED", "matched": matched,
            "expected": expected, "atomic": atomic_count, "locked": locked_count}


def native_thread_safety_probe(threads=4, operations=2000, inject_missing_call=False):
    """Real C11 atomic and native-lock work by several no-GIL OS threads."""
    runtime = actual_free_threaded_runtime()
    if runtime["status"] != "ACTUAL_FREE_THREADED_NO_GIL_RUNNING":
        return {"status": "NOT_RUN_NO_REAL_FREE_THREADED_INTERPRETER",
                "runtime": runtime, "unknown_native_package_imported": False}
    if (type(threads) is not int or type(operations) is not int or
            not 2 <= threads <= MAX_THREADS or
            not 10 <= operations <= MAX_OPERATIONS_PER_THREAD or
            type(inject_missing_call) is not bool):
        raise ValueError("unsafe_or_invalid_threads_fixture_limits")
    compiler = _compiler()
    if compiler is None:
        return {"status": "NOT_RUN_TRUSTED_C_COMPILER_MISSING", "runtime": runtime}
    with tempfile.TemporaryDirectory(prefix="rph-v23-real-nogil-") as folder:
        native_path = _compile_curated_native(folder, compiler)
        spec = importlib.util.spec_from_file_location(NATIVE_MODULE, str(native_path))
        if spec is None or spec.loader is None:
            raise ValueError("trusted_extension_loader_unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        after_import = actual_free_threaded_runtime()
        if after_import["actual_gil_enabled"] is not False:
            return {"status": "NATIVE_EXTENSION_ENABLED_GIL_REJECTED",
                    "runtime": runtime, "after_import": after_import,
                    "unknown_native_package_imported": False}
        barrier = threading.Barrier(threads)
        discovered = set()
        observed_lock = threading.Lock()
        caught = []
        start = time.monotonic()

        def worker(index):
            with observed_lock:
                discovered.add(threading.get_ident())
            try:
                barrier.wait(timeout=5)
                for number in range(operations):
                    # A deterministic omission tests the gate; never invoke
                    # undefined-behaviour/data-racing native C code.
                    if inject_missing_call and index == 0 and number == 0:
                        continue
                    module.bump_atomic()
                    module.bump_locked()
            except (Exception, RuntimeError) as error:
                caught.append(type(error).__name__)

        workers = [threading.Thread(target=worker, args=(index,), daemon=True)
                   for index in range(threads)]
        for item in workers:
            item.start()
        for item in workers:
            item.join(timeout=15)
        alive = any(item.is_alive() for item in workers)
        elapsed = time.monotonic() - start
        atomic_count, locked_count = module.snapshot()
        expected = threads * operations
        oracle = verify_native_counts(expected, atomic_count, locked_count)
        no_gil_after = actual_free_threaded_runtime()["actual_gil_enabled"] is False
        success = (oracle["matched"] and not caught and not alive and no_gil_after and
                   len(discovered) == threads and not inject_missing_call)
        return {"status": "REAL_NO_GIL_NATIVE_THREAD_SAFETY_FIXTURE_VERIFIED" if success
                else "NATIVE_TEST_MUTANT_REJECTED" if inject_missing_call and not oracle["matched"]
                else "NATIVE_THREAD_SAFETY_NOT_VERIFIED",
                "runtime": runtime,
                "free_threaded_verified_before_import": True,
                "gil_remained_disabled_after_native_import": no_gil_after,
                "actual_distinct_os_thread_ids": len(discovered),
                "threads": threads, "operations_per_thread": operations,
                "real_native_function_calls_requested": 2 * expected,
                "count_oracle": oracle,
                "elapsed_ms": round(elapsed * 1000, 3),
                "worker_errors": caught[:4], "threads_still_alive": alive,
                "mutant_injection": inject_missing_call,
                "native_fixture_kind": module.fixture_kind,
                "third_party_native_packages_qualified": False,
                "unknown_project_or_package_source_compiled": False,
                "native_extension_loaded_from_curated_local_fixture": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("runtime", "native", "mutant"),
                        default="runtime")
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--operations", type=int, default=2000)
    args = parser.parse_args(argv)
    try:
        result = (actual_free_threaded_runtime() if args.mode == "runtime" else
                  native_thread_safety_probe(args.threads, args.operations,
                                             inject_missing_call=args.mode == "mutant"))
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        result = {"status": "NO_EVIDENCE_NO_PASS", "unknown_source_executed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] not in ("NO_EVIDENCE_NO_PASS",
                                           "NATIVE_THREAD_SAFETY_NOT_VERIFIED",
                                           "NATIVE_EXTENSION_ENABLED_GIL_REJECTED") else 2


if __name__ == "__main__":
    raise SystemExit(main())
