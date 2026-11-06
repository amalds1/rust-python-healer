"""Trusted v0.21 runtime probes and read-only Python ecosystem inspection.

Never import/exec supplied source, notebook cells, project configs or arbitrary
test commands.  Any subprocess receives a FIXED local program selected from
an internal allowlist.  TaskGroup and forkserver probes execute only trusted
fixture code.  No claim of general sandboxing or arbitrary-code correctness.
"""

import argparse
import ast
import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_TEXT_BYTES = 131_072
MAX_CONFIG_BYTES = 16_384
MAX_CELLS = 64
MAX_CELL_BYTES = 16_384
MAX_DISCOVERY_ENTRIES = 128
MAX_CHILD_SECONDS = 8

TRUSTED_TASKGROUP = '''import asyncio, json, sys
if sys.version_info < (3, 11):
    print(json.dumps({"status": "NOT_SUPPORTED", "reason": "taskgroup_requires_3_11"}))
else:
    async def fail(kind):
        raise kind("PRIVATE_TASK_FAILURE")
    async def run():
        counts = {"value": 0, "type": 0}
        try:
            async with asyncio.TaskGroup() as group:
                group.create_task(fail(ValueError))
                group.create_task(fail(TypeError))
        except* ValueError as caught:
            counts["value"] = len(caught.exceptions)
        except* TypeError as caught:
            counts["type"] = len(caught.exceptions)
        return counts
    async def nested():
        observed = {"inner_value": 0, "outer_type": 0}
        try:
            raise ExceptionGroup("SECRET", [ExceptionGroup("SECRET_INNER",
                                      [ValueError("SECRET_VALUE")]),
                                      TypeError("SECRET_TYPE")])
        except* ValueError as caught:
            observed["inner_value"] = len(caught.exceptions)
        except* TypeError as caught:
            observed["outer_type"] = len(caught.exceptions)
        return observed
    task = asyncio.run(run())
    sub = asyncio.run(nested())
    print(json.dumps({"status": "TRUSTED_RUNTIME_VERIFIED",
                      "taskgroup": task, "nested_group": sub,
                      "except_star_runtime_executed": True,
                      "untrusted_source_executed": False}, sort_keys=True))
'''

TRUSTED_TEST_PROGRAMS = {
    "unittest_pass": '''import json, unittest
class FixedTest(unittest.TestCase):
    def test_real_fixed_case(self):
        self.assertEqual(sum((2, 3)), 5)
suite = unittest.defaultTestLoader.loadTestsFromTestCase(FixedTest)
result = unittest.TestResult()
suite.run(result)
print(json.dumps({"passed": result.testsRun == 1 and result.wasSuccessful(),
                  "tests": result.testsRun, "failures": len(result.failures)}))
''',
    "unittest_negative": '''import json, unittest
class FixedTest(unittest.TestCase):
    def test_expected_failure(self):
        self.assertEqual(2 + 2, 5)
suite = unittest.defaultTestLoader.loadTestsFromTestCase(FixedTest)
result = unittest.TestResult()
suite.run(result)
print(json.dumps({"passed": result.wasSuccessful(),
                  "tests": result.testsRun, "failures": len(result.failures)}))
''',
    "compile_positive": '''import json
compile("def trusted():\\n    return 4\\n", "<fixed>", "exec", dont_inherit=True)
print(json.dumps({"passed": True, "tests": 1, "failures": 0}))
''',
}

TRUSTED_DIFFERENTIAL = '''import json, sys
case = sys.argv[1]
FIXTURES = {
    "equivalent_add": (lambda x: x + 1, lambda x: 1 + x, (-2, 0, 5)),
    "faulty_add": (lambda x: x + 1, lambda x: x + 2, (-2, 0, 5)),
    "equivalent_error": (
        lambda x: 1 // x, lambda x: divmod(1, x)[0], (0, 1, 2)),
}
left, right, inputs = FIXTURES[case]
def evaluate(function, value):
    try:
        return ["VALUE", function(value)]
    except Exception as error:
        return ["EXCEPTION_CLASS", type(error).__name__]
observed = [(evaluate(left, value), evaluate(right, value)) for value in inputs]
print(json.dumps({"status": "MATCH" if all(a == b for a, b in observed)
                  else "DIFFERENCE", "inputs": len(inputs),
                  "identical_results": sum(a == b for a, b in observed),
                  "untrusted_source_executed": False}, sort_keys=True))
'''

TRUSTED_VERSION_PROBE = '''import json, sys
print(json.dumps({"implementation": sys.implementation.name,
                  "python_version": "%d.%d" % sys.version_info[:2]}))
'''


def _json_unique_keys(pairs):
    found = {}
    for key, value in pairs:
        if key in found:
            raise ValueError("duplicate_json_key")
        found[key] = value
    return found


def _bounded_text(value, limit=MAX_TEXT_BYTES):
    if not isinstance(value, str):
        raise TypeError("inspection_requires_utf8_text")
    try:
        raw = value.encode("utf-8")
    except UnicodeError:
        raise ValueError("invalid_inspection_unicode") from None
    if len(raw) > limit or b"\x00" in raw:
        raise ValueError("inspection_text_limit")
    return raw


def _fixed_subprocess(program, interpreter=None, arguments=()):
    """No shell, no network, no unknown command/source, minimal environment."""
    allowlisted_programs = frozenset((TRUSTED_TASKGROUP, TRUSTED_VERSION_PROBE,
                                     TRUSTED_DIFFERENTIAL,
                                     *TRUSTED_TEST_PROGRAMS.values()))
    if not isinstance(program, str) or program not in allowlisted_programs:
        raise ValueError("trusted_subprocess_program_not_allowlisted")
    executable = os.fspath(interpreter or sys.executable)
    environment = {"PATH": os.defpath, "PYTHONIOENCODING": "utf-8",
                   "PYTHONHASHSEED": "0"}
    if os.name == "nt" and os.environ.get("SystemRoot"):
        # Windows CPython asyncio/OS entropy startup needs this OS location.
        environment["SystemRoot"] = os.environ["SystemRoot"]
    try:
        child = subprocess.run(
            [executable, "-I", "-S", "-c", program, *arguments],
            capture_output=True, timeout=MAX_CHILD_SECONDS, check=False,
            env=environment)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("trusted_subprocess_unavailable_or_timeout") from None
    if child.returncode or len(child.stdout) > 4096 or len(child.stderr) > 4096:
        raise ValueError("trusted_subprocess_failed")
    try:
        result = json.loads(child.stdout, object_pairs_hook=_json_unique_keys)
    except (ValueError, UnicodeError):
        raise ValueError("trusted_subprocess_invalid_json") from None
    if not isinstance(result, dict):
        raise TypeError("trusted_subprocess_invalid_shape")
    return result


def probe_exceptiongroups(interpreter=None):
    """Real TaskGroup, nested ExceptionGroup, except* on selected CPython."""
    version_probe = _fixed_subprocess(TRUSTED_VERSION_PROBE, interpreter)
    version = version_probe.get("python_version")
    if (version_probe.get("implementation") != "cpython" or
            not isinstance(version, str) or not re.fullmatch(r"3\.[0-9]{1,2}", version)):
        raise ValueError("trusted_python_version_unknown")
    minor = int(version.split(".")[1])
    if minor < 11:
        return {"status": "NOT_SUPPORTED", "reason": "taskgroup_requires_3_11",
                "trusted_fixture_executed": False, "user_source_executed": False}
    result = _fixed_subprocess(TRUSTED_TASKGROUP, interpreter)
    if result.get("status") == "NOT_SUPPORTED":
        return {"status": "NOT_SUPPORTED", "reason": "taskgroup_requires_3_11",
                "trusted_fixture_executed": False, "user_source_executed": False}
    if (result.get("status") != "TRUSTED_RUNTIME_VERIFIED" or
            result.get("taskgroup") != {"value": 1, "type": 1} or
            result.get("nested_group") != {"inner_value": 1, "outer_type": 1} or
            result.get("except_star_runtime_executed") is not True or
            result.get("untrusted_source_executed") is not False):
        raise ValueError("trusted_exceptiongroup_runtime_mismatch")
    return {"status": "TRUSTED_RUNTIME_VERIFIED", "taskgroup": result["taskgroup"],
            "nested_group": result["nested_group"],
            "except_star_runtime_executed": True,
            "trusted_fixture_executed": True, "user_source_executed": False,
            "arbitrary_async_project_verified": False}


def _parse_only(source):
    raw = _bounded_text(source, MAX_CELL_BYTES)
    try:
        ast.parse(source, filename="<offline-cell>", mode="exec")
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return "INVALID_OR_UNSUPPORTED_SYNTAX"
    if not raw.strip():
        return "EMPTY"
    return "PYTHON_SYNTAX_VALID"


def inspect_notebook(text):
    """Read notebook cells and parse Python syntax, never run magic or code."""
    raw = _bounded_text(text)
    try:
        notebook = json.loads(raw, object_pairs_hook=_json_unique_keys,
                              parse_constant=lambda _: (_ for _ in ()).throw(
                                  ValueError("invalid_json_number")))
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("invalid_notebook_json") from None
    if (not isinstance(notebook, dict) or type(notebook.get("nbformat")) is not int or
            notebook["nbformat"] != 4 or not isinstance(notebook.get("cells"), list) or
            len(notebook["cells"]) > MAX_CELLS):
        raise ValueError("invalid_bounded_notebook_schema")
    results = []
    for index, cell in enumerate(notebook["cells"]):
        if not isinstance(cell, dict) or cell.get("cell_type") not in ("code", "markdown", "raw"):
            raise ValueError("invalid_cell_schema")
        if cell["cell_type"] != "code":
            continue
        source = cell.get("source")
        if isinstance(source, list) and all(isinstance(item, str) for item in source):
            source = "".join(source)
        if not isinstance(source, str):
            raise TypeError("invalid_cell_source")
        _bounded_text(source, MAX_CELL_BYTES)
        if any(line.lstrip().startswith(("%", "!")) for line in source.splitlines()):
            status = "IPYTHON_MAGIC_NOT_PYTHON_AST"
        else:
            status = _parse_only(source)
        results.append({"cell_index": index, "static_syntax_status": status,
                        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest()})
    return {"status": "STATIC_NOTEBOOK_INSPECTION", "code_cells": len(results),
            "results": results, "notebook_executed": False,
            "extensions_loaded": False, "runtime_package_imported": False}


def inspect_embedded_python(markdown):
    """Parse only fenced python/py blocks; all surrounding prose is ignored."""
    _bounded_text(markdown)
    pattern = re.compile(r"(?ms)^```(?:python|py)[ \t]*\n(.*?)^```[ \t]*$")
    fragments = pattern.findall(markdown)
    if len(fragments) > MAX_CELLS:
        raise ValueError("embedded_cell_count_limit")
    results = []
    for index, fragment in enumerate(fragments):
        results.append({"cell_index": index, "static_syntax_status": _parse_only(fragment),
                        "source_sha256": hashlib.sha256(fragment.encode("utf-8")).hexdigest()})
    return {"status": "STATIC_EMBEDDED_INSPECTION", "code_cells": len(results),
            "results": results, "source_executed": False}


def run_allowlisted_test(case_id, interpreter=None):
    """Only fixed programs in this module; no command string is accepted."""
    if not isinstance(case_id, str) or case_id not in TRUSTED_TEST_PROGRAMS:
        raise ValueError("test_case_not_allowlisted")
    result = _fixed_subprocess(TRUSTED_TEST_PROGRAMS[case_id], interpreter)
    if (type(result.get("passed")) is not bool or
            type(result.get("tests")) is not int or not 0 < result["tests"] <= 4 or
            type(result.get("failures")) is not int or
            not 0 <= result["failures"] <= result["tests"]):
        raise ValueError("trusted_test_invalid_response")
    return {"status": "TRUSTED_TEST_PASS" if result["passed"] else "TRUSTED_TEST_FAIL",
            "case_id": case_id, "tests_run": result["tests"],
            "failure_count": result["failures"], "user_code_executed": False,
            "shell_invoked": False, "fixture_executed": True}


def probe_fixed_differential(case_id, interpreter=None):
    """Compare only hardcoded original/candidate functions on fixed inputs."""
    if case_id not in ("equivalent_add", "faulty_add", "equivalent_error") or not isinstance(
            case_id, str):
        raise ValueError("differential_case_not_allowlisted")
    result = _fixed_subprocess(TRUSTED_DIFFERENTIAL, interpreter, (case_id,))
    if (result.get("status") not in ("MATCH", "DIFFERENCE") or
            result.get("inputs") != 3 or
            type(result.get("identical_results")) is not int or
            not 0 <= result["identical_results"] <= 3 or
            result.get("untrusted_source_executed") is not False):
        raise ValueError("trusted_differential_invalid_response")
    equivalent = result["status"] == "MATCH"
    if equivalent != (result["identical_results"] == result["inputs"]):
        raise ValueError("trusted_differential_inconsistent")
    return {"status": "MATCHED_TRUSTED_CASES" if equivalent else "DIFFERENCE_DETECTED",
            "case_id": case_id, "input_cases": result["inputs"],
            "matching_cases": result["identical_results"],
            "untrusted_source_executed": False,
            "arbitrary_program_equivalence_proven": False}


def _read_config(path):
    """No-follow, regular-file-only bounded read, with change detection."""
    if path.is_symlink():
        raise ValueError("discovery_config_symlink_refused")
    try:
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                             getattr(os, "O_NONBLOCK", 0))
    except OSError:
        raise ValueError("discovery_config_unreadable") from None
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_size > MAX_CONFIG_BYTES):
            raise ValueError("discovery_config_not_unique_bounded_regular_file")
        raw = stream.read(MAX_CONFIG_BYTES + 1)
        after = os.fstat(stream.fileno())
        def identity(item):
            return (item.st_dev, item.st_ino, item.st_size,
                    item.st_mtime_ns, item.st_ctime_ns)
        if len(raw) > MAX_CONFIG_BYTES or identity(before) != identity(after):
            raise ValueError("discovery_config_changed_or_oversized")
    try:
        return raw.decode("utf-8")
    except UnicodeError:
        raise ValueError("discovery_config_invalid_utf8") from None


def discover_test_frameworks(project_directory):
    """Read fixed config names and tests/ file names; never import or run."""
    root = Path(project_directory)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("discovery_root_invalid_or_symlink")
    config = {}
    for name in ("pytest.ini", "tox.ini", "noxfile.py", "pyproject.toml", "setup.cfg"):
        path = root / name
        if path.exists() or path.is_symlink():
            config[name] = _read_config(path)
    tests = root / "tests"
    unittest_file_count = 0
    if tests.is_symlink():
        raise ValueError("discovery_tests_symlink_refused")
    if tests.exists():
        if not tests.is_dir():
            raise ValueError("discovery_tests_not_directory")
        with os.scandir(tests) as iterator:
            for number, entry in enumerate(iterator):
                if number >= MAX_DISCOVERY_ENTRIES:
                    raise ValueError("discovery_tests_entry_limit")
                if (entry.name.startswith("test_") and entry.name.endswith(".py") and
                        entry.is_file(follow_symlinks=False)):
                    unittest_file_count += 1
    pytest = bool(re.search(r"(?m)^\s*\[pytest\]\s*$", config.get("pytest.ini", "")) or
                  re.search(r"(?m)^\s*\[tool\.pytest\.ini_options\]\s*$",
                            config.get("pyproject.toml", "")) or
                  re.search(r"(?m)^\s*\[tool:pytest\]\s*$", config.get("setup.cfg", "")))
    tox = bool(re.search(r"(?m)^\s*\[tox\]\s*$", config.get("tox.ini", "")) or
               re.search(r"(?m)^\s*\[tool\.tox\]\s*$", config.get("pyproject.toml", "")))
    nox = "noxfile.py" in config
    return {"status": "READ_ONLY_FRAMEWORK_DISCOVERY",
            "frameworks": {"pytest": pytest, "unittest": unittest_file_count > 0,
                           "tox": tox, "nox": nox},
            "unittest_pattern_files": unittest_file_count,
            "configuration_files_observed": sorted(config),
            "configs_executed_or_imported": False,
            "test_commands_executed": False,
            "arbitrary_framework_support_verified": False}


def probe_injected_failure(case_id):
    """Real bounded trusted in-memory DB and temporary-file rollback fixtures."""
    known = ("sqlite_rollback", "network_stub", "update_rollback",
             "update_broken_rollback")
    if not isinstance(case_id, str) or case_id not in known:
        raise ValueError("failure_injection_case_not_allowlisted")
    if case_id == "sqlite_rollback":
        connection = sqlite3.connect(":memory:")
        try:
            connection.execute("CREATE TABLE state(version INTEGER NOT NULL)")
            try:
                with connection:
                    connection.execute("INSERT INTO state VALUES(99)")
                    raise RuntimeError("trusted_injected_db_error")
            except RuntimeError:
                pass
            recovered = connection.execute("SELECT COUNT(*) FROM state").fetchone()[0] == 0
        finally:
            connection.close()
        observed = {"table_rows_after_failure": 0 if recovered else 1,
                    "sqlite_transaction_rolled_back": recovered}
    elif case_id == "network_stub":
        class TrustedNetworkStub:
            def __init__(self):
                self.calls = 0

            def fetch(self):
                self.calls += 1
                raise ConnectionError("trusted_injected_network_failure")

        client = TrustedNetworkStub()
        try:
            client.fetch()
        except ConnectionError:
            recovered = True
        else:
            recovered = False
        observed = {"stub_calls": client.calls, "actual_network_used": False,
                    "injected_connection_failure_caught": recovered}
    else:
        with tempfile.TemporaryDirectory(prefix="trusted_v21_update_") as temporary:
            target = Path(temporary) / "state.txt"
            backup = Path(temporary) / "backup.txt"
            original = b"TRUSTED_LAST_KNOWN_GOOD"
            target.write_bytes(original)
            backup.write_bytes(original)
            try:
                target.write_bytes(b"TRUSTED_NEW_STAGE")
                raise RuntimeError("trusted_update_failure")
            except RuntimeError:
                if case_id == "update_rollback":
                    os.replace(backup, target)
            recovered = target.read_bytes() == original
        observed = {"restored_previous_bytes": recovered,
                    "only_temporary_fixture_files_touched": True}
    return {"status": "INJECTED_FAILURE_RECOVERED" if recovered else
            "INJECTED_FAILURE_NOT_RECOVERED",
            "case_id": case_id, "observations": observed,
            "unknown_source_executed": False, "network_used": False,
            "user_files_modified": False,
            "production_failure_paths_verified": False}


def _forkserver_worker(results):
    """Only this trusted, importable module target runs inside forkserver."""
    results.put(os.getpid())


def _trusted_forkserver_child_probe():
    import multiprocessing

    if "forkserver" not in multiprocessing.get_all_start_methods():
        return {"status": "NOT_SUPPORTED"}
    try:
        context = multiprocessing.get_context("forkserver")
        queue = context.Queue()
        child = context.Process(target=_forkserver_worker, args=(queue,))
        child.start()
        pid = queue.get(timeout=4)
        child.join(timeout=4)
        healthy = child.exitcode == 0 and isinstance(pid, int) and pid != os.getpid()
        queue.close()
    except (OSError, RuntimeError, ValueError, EOFError, TimeoutError) as failure:
        return {"status": "NOT_RUN", "reason": type(failure).__name__}
    return {"status": "TRUSTED_FORKSERVER_OBSERVED" if healthy else "NOT_RUN",
            "distinct_child_process": healthy}


def probe_forkserver(interpreter=None):
    """Runs this module's fixed process target; no arbitrary multiprocessing."""
    executable = os.fspath(interpreter or sys.executable)
    environment = {"PATH": os.defpath, "PYTHONIOENCODING": "utf-8"}
    if os.name == "nt" and os.environ.get("SystemRoot"):
        environment["SystemRoot"] = os.environ["SystemRoot"]
    try:
        completed = subprocess.run(
            [executable, "-I", "-S", str(Path(__file__).resolve()),
             "--internal-trusted-forkserver-probe"],
            capture_output=True, check=False, timeout=MAX_CHILD_SECONDS,
            env=environment)
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "NOT_RUN", "reason": "forkserver_subprocess_unavailable",
                "distinct_child_process": False,
                "arbitrary_process_start_methods_verified": False,
                "user_source_executed": False}
    if completed.returncode or len(completed.stdout) > 2048:
        return {"status": "NOT_RUN", "reason": "forkserver_probe_failed",
                "distinct_child_process": False,
                "arbitrary_process_start_methods_verified": False,
                "user_source_executed": False}
    try:
        report = json.loads(completed.stdout)
    except (ValueError, UnicodeError):
        report = {"status": "NOT_RUN"}
    if report.get("status") not in ("TRUSTED_FORKSERVER_OBSERVED", "NOT_SUPPORTED",
                                    "NOT_RUN"):
        report = {"status": "NOT_RUN"}
    return {"status": report["status"],
            "distinct_child_process": report.get("distinct_child_process", False),
            "reason": report.get("reason"),
            "user_source_executed": False,
            "arbitrary_process_start_methods_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--internal-trusted-forkserver-probe", action="store_true")
    arguments = parser.parse_args()
    if arguments.internal_trusted_forkserver_probe:
        print(json.dumps(_trusted_forkserver_child_probe(), sort_keys=True))
        return 0
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())

