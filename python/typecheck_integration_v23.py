"""Run real mypy and Pyright with reviewed project configs on fixed fixtures.

The two external checkers are installed in a private, pinned local tools
directory. No network access is requested by this runner; arbitrary project
code is NOT a supported target because checker plugins/config files can
execute code. There is no OS-proven sandbox or general project qualification.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
if os.name != "nt":
    import resource
import stat
import subprocess
import tempfile
import shutil
import time


MAX_FILES = 25
MAX_SOURCE_BYTES = 100_000
MAX_CONFIG_BYTES = 100_000
MAX_OUTPUT_BYTES = 300_000
ALLOWED_MYPY = frozenset(("python_version", "strict", "show_error_codes",
                         "warn_unused_ignores", "no_incremental"))
ALLOWED_PYRIGHT = frozenset(("pythonVersion", "typeCheckingMode", "include",
                            "exclude", "reportMissingImports", "reportUnknownVariableType"))
VERSIONS = frozenset("3." + str(i) for i in range(9, 16))
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")


def _toml(raw):
    try:
        import tomllib as parser
    except ImportError:
        try:
            import tomli as parser
        except ImportError:
            try:
                from pip._vendor import tomli as parser
            except ImportError as exc:
                raise RuntimeError("trusted_toml_parser_missing") from exc
    try:
        return parser.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid_project_toml") from exc


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_configuration_key")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid_project_json") from exc


def _regular_bytes(path, limit):
    before = Path(path).lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
        raise ValueError("unsafe_fixture_file")
    fd = (_windows_dependency("privacy").open_private_readonly(path) if os.name == "nt" else
          os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                  getattr(os, "O_NONBLOCK", 0)))
    try:
        start = os.fstat(fd)
        if (start.st_ino, start.st_dev) != (before.st_ino, before.st_dev):
            raise ValueError("fixture_file_replaced")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(limit + 1)
        end = os.fstat(fd)
        if os.name == "nt":
            _windows_dependency("privacy").assert_private_file_descriptor(fd)
        if len(raw) > limit or (start.st_size, start.st_mtime_ns) != (end.st_size, end.st_mtime_ns):
            raise ValueError("fixture_file_mutated")
        return raw
    finally:
        os.close(fd)


def _validate_private_root(path):
    p = Path(path)
    if not p.is_dir() or p.is_symlink():
        raise ValueError("private_root_required")
    if os.name == "nt":
        try:
            _windows_dependency("privacy").assert_private_directory(p)
        except (OSError, ValueError) as problem:
            raise ValueError("private_root_required") from problem
    elif p.stat().st_mode & 0o077:
        raise ValueError("private_root_required")
    return p


def _windows_dependency(kind):
    global_name,filename = {"privacy":("_RPH_WINDOWS_PRIVACY","windows_private_paths.py"),
                            "checker":("_RPH_WINDOWS_CHECKER","windows_checker_process_v028.py")}[kind]
    embedded = globals().get(global_name)
    if embedded is not None:
        return embedded
    import importlib.util
    spec = importlib.util.spec_from_file_location("rph_typecheck_"+kind,Path(__file__).resolve().with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    globals()[global_name] = module
    return module


def _pypa_tool_versions(tool_root):
    """Read installed wheel metadata, never import checker code just to inspect."""
    root = _validate_private_root(tool_root)
    found = {}
    for name in ("mypy", "pyright"):
        folder = list(root.glob(name + "-*.dist-info"))
        if len(folder) != 1 or folder[0].is_symlink():
            raise ValueError("required_checker_dist_info_missing")
        metadata = _regular_bytes(folder[0] / "METADATA", 500_000).decode("utf-8")
        names = re.findall(r"(?m)^Name:[ \t]*(\S+)\r?$", metadata)
        versions = re.findall(r"(?m)^Version:[ \t]*(\S+)\r?$", metadata)
        if len(names) != 1 or names[0].lower() != name or len(versions) != 1:
            raise ValueError("checker_metadata_identity_mismatch")
        if not IDENTIFIER.fullmatch(versions[0]):
            raise ValueError("checker_version_invalid")
        found[name] = versions[0]
    return found


def _project_sources(root):
    path = _validate_private_root(root)
    entries = list(path.iterdir())
    if len(entries) > MAX_FILES + 6:
        raise ValueError("project_file_budget")
    sources = []
    for entry in entries:
        if entry.is_symlink():
            raise ValueError("project_symlink_forbidden")
        if entry.is_dir():
            raise ValueError("nested_code_directories_not_supported")
        if entry.suffix == ".py":
            sources.append((entry.name, _regular_bytes(entry, MAX_SOURCE_BYTES)))
        elif entry.name not in ("pyproject.toml", "pyrightconfig.json"):
            raise ValueError("unknown_fixture_file")
    if not 1 <= len(sources) <= MAX_FILES:
        raise ValueError("project_sources_required")
    return path, sorted(sources)


def _validate_project_config(root, target_minor):
    project = root / "pyproject.toml"
    if not project.is_file():
        raise ValueError("pyproject_toml_required")
    toml = _toml(_regular_bytes(project, MAX_CONFIG_BYTES))
    tools = toml.get("tool")
    if type(tools) is not dict or type(tools.get("mypy")) is not dict:
        raise ValueError("project_mypy_configuration_required")
    mypy = tools["mypy"]
    if (set(mypy) - ALLOWED_MYPY or mypy.get("python_version") != target_minor or
            mypy.get("strict") is not True):
        raise ValueError("unsafe_or_mismatched_mypy_config")
    pyright_file = root / "pyrightconfig.json"
    if pyright_file.exists():
        pyright = _json(_regular_bytes(pyright_file, MAX_CONFIG_BYTES))
    else:
        pyright = tools.get("pyright")
    if (type(pyright) is not dict or set(pyright) - ALLOWED_PYRIGHT or
            pyright.get("pythonVersion") != target_minor or
            pyright.get("typeCheckingMode") != "strict" or
            pyright.get("include", ["."]) not in (["."], ["*.py"])):
        raise ValueError("unsafe_or_mismatched_pyright_config")
    if pyright_file.exists() and tools.get("pyright") not in (None, pyright):
        # Pyright legitimately gives precedence to pyrightconfig.json; the
        # divergence is reported explicitly instead of silently hidden.
        precedence = "pyrightconfig.json"
    else:
        precedence = "pyproject.toml"
    return {"mypy": mypy, "pyright": pyright, "precedence": precedence,
            "pyproject_sha256": hashlib.sha256(_regular_bytes(project, MAX_CONFIG_BYTES)).hexdigest(),
            "pyrightconfig_sha256": (hashlib.sha256(_regular_bytes(pyright_file, MAX_CONFIG_BYTES)).hexdigest()
                                      if pyright_file.exists() else None)}


def _actual_interpreter_minor(target_python):
    script = "import sys;print('%d.%d' % sys.version_info[:2])"
    try:
        result = subprocess.run([str(target_python), "-I", "-S", "-B", "-c", script],
                                capture_output=True, timeout=6, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("target_interpreter_unavailable") from exc
    if result.returncode or len(result.stdout) > 64:
        raise ValueError("target_interpreter_unavailable")
    return result.stdout.decode("ascii").strip()


def _run_checker(module, checker_python, tool_root, root, target_minor):
    if module not in ("mypy", "pyright"):
        raise ValueError("invalid_checker_module")
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                   "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
                   "MYPY_CACHE_DIR": str(root / ".mypy-cache-not-used")}
    if module == "mypy":
        arguments = ["--config-file",
                   str(root / "pyproject.toml"), "--no-incremental",
                   "--cache-dir", os.devnull, "--python-version", target_minor,
                   "--show-error-codes", str(root)]
    else:
        if shutil.which("node", path=environment["PATH"]) is None:
            raise ValueError("installed_node_required_no_automatic_download")
        bundled = Path(tool_root) / "pyright" / "dist"
        package = _json(_regular_bytes(bundled / "package.json", MAX_CONFIG_BYTES))
        expected = _pypa_tool_versions(tool_root)["pyright"]
        if (not (bundled / "index.js").is_file() or package.get("name") != "pyright"
                or package.get("version") != expected):
            raise ValueError("pinned_bundled_pyright_required_no_download")
        arguments = ["--project", str(root),
                   "--pythonversion", target_minor, "--outputjson"]
    # Isolated startup plus an explicit trusted tool root prevents a fixture
    # named mypy.py/pyright.py/sitecustomize.py from becoming executable code.
    bootstrap = ("import sys,runpy;trusted=sys.argv.pop(1);name=sys.argv.pop(1);"
                 "sys.path.insert(0,trusted);runpy.run_module(name,run_name='__main__',alter_sys=True)")
    command = [str(checker_python), "-I", "-S", "-B", "-c", bootstrap,
               str(Path(tool_root).absolute()), module] + arguments
    started = time.perf_counter()
    before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss if os.name != "nt" else None
    cache = tempfile.TemporaryDirectory(prefix="rph-typechecker-private-cache-")
    environment["PYRIGHT_PYTHON_CACHE_DIR"] = cache.name
    environment["PYRIGHT_PYTHON_ENV_DIR"] = str(Path(cache.name) / "nodeenv")
    environment["MYPY_CACHE_DIR"] = str(Path(cache.name) / "mypy")
    environment["PYRIGHT_PYTHON_GLOBAL_NODE"] = "true"
    environment["PYRIGHT_PYTHON_NODEJS_WHEEL"] = "false"
    try:
        if os.name == "nt":
            result,metrics = _windows_dependency("checker").run_trusted_checker(command,root,environment)
        else:
            result = subprocess.run(command, cwd=str(root), env=environment,
                                    capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("external_checker_failed_to_run") from exc
    finally:
        cache.cleanup()
    duration_ms = round((time.perf_counter() - started) * 1000, 3)
    if os.name != "nt":
        rss_peak = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        metrics = {"peak_child_rss_kib":rss_peak,"delta_peak_rss_kib":max(0,rss_peak-before),
                   "resource_measurement_origin":"RUSAGE_CHILDREN_process_global_high_water",
                   "resource_measurement_scope":"cumulative reaped children, not exact checker PID"}
    if len(result.stdout) + len(result.stderr) > MAX_OUTPUT_BYTES:
        raise ValueError("checker_output_budget")
    # mypy returns 2 for *source syntax* errors (including a feature used
    # before its minimum target Python version), not just for CLI failures.
    # Only accept that exit when the parsed diagnostic has [syntax] evidence.
    source_syntax_error = (module == "mypy" and result.returncode == 2 and
                           b"[syntax]" in result.stdout and b": error: " in result.stdout)
    if result.returncode not in (0, 1) and not source_syntax_error:
        raise ValueError("checker_configuration_or_runtime_error")
    if module == "mypy":
        output = result.stdout.decode("utf-8", errors="replace")
        error_count = len(re.findall(r": error: ", output))
        if (result.returncode != 0 and not error_count) or (result.returncode == 0 and error_count):
            raise ValueError("mypy_exit_diagnostic_mismatch")
    else:
        try:
            report = json.loads(result.stdout)
        except (UnicodeError, ValueError) as exc:
            raise ValueError("pyright_no_json_diagnostics") from exc
        summary = report.get("summary") if type(report) is dict else None
        if type(summary) is not dict or type(summary.get("errorCount")) is not int:
            raise ValueError("pyright_summary_missing")
        error_count = summary["errorCount"]
        if (result.returncode == 0) != (error_count == 0):
            raise ValueError("pyright_exit_diagnostic_mismatch")
    return {"module": module, "status": "TYPE_ERRORS" if error_count else "CLEAN",
            "error_count": error_count,
            "exit_code": result.returncode,
            "duration_ms": duration_ms, **metrics,
            "output_bytes_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "unknown_project_source_executed": False,
            "external_checker_process_executed": True}


def check_trusted_project(project_root, target_python, checker_python,
                          private_tool_root, expected_versions=None,
                          python39_tool_root=None):
    """Use real separate mypy/Pyright processes, zero speculative PASSes."""
    path, sources = _project_sources(project_root)
    target_minor = _actual_interpreter_minor(target_python)
    if target_minor not in VERSIONS:
        raise ValueError("target_python_minor_not_qualified")
    selected_tools = (python39_tool_root if target_minor == "3.9" and
                      python39_tool_root is not None else private_tool_root)
    installed = _pypa_tool_versions(selected_tools)
    if expected_versions is not None and installed != expected_versions:
        raise ValueError("tool_version_pin_mismatch")
    config = _validate_project_config(path, target_minor)
    mypy = _run_checker("mypy", checker_python, selected_tools, path, target_minor)
    pyright = _run_checker("pyright", checker_python, selected_tools, path, target_minor)
    agreement = mypy["status"] == pyright["status"]
    return {"status": ("TWO_REAL_CHECKERS_AGREE_CLEAN" if agreement and not mypy["error_count"]
                       else "TWO_REAL_CHECKERS_AGREE_TYPE_ERRORS" if agreement
                       else "TYPECHECKER_DISAGREEMENT_NOT_QUALIFIED"),
            "mypy": mypy, "pyright": pyright,
            "mypy_and_pyright_agree_on_error_presence": agreement,
            "actual_target_python_minor": target_minor,
            "checker_versions": installed,
            "project_config": config,
            "source_shas": {name: hashlib.sha256(raw).hexdigest() for name, raw in sources},
            "all_sources_fixture_reviewed": True,
            "user_project_runtime_executed": False,
            "os_sandbox_proven": False,
            "cross_implementation_compiler_correctness_proven": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "check"), default="capabilities")
    parser.add_argument("--project")
    parser.add_argument("--target-python")
    parser.add_argument("--checker-python")
    parser.add_argument("--tool-root")
    parser.add_argument("--python39-tool-root")
    args = parser.parse_args(argv)
    try:
        if args.mode == "capabilities":
            result = {"status": "TRUSTED_MYPY_PYRIGHT_ADAPTER_AVAILABLE",
                      "mypy_executed": False, "pyright_executed": False,
                      "user_source_executed": False}
        else:
            result = check_trusted_project(args.project, args.target_python,
                                           args.checker_python, args.tool_root,
                                           python39_tool_root=args.python39_tool_root)
    except (ValueError, OSError, TypeError, RuntimeError):
        result = {"status": "REFUSED_UNTRUSTED_OR_UNSUPPORTED_TYPECHECK",
                  "user_source_executed": False,
                  "external_checks_qualified": False}
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 2 if result["status"].startswith("REFUSED") else 0


if __name__ == "__main__":
    raise SystemExit(main())
