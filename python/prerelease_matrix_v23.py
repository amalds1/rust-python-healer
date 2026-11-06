"""Genuine CPython alpha/beta/RC and future 3.16-alpha compile-only checks.

Four immutable, trusted local CPython binaries are probed. Their releaselevel,
micro, and serial are taken from the running interpreter, never filename alone.
One existing 100-case curated suite and additional grammar checks run without
executing unknown source. Passing 3.16a1 does NOT qualify future stable 3.16,
foreign platforms, native packages, or all intervening pre-releases.
"""

import argparse
import ast
from contextlib import contextmanager, ExitStack
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import types
import zipfile


PREVIEW_BINARIES = (
    ("3.15.0a1", 15, "alpha", 1, "python3.15"),
    ("3.15.0b1", 15, "beta", 1, "python3.15"),
    ("3.15.0rc1", 15, "candidate", 1, "python3.15"),
    ("3.16.0a1", 16, "alpha", 1, "python3.16"),
)
MAX_BINARY_BYTES = 80_000_000
MAX_CHILD_REPORT_BYTES = 32_768
TRUSTED_VERSION_SUITE_SHA256 = "6db3a07ff9177552dafaef669184aa0178a6152b0302b76810d5d20f224827ef"
WINDOWS_PREVIEW_ARCHIVES = {
    "3.15.0a1": (35723877, "f6da6369e1ee11be4490046a40988b1eb7d70fc54dfdbe770dd180fc05d16944"),
    "3.15.0b1": (48868871, "3d2eff8e413fce4ef90ba4d4dca8a66a1556991e9470a4dc7093892218703ea6"),
    "3.15.0rc1": (49204463, "c5b0d2123e74dfc806799a0c03a210e9f1fdf2fb5811b942e65751a0603e07f2"),
    "3.16.0a1": (45077498, "d70c353262f6a2ccd50cd5aa9273e22bc217a75d9ce1855b07b83fc2e6296454"),
}
# Primary references: python.org/ftp/python/{3.15.0,3.16.0}/windows-VERSION.json,
# entry pythoncore-3.MINOR-64. No caller key/pin or receipt selects these hashes.
WINDOWS_PRIVACY_SOURCE_SHA256 = "4757571c16b83bd3bfff832b9838c6f75794ccbbd16cd27f78dfd4fa7e855f43"
MAX_WINDOWS_ARCHIVE_BYTES = 60_000_000
MAX_WINDOWS_MEMBER_BYTES = 128_000_000
MAX_WINDOWS_EXPANDED_BYTES = 512_000_000

_WINDOWS_PREVIEW_CHILD = r'''
import hashlib,json,os,sys
from pathlib import Path
raw=sys.stdin.buffer.read(512001)
if len(raw)>512000: raise ValueError('preview_bootstrap_input_budget')
data=json.loads(raw)
module=data['module_source'].encode('utf-8');suite=data['suite_source'].encode('utf-8')
graph={'prerelease_matrix_v23.py':hashlib.sha256(module).hexdigest(),'version_suite.py':hashlib.sha256(suite).hexdigest()}
if graph!=data['source_graph']: raise ValueError('preview_bootstrap_graph_mismatch')
loaded={'__name__':'rph_pinned_preview_child','__file__':'<pinned-preview-snapshot>',
        '_RPH_PREVIEW_SUITE_SOURCE':suite}
exec(compile(module,'<pinned-preview-module>','exec',dont_inherit=True),loaded)
result=loaded['run_selected_preview_suite']()
print(json.dumps({'probe_schema':1,'challenge':data['challenge'],'source_graph':graph,
 'executable_sha256':hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
 'pid':os.getpid(),'ppid':os.getppid(),'result':result},sort_keys=True))
'''


def actual_release_identity():
    """Actual ``sys.version_info`` is the only release-phase authority."""
    version = sys.version_info
    label = "{}.{}.{}{}{}".format(version.major, version.minor, version.micro,
                                  {"alpha": "a", "beta": "b", "candidate": "rc",
                                   "final": ""}.get(version.releaselevel, "unknown"),
                                  "" if version.releaselevel == "final" else version.serial)
    is_preview = version.releaselevel in ("alpha", "beta", "candidate")
    return {"status": "ACTUAL_CPYTHON_PREVIEW_IDENTITY" if is_preview and
            sys.implementation.name == "cpython" else "ACTUAL_FINAL_OR_OTHER_IMPLEMENTATION",
            "implementation": sys.implementation.name,
            "major": version.major, "minor": version.minor, "micro": version.micro,
            "releaselevel": version.releaselevel, "serial": version.serial,
            "version_label": label,
            "is_prerelease": is_preview,
            "real_interpreter_executed": True,
            "supported_stable_3_16_qualified": False,
            "other_platform_executed": False}


def checked_release_expectation(expected_label):
    """Refuse a phase/version mismatch; callers cannot spoof sys.version_info."""
    if not isinstance(expected_label, str) or not re.fullmatch(r"3\.(?:15|16)\.0(?:a|b|rc)\d+", expected_label):
        raise ValueError("invalid_expected_python_preview_version")
    actual = actual_release_identity()
    matched = (actual["version_label"] == expected_label and
               actual["is_prerelease"] and actual["implementation"] == "cpython")
    return {"status": "REAL_VERSION_PHASE_MATCH" if matched else
            "WRONG_OR_MISSING_PREVIEW_INTERPRETER_REJECTED",
            "requested": expected_label,
            "actual": actual["version_label"],
            "observed_releaselevel": actual["releaselevel"],
            "matched": bool(matched),
            "phase_proof_from_sys_version_info": True,
            "binary_publisher_attested": False}


def compile_extra_grammar_oracles():
    """Actual compile + AST checks; no snippet is executed."""
    if sys.implementation.name != "cpython" or sys.version_info[:2] < (3, 15):
        return {"status": "NOT_RUN_PREVIEW_ORACLES_REQUIRE_3_15_PLUS",
                "grammar_checks": 0, "passes": 0}
    syntax_cases = (
        ("pattern_matching", "match value:\n    case 1:\n        pass", True),
        ("exception_groups", "try:\n    pass\nexcept* ValueError:\n    pass", True),
        ("generic_class", "class Box[T]:\n    pass", True),
        ("template_string", "text = t'hello {name}'", True),
        ("missing_colon", "if True\n    pass", False),
        ("invalid_name_assignment", "42 = x", False),
        ("unterminated_string", "message = 'unknown", False),
        ("await_top_level", "await task()", False),
    )
    checks = []
    for label, source, expected in syntax_cases:
        try:
            tree = ast.parse(source, filename="<curated-prerelease-{}>".format(label), mode="exec")
            compile(tree, "<curated-prerelease-{}>".format(label), "exec", dont_inherit=True)
            valid = True
        except (SyntaxError, ValueError):
            valid = False
        checks.append({"name": label, "status": "PASS" if valid == expected else "FAIL",
                       "code_executed": False})
    good = sum(item["status"] == "PASS" for item in checks)
    return {"status": "SELECTED_PRERELEASE_GRAMMAR_ORACLES_PASS" if good == len(checks)
            else "PRERELEASE_GRAMMAR_ORACLE_FAILURE",
            "grammar_checks": len(checks), "passes": good, "checks": checks,
            "curated_compile_only": True}


def _trusted_suite_path():
    module_location = globals().get("__file__")
    if not isinstance(module_location, str):
        return None
    suite = Path(module_location).resolve().parents[1] / "python" / "version_suite.py"
    if not suite.is_file() or suite.is_symlink() or suite.stat().st_size > 100_000:
        return None
    return suite


def run_selected_preview_suite():
    """Execute only known fixed project-owned 100-case stdlib fixtures."""
    actual = actual_release_identity()
    if actual["status"] != "ACTUAL_CPYTHON_PREVIEW_IDENTITY":
        return {"status": "NOT_RUN_NOT_ACTUAL_CPYTHON_PRERELEASE",
                "actual": actual, "cases_pass": 0}
    source = globals().get("_RPH_PREVIEW_SUITE_SOURCE")
    if source is None:
        suite_path = _trusted_suite_path()
        if suite_path is None:
            return {"status": "NOT_RUN_CURATED_SUITE_NOT_AVAILABLE",
                    "actual": actual, "cases_pass": 0}
        source = suite_path.read_bytes()
    if isinstance(source, str):
        source = source.encode("utf-8")
    if type(source) is not bytes or len(source) > 100_000:
        raise ValueError("invalid_pinned_preview_suite_source")
    digest = hashlib.sha256(source).hexdigest()
    if digest != TRUSTED_VERSION_SUITE_SHA256:
        return {"status": "NOT_RUN_CURATED_SUITE_SHA_MISMATCH",
                "actual": actual, "cases_pass": 0,
                "unknown_project_source_executed": False}
    loaded = {"__name__": "rph_curated_suite_only", "__builtins__": __builtins__}
    # Exactly the SHA-pinned bytes are executed; the filesystem cannot swap
    # the file between an integrity check and this compiled code object.
    exec(compile(source, "<trusted-rph-version-suite>", "exec", dont_inherit=True), loaded)
    result = loaded["run_suite"]()
    grammar = compile_extra_grammar_oracles()
    total_pass = result.get("pass") == 100 and result.get("fail") == 0 and \
        result.get("status") == "PASS" and grammar.get("passes") == 8
    return {"status": "PREVIEW_100_LANGUAGE_AND_8_GRAMMAR_PASS_NOT_FULL" if total_pass
            else "PREVIEW_SELECTED_COMPATIBILITY_FAILED",
            "actual": actual,
            "curated_suite_sha256": digest,
            "actual_tests_pass": result.get("pass"),
            "actual_tests_fail": result.get("fail"),
            "actual_tests_total": result.get("cases"),
            "additional_grammar_checks": grammar,
            "selected_suite_passed": bool(total_pass),
            "unknown_project_code_executed": False,
            "future_stable_python_3_16_qualified": False,
            "all_pypi_packages_qualified": False}


def _known_preview_executable(root, item):
    version, minor, _level, _serial, name = item
    if sys.platform == "win32":
        binary = root / ("cpython-{}-windows-amd64".format(version)) / "python.exe"
        entry = binary.lstat()
        if (not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1 or
                not 20_000 < entry.st_size < MAX_BINARY_BYTES):
            raise ValueError("invalid_exact_windows_preview_binary")
        return binary
    binary = root / ("cpython-{}-linux-x86_64-gnu".format(version)) / "bin" / name
    entry = binary.lstat()
    if (not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1 or
            not 500_000 < entry.st_size < MAX_BINARY_BYTES or not os.access(binary, os.X_OK)):
        raise ValueError("invalid_exact_preview_binary")
    if minor not in (15, 16):
        raise ValueError("unsupported_preview_minor")
    return binary


def run_known_preview_matrix(windows_root=None):
    """Four separately executed genuine pre-release binaries, pinned paths."""
    if sys.platform == "win32":
        return _run_windows_preview_matrix(windows_root)
    if windows_root is not None:
        raise ValueError("windows_preview_root_on_other_platform")
    own = globals().get("__file__")
    if not isinstance(own, str):
        return {"status": "NOT_RUN_PROJECT_ROOT_UNAVAILABLE"}
    project = Path(own).resolve().parents[1]
    candidates = project.parent / "prerelease-python-v23"
    if not candidates.is_dir() or candidates.is_symlink():
        return {"status": "NOT_RUN_PRERELEASE_BINARIES_MISSING"}
    records = []
    for item in PREVIEW_BINARIES:
        version, expected_minor, expected_level, expected_serial, _ = item
        try:
            binary = _known_preview_executable(candidates, item)
            process = subprocess.run([str(binary), "-I", "-S", "-B", str(project / "python" /
                                      "prerelease_matrix_v23.py"), "--mode", "suite"],
                                     cwd=str(project), stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     timeout=20, check=False)
            if (process.returncode != 0 or len(process.stdout) > MAX_CHILD_REPORT_BYTES or
                    len(process.stderr) > MAX_CHILD_REPORT_BYTES):
                raise ValueError("preview_subprocess_failed_or_output_exceeded_quota")
            result = json.loads(process.stdout)
            actual = result.get("actual", {})
            exact = (actual.get("version_label") == version and
                     actual.get("minor") == expected_minor and
                     actual.get("releaselevel") == expected_level and
                     actual.get("serial") == expected_serial and
                     result.get("selected_suite_passed") is True)
            records.append({"expected": version,
                            "actual": actual.get("version_label"),
                            "actual_releaselevel": actual.get("releaselevel"),
                            "actual_minor": actual.get("minor"),
                            "actual_tests_pass": result.get("actual_tests_pass"),
                            "extra_grammar_pass": result.get("additional_grammar_checks", {}).get("passes"),
                            "exact_real_executable": exact,
                            "curated_suite_sha256": result.get("curated_suite_sha256"),
                            "binary_sha256": _sha_regular_binary(binary)})
        except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
            records.append({"expected": version, "exact_real_executable": False,
                            "reason": "NOT_RUN_OR_FAILED"})
    three_phases = all(item["exact_real_executable"] for item in records[:3])
    future_alpha = records[3]["exact_real_executable"]
    return {"status": "REAL_ALPHA_BETA_RC_PREVIEW_MATRIX_QUALIFIED_LOCAL" if three_phases
            else "PREVIEW_PHASE_MATRIX_UNVERIFIED",
            "real_versions": records,
            "alpha_beta_releasecandidate_verified": three_phases,
            "future_3_16_alpha_selected_tests_passed": future_alpha,
            "future_3_16_stable_fully_qualified": False,
            "external_publisher_and_binary_provenance_attested": False,
            "unknown_project_source_executed": False,
            "actual_subprocesses_executed": sum(item["exact_real_executable"] for item in records)}


def _windows_preview_privacy():
    supplied = globals().get("_RPH_WINDOWS_PRIVACY")
    if supplied is not None:
        return supplied
    location = globals().get("__file__")
    if not isinstance(location, str):
        raise ValueError("trusted_windows_privacy_helper_missing")
    path = Path(location).parent / "windows_private_paths.py"
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > 40_000):
        raise ValueError("invalid_windows_preview_privacy_helper")
    with path.open("rb") as stream:
        source = stream.read(40001)
    if len(source) > 40000 or hashlib.sha256(source).hexdigest() != WINDOWS_PRIVACY_SOURCE_SHA256:
        raise ValueError("windows_preview_privacy_source_pin_mismatch")
    loaded = types.ModuleType("rph_windows_preview_privacy")
    exec(compile(source, "<pinned-windows-preview-privacy>", "exec", dont_inherit=True), loaded.__dict__)
    return loaded


def _preview_stream_digest(stream, limit):
    digest, size = hashlib.sha256(), 0
    while True:
        block = stream.read(min(1024 * 1024, limit + 1 - size))
        if not block:
            return digest.hexdigest(), size
        size += len(block)
        if size > limit:
            raise ValueError("windows_preview_read_budget")
        digest.update(block)


def _preview_member_parts(name):
    if (not isinstance(name, str) or not 0 < len(name) <= 512 or "\\" in name or
            ":" in name or name.startswith("/") or "\x00" in name):
        raise ValueError("unsafe_windows_preview_archive_member")
    parts = tuple(name.rstrip("/").split("/"))
    reserved = {"CON", "PRN", "AUX", "NUL"} | {"COM" + str(i) for i in range(1, 10)} | {"LPT" + str(i) for i in range(1, 10)}
    if (not 1 <= len(parts) <= 32 or any(not part or part in (".", "..") or part.endswith((".", " ")) or
            part.split(".")[0].upper() in reserved for part in parts)):
        raise ValueError("unsafe_windows_preview_archive_member")
    return parts


def _preview_fd_identity(stream):
    metadata = os.fstat(stream.fileno())
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns, metadata.st_nlink)


@contextmanager
def _windows_preview_bundle_lease(root, item):
    """Primary archive pins plus all extracted files held read-only through child."""
    privacy = _windows_preview_privacy()
    kernel, security = privacy._libraries()
    root = Path(privacy._local_absolute_path(root))
    version = item[0]
    expected_size, expected_pin = WINDOWS_PREVIEW_ARCHIVES[version]
    folder = root / ("cpython-{}-windows-amd64".format(version))
    streams, directory_handles = [], []
    started = time.monotonic()
    with ExitStack() as stack:
        kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
        kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
        directories = list(reversed(root.parents)) + [root, folder]
        for directory in directories:
            handle = kernel.CreateFileW(str(directory), 0x00020080, 3, None, 3, 0x02200000, None)
            if not handle or handle == ctypes.c_void_p(-1).value:
                raise ValueError("windows_preview_directory_open_refused")
            stack.callback(kernel.CloseHandle, handle)
            info = privacy._FileInformation()
            if (not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)) or
                    not info.attributes & 0x10 or info.attributes & 0x400):
                raise ValueError("windows_preview_directory_reparse_or_type")
            final = ctypes.create_unicode_buffer(32768)
            length = kernel.GetFinalPathNameByHandleW(handle, final, len(final), 0)
            if not 0 < length < len(final):
                raise ValueError("windows_preview_directory_identity_missing")
            normalized = final.value[4:] if final.value.startswith("\\\\?\\") else final.value
            if os.path.normcase(os.path.normpath(normalized)) != os.path.normcase(os.path.normpath(str(directory))):
                raise ValueError("windows_preview_ancestor_alias_refused")
            if directory in (root, folder):
                privacy._inspect_private_handle(handle, True, kernel, security)
            directory_handles.append((handle, (info.volume, info.index_high, info.index_low)))
        archive = root / ("python-{}-amd64.zip".format(version))
        archive_stream = stack.enter_context(os.fdopen(privacy.open_private_readonly(archive), "rb", buffering=0))
        archive_identity = _preview_fd_identity(archive_stream)
        pin, size = _preview_stream_digest(archive_stream, MAX_WINDOWS_ARCHIVE_BYTES)
        if pin != expected_pin or size != expected_size:
            raise ValueError("windows_preview_primary_archive_pin_mismatch")
        expected_files, expected_directories, executable_sha = set(), set(), None
        with zipfile.ZipFile(archive_stream) as zipped:
            infos = zipped.infolist()
            if (not 1 < len(infos) <= 10000 or sum(row.file_size for row in infos) > MAX_WINDOWS_EXPANDED_BYTES):
                raise ValueError("windows_preview_archive_quota")
            seen = set()
            for row in infos:
                parts = _preview_member_parts(row.filename)
                name = "/".join(parts)
                if (name.casefold() in seen or row.flag_bits & 1 or row.file_size > MAX_WINDOWS_MEMBER_BYTES or
                        stat.S_IFMT(row.external_attr >> 16) == stat.S_IFLNK):
                    raise ValueError("windows_preview_archive_member_refused")
                seen.add(name.casefold())
                for index in range(1, len(parts)):
                    expected_directories.add("/".join(parts[:index]))
                if row.is_dir():
                    expected_directories.add(name)
                    continue
                expected_files.add(name)
                stream = stack.enter_context(os.fdopen(privacy.open_private_readonly(folder.joinpath(*parts)), "rb", buffering=0))
                before = _preview_fd_identity(stream)
                extracted_pin, extracted_bytes = _preview_stream_digest(stream, MAX_WINDOWS_MEMBER_BYTES)
                with zipped.open(row) as member:
                    member_pin, member_bytes = _preview_stream_digest(member, MAX_WINDOWS_MEMBER_BYTES)
                if extracted_bytes != row.file_size or member_bytes != row.file_size or extracted_pin != member_pin:
                    raise ValueError("windows_preview_extracted_member_mismatch")
                streams.append((stream, before))
                if name == "python.exe":
                    executable_sha = extracted_pin
                if time.monotonic() - started > 90:
                    raise ValueError("windows_preview_bundle_validation_deadline")
        if executable_sha is None:
            raise ValueError("windows_preview_python_executable_missing")
        observed_files, observed_directories = set(), set()
        for current, folders, files in os.walk(folder):
            for name in folders:
                directory = Path(current) / name
                observed_directories.add(directory.relative_to(folder).as_posix())
                handle = kernel.CreateFileW(str(directory), 0x00020080, 3, None, 3, 0x02200000, None)
                if not handle or handle == ctypes.c_void_p(-1).value:
                    raise ValueError("windows_preview_subdirectory_open_refused")
                stack.callback(kernel.CloseHandle, handle)
                privacy._inspect_private_handle(handle, True, kernel, security)
                info = privacy._FileInformation()
                if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
                    raise ValueError("windows_preview_subdirectory_info_missing")
                directory_handles.append((handle, (info.volume, info.index_high, info.index_low)))
            observed_files.update((Path(current) / name).relative_to(folder).as_posix() for name in files)
        if observed_files != expected_files or observed_directories != expected_directories:
            raise ValueError("windows_preview_unexpected_bundle_entries")
        yield {"archive_sha256": pin, "executable_sha256": executable_sha,
               "archive_bytes": size, "verified_files": len(streams), "runtime_directory": folder}
        after_files, after_directories = set(), set()
        for current, folders, files in os.walk(folder):
            after_directories.update((Path(current) / name).relative_to(folder).as_posix() for name in folders)
            after_files.update((Path(current) / name).relative_to(folder).as_posix() for name in files)
        if after_files != expected_files or after_directories != expected_directories:
            raise ValueError("windows_preview_bundle_namespace_changed")
        if _preview_fd_identity(archive_stream) != archive_identity:
            raise ValueError("windows_preview_archive_identity_changed")
        for stream, before in streams:
            privacy.assert_private_file_descriptor(stream.fileno())
            if _preview_fd_identity(stream) != before or before[-1] != 1:
                raise ValueError("windows_preview_held_member_changed")
        for handle, before in directory_handles:
            info = privacy._FileInformation()
            if (not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)) or info.attributes & 0x400 or
                    (info.volume, info.index_high, info.index_low) != before):
                raise ValueError("windows_preview_directory_identity_changed")


def _windows_preview_sources():
    privacy = _windows_preview_privacy()
    module = globals().get("_RPH_PREVIEW_MODULE_SOURCE")
    suite = globals().get("_RPH_PREVIEW_SUITE_SOURCE")
    for role in ("module", "suite"):
        value = module if role == "module" else suite
        if value is None:
            own = globals().get("__file__")
            if not isinstance(own, str):
                raise ValueError("windows_preview_source_snapshot_unavailable")
            path = Path(own) if role == "module" else Path(own).parent / "version_suite.py"
            with os.fdopen(privacy.open_private_readonly(path), "rb") as stream:
                value = stream.read(200001)
        if isinstance(value, str): value = value.encode("utf-8")
        if type(value) is not bytes or len(value) > 200000:
            raise ValueError("windows_preview_source_snapshot_budget")
        if role == "module": module = value
        else: suite = value
    if hashlib.sha256(suite).hexdigest() != TRUSTED_VERSION_SUITE_SHA256:
        raise ValueError("windows_preview_curated_source_pin_mismatch")
    graph = {"prerelease_matrix_v23.py": hashlib.sha256(module).hexdigest(), "version_suite.py": hashlib.sha256(suite).hexdigest()}
    return module, suite, graph


def _validate_windows_preview_report(payload, item, challenge, graph, executable_sha, child_pid):
    expected_keys = {"probe_schema", "challenge", "source_graph", "executable_sha256", "pid", "ppid", "result"}
    if (type(payload) is not dict or set(payload) != expected_keys or type(payload.get("probe_schema")) is not int or payload["probe_schema"] != 1 or
            payload.get("challenge") != challenge or payload.get("source_graph") != graph or
            payload.get("executable_sha256") != executable_sha or type(child_pid) is not int or child_pid <= 0 or
            payload.get("pid") != child_pid or payload.get("ppid") != os.getpid()):
        raise ValueError("windows_preview_process_or_source_graph_unverified")
    result = payload.get("result")
    if type(result) is not dict or type(result.get("actual")) is not dict:
        raise ValueError("windows_preview_invalid_child_report")
    actual = result["actual"]
    version, minor, level, serial, _ = item
    grammar = result.get("additional_grammar_checks")
    names = {"pattern_matching", "exception_groups", "generic_class", "template_string", "missing_colon", "invalid_name_assignment", "unterminated_string", "await_top_level"}
    integers = (("major", 3), ("minor", minor), ("micro", 0), ("serial", serial))
    counts = (("actual_tests_total", 100), ("actual_tests_pass", 100), ("actual_tests_fail", 0))
    if (actual.get("status") != "ACTUAL_CPYTHON_PREVIEW_IDENTITY" or actual.get("version_label") != version or any(type(actual.get(key)) is not int or actual[key] != value for key, value in integers) or
            actual.get("releaselevel") != level or
            actual.get("implementation") != "cpython" or actual.get("is_prerelease") is not True or
            actual.get("real_interpreter_executed") is not True or
            actual.get("supported_stable_3_16_qualified") is not False or actual.get("other_platform_executed") is not False or
            result.get("status") != "PREVIEW_100_LANGUAGE_AND_8_GRAMMAR_PASS_NOT_FULL" or result.get("selected_suite_passed") is not True or
            any(type(result.get(key)) is not int or result[key] != value for key, value in counts) or
            result.get("curated_suite_sha256") != TRUSTED_VERSION_SUITE_SHA256 or
            result.get("future_stable_python_3_16_qualified") is not False or result.get("unknown_project_code_executed") is not False or
            result.get("all_pypi_packages_qualified") is not False or type(grammar) is not dict):
        raise ValueError("windows_preview_phase_or_selected_suite_unverified")
    checks = grammar.get("checks")
    if (grammar.get("status") != "SELECTED_PRERELEASE_GRAMMAR_ORACLES_PASS" or grammar.get("passes") != 8 or
            grammar.get("grammar_checks") != 8 or grammar.get("curated_compile_only") is not True or
            type(checks) is not list or len(checks) != 8 or any(type(row) is not dict for row in checks) or
            any(type(row.get("name")) is not str for row in checks) or
            {row.get("name") for row in checks} != names or
            any(row.get("status") != "PASS" or row.get("code_executed") is not False for row in checks)):
        raise ValueError("windows_preview_grammar_oracles_unverified")
    return result


def _preview_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError("duplicate_windows_preview_json_key")
        result[key] = value
    return result


def _run_windows_preview_child(binary, module, suite, graph, bundle, item, timeout=20):
    challenge = secrets.token_hex(16)
    request = json.dumps({"module_source": module.decode("utf-8"), "suite_source": suite.decode("utf-8"),
        "source_graph": graph, "challenge": challenge}).encode("utf-8")
    if len(request) > 512000: raise ValueError("windows_preview_child_input_budget")
    environment = {key: os.environ[key] for key in ("SystemRoot", "WINDIR") if key in os.environ}
    environment["PATH"] = str(binary.parent) + os.pathsep + str(Path(environment.get("SystemRoot", "C:/Windows")) / "System32")
    with subprocess.Popen([str(binary), "-I", "-S", "-B", "-c", _WINDOWS_PREVIEW_CHILD], cwd=str(bundle["runtime_directory"]),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)) as child:
        try:
            stdout, stderr = child.communicate(request, timeout=timeout)
        except subprocess.TimeoutExpired:
            child.kill(); child.communicate(timeout=5)
            raise ValueError("windows_preview_own_child_timeout")
        if child.returncode != 0 or len(stdout) > MAX_CHILD_REPORT_BYTES or len(stderr) > MAX_CHILD_REPORT_BYTES:
            raise ValueError("windows_preview_child_failed_or_output_budget")
        payload = json.loads(stdout, object_pairs_hook=_preview_json_object)
        result = _validate_windows_preview_report(payload, item, challenge, graph, bundle["executable_sha256"], child.pid)
        return result, payload, child.pid


def _run_windows_preview_matrix(root=None):
    own = globals().get("__file__")
    if root is None:
        if not isinstance(own, str): return {"status": "NOT_RUN_PROJECT_ROOT_UNAVAILABLE"}
        root = Path(own).resolve().parents[2] / "python-preview-windows-v029"
    root = Path(root)
    if not root.is_dir(): return {"status": "NOT_RUN_PRERELEASE_BINARIES_MISSING"}
    module, suite, graph = _windows_preview_sources()
    records = []
    for item in PREVIEW_BINARIES:
        version, minor, level, serial, _ = item
        try:
            binary = _known_preview_executable(root, item)
            with _windows_preview_bundle_lease(root, item) as bundle:
                result, payload, child_pid = _run_windows_preview_child(binary, module, suite, graph, bundle, item)
                record = {"expected": version, "actual": result["actual"]["version_label"], "actual_releaselevel": level,
                    "actual_minor": minor, "actual_tests_pass": result["actual_tests_pass"],
                    "extra_grammar_pass": result["additional_grammar_checks"]["passes"], "exact_real_executable": True,
                    "curated_suite_sha256": result["curated_suite_sha256"], "binary_sha256": bundle["executable_sha256"],
                    "archive_sha256": bundle["archive_sha256"], "archive_bytes": bundle["archive_bytes"],
                    "verified_bundle_files": bundle["verified_files"], "source_graph": graph, "child_pid": child_pid,
                    "challenge_matched": True, "child_report": payload,
                    "independent_publisher_signature_verified": False}
            records.append(record)
        except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, subprocess.TimeoutExpired, json.JSONDecodeError):
            records.append({"expected": version, "exact_real_executable": False, "reason": "NOT_RUN_OR_FAILED_PRIMARY_PINNED_WINDOWS_PREVIEW"})
    phases = all(row["exact_real_executable"] for row in records[:3])
    return {"status": "REAL_ALPHA_BETA_RC_PREVIEW_MATRIX_QUALIFIED_LOCAL" if phases else "PREVIEW_PHASE_MATRIX_UNVERIFIED",
        "runtime_variant": "WINDOWS_PRIMARY_PINNED_PREVIEW_V029", "real_versions": records,
        "alpha_beta_releasecandidate_verified": phases,
        "future_3_16_alpha_selected_tests_passed": records[3]["exact_real_executable"],
        "future_3_16_stable_fully_qualified": False, "external_publisher_and_binary_provenance_attested": False,
        "unknown_project_source_executed": False, "source_graph": graph,
        "actual_subprocesses_executed": sum(row["exact_real_executable"] for row in records),
        "scope": "Primary archive SHA pins and held private extracted bytes; selected fixed fixtures only, no general OS sandbox or independent signature-chain qualification"}


def _sha_regular_binary(path):
    """File version identity uses an actual local executable's SHA256."""
    sha = hashlib.sha256()
    with path.open("rb") as source:
        while True:
            data = source.read(1024 * 1024)
            if not data:
                return sha.hexdigest()
            sha.update(data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("identity", "phase", "grammar", "suite", "matrix"),
                        default="identity")
    parser.add_argument("--expected")
    parser.add_argument("--windows-root", type=Path, help="Windows-only locator; official archive pins remain fixed")
    parser.add_argument("--json", type=Path,
                        help="Bewaar het lokale echte-preview-rapport in een bestaand bewijsdirectory")
    args = parser.parse_args(argv)
    try:
        if args.windows_root is not None and (sys.platform != "win32" or args.mode != "matrix"):
            raise ValueError("windows_preview_root_requires_windows_matrix_mode")
        if args.mode == "identity":
            report = actual_release_identity()
        elif args.mode == "phase":
            report = checked_release_expectation(args.expected)
        elif args.mode == "grammar":
            report = compile_extra_grammar_oracles()
        elif args.mode == "suite":
            report = run_selected_preview_suite()
        else:
            report = run_known_preview_matrix(args.windows_root)
    except (OSError, ValueError, RuntimeError):
        report = {"status": "NOT_RUN_OR_INVALID_PREVIEW_EVIDENCE"}
    encoded = json.dumps(report, sort_keys=True)
    if args.json is not None:
        if args.json.parent.is_symlink() or not args.json.parent.is_dir() or args.json.is_symlink():
            parser.error("invalid_preview_report_output_path")
        args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(encoded)
    return 0 if not report["status"].startswith(("PREVIEW_PHASE_MATRIX_UNVERIFIED",
                                           "PREVIEW_SELECTED_COMPATIBILITY_FAILED",
                                           "NOT_RUN_OR_INVALID")) else 2


if __name__ == "__main__":
    raise SystemExit(main())
