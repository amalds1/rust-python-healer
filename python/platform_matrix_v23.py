"""Native-wheel ABI and subinterpreter probes on trusted compiled C fixtures.

Only this running Linux/Windows CPython interpreter and its own headers/compiler
are used. Nothing claims macOS, musl, free-threaded, PyPy, all CPython
microbuilds or cross-version import of an incompatible binary. No submitted
project source, wheel or native extension is built or executed.
"""

import argparse
import base64
import hashlib
import importlib.machinery
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import subprocess
import sys
import sysconfig
import tempfile
import zipfile


MODULE = "rph_v23_native"
MODULE_LEGACY = "rph_v23_legacy"
VERSION = "0.0.1"
LIMIT_WHEEL_BYTES = 8_000_000
MAX_CAPTURE_BYTES = 4096
TRUSTED_COMPILERS = (Path("/usr/bin/cc"), Path("/usr/bin/gcc"))
WINDOWS_TOOL_ROOTS = (Path("C:/Program Files (x86)/Microsoft Visual Studio"),
                      Path("C:/Program Files/Microsoft Visual Studio"))
WINDOWS_SDK_ROOT = Path("C:/Program Files (x86)/Windows Kits/10")

_MULTIPHASE_C = r'''
#include <Python.h>
static int mod_exec(PyObject *m) {
    return PyModule_AddStringConstant(m, "fixture_proof", "MULTIPHASE_TRUSTED");
}
static PyModuleDef_Slot mod_slots[] = {
    {Py_mod_exec, mod_exec},
#if PY_VERSION_HEX >= 0x030C0000
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
#endif
    {0, NULL}
};
static struct PyModuleDef mod_def = {
    PyModuleDef_HEAD_INIT, "rph_v23_native", NULL, 0, NULL,
    mod_slots, NULL, NULL, NULL
};
PyMODINIT_FUNC PyInit_rph_v23_native(void) {
    return PyModuleDef_Init(&mod_def);
}
'''

_LEGACY_C = r'''
#include <Python.h>
static struct PyModuleDef mod_def = {
    PyModuleDef_HEAD_INIT, "rph_v23_legacy", NULL, -1, NULL
};
PyMODINIT_FUNC PyInit_rph_v23_legacy(void) {
    return PyModule_Create(&mod_def);
}
'''

_IMPORT_CODE = r'''
import importlib.util, sys
filename = sys.argv[1]
spec = importlib.util.spec_from_file_location("rph_v23_native", filename)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert module.fixture_proof == "MULTIPHASE_TRUSTED"
print("NATIVE_IMPORT_VERIFIED")
'''

_SUBINTERP_CODE = r'''
import importlib, json, sys
module_name = "_xxsubinterpreters" if sys.version_info[:2] < (3, 13) else "_interpreters"
api = importlib.import_module(module_name)
identifier = api.create()
filename = sys.argv[1]
try:
    embedded = (
        "import importlib.util\n"
        "s=importlib.util.spec_from_file_location('rph_v23_native'," + repr(filename) + ")\n"
        "m=importlib.util.module_from_spec(s)\n"
        "s.loader.exec_module(m)\n"
        "assert m.fixture_proof=='MULTIPHASE_TRUSTED'\n"
    )
    failure = api.run_string(identifier, embedded)
    if failure is not None:
        raise RuntimeError("fixed_multiphase_subinterpreter_execution_failed")
    print("SUBINTERP_MULTIPHASE_NATIVE_VERIFIED")
finally:
    api.destroy(identifier)
'''

_LEGACY_SUBINTERP_CODE = r'''
import importlib, sys
api = importlib.import_module("_xxsubinterpreters" if sys.version_info[:2] < (3, 13)
                              else "_interpreters")
identifier = api.create()
filename = sys.argv[1]
try:
    embedded = (
        "import importlib.util\n"
        "s=importlib.util.spec_from_file_location('rph_v23_legacy'," + repr(filename) + ")\n"
        "m=importlib.util.module_from_spec(s)\n"
        "s.loader.exec_module(m)\n"
    )
    try:
        failure = api.run_string(identifier, embedded)
    except Exception as error:
        if (type(error).__name__ != "RunFailedError" or "ImportError" not in str(error)
                or "rph_v23_legacy" not in str(error)):
            raise
        refused = True
    else:
        refused = failure is not None
        if refused and (getattr(getattr(failure, "type", None), "__name__", None) != "ImportError"
                        or "rph_v23_legacy" not in getattr(failure, "msg", "")):
            raise RuntimeError("unexpected_singlephase_subinterpreter_failure")
    print("LEGACY_SINGLE_PHASE_REFUSED" if refused else "LEGACY_SINGLE_PHASE_ACCEPTED_OLD_POLICY")
finally:
    api.destroy(identifier)
'''


def _source_safety():
    """The embedded sources are immutable literals, not user-supplied code."""
    return {"multiphase_fixture_sha256": hashlib.sha256(_MULTIPHASE_C.encode()).hexdigest(),
            "singlephase_fixture_sha256": hashlib.sha256(_LEGACY_C.encode()).hexdigest(),
            "submitted_source_compiled": False}


def _compiler():
    if sys.platform == "win32":
        # No PATH/compiler environment override and no caller source is built.
        # These are locally installed toolchains, not publisher authentication.
        for root in WINDOWS_TOOL_ROOTS:
            for path in sorted(root.glob("*/*/VC/Tools/MSVC/*/bin/Hostx64/x64/cl.exe"), reverse=True):
                if path.is_file() and not path.is_symlink():
                    return str(path)
        return None
    for path in TRUSTED_COMPILERS:
        try:
            metadata = path.stat()
        except OSError:
            continue
        if stat.S_ISREG(metadata.st_mode) and os.access(str(path), os.X_OK):
            return str(path)
    return None


def actual_runtime():
    """Collect this very interpreter's ABI and native-extension settings."""
    minor = sys.version_info.minor
    include = sysconfig.get_path("include")
    header = Path(include, "Python.h") if isinstance(include, str) else None
    import_library = Path(sys.base_prefix) / "libs" / "python{}{}.lib".format(*sys.version_info[:2])
    suffix = sysconfig.get_config_var("EXT_SUFFIX")
    soabi = sysconfig.get_config_var("SOABI")
    os_tag = sysconfig.get_platform().lower().replace("-", "_").replace(".", "_")
    version = "{}.{}.{}".format(*sys.version_info[:3])
    flags = "t" if bool(sysconfig.get_config_var("Py_GIL_DISABLED")) else ""
    abi = "cp3{}{}".format(minor, flags)
    return {"status": "ACTUAL_RUNNING_CPYTHON_ABI_INSPECTED",
            "implementation": sys.implementation.name,
            "version": version, "minor": minor,
            "soabi": soabi, "extension_suffix": suffix,
            "extension_suffixes": list(importlib.machinery.EXTENSION_SUFFIXES),
            "python_tag": "cp3{}".format(minor), "abi_tag": abi,
            "platform_tag": os_tag, "linux_host": sys.platform == "linux",
            "windows_host": sys.platform == "win32",
            "executable_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
            "architecture": platform.machine().lower(),
            "headers_present": isinstance(include, str) and
            Path(include, "Python.h").is_file(),
            "include_dir": include,
            "python_header_sha256": hashlib.sha256(header.read_bytes()).hexdigest() if header and header.is_file() else None,
            "windows_import_library_sha256": hashlib.sha256(import_library.read_bytes()).hexdigest() if sys.platform == "win32" and import_library.is_file() else None,
            "free_threaded": bool(flags),
            "real_interpreter_queried": True,
            "other_os_or_implementation_tested": False}


def _checked_process(command, cwd, timeout=20, environment=None):
    run = subprocess.run(command, cwd=str(cwd), stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         timeout=timeout, check=False, env=environment)
    return {"returncode": run.returncode,
            "stdout": run.stdout[:MAX_CAPTURE_BYTES].decode("utf-8", "replace"),
            "captured_output_bounded": len(run.stdout) <= MAX_CAPTURE_BYTES and
            len(run.stderr) <= MAX_CAPTURE_BYTES,
            "stderr_bytes": len(run.stderr), "stdout_bytes": len(run.stdout)}


def _compile_fixture(folder, name, source, suffix, include_dir, compiler):
    if name not in (MODULE, MODULE_LEGACY) or source not in (_MULTIPHASE_C, _LEGACY_C):
        raise ValueError("only_curated_native_source_may_compile")
    origin = Path(folder) / (name + ".c")
    origin.write_text(source, encoding="utf-8")
    binary = Path(folder) / (name + suffix)
    environment = None
    if sys.platform == "win32":
        if compiler != _compiler() or not compiler:
            raise ValueError("only_installed_msvc_fixture_compiler")
        toolset = Path(compiler).parents[3]
        sdk_versions = sorted((WINDOWS_SDK_ROOT / "Include").glob("10.*"), reverse=True)
        if not sdk_versions:
            raise RuntimeError("windows_sdk_not_available")
        sdk_include = sdk_versions[0]
        sdk_library = WINDOWS_SDK_ROOT / "Lib" / sdk_include.name
        python_library = Path(sys.base_prefix) / "libs" / ("python{}{}.lib".format(*sys.version_info[:2]))
        if not python_library.is_file() or Path(include_dir) != Path(sysconfig.get_path("include")):
            raise ValueError("own_cpython_headers_import_library_required")
        command = [compiler, "/nologo", "/LD", "/MD", "/Od", "/I" + include_dir,
                   "/I" + str(toolset / "include")]
        command += ["/I" + str(sdk_include / part) for part in ("ucrt", "shared", "um")]
        command += ["/Fo" + str(Path(folder) / (name + ".obj")), "/Fe" + str(binary), str(origin),
                    "/link", "/NOLOGO", "/OUT:" + str(binary), "/IMPLIB:" + str(Path(folder) / (name + ".lib")),
                    "/LIBPATH:" + str(toolset / "lib/x64"),
                    "/LIBPATH:" + str(sdk_library / "ucrt/x64"),
                    "/LIBPATH:" + str(sdk_library / "um/x64"), str(python_library)]
        environment = {key: os.environ[key] for key in ("SystemRoot", "WINDIR") if key in os.environ}
        systemroot = Path(environment.get("SystemRoot", "C:/Windows"))
        environment.update({"PATH": os.pathsep.join((str(Path(compiler).parent), str(systemroot / "System32"))),
                            "TEMP": str(folder), "TMP": str(folder)})
    else:
        command = [compiler, "-shared", "-fPIC", "-O0", "-I", include_dir,
                   "-o", str(binary), str(origin)]
    result = _checked_process(command, folder, environment=environment)
    if result["returncode"] != 0 or not binary.is_file() or binary.stat().st_size > LIMIT_WHEEL_BYTES:
        raise RuntimeError("trusted_native_fixture_compile_failed")
    return binary


def _validate_native_payload(data, suffix):
    if suffix.endswith(".so"):
        if not data.startswith(b"\x7fELF"):
            raise ValueError("compiled_native_payload_not_elf_or_oversized")
        return "ELF"
    if not suffix.endswith(".pyd") or sys.platform != "win32":
        raise ValueError("unsupported_native_extension_suffix")
    if len(data) < 64 or data[:2] != b"MZ":
        raise ValueError("compiled_native_payload_not_pe")
    pe = struct.unpack_from("<I", data, 60)[0]
    if pe < 64 or pe + 26 > len(data) or data[pe:pe + 4] != b"PE\x00\x00":
        raise ValueError("compiled_native_payload_not_pe")
    machine, sections = struct.unpack_from("<HH", data, pe + 4)
    optional_bytes, characteristics = struct.unpack_from("<HH", data, pe + 20)
    optional_magic = struct.unpack_from("<H", data, pe + 24)[0]
    section_table = pe + 24 + optional_bytes
    if (machine != 0x8664 or optional_magic != 0x20b or not characteristics & 0x2000 or
            not 1 <= sections <= 32 or optional_bytes < 112 or section_table + sections * 40 > len(data)):
        raise ValueError("compiled_native_payload_pe_architecture_or_headers_invalid")
    for index in range(sections):
        length, offset = struct.unpack_from("<II", data, section_table + index * 40 + 16)
        if offset + length > len(data):
            raise ValueError("compiled_native_payload_pe_section_out_of_bounds")
    return "PE32+_AMD64_DLL"


def _record_line(path, contents):
    encoded = base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).rstrip(b"=").decode()
    return "{},sha256={},{}\n".format(path, encoded, len(contents))


def make_native_wheel_bytes(binary, runtime):
    """One local PEP427 wheel with a genuinely compiled extension payload."""
    suffix = runtime["extension_suffix"]
    if not isinstance(suffix, str) or not suffix.endswith((".so", ".pyd")):
        raise ValueError("unsupported_native_extension_suffix")
    candidate = Path(binary)
    metadata = candidate.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or
            not 0 < metadata.st_size <= LIMIT_WHEEL_BYTES or
            candidate.name != MODULE + suffix):
        raise ValueError("unsafe_compiled_native_payload")
    fd = os.open(str(candidate), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        observed = os.fstat(fd)
        if (observed.st_dev, observed.st_ino, observed.st_size, observed.st_mtime_ns) != (
                metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns):
            raise ValueError("compiled_native_payload_changed")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(LIMIT_WHEEL_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > LIMIT_WHEEL_BYTES:
        raise ValueError("compiled_native_payload_oversized")
    _validate_native_payload(data, suffix)
    distinfo = "rph_v23_native-{}.dist-info".format(VERSION)
    wheel_name = "rph_v23_native-{}-{}-{}-{}.whl".format(
        VERSION, runtime["python_tag"], runtime["abi_tag"], runtime["platform_tag"])
    tag = "{}-{}-{}".format(runtime["python_tag"], runtime["abi_tag"],
                           runtime["platform_tag"])
    payload = {MODULE + suffix: data,
               distinfo + "/WHEEL": ("Wheel-Version: 1.0\nGenerator: rust-python-healer-v23\n"
                                      "Root-Is-Purelib: false\nTag: {}\n".format(tag)).encode(),
               distinfo + "/METADATA": ("Metadata-Version: 2.1\nName: rph-v23-native\n"
                                         "Version: {}\n".format(VERSION)).encode()}
    record_name = distinfo + "/RECORD"
    record = "".join(_record_line(path, content) for path, content in sorted(payload.items()))
    payload[record_name] = (record + "{},,\n".format(record_name)).encode()
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in sorted(payload.items()):
            entry = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_STORED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, content)
    return {"name": wheel_name, "bytes": stream.getvalue(),
            "native_entry": MODULE + suffix, "tag": tag}


def verify_native_wheel_bytes(wheel, pin, native_entry):
    """Verify SHA pin, RECORD and archive entries, independent of imports."""
    if not isinstance(wheel, bytes) or len(wheel) > LIMIT_WHEEL_BYTES or len(wheel) < 16:
        raise ValueError("invalid_native_wheel_size")
    if not isinstance(pin, str) or not re.fullmatch(r"[0-9a-f]{64}", pin):
        raise ValueError("trusted_wheel_sha256_pin_required")
    if hashlib.sha256(wheel).hexdigest() != pin:
        raise ValueError("wheel_pin_mismatch")
    if (not isinstance(native_entry, str) or not native_entry.startswith(MODULE + ".")
            or not native_entry.endswith((".so", ".pyd")) or "/" in native_entry
            or "\\" in native_entry):
        raise ValueError("invalid_expected_native_entry")
    with zipfile.ZipFile(io.BytesIO(wheel), "r") as archive:
        infos = archive.infolist()
        if (len(infos) != 4 or sum(info.file_size for info in infos) > LIMIT_WHEEL_BYTES
                or any(info.file_size > LIMIT_WHEEL_BYTES or
                       info.compress_type != zipfile.ZIP_STORED or
                       info.flag_bits & 1 for info in infos)):
            raise ValueError("native_wheel_entry_quota_or_encoding")
        names = archive.namelist()
        if len(names) != 4 or len(set(names)) != 4 or any(
                not name or name.startswith("/") or "\\" in name or
                ".." in Path(name).parts for name in names):
            raise ValueError("unsafe_native_wheel_entries")
        if native_entry not in names:
            raise ValueError("native_extension_missing")
        records = [x for x in names if x.endswith(".dist-info/RECORD")]
        if len(records) != 1:
            raise ValueError("missing_record")
        records_data = archive.read(records[0]).decode("ascii").splitlines()
        expected = {}
        for row in records_data:
            fields = row.split(",")
            if len(fields) != 3 or fields[0] in expected:
                raise ValueError("invalid_native_wheel_record")
            expected[fields[0]] = tuple(fields[1:])
        if set(expected) != set(names) or expected[records[0]] != ("", ""):
            raise ValueError("record_missing_or_duplicate_entries")
        for path in names:
            if path == records[0]:
                continue
            payload = archive.read(path)
            if _record_line(path, payload).strip() != ",".join((path,) + expected[path]):
                raise ValueError("wheel_record_hash_or_size_mismatch")
        binary = archive.read(native_entry)
        _validate_native_payload(binary, native_entry)
    return {"status": "PINNED_NATIVE_WHEEL_RECORD_VERIFIED",
            "wheel_sha256": pin, "native_sha256": hashlib.sha256(binary).hexdigest(),
            "record_entries": len(names), "untrusted_native_code_imported": False}


def qualify_local_native():
    """Build/test in a private tempdir with the *running* CPython only."""
    runtime = actual_runtime()
    compiler = _compiler()
    if not ((runtime["linux_host"] or runtime["windows_host"] and runtime["platform_tag"] == "win_amd64") and runtime["implementation"] == "cpython" and
            runtime["headers_present"] and compiler and
            isinstance(runtime["extension_suffix"], str) and
            runtime["extension_suffix"].endswith((".so", ".pyd"))):
        return {"status": "NOT_RUN_REQUIRED_NATIVE_FIXTURE_TOOLCHAIN_MISSING",
                "runtime": runtime, "other_os_tested": False}
    with tempfile.TemporaryDirectory(prefix="rph-v23-native-matrix-") as directory:
        folder = Path(directory)
        native = _compile_fixture(folder, MODULE, _MULTIPHASE_C,
                                  runtime["extension_suffix"], runtime["include_dir"], compiler)
        original_sha = hashlib.sha256(native.read_bytes()).hexdigest()
        parent_import = _checked_process([sys.executable, "-I", "-S", "-B", "-c",
                                          _IMPORT_CODE, str(native)], folder)
        child_import = _checked_process([sys.executable, "-I", "-S", "-B", "-c",
                                         _SUBINTERP_CODE, str(native)], folder)
        native_wheel = make_native_wheel_bytes(native, runtime)
        wheel_pin = hashlib.sha256(native_wheel["bytes"]).hexdigest()
        verified = verify_native_wheel_bytes(native_wheel["bytes"], wheel_pin,
                                             native_wheel["native_entry"])
        legacy = _compile_fixture(folder, MODULE_LEGACY, _LEGACY_C,
                                  runtime["extension_suffix"], runtime["include_dir"], compiler)
        legacy_result = _checked_process([sys.executable, "-I", "-S", "-B", "-c",
                                          _LEGACY_SUBINTERP_CODE, str(legacy)], folder)
        import_proven = parent_import["returncode"] == 0 and \
            "NATIVE_IMPORT_VERIFIED" in parent_import["stdout"]
        subinterp_proven = child_import["returncode"] == 0 and \
            "SUBINTERP_MULTIPHASE_NATIVE_VERIFIED" in child_import["stdout"]
        wheel_proven = verified["status"] == "PINNED_NATIVE_WHEEL_RECORD_VERIFIED" and \
            verified["native_sha256"] == original_sha
        legacy_refused = legacy_result["returncode"] == 0 and \
            "LEGACY_SINGLE_PHASE_REFUSED" in legacy_result["stdout"]
        expected_legacy = "LEGACY_SINGLE_PHASE_REFUSED" if sys.version_info[:2] >= (3, 12) else "LEGACY_SINGLE_PHASE_ACCEPTED_OLD_POLICY"
        legacy_policy_proven = legacy_result["returncode"] == 0 and legacy_result["stdout"].strip() == expected_legacy
        success = import_proven and subinterp_proven and wheel_proven and legacy_policy_proven
        return {"status": "LOCAL_NATIVE_WHEEL_ABI_SUBINTERP_VERIFIED" if success else
                "INSUFFICIENT_NATIVE_INTERPRETER_EVIDENCE",
                "runtime": runtime,
                "native_source_fixtures": _source_safety(),
                "trusted_compiler_invoked": True, "compiled_native_sha256": original_sha,
                "compiler_path": compiler, "compiler_sha256": hashlib.sha256(Path(compiler).read_bytes()).hexdigest(),
                "native_binary_format": _validate_native_payload(native.read_bytes(), runtime["extension_suffix"]),
                "windows_local_fixture_qualified": success and runtime["windows_host"],
                "compiler_publisher_authenticated": False,
                "trusted_native_import_in_host_pass": import_proven,
                "trusted_native_import_in_subinterp_pass": subinterp_proven,
                "native_wheel_sha_pin_and_record_pass": wheel_proven,
                "wheel_tag": native_wheel["tag"], "wheel_name": native_wheel["name"],
                "wheel_sha256": wheel_pin,
                "singlephase_refused_in_subinterp": legacy_refused,
                "legacy_subinterpreter_result": legacy_result["stdout"].strip(),
                "legacy_singlephase_policy_pass": legacy_policy_proven,
                "subinterpreter_error_return_checked": True,
                "unknown_project_source_executed": False,
                "unknown_native_binary_loaded": False,
                "other_python_minor_binaries_executed": False,
                "windows_macos_musl_qualified": False,
                "free_threaded_build_qualified": runtime["free_threaded"]}


def environmental_gaps():
    """Explicit NOT_RUN ledger for uninstalled/non-permitted runtime variants."""
    return {"status": "ENVIRONMENT_GAPS_RECORDED_NO_FALSE_PASS",
            "free_threaded_runtime": bool(sysconfig.get_config_var("Py_GIL_DISABLED")),
            "actual_pypy_runtime": sys.implementation.name == "pypy",
            "running_on_windows": sys.platform == "win32",
            "running_on_macos": sys.platform == "darwin",
            "all_supported_microversions_tested": False,
            "forkserver_qualified": False,
            "other_os_abi_qualified": False,
            "f050_status": "NOT_RUN", "f167_status": "BLOCKED_OR_NOT_RUN",
            "f171_status": "NOT_RUN", "f174_status": "NOT_RUN",
            "f176_native_status": "NOT_RUN", "f177_status": "NOT_RUN"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("native", "runtime", "gaps"), default="runtime")
    args = parser.parse_args(argv)
    try:
        if args.mode == "native":
            result = qualify_local_native()
        elif args.mode == "gaps":
            result = environmental_gaps()
        else:
            result = actual_runtime()
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile,
            subprocess.TimeoutExpired):
        result = {"status": "NOT_RUN_NATIVE_PROBE_ERROR", "source_executed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] not in (
        "INSUFFICIENT_NATIVE_INTERPRETER_EVIDENCE", "NOT_RUN_NATIVE_PROBE_ERROR") else 2


if __name__ == "__main__":
    raise SystemExit(main())
