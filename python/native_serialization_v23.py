"""Real native F258/F259 library fixtures on pinned wheel-only CPython runtimes.

Never imports project code, builds source distributions, loads unknown native
libraries, starts network services or intentionally crashes a Python process.
Only owner-private explicit targets with pinned PyArrow/protobuf/Cython/cffi/
orjson distributions are used. Native error classification uses a fixed bogus
non-ELF fixture and captured text, not unknown machine code execution.
"""

import argparse
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


PINS = {
    "3.9": ("21.0.0", "6.33.6", "3.3.0", "2.0.0", "3.11.5"),
    "3.10": ("25.0.1", "7.36.2", "3.3.0", "2.1.1", "3.13.0"),
    "3.11": ("26.0.0", "7.36.2", "3.3.0", "2.1.1", "3.13.0"),
    "3.12": ("26.0.0", "7.36.2", "3.3.0", "2.1.1", "3.13.0"),
    "3.13": ("26.0.0", "7.36.2", "3.3.0", "2.1.1", "3.13.0"),
    "3.14": ("26.0.0", "7.36.2", "3.3.0", "2.1.1", "3.13.0"),
    "3.15": ("26.0.0", "7.36.2", "3.3.0", "2.1.1", "3.13.0"),
}
NAMES = ("pyarrow", "protobuf", "Cython", "cffi", "orjson")
NATIVE_EXTENSIONS = frozenset((".so", ".pyd", ".dylib"))
NATIVE_TRACE_PATTERNS = (
    ("NATIVE_MODULE_UNDEFINED_SYMBOL", re.compile(r"(?:undefined symbol:|Symbol not found:)", re.I)),
    ("NATIVE_CPYTHON_ABI_TAG_MISMATCH", re.compile(r"(?:wrong ELF class|wrong architecture|incompatible ABI)", re.I)),
    ("NATIVE_FILE_INVALID", re.compile(r"(?:file too short|invalid ELF header|not a valid Win32 application)", re.I)),
)


_REVIEWED_WINDOWS_MANIFESTS = {'3.9': 'f76f05fe23e2f2ce92723fb6d4c1f2f890db9ef54025abd92ee4eb3385c8f71e', '3.10': 'd298be1f78846be2717a96ad4014cfa2e9875f2ffb23544c2bd6e0d1d894e6c4', '3.11': 'ed48bda2ab15334dc16db62ac0c03a56b71928b10a383cae8d6e54b127d5fb5b', '3.12': '097b4484f2183ed9977e2b65d8ec3753b8992cddd8c88869eb32542be248db0e', '3.13': '00b8fc5e57e049970ad22312e903a9a951fc603849361d858dc7347352fc0153', '3.14': '0f94b44a7d90019493d9c09b98a30f8ae5f2474f6ce25ef2908dcf6d44e069b1', '3.15': 'cfa96ca9157e5a6dc2aec4dc77e51857a91cbc331d703f23f962f2f52291ab33'}  # Exact independently reviewed local fixed-fixture manifests.


def _verified_windows_target(path):
    import importlib.util
    helper = globals().get("_RPH_ECOSYSTEM_INTEGRITY")
    if helper is None:
        location = Path(__file__).with_name("ecosystem_wheel_integrity_v030.py")
        spec = importlib.util.spec_from_file_location("_fixed_ecosystem_integrity", location)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
    minor = "{}.{}".format(sys.version_info.major, sys.version_info.minor)
    expected = _REVIEWED_WINDOWS_MANIFESTS.get(minor)
    if expected is None:
        raise ValueError("independently_reviewed_windows_wheel_bundle_required")
    result = helper.verify_private_target(path, expected)
    actual = "{}.{}.{}".format(*sys.version_info[:3])
    if result["runtime"] != actual:
        raise ValueError("reviewed_wheel_runtime_identity_mismatch")


def _private_target(target):
    target = Path(target)
    if os.name == "nt":
        _verified_windows_target(target)
    else:
        info = target.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077
                or info.st_uid != os.getuid()):
            raise ValueError("private_pinned_wheels_required")
    path = target.resolve()
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
    minor = "{}.{}".format(sys.version_info.major, sys.version_info.minor)
    if minor not in PINS:
        raise ValueError("unsupported_interpreter_minor")
    versions = {}
    for package, expected in zip(NAMES, PINS[minor]):
        try:
            actual = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError as error:
            raise ValueError("missing_pinned_native_wheel:" + package) from error
        if actual != expected:
            raise ValueError("pinned_native_wheel_version_mismatch:" + package)
        versions[package] = actual
    return versions


def _assert_native_file(candidate, target):
    if candidate is None:
        raise ValueError("native_extension_file_missing")
    actual = Path(candidate).resolve()
    actual.relative_to(Path(target).resolve())
    if actual.suffix not in NATIVE_EXTENSIONS:
        raise ValueError("native_extension_filename_unexpected")
    return actual.stat().st_size


def classify_captured_native_error(raw):
    """Final exception line only; never return sensitive text or false runtime proof."""
    if type(raw) is not bytes or len(raw) > 65536:
        raise ValueError("invalid_or_excessive_native_trace")
    lines = [line.strip() for line in raw.decode("utf-8", "replace").splitlines()
             if line.strip()]
    tail = lines[-1][:1024] if lines else ""
    return [{"rule_id": rule, "status": "CAPTURED_NATIVE_ERROR_UNVERIFIED_CAUSE",
             "private_error_content_exposed": False,
             "untrusted_binary_executed": False}
            for rule, pattern in NATIVE_TRACE_PATTERNS if pattern.search(tail)]


def trusted_serialization_fixture(target):
    """Real in-RAM Arrow/Parquet and protobuf schema/compatibility oracles."""
    versions = _private_target(target)
    import numpy as np
    import pyarrow as pa
    import pyarrow.parquet as pq
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
    from google.protobuf.message import DecodeError

    array = pa.array([7, 8, 9], type=pa.int64())
    native = array.to_numpy(zero_copy_only=True)
    assert isinstance(native, np.ndarray)
    assert list(native) == [7, 8, 9]
    zero_copy = native.ctypes.data == array.buffers()[1].address
    assert zero_copy

    table = pa.table({"id": pa.array([7, 8], type=pa.int64()),
                      "title": pa.array(["first", "second"])})
    stream = pa.BufferOutputStream()
    pq.write_table(table, stream, compression="NONE")
    payload = stream.getvalue().to_pybytes()
    read = pq.read_table(pa.BufferReader(payload))
    assert read.schema.equals(table.schema)
    assert read.column("id").to_pylist() == [7, 8]
    assert read.column("title").to_pylist() == ["first", "second"]
    if len(payload) > 2_000_000:
        raise ValueError("trusted_parquet_fixture_unbounded")
    failures = []
    try:
        pq.read_table(pa.BufferReader(b"NOT_A_VALID_PARQUET_FILE_V23"))
    except (pa.ArrowInvalid, OSError):
        failures.append("CORRUPT_PARQUET_REJECTED")
    try:
        pa.array(["not-an-int"], type=pa.int64())
    except (pa.ArrowInvalid, pa.ArrowTypeError, ValueError):
        failures.append("ARROW_SCHEMA_TYPE_MISMATCH_REJECTED")

    schema = descriptor_pb2.FileDescriptorProto()
    schema.name = "rph_v23_serial.proto"
    schema.package = "rph_fixed"
    record = schema.message_type.add()
    record.name = "Record"
    id_field = record.field.add()
    id_field.name, id_field.number, id_field.label, id_field.type = "id", 1, 1, 5
    text_field = record.field.add()
    text_field.name, text_field.number, text_field.label, text_field.type = "label", 2, 1, 9
    pool = descriptor_pool.DescriptorPool()
    pool.Add(schema)
    Record = message_factory.GetMessageClass(pool.FindMessageTypeByName("rph_fixed.Record"))
    encoded = Record(id=7, label="trusted").SerializeToString()
    decoded = Record.FromString(encoded)
    assert decoded.id == 7 and decoded.label == "trusted"
    try:
        Record.FromString(b"\xff")
    except DecodeError:
        failures.append("CORRUPT_PROTOBUF_REJECTED")
    assert len(failures) == 3

    # An additive optional field remains backward-readable by the old schema.
    expanded = descriptor_pb2.FileDescriptorProto()
    expanded.CopyFrom(schema)
    expanded.name = "rph_v23_serial_new.proto"
    expanded_field = expanded.message_type[0].field.add()
    expanded_field.name, expanded_field.number = "extra", 3
    expanded_field.label, expanded_field.type = 1, 9
    newer_pool = descriptor_pool.DescriptorPool()
    newer_pool.Add(expanded)
    NewRecord = message_factory.GetMessageClass(
        newer_pool.FindMessageTypeByName("rph_fixed.Record"))
    old_reader = Record.FromString(NewRecord(id=8, label="old-readable", extra="new").SerializeToString())
    protobuf_additive_compatibility = old_reader.id == 8 and old_reader.label == "old-readable"
    assert protobuf_additive_compatibility

    return {"status": "REAL_ARROW_PARQUET_PROTOBUF_SCHEMA_COMPAT_VERIFIED",
            "python": "{}.{}".format(sys.version_info.major, sys.version_info.minor),
            "pin_versions": versions,
            "real_native_pyarrow_runtime": True,
            "real_parquet_in_memory_roundtrip": True,
            "real_arrow_zero_copy_same_memory_pointer": zero_copy,
            "real_protobuf_dynamic_schema_roundtrip": True,
            "real_protobuf_additive_schema_compatibility": protobuf_additive_compatibility,
            "actual_negative_runtime_oracles": failures,
            "unknown_project_code_executed": False,
            "external_dataset_or_network_used": False,
            "all_serialization_formats_universally_qualified": False}


def _windows_system_ucrt():
    """Use the OS-provided absolute system path; no PATH/SystemRoot input."""
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    kernel.GetSystemDirectoryW.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel.GetSystemDirectoryW(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise OSError("trusted_windows_system_directory_unavailable")
    return str(Path(buffer.value) / "ucrtbase.dll")


def _actual_fixed_windows_loader_classification(path):
    """Locale-independent real loader rejection of our fixed ASCII marker."""
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
    kernel.LoadLibraryExW.restype = wintypes.HMODULE
    ctypes.set_last_error(0)
    handle = kernel.LoadLibraryExW(str(path), None, 0x1000 | 0x100)
    if handle:
        kernel.FreeLibrary.argtypes = [wintypes.HMODULE]
        kernel.FreeLibrary.restype = wintypes.BOOL
        kernel.FreeLibrary(handle)
        raise AssertionError("fixed_ascii_marker_unexpectedly_loaded")
    code = ctypes.get_last_error()
    if code != 193:
        raise OSError(code, "fixed_ascii_loader_rejection_unexpected")
    return [{"rule_id": "NATIVE_FILE_INVALID", "actual_windows_error": code,
             "status": "ACTUAL_FIXED_ASCII_WINDOWS_LOADER_REJECTION",
             "private_error_content_exposed": False,
             "untrusted_binary_executed": False}]


def trusted_native_fixture(target):
    """Real Cython native module, cffi/libc and Rust/PyO3-powered orjson."""
    versions = _private_target(target)
    import Cython
    from Cython.Compiler import Scanning
    import cffi
    import orjson
    _assert_native_file(Scanning.__file__, target)
    _assert_native_file(orjson.orjson.__file__, target)
    assert Cython.__version__ == versions["Cython"]
    assert cffi.__version__ == versions["cffi"]
    assert orjson.__version__ == versions["orjson"]

    ffi = cffi.FFI()
    ffi.cdef("size_t strlen(const char *);")
    libc = ffi.dlopen(_windows_system_ucrt() if os.name == "nt" else None)
    actual_len = libc.strlen(b"trusted-cffi-v23")
    assert actual_len == 16
    failures = []
    try:
        ffi.new("NONEXISTENT_NATIVE_TYPE_V23 *")
    except (cffi.FFIError, cffi.CDefError):
        failures.append("CFFI_INVALID_NATIVE_DECLARATION_REJECTED")
    encoded = orjson.dumps({"id": 7, "trusted": True})
    assert orjson.loads(encoded) == {"id": 7, "trusted": True}
    try:
        orjson.dumps(object())
    except orjson.JSONEncodeError:
        failures.append("PYO3_ORJSON_UNSUPPORTED_OBJECT_REJECTED")
    try:
        orjson.loads(b"{this is invalid json}")
    except orjson.JSONDecodeError:
        failures.append("PYO3_ORJSON_CORRUPT_JSON_REJECTED")

    # The only intentionally invalid native module is a fixed non-ELF marker,
    # not an unknown, partially compatible or executable machine-code binary.
    with tempfile.TemporaryDirectory(prefix="rph-native-invalid-v23-") as folder:
        invalid = Path(folder) / ("_rph_native_invalid_v23.pyd" if os.name == "nt"
                                  else "_rph_native_invalid_v23.so")
        invalid.write_bytes(b"THIS_IS_NOT_AN_EXECUTABLE_ELF")
        spec = importlib.util.spec_from_file_location("_rph_native_invalid_v23", str(invalid))
        try:
            importlib.util.module_from_spec(spec)
        except ImportError as error:
            rejected = True
            classifier = (_actual_fixed_windows_loader_classification(invalid)
                          if os.name == "nt" else classify_captured_native_error(
                              ("ImportError: " + str(error)).encode("utf-8", "replace")))
        else:
            rejected = False
            classifier = []
    assert rejected and classifier
    assert len(failures) == 3
    return {"status": "REAL_CYTHON_CFFI_RUST_NATIVE_FIXTURES_VERIFIED",
            "python": "{}.{}".format(sys.version_info.major, sys.version_info.minor),
            "pin_versions": versions,
            "compiled_cython_native_scanning_imported": True,
            "cffi_real_libc_strlen_bytes": actual_len,
            "rust_orjson_native_extension_imported": True,
            "rust_orjson_json_roundtrip_verified": True,
            "fixed_non_elf_rejected_before_native_initialization": rejected,
            "captured_native_loader_error_classified": bool(classifier),
            "actual_negative_runtime_oracles": failures,
            "unknown_native_machine_code_executed": False,
            "unknown_project_code_executed": False,
            "native_crash_test_intentionally_not_run": True,
            "all_native_abi_variants_universally_qualified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "serialization", "native"),
                        default="capabilities")
    parser.add_argument("--target", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.mode == "capabilities":
            result = {"status": "PINNED_NATIVE_SERIALIZATION_ADAPTER_AVAILABLE",
                      "real_packages_imported": False,
                      "unknown_project_code_executed": False,
                      "private_pinned_target_required": True,
                      "supported_modes": ["serialization", "native"]}
        elif args.target is None:
            raise ValueError("private_pinned_target_required")
        elif args.mode == "serialization":
            result = trusted_serialization_fixture(args.target)
        else:
            result = trusted_native_fixture(args.target)
    except (AssertionError, ValueError, ImportError, RuntimeError, OSError, AttributeError) as error:
        print(json.dumps({"status": "NO_PASS_NATIVE_OR_SERIALIZATION_UNVERIFIED",
                          "reason_code": type(error).__name__,
                          "unknown_project_code_executed": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
