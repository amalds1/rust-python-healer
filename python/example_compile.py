"""Offline, HMAC-attested compile checks for locally cached Python examples.

No download is performed here.  A trusted operator must obtain and license each
example, place it beneath a trusted local blob root, and sign the exact manifest
with a private key.  The verifier checks that authorization *claim* and the
blob digest, then asks a selected, operator-trusted CPython executable to
``compile`` the UTF-8 source.  It NEVER executes, imports, or tests examples.

HMAC proves possession of the operator key, NOT publisher authenticity or
copyright permission.  The status intentionally remains PARTIAL_COMPILE_ONLY.
"""

import argparse
import hashlib
import hmac
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

MAX_MANIFEST_BYTES = 131_072
MAX_TRUST_BYTES = 4096
MAX_EXAMPLES = 32
MAX_BLOB_BYTES = 32_768
MAX_SUBPROCESS_SECONDS = 5
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z")
VERSION = re.compile(r"3\.(?:9|1[0-9]|[2-9][0-9])\Z")
LICENSE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,63}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
COMPONENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z")


def _windows_dependency(name, filename):
    module = globals().get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module

# This is a FIXED, locally controlled child program.  Source from a manifest is
# passed only as stdin bytes, then compiled, never exec'd or imported.
TRUSTED_COMPILER = '''import json, sys
result = {"implementation": sys.implementation.name,
          "python_version": "%d.%d" % sys.version_info[:2],
          "compile_status": "OTHER_COMPILE_ERROR"}
try:
    source = sys.stdin.buffer.read(32769)
    if len(source) > 32768 or b"\\x00" in source:
        result["compile_status"] = "INPUT_REJECTED"
    else:
        compile(source.decode("utf-8"), "<offline-example>", "exec",
                dont_inherit=True)
        result["compile_status"] = "COMPILES"
except SyntaxError as error:
    result["compile_status"] = "SYNTAX_ERROR"
    result["syntax_line"] = error.lineno
except (UnicodeError, ValueError):
    result["compile_status"] = "INPUT_REJECTED"
except Exception:
    result["compile_status"] = "OTHER_COMPILE_ERROR"
print(json.dumps(result, sort_keys=True))
'''


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def read_bounded(path, limit, private=False):
    """A unique regular file, no symlink leaf, changed-file and size checks."""
    if Path(path).is_symlink():
        raise ValueError("input_symlink_refused")
    try:
        if private and os.name == "nt":
            privacy = _windows_dependency("_RPH_WINDOWS_PRIVACY", "windows_private_paths.py")
            fd = privacy.open_private_readonly(Path(path).absolute())
        else:
            fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_NONBLOCK", 0))
    except OSError:
        raise ValueError("input_unreadable") from None
    try:
        stream = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                before.st_size > limit):
            raise ValueError("input_not_unique_regular_bounded_file")
        if private and os.name != "nt" and (stat.S_IMODE(before.st_mode) & 0o077):
            raise ValueError("trust_key_must_be_owner_only")
        value = stream.read(limit + 1)
        if private and os.name == "nt":
            privacy.assert_private_file_descriptor(stream.fileno())
        after = os.fstat(stream.fileno())
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_size,
                    info.st_mtime_ns, info.st_ctime_ns)
        if (not stat.S_ISREG(after.st_mode) or after.st_nlink != 1
                or (private and os.name != "nt" and stat.S_IMODE(after.st_mode) & 0o077)
                or len(value) != before.st_size or len(value) > limit
                or identity(before) != identity(after)):
            raise ValueError("input_changed_or_oversized")
    return value


def read_json(path, limit, private=False):
    try:
        return json.loads(read_bounded(path, limit, private).decode("utf-8"),
                          object_pairs_hook=duplicate_keys,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              ValueError("invalid_json_constant")))
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError("invalid_or_unreadable_manifest_or_trust") from None


def validate_trust(trust):
    if (not isinstance(trust, dict) or set(trust) !=
            {"schema_version", "source_id", "hostname", "licenses", "key_hex"} or
            type(trust["schema_version"]) is not int or
            trust["schema_version"] != 1):
        raise ValueError("invalid_trust_schema")
    if not isinstance(trust["source_id"], str) or not ID.fullmatch(trust["source_id"]):
        raise ValueError("invalid_trust_source_id")
    hostname = trust["hostname"]
    if (not isinstance(hostname, str) or len(hostname) > 128 or
            hostname != hostname.lower() or
            not re.fullmatch(r"[a-z0-9][a-z0-9.-]+", hostname) or
            hostname.startswith(".") or ".." in hostname or hostname.endswith(".")):
        raise ValueError("invalid_trust_hostname")
    licenses = trust["licenses"]
    if (not isinstance(licenses, list) or not 0 < len(licenses) <= 24 or
            any(not isinstance(license_, str) or not LICENSE.fullmatch(license_)
                for license_ in licenses) or len(set(licenses)) != len(licenses)):
        raise ValueError("invalid_trust_licenses")
    if not isinstance(trust["key_hex"], str) or not HEX64.fullmatch(trust["key_hex"]):
        raise ValueError("invalid_trust_key")


def validate_blob_path(value, suffix=".py"):
    if (not isinstance(value, str) or not 0 < len(value) <= 256 or
            not value.endswith(suffix) or "\\" in value or
            not all(COMPONENT.fullmatch(part) and part not in (".", "..")
                    for part in value.split("/"))):
        raise ValueError("unsafe_blob_path")
    return value.split("/")


def validate_manifest(manifest, trust):
    validate_trust(trust)
    required = {"schema_version", "manifest_id", "source_id", "examples", "signature"}
    if (not isinstance(manifest, dict) or set(manifest) != required or
            type(manifest["schema_version"]) is not int or
            manifest["schema_version"] != 1 or
            not isinstance(manifest["manifest_id"], str) or
            not ID.fullmatch(manifest["manifest_id"]) or
            manifest["source_id"] != trust["source_id"] or
            not isinstance(manifest["signature"], str) or
            not HEX64.fullmatch(manifest["signature"])):
        raise ValueError("invalid_example_manifest")
    examples = manifest["examples"]
    if not isinstance(examples, list) or not 0 < len(examples) <= MAX_EXAMPLES:
        raise ValueError("invalid_example_count")
    ids, paths = set(), set()
    required_row = {"id", "blob", "sha256", "python_version", "uri",
                    "license", "ingest_authorized", "expected_compile"}
    for row in examples:
        if not isinstance(row, dict) or set(row) != required_row:
            raise ValueError("invalid_example_record")
        if not isinstance(row["id"], str) or not ID.fullmatch(row["id"]):
            raise ValueError("invalid_example_id")
        validate_blob_path(row["blob"])
        if row["id"] in ids or row["blob"] in paths:
            raise ValueError("duplicate_example_id_or_blob")
        ids.add(row["id"])
        paths.add(row["blob"])
        if not isinstance(row["sha256"], str) or not HEX64.fullmatch(row["sha256"]):
            raise ValueError("invalid_example_sha256")
        if (not isinstance(row["python_version"], str) or
                not VERSION.fullmatch(row["python_version"])):
            raise ValueError("invalid_exact_python_version")
        if row["expected_compile"] not in ("COMPILES", "SYNTAX_ERROR"):
            raise ValueError("invalid_compile_expectation")
        if type(row["ingest_authorized"]) is not bool or not row["ingest_authorized"]:
            raise ValueError("example_ingestion_not_authorized")
        if (not isinstance(row["license"], str) or
                row["license"] not in trust["licenses"]):
            raise ValueError("example_license_not_authorized")
        uri = row["uri"]
        if not isinstance(uri, str) or len(uri) > 2048 or any(c in uri for c in "\r\n\0"):
            raise ValueError("invalid_example_uri")
        try:
            parts = urlsplit(uri)
            allowed_host = (parts.hostname == trust["hostname"] and
                            parts.scheme == "https" and
                            parts.port in (None, 443) and
                            not parts.username and not parts.password and
                            not parts.query and not parts.fragment)
        except ValueError:
            allowed_host = False
        if not allowed_host:
            raise ValueError("example_provenance_host_not_authorized")
    expected = hmac.new(bytes.fromhex(trust["key_hex"]),
                        canonical({key: value for key, value in manifest.items()
                                   if key != "signature"}), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, manifest["signature"]):
        raise ValueError("example_manifest_hmac_invalid")
    return examples


def sign_manifest_for_test(manifest, key_hex):
    """Deterministic test fixture signer; not a publisher signature."""
    return hmac.new(bytes.fromhex(key_hex),
                    canonical({key: value for key, value in manifest.items()
                               if key != "signature"}), hashlib.sha256).hexdigest()


def read_blob(root, relative, suffix=".py"):
    """Walk each directory using O_NOFOLLOW, preventing traversal and races."""
    components = validate_blob_path(relative, suffix)
    if os.name == "nt":
        if Path(root).is_symlink():
            raise ValueError("blob_root_symlink_refused")
        try:
            raw = _windows_dependency("_RPH_WINDOWS_BLOB_READER", "windows_blob_reader_v029.py").read_blob_beneath(root, components, MAX_BLOB_BYTES)
        except (OSError, ValueError) as error:
            if str(error) == "blob_not_unique_regular_bounded_file":
                raise
            raise ValueError("blob_unreadable_or_symlink") from None
        return _validate_blob_bytes(raw)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    current = None
    try:
        if Path(root).is_symlink():
            raise ValueError("blob_root_symlink_refused")
        current = os.open(str(root), directory_flags)
        for component in components[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=current)
            os.close(current)
            current = next_fd
        fd = os.open(components[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_NONBLOCK", 0), dir_fd=current)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
                    before.st_size > MAX_BLOB_BYTES):
                raise ValueError("blob_not_unique_regular_bounded_file")
            raw = stream.read(MAX_BLOB_BYTES + 1)
            after = os.fstat(stream.fileno())
            def identity(info):
                return (info.st_dev, info.st_ino, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns)
            if len(raw) > MAX_BLOB_BYTES or identity(before) != identity(after):
                raise ValueError("blob_changed_or_oversized")
    except OSError:
        raise ValueError("blob_unreadable_or_symlink") from None
    finally:
        if current is not None:
            os.close(current)
    return _validate_blob_bytes(raw)


def _validate_blob_bytes(raw):
    if b"\x00" in raw:
        raise ValueError("blob_contains_nul")
    try:
        raw.decode("utf-8")
    except UnicodeError:
        raise ValueError("blob_invalid_utf8") from None
    return raw


def compile_only(source, interpreter=None):
    """Use a trusted selected CPython subprocess for syntax, never execution."""
    executable = os.fspath(interpreter or sys.executable)
    environment = {"PATH": os.defpath, "PYTHONIOENCODING": "utf-8",
                   "PYTHONHASHSEED": "0"}
    if os.name == "nt" and os.environ.get("SystemRoot"):
        # Required by Windows CPython's OS entropy provider, including 3.9/3.10.
        environment["SystemRoot"] = os.environ["SystemRoot"]
    try:
        result = subprocess.run(
            [executable, "-I", "-S", "-c", TRUSTED_COMPILER],
            input=source, capture_output=True,
            timeout=MAX_SUBPROCESS_SECONDS, check=False,
            env=environment)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("trusted_compiler_unavailable_or_timed_out") from None
    if result.returncode or len(result.stdout) > 4096 or len(result.stderr) > 4096:
        raise ValueError("trusted_compiler_failed")
    try:
        report = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise ValueError("trusted_compiler_invalid_response") from None
    if (not isinstance(report, dict) or
            report.get("implementation") != "cpython" or
            not isinstance(report.get("python_version"), str) or
            not VERSION.fullmatch(report["python_version"]) or
            report.get("compile_status") not in (
                "COMPILES", "SYNTAX_ERROR", "OTHER_COMPILE_ERROR", "INPUT_REJECTED")):
        raise ValueError("trusted_compiler_unexpected_response")
    return report


def evaluate_manifest(manifest_path, blob_root, trust_path, interpreter=None):
    """Return private-source-free per-example compile evidence, fail closed."""
    manifest = read_json(manifest_path, MAX_MANIFEST_BYTES)
    trust = read_json(trust_path, MAX_TRUST_BYTES, private=True)
    examples = validate_manifest(manifest, trust)
    observations = []
    for row in examples:
        raw = read_blob(blob_root, row["blob"])
        digest = hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(digest, row["sha256"]):
            raise ValueError("example_sha256_mismatch")
        compile_result = compile_only(raw, interpreter)
        if compile_result["python_version"] != row["python_version"]:
            raise ValueError("interpreter_python_version_mismatch")
        observed = compile_result["compile_status"]
        observations.append({
            "id": row["id"],
            "python_version": row["python_version"],
            "sha256": digest,
            "expected_compile": row["expected_compile"],
            "observed_compile": observed,
            "status": "PASS" if observed == row["expected_compile"] else "FAIL",
        })
    passed = sum(1 for row in observations if row["status"] == "PASS")
    return {
        "schema_version": 1,
        "status": "PARTIAL_COMPILE_ONLY" if passed == len(observations) else "FAILED",
        "manifest_id": manifest["manifest_id"],
        "source_id": manifest["source_id"],
        "operator_manifest_hmac_verified": True,
        "publisher_authenticated": False,
        "legal_permission_independently_verified": False,
        "network_used": False,
        "source_executed": False,
        "example_tests_executed": False,
        "compile_only": True,
        "examples_checked": len(observations),
        "passed_expectations": passed,
        "failed_expectations": len(observations) - passed,
        "results": observations,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("blob_root", type=Path)
    parser.add_argument("trust_file", type=Path)
    parser.add_argument("--interpreter", default=sys.executable,
                        help="Operator-trusted CPython path; never read from the manifest")
    args = parser.parse_args()
    try:
        report = evaluate_manifest(args.manifest, args.blob_root,
                                   args.trust_file, args.interpreter)
    except ValueError as error:
        report = {"status": "NOT_RUN", "reason": str(error),
                  "source_executed": False, "network_used": False,
                  "example_tests_executed": False, "compile_only": True}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "PARTIAL_COMPILE_ONLY" else 1


if __name__ == "__main__":
    sys.exit(main())
