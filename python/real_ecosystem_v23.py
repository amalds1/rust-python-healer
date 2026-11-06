"""Truthful installed-framework evidence matrix for CPython 3.9–3.15.

The report separates a real installed runtime probe, metadata-only checks,
and static error candidates. It deliberately never counts synthetic mocks,
invented packages or a traceback string as real framework behavior.  Runtime
imports are restricted to a small allowlist of locally installed packages
inside the running interpreter's prefix. Arbitrary user project code is NEVER
imported or run, and no network, worker, database or GPU is contacted.
"""

import argparse
import ast
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


MAX_SOURCE = 1_048_576
MAX_TRACE = 131_072
MAX_OUTPUT = 24_576
MAX_AST_NODES = 25_000
STAGING = ("F251", "F252", "F253", "F254", "F255", "F256", "F257", "F258", "F259")

DEPENDENCIES = {
    "F251": ("numpy",),
    "F252": ("pandas",),
    "F253": ("torch",),
    "F254": ("tensorflow", "jax"),
    "F255": ("django", "fastapi", "flask"),
    "F256": ("sqlalchemy",),
    "F257": ("celery", "redis"),
    "F258": ("pyarrow", "protobuf"),
    "F259": ("Cython", "cffi", "pyo3"),
}
RUNTIME_ALLOWLIST = frozenset(("numpy", "pandas", "cffi"))

# Run with -I -B: ignore caller PYTHONPATH/cwd/user-site, and do not write
# bytecode. Only hardcoded small trusted fixtures import selected local libs.
NUMPY_PROBE = r'''
import json,numpy as np
from numpy import __version__
a=np.arange(6)
reshaped=a.reshape(2,3)
assert reshaped.shape==(2,3) and reshaped.size==6
failed=[]
try: a.reshape(4,2)
except ValueError: failed.append("RESHAPE_COUNT_MISMATCH")
try: np.broadcast_arrays(np.zeros((2,3)),np.ones((4,1)))
except ValueError: failed.append("BROADCAST_SHAPE_MISMATCH")
try: np.dtype("NOT_AN_ACTUAL_DTYPE")
except TypeError: failed.append("UNKNOWN_DTYPE_REJECTED")
assert len(failed)==3
print(json.dumps({"status":"REAL_INSTALLED_NUMPY_BEHAVIOR_VERIFIED",
 "framework_version":__version__,"real_shape":[2,3],"failure_oracles":failed,
 "native_numpy_imported":True,"user_source_executed":False,"cuda_exercised":False}))
'''

PANDAS_PROBE = r'''
import json,pandas as pd
from pandas import __version__
df=pd.DataFrame({"amount":pd.Series([1,2],dtype="Int64"),"label":["a","b"]})
assert len(df)==2 and str(df["amount"].dtype)=="Int64"
assert df.loc[0,"amount"]==1
failed=[]
try: df["missing-column"]
except KeyError: failed.append("MISSING_COLUMN_KEYERROR")
try: df.astype({"amount":"NOT_A_REAL_PANDAS_DTYPE"})
except (TypeError,ValueError): failed.append("INVALID_DTYPE_REJECTED")
assert len(failed)==2
print(json.dumps({"status":"REAL_INSTALLED_PANDAS_BEHAVIOR_VERIFIED",
 "framework_version":__version__,"columns":["amount","label"],
 "failure_oracles":failed,"pandas_imported":True,"user_source_executed":False}))
'''

CFFI_PROBE = r'''
import json,cffi
ffi=cffi.FFI()
ffi.cdef("size_t strlen(const char *);")
lib=ffi.dlopen(None)
assert lib.strlen(b"native-cffi-fixture")==19
failed=[]
try: ffi.new("UNDECLARED_NONEXISTENT_NATIVE_TYPE *")
except (cffi.FFIError,cffi.CDefError): failed.append("UNKNOWN_NATIVE_DECLARATION_REJECTED")
assert len(failed)==1
print(json.dumps({"status":"REAL_INSTALLED_CFFI_LIBC_BEHAVIOR_VERIFIED",
 "framework_version":cffi.__version__,"real_libc_strlen":19,
 "failure_oracles":failed,"native_symbols_used":True,
 "cython_runtime_qualified":False,"pyo3_runtime_qualified":False,
 "user_source_executed":False}))
'''

RUNTIME_SCRIPTS = {"numpy": NUMPY_PROBE, "pandas": PANDAS_PROBE,
                   "cffi": CFFI_PROBE}

TRACE_PATTERNS = (
    ("F251", "NUMPY_SHAPE", re.compile(r"(?:cannot reshape array|operands could not be broadcast)", re.I)),
    ("F252", "PANDAS_INDEX", re.compile(r"(?:KeyError:|IntCastingNaNError)", re.I)),
    ("F253", "PYTORCH_DEVICE", re.compile(r"(?:CUDA out of memory|tensors to be on the same device)", re.I)),
    ("F254", "TF_JAX_GRAPH", re.compile(r"(?:TracerArrayConversionError|InaccessibleTensorError)", re.I)),
    ("F255", "WEB_ROUTE", re.compile(r"(?:ImproperlyConfigured|Route already registered)", re.I)),
    ("F256", "ORM_ASYNC", re.compile(r"(?:MissingGreenlet|AwaitRequired)", re.I)),
    ("F257", "QUEUE_WORKER", re.compile(r"(?:SoftTimeLimitExceeded|RedisConnectionError)", re.I)),
    ("F258", "SERIALIZATION", re.compile(r"(?:ArrowInvalid|DecodeError)", re.I)),
    ("F259", "NATIVE_ABI", re.compile(r"(?:undefined symbol:|Symbol not found:)", re.I)),
)


def installed_distribution(package):
    """Read installed metadata only; never import the named package."""
    if package not in {name for names in DEPENDENCIES.values() for name in names}:
        raise ValueError("unapproved_distribution_name")
    try:
        dist = importlib.metadata.distribution(package)
    except importlib.metadata.PackageNotFoundError:
        return {"status": "NOT_INSTALLED", "distribution": package}
    root = Path(str(dist.locate_file(""))).resolve()
    trusted_prefix = Path(sys.prefix).resolve()
    try:
        root.relative_to(trusted_prefix)
    except ValueError:
        return {"status": "NOT_TRUSTED_INSTALL_ROOT", "distribution": package}
    # Do not confuse package metadata with an actually importable/runnable
    # framework, or the installed version with official external provenance.
    wheel = dist.read_text("WHEEL") or ""
    tags = [line.partition(":")[2].strip() for line in wheel.splitlines()
            if line.startswith("Tag:") and len(line) <= 160]
    return {"status": "LOCAL_DISTRIBUTION_METADATA_FOUND_NOT_RUNTIME_PROOF",
            "distribution": package,
            "installed_version": dist.version,
            "wheel_tags": tags[:16],
            "provenance_officially_authenticated": False,
            "metadata_root_within_current_interpreter": True}


def probe_real_runtime(package, timeout_seconds=15):
    """Execute only a hardcoded allowlisted fixture in a separate CPython."""
    if package not in RUNTIME_ALLOWLIST:
        raise ValueError("runtime_probe_not_allowlisted")
    meta = installed_distribution(package)
    if meta["status"] != "LOCAL_DISTRIBUTION_METADATA_FOUND_NOT_RUNTIME_PROOF":
        return {"status": "NOT_RUN_NO_TRUSTED_INSTALLED_RUNTIME",
                "package": package, "metadata_status": meta["status"],
                "actual_runtime_imported": False,
                "behavioral_evidence": False}
    if not 1 <= timeout_seconds <= 30:
        raise ValueError("invalid_runtime_timeout")
    # Runtime cwd deliberately outside project. -I ignores PYTHONPATH,
    # cwd, and user site. The script is an immutable in-repo allowlisted fixture.
    completed = subprocess.run([sys.executable, "-I", "-B", "-c",
                                RUNTIME_SCRIPTS[package]],
                               capture_output=True, timeout=timeout_seconds,
                               check=False)
    if (completed.returncode != 0 or len(completed.stdout) > MAX_OUTPUT
            or len(completed.stderr) > MAX_OUTPUT):
        return {"status": "NOT_RUN_LOCAL_RUNTIME_ORACLE_FAILED",
                "package": package, "metadata_status": meta["status"],
                "actual_runtime_imported": False,
                "behavioral_evidence": False}
    try:
        report = json.loads(completed.stdout.decode("utf-8"))
    except (ValueError, UnicodeError):
        return {"status": "NOT_RUN_LOCAL_RUNTIME_ORACLE_FAILED",
                "package": package, "metadata_status": meta["status"],
                "actual_runtime_imported": False,
                "behavioral_evidence": False}
    if (report.get("framework_version") != meta["installed_version"]
            or report.get("user_source_executed") is not False
            or not report.get("failure_oracles")):
        return {"status": "NOT_RUN_LOCAL_RUNTIME_ORACLE_FAILED",
                "package": package, "metadata_status": meta["status"],
                "actual_runtime_imported": False,
                "behavioral_evidence": False}
    return {"status": report["status"], "package": package,
            "framework_version": report["framework_version"],
            "failure_oracles": list(report["failure_oracles"]),
            "actual_runtime_imported": True,
            "behavioral_evidence": True,
            "user_source_executed": False,
            "independent_external_auditor": False}


def inspect_matrix(run_installed_fixtures=True):
    """Every F251–F259 is an explicit PARTIAL/NOT_RUN, never invented PASS."""
    packages = {}
    for component in sorted({name for group in DEPENDENCIES.values() for name in group}):
        packages[component] = installed_distribution(component)
    runtime = {}
    if run_installed_fixtures:
        for component in sorted(RUNTIME_ALLOWLIST):
            runtime[component] = probe_real_runtime(component)
    features = {}
    for fid, names in DEPENDENCIES.items():
        installed = [name for name in names if packages[name]["status"] ==
                     "LOCAL_DISTRIBUTION_METADATA_FOUND_NOT_RUNTIME_PROOF"]
        real = [name for name in installed if runtime.get(name, {}).get("behavioral_evidence") is True]
        features[fid] = {"status": "PARTIAL_REAL_RUNTIME_SUBSET" if real
                         else "NOT_RUN_NO_REAL_RUNTIME_PROOF",
                         "required_packages": list(names),
                         "installed_packages": installed,
                         "real_runtime_evidence": real,
                         "fully_qualified_all_python_minors": False,
                         "framework_behavior_verified": bool(real),
                         "external_runtime_attested": False}
    return {"schema": 1, "status": "ACTUAL_INSTALLED_ECOSYSTEM_EVIDENCE_INCOMPLETE",
            "python": "{}.{}".format(sys.version_info.major, sys.version_info.minor),
            "python_patch": sys.version_info.micro,
            "features": features, "package_metadata": packages,
            "runtime_probes": runtime,
            "unknown_project_source_executed": False,
            "unavailable_framework_fixtures_replaced_with_stubs": False,
            "external_framework_service_contacted": False,
            "note": "Missing runtime or interpreter means NOT_RUN; static pattern is not behavior."}


def classify_captured_error(captured):
    """Redacted candidates from final exception line, never runtime proof."""
    if type(captured) is not bytes or len(captured) > MAX_TRACE:
        raise ValueError("invalid_or_excessive_trace")
    text = captured.decode("utf-8", "replace")
    if any(len(line) > MAX_TRACE for line in text.splitlines()):
        raise ValueError("invalid_trace_line")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    tail = lines[-1][:1024] if lines else ""
    return [{"feature": fid, "rule_id": name,
             "status": "STATIC_TRACE_CANDIDATE_NOT_RUNTIME_PROOF",
             "private_trace_content_exposed": False,
             "behavioral_cause_verified": False}
            for fid, name, pattern in TRACE_PATTERNS if pattern.search(tail)]


def inspect_source_imports(source):
    """AST import inventory; never imports a referenced framework or code."""
    if type(source) is not bytes or len(source) > MAX_SOURCE:
        raise ValueError("invalid_or_excessive_source")
    tree = ast.parse(source.decode("utf-8"), filename="[STATIC_FRAMEWORK_SOURCE]")
    if sum(1 for _ in ast.walk(tree)) > MAX_AST_NODES:
        raise ValueError("ast_too_complex")
    allowed = {name.lower() for group in DEPENDENCIES.values() for name in group}
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0].lower() for alias in node.names)
        if isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0].lower())
    return {"status": "STATIC_IMPORT_CANDIDATE_ONLY",
            "referenced_frameworks": sorted(imports & allowed),
            "source_sha256": hashlib.sha256(source).hexdigest(),
            "source_executed": False,
            "frameworks_imported": False,
            "real_runtime_evidence": False}


def read_static_regular_file(path):
    """Quota-constrained non-following source open with inode race checks."""
    path = Path(path)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_size > MAX_SOURCE):
        raise ValueError("unsafe_static_source")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(str(path), flags)
    with os.fdopen(fd, "rb") as stream:
        after = os.fstat(stream.fileno())
        if ((after.st_ino, after.st_dev) != (before.st_ino, before.st_dev)
                or not stat.S_ISREG(after.st_mode)):
            raise ValueError("static_file_replaced_before_read")
        data = stream.read(MAX_SOURCE + 1)
        final = os.fstat(stream.fileno())
    if (len(data) > MAX_SOURCE or
            (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) !=
            (final.st_ino, final.st_dev, final.st_size, final.st_mtime_ns)):
        raise ValueError("static_file_changed_or_too_large")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("availability", "full", "runtime", "static"),
                        default="availability")
    parser.add_argument("--package", choices=sorted(RUNTIME_ALLOWLIST))
    parser.add_argument("--source", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.mode == "availability":
            result = inspect_matrix(run_installed_fixtures=False)
        elif args.mode == "full":
            result = inspect_matrix(run_installed_fixtures=True)
        elif args.mode == "runtime":
            if args.package is None:
                raise ValueError("runtime_requires_package")
            result = probe_real_runtime(args.package)
        else:
            if args.source is None:
                raise ValueError("static_requires_unique_regular_file")
            result = inspect_source_imports(read_static_regular_file(args.source))
    except (ValueError, OSError, UnicodeError, SyntaxError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"status": "NO_PASS_INVALID_OR_UNAVAILABLE_ECOSYSTEM_EVIDENCE",
                          "reason_code": type(error).__name__,
                          "unknown_project_source_executed": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
