"""Fail-closed version matrix for *all* unresolved F001-F260 checklist items.

Selected trusted regression modules provide SCOPED evidence; they never
convert an open checklist item into a full-feature PASS. Missing interpreters,
missing test suites and skips are NOT_RUN. No unknown project code is run.
"""

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKLIST_AUDIT = ROOT / "tools" / "audit_function_checklist.py"
FEATURE_TESTS = {
    "F050": ("test_microversion_matrix_v25.py",),
    "F090": ("test_binary_self_update_v27.py",),
    "F127": ("test_code_model_router_v24.py", "test_code_model_matrix_v24.py"),
    "F135": ("test_lsp_interop_v25.py", "test_ide_client_packages_v27.py"),
    "F150": ("test_dr_recovery_v26.py",),
    "F177": ("test_macos_universal_wheels_v27.py",),
    "F208": ("test_untrusted_output_guard_v27.py",),
    "F207": ("test_privacy_redaction_v25.py",),
    "F239": ("test_mutation_approval_gate_v26.py",),
    "F241": ("test_dap_client_conformance_v26.py", "test_ide_client_packages_v27.py"),
    "F247": ("test_oci_layout_v25.py",),
}
EXPECTED_OPEN_FEATURES = frozenset((
    "F039", "F046", "F050", "F090", "F107", "F108", "F110", "F114",
    "F127", "F134", "F135", "F139", "F146", "F147", "F150",
    "F177", "F204", "F205", "F206", "F207", "F208",
    "F239", "F241", "F247", "F248",
))
EXPECTED_VERSIONS = tuple(f"3.{n}" for n in range(9, 16))
RUN_CASES = re.compile(r"Ran ([1-9][0-9]*) tests? in ", re.ASCII)
SKIPPED = re.compile(r"skipped=([1-9][0-9]*)", re.ASCII)


def checklist_items(path):
    spec = importlib.util.spec_from_file_location("rph_open_items_audit", CHECKLIST_AUDIT)
    audit = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(audit)
    items = audit.parse_checklist(Path(path).read_text(encoding="utf-8"))
    if len(items) != 260:
        raise ValueError("expected_complete_260_item_checklist")
    return items


def _sha(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for portion in iter(lambda: stream.read(1_048_576), b""):
            value.update(portion)
    return value.hexdigest()


def python_identity(path, expected):
    executable = Path(path).resolve(strict=True)
    output = subprocess.run([str(executable), "-I", "-S", "-B", "-c",
                             "import sys,json;print(json.dumps({'version':list(sys.version_info[:3]),'implementation':sys.implementation.name}))"],
                            capture_output=True, timeout=10, check=False)
    if output.returncode != 0 or len(output.stdout) > 2048:
        raise ValueError("python_version_probe_failed")
    identity = json.loads(output.stdout)
    version = identity.get("version")
    if (identity.get("implementation") != "cpython" or
            not isinstance(version, list) or len(version) != 3 or
            any(type(part) is not int for part in version) or
            "{}.{}".format(*version[:2]) != expected):
        raise ValueError("python_minor_identity_mismatch")
    return {"minor": expected, "micro": ".".join(map(str, version)),
            "executable_sha256": _sha(executable), "path": str(executable)}


def scoped_test(interpreter, filename, timeout=40):
    if not re.fullmatch(r"test_[a-z0-9_]+\.py", filename):
        raise ValueError("untrusted_regression_filename")
    script = ROOT / "tests" / filename
    if not script.is_file() or script.is_symlink():
        return {"status": "NOT_RUN", "reason": "TRUSTED_TEST_FILE_NOT_PRESENT"}
    pinned = _sha(script)
    try:
        result = subprocess.run([str(interpreter), "-I", "-B", "-m", "unittest",
                                 "discover", "-s", str(ROOT / "tests"), "-p", filename,
                                 "-q"], cwd=str(ROOT), capture_output=True,
                                timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "NOT_RUN", "reason": "TEST_PROCESS_MISSING_OR_TIMEOUT",
                "test_sha256": pinned}
    output = (result.stdout + result.stderr)
    summary = RUN_CASES.search(output.decode("utf-8", "replace"))
    ran = int(summary.group(1)) if summary else 0
    skip = SKIPPED.search(output.decode("utf-8", "replace"))
    skipped = int(skip.group(1)) if skip else 0
    status = ("SCOPED_PASS_NOT_FULL_FEATURE" if result.returncode == 0 and
              ran > 0 and skipped == 0 and b"OK" in output else
              "NOT_RUN" if skipped else "SCOPED_FAIL")
    return {"status": status, "executed_tests": ran, "skipped": skipped,
            "exit_code": result.returncode, "output_sha256": hashlib.sha256(output).hexdigest(),
            "test_sha256": pinned, "raw_output_stored": False}


def collect(items, interpreters):
    open_items = [record for record in items if record["status"] != "IMPLEMENTED_TESTED"]
    if {row["id"] for row in open_items} != EXPECTED_OPEN_FEATURES or set(FEATURE_TESTS) - EXPECTED_OPEN_FEATURES:
        raise ValueError("open_checklist_changed_review_required")
    results = []
    cache = {}
    for minor in EXPECTED_VERSIONS:
        path = interpreters.get(minor)
        if path is None:
            results.append({"minor": minor, "status": "NOT_RUN", "reason": "PYTHON_NOT_FOUND",
                            "features": [{"id": item["id"], "checklist_status": item["status"],
                                          "evidence": "NOT_RUN"} for item in open_items]})
            continue
        try:
            identity = python_identity(path, minor)
        except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired):
            results.append({"minor": minor, "status": "NOT_RUN", "reason": "INVALID_INTERPRETER",
                            "features": [{"id": item["id"], "checklist_status": item["status"],
                                          "evidence": "NOT_RUN"} for item in open_items]})
            continue
        rows = []
        for item in open_items:
            filenames = FEATURE_TESTS.get(item["id"], ())
            checks = []
            for filename in filenames:
                if (minor, filename) not in cache:
                    cache[(minor, filename)] = scoped_test(identity["path"], filename)
                checks.append({"fixture": filename, **cache[(minor, filename)]})
            state = ("SCOPED_PASS_NOT_FULL_FEATURE" if checks and
                     all(c["status"] == "SCOPED_PASS_NOT_FULL_FEATURE" for c in checks) else
                     "NOT_RUN" if not checks or any(c["status"] == "NOT_RUN" for c in checks) else
                     "SCOPED_FAIL")
            rows.append({"id": item["id"], "checklist_status": item["status"],
                         "evidence": state, "checks": checks, "full_feature_verified": False})
        results.append({**identity, "status": "INCOMPLETE_NOT_ALL_PASS",
                        "features": rows})
    return {"schema_version": 1, "collected_utc": datetime.now(timezone.utc).isoformat(),  # noqa: UP017 - Python 3.9
            "status": "INCOMPLETE_NOT_ALL_PASS", "all_260_functions_qualified": False,
            "independent_external_audit": False, "unknown_project_code_executed": False,
            "closed_feature_count": len(items) - len(open_items),
            "open_feature_count": len(open_items),
            "planned_feature_minor_cells": len(open_items) * len(EXPECTED_VERSIONS),
            "results": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python-bin", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    interpreters = {}
    for minor in EXPECTED_VERSIONS:
        item = args.python_bin / ("python" + minor)
        if item.exists():
            interpreters[minor] = item
    try:
        data = collect(checklist_items(ROOT / "docs" / "FUNCTION_CHECKLIST.md"), interpreters)
        serialized = json.dumps(data, sort_keys=True, ensure_ascii=True, indent=2) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(serialized)
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "NOT_RUN", "reason": type(exc).__name__}))
        return 2
    counts = {}
    for row in data["results"]:
        for feature in row["features"]:
            counts[feature["evidence"]] = counts.get(feature["evidence"], 0) + 1
    print(json.dumps({"status": data["status"], "open_items": len([x for x in
                      checklist_items(ROOT / "docs" / "FUNCTION_CHECKLIST.md")
                      if x["status"] != "IMPLEMENTED_TESTED"]),
                      "per_minor_evidence": counts}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
