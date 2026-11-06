"""Re-run genuine seven-minor stdlib AST/native coverage; persist proof JSON."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
VERSIONS = ["3." + str(number) for number in range(9, 16)]
SCAN = ROOT / "python" / "stdlib_native_complete_v23.py"


def _interpreter(version):
    return (sys.executable if version == "3.12" else
            str(WORKSPACE / ".python-bin" / ("python" + version)))


def _one(version):
    python = _interpreter(version)
    probe = subprocess.run([python, "-I", "-S", "-B", "-c",
                            "import hashlib,json,sysconfig;from pathlib import Path;"
                            "path=Path(sysconfig.get_path('stdlib')).resolve();"
                            "print(json.dumps({'root':str(path),'sha':"
                            "hashlib.sha256(str(path).encode()).hexdigest()}))"],
                           capture_output=True, check=False, timeout=8)
    if probe.returncode != 0:
        raise ValueError("stdlib_source_root_probe_failed")
    pinned = json.loads(probe.stdout)
    process = subprocess.run([python, "-I", "-S", "-B", str(SCAN),
                              "--mode", "extract", "--source-root", pinned["root"],
                              "--source-root-sha256", pinned["sha"]],
                             capture_output=True, check=False, timeout=30)
    if process.returncode != 0:
        raise ValueError("stdlib_source_native_extractor_failed")
    result = json.loads(process.stdout)
    if (result["status"] != "BROAD_STDLIB_AST_PLUS_NATIVE_LOCAL_PASS" or
            result["python_minor"] != version or
            result["uncovered_independent_native_symbols"] or
            not result["qualified_f068_bounded_local_scope"]):
        raise ValueError("stdlib_oracle_or_version_failed")
    result["exact_installed_stdlib_root_sha256"] = pinned["sha"]
    result["exact_source_root_verified_via_real_python"] = True
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error("output already exists: no overwrite")
    rows = []
    for version in VERSIONS:
        try:
            rows.append(_one(version))
        except (OSError, ValueError, json.JSONDecodeError):
            print(json.dumps({"status": "NOT_RUN_OR_INCOMPLETE",
                              "failed_python_minor": version}))
            return 2
    report = {
        "schema_version": 1,
        "tested_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "SEVEN_REAL_STDLIB_AST_NATIVE_BOUNDARY_GATES_PASS",
        "covered_python_minors": VERSIONS,
        "total_real_stdlib_source_files_scanned": sum(row["source_files_scanned"]
                                                      for row in rows),
        "total_real_static_api_candidates": sum(row["static_api_declaration_candidates"]
                                               for row in rows),
        "total_real_native_runtime_symbols": sum(row["native_runtime_symbols"]
                                                for row in rows),
        "total_actual_native_text_signatures": sum(row["native_signature_count"]
                                                   for row in rows),
        "independent_native_coverage_oracles_all_pass": all(
            not row["uncovered_independent_native_symbols"] for row in rows),
        "actual_source_root_pin_checked_all_seven": True,
        "stdlib_C_level_complete": False,
        "dynamic_stdlib_exports_complete": False,
        "unknown_code_executed": False,
        "per_version": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps({"status": report["status"],
                      "python_minors": len(rows),
                      "source_files": report["total_real_stdlib_source_files_scanned"],
                      "static_apis": report["total_real_static_api_candidates"],
                      "native_symbols": report["total_real_native_runtime_symbols"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
