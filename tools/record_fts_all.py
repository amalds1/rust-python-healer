"""Re-run and retain five independent FTS5 rounds per real CPython minor."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "tools" / "bench_fts.py"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interpreter", action="append", required=True)
    parser.add_argument("--json", required=True, type=Path)
    args = parser.parse_args()
    if len(args.interpreter) != 7:
        parser.error("seven explicit real CPython interpreters required")
    results = []
    seen = set()
    for item in args.interpreter:
        version, marker, path = item.partition("=")
        if marker != "=" or version not in {"3." + str(x) for x in range(9, 16)}:
            parser.error("invalid interpreter mapping")
        if version in seen:
            parser.error("duplicate CPython minor")
        seen.add(version)
        process = subprocess.run([str(Path(path).resolve()), str(BENCH),
                                  "--records", "10000", "--queries", "30", "--runs", "5"],
                                 cwd=str(ROOT), capture_output=True, text=True,
                                 timeout=120, check=False)
        if process.returncode != 0:
            raise RuntimeError("FTS measurement failed to complete: " + version)
        data = json.loads(process.stdout)
        if (not data["python_version"].startswith(version + ".") or
                data["independent_runs"] != 5 or len(data["runs"]) != 5 or
                data["records"] != 10000 or
                data["total_query_measurements"] != 150 or
                data["fts_p95_status"] != "PASS"):
            raise AssertionError("FTS performance gate not proven: " + version)
        results.append({"minor": version, **data})
        print("CPython {}: 5/5 FTS5 rounds PASS".format(version), flush=True)
    report = {"schema_version": 1,
              "tested_at_utc": datetime.now(timezone.utc).isoformat(),
              "suite_sha256": hashlib.sha256(BENCH.read_bytes()).hexdigest(),
              "scope": "SQLite FTS5 synthetic 10000 documents, not production corpus",
              "independent_rounds": 35,
              "total_query_measurements": 1050,
              "status": "PASS", "versions": results}
    args.json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
