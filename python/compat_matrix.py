"""Conservative compile-only compatibility matrix for CPython 3.9+.

Only an interpreter with the matching major.minor can validate that version.
Never claims full runtime/package compatibility from a successful compile.
"""

import argparse
import json
from pathlib import Path
import re
import subprocess


PROBE = r'''
import json, sys, tokenize
version = sys.version_info
result = {"actual": f"{version.major}.{version.minor}.{version.micro}",
          "implementation": sys.implementation.name, "compile": "NOT_RUN",
          "error": None}
try:
    with tokenize.open(sys.argv[1]) as handle:
        source = handle.read()
    compile(source, sys.argv[1], "exec", dont_inherit=True)
except (SyntaxError, UnicodeError, ValueError, OSError) as exc:
    result["compile"] = "FAIL"
    result["error"] = str(exc)
else:
    result["compile"] = "PASS"
print(json.dumps(result))
'''


def parse_version(value):
    if not isinstance(value, str) or not re.fullmatch(r"3\.(\d+)(?:\.(\d+))?", value):
        raise ValueError(f"ongeldige CPython-versie: {value!r}")
    parts = [int(x) for x in value.split(".")]
    if parts[1] < 9 or parts[1] > 99:
        raise ValueError("de versie ligt buiten de toegelaten matrix")
    return parts


def matrix(file_path, manifest, overrides=None, timeout=10, suite_path=None):
    config = json.loads(Path(manifest).read_text(encoding="utf-8"))
    first = parse_version(config["minimum_python"])[1]
    latest = parse_version(config["latest_stable"])[1]
    if first > latest:
        raise ValueError("minimale versie ligt na de nieuwste stabiele versie")
    source = Path(file_path)
    if not source.is_file() or source.stat().st_size > 4_000_000:
        raise ValueError("er is een Python-bronbestand van maximaal 4 MB vereist")
    overrides = overrides or {}
    suite_path = Path(suite_path) if suite_path else Path(__file__).with_name("version_suite.py")
    items = []
    for minor in range(first, latest + 1):
        label = f"3.{minor}"
        executable = overrides.get(label, f"python{label}")
        record = {"version": label, "interpreter": executable,
                  "status": "NOT_RUN", "compile": "NOT_RUN", "actual": None,
                  "tests": "NOT_RUN", "tests_pass": 0, "tests_fail": 0,
                  "error": "interpreter ontbreekt of is niet gestart"}
        try:
            proc = subprocess.run([executable, "-I", "-S", "-B", "-c", PROBE,
                                   str(source.resolve())], capture_output=True,
                                  text=True, timeout=timeout, check=False)
            if proc.returncode != 0:
                record["error"] = f"interpreter exit {proc.returncode}: {proc.stderr[:300]}"
            else:
                result = json.loads(proc.stdout)
                record["actual"] = result["actual"]
                record["error"] = result["error"]
                if result["implementation"] != "cpython" or not result["actual"].startswith(label + "."):
                    record["error"] = f"vereist CPython {label}, gevonden {result['actual']} {result['implementation']}"
                else:
                    record["compile"] = result["compile"]
                    try:
                        suite = subprocess.run(
                            [executable, "-I", "-S", "-B", str(suite_path.resolve())],
                            capture_output=True, text=True, timeout=timeout, check=False,
                        )
                        if suite.returncode == 0:
                            details = json.loads(suite.stdout)
                            if details["cases"] == 100 and details["pass"] + details["fail"] == 100:
                                record["tests"] = details["status"]
                                record["tests_pass"] = details["pass"]
                                record["tests_fail"] = details["fail"]
                            else:
                                record["error"] = "testsuite bevat geen 100 geldige testresultaten"
                        else:
                            record["error"] = "testsuite faalde: " + suite.stderr[:300]
                    except (FileNotFoundError, PermissionError,
                            subprocess.TimeoutExpired, ValueError, KeyError) as exc:
                        record["error"] = str(exc)
                    if record["tests"] != "NOT_RUN":
                        record["status"] = "PASS" if record["compile"] == "PASS" and record["tests"] == "PASS" else "FAIL"
        except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired) as exc:
            record["error"] = str(exc)
        items.append(record)
    return {
        "range": f"3.{first}–3.{latest}",
        "latest_stable": config["latest_stable"],
        "results": items,
        "tests_planned": 100 * len(items),
        "tests_executed": sum(r["tests_pass"] + r["tests_fail"] for r in items),
        "tests_pass": sum(r["tests_pass"] for r in items),
        "tests_fail": sum(r["tests_fail"] for r in items),
        "all_version_suites_pass": all(r["status"] == "PASS" for r in items),
        "full_compatibility": "NOT_VERIFIED",
        "reason": "100 geselecteerde checks per versie bewijzen niet alle package-API's, ABIs of projectgedrag",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--suite-path", default=None)
    parser.add_argument("--json", type=Path, default=None,
                        help="Schrijf ook het exacte machineleesbare lokale testrapport")
    parser.add_argument("--interpreter", action="append", default=[],
                        help="Versie=pad, bijvoorbeeld 3.9=/opt/cpython39/bin/python3.9")
    args = parser.parse_args()
    overrides = {}
    for value in args.interpreter:
        if "=" not in value:
            parser.error("interpreter moet VERSIE=PAD zijn")
        label, path = value.split("=", 1)
        parse_version(label)
        if not path:
            parser.error("interpreterpad is leeg")
        overrides[label] = path
    report = matrix(args.file, args.manifest, overrides, suite_path=args.suite_path)
    encoded = json.dumps(report, indent=2)
    if args.json is not None:
        if not args.json.parent.is_dir() or args.json.is_symlink():
            parser.error("rapportaanduiding moet een bestaand regulier pad zijn")
        args.json.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)


if __name__ == "__main__":
    main()
