"""Record actual CPython 3.9–3.15 compiler-trained model evidence.

The embedded selftest intentionally does NOT assert external auditor approval,
general-purpose auto-repair, or execution of unknown user code.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
ROUTER = ROOT / "python" / "code_model_router_v24.py"
MINORS = tuple("3.{}".format(i) for i in range(9, 16))


def measure_version(version, interpreter):
    if not interpreter.is_absolute() or not interpreter.resolve().is_file():
        raise ValueError("missing_explicit_python_interpreter")
    probe = subprocess.run([str(interpreter), "-I", "-S", "-B", "-c",
                            "import sys;print('%s.%s'%sys.version_info[:2])"],
                           capture_output=True, text=True, timeout=10, check=False)
    if probe.returncode or probe.stdout.strip() != version:
        raise ValueError("unverified_python_minor:" + version)
    attempt = subprocess.run([str(interpreter), "-I", "-S", "-B", str(ROUTER),
                              "--mode", "selftest"], capture_output=True,
                             text=True, timeout=40, check=False)
    if attempt.returncode:
        raise ValueError("model_selftest_nonzero:" + version)
    data = json.loads(attempt.stdout)
    calibration = data["calibration"]
    if (data["status"] != "TRUSTED_CODE_MODEL_LOCAL_SELFTEST_NO_EXTERNAL_AUDIT" or
            calibration["status"] != "TWO_ACTUALLY_TRAINED_CODE_MODELS_CALIBRATED" or
            data["model_routing_demonstrated"] is not True or
            data["external_independent_auditor_attested"] is not False or
            data["source_code_executed"] is not False or
            calibration["arbitrary_project_repair_verified"] is not False or
            set(data["reports"]) != {"multinomial_nb", "multiclass_perceptron"}):
        raise ValueError("unqualified_or_misrepresented_model_results:" + version)
    summaries = {}
    for family, report in data["reports"].items():
        if (report["actual_oracle_runs"] != 32 or
                report["exact_repair_rate"] < 0.95 or
                set(report["per_kind_repair_rate"]) !=
                {"COLON", "PAREN", "BRACKET", "BRACE"} or
                min(report["per_kind_repair_rate"].values()) < .95 or
                report["p95_wall_us"] <= 0 or report["p95_cpu_us"] <= 0 or
                report["compute_cost_unit"] != "actual_process_CPU_microseconds_not_money"):
            raise ValueError("insufficient_real_model_quality:" + version)
        summaries[family] = report
    return {"version": version, "python_executable": str(interpreter.resolve()),
            "actual_train_examples_per_model": 120,
            "actual_disjoint_holdout_cases_per_model": 32,
            "model_reports": summaries, "local_selftest_pass": True,
            "external_audit_claimed": False, "unknown_source_executed": False,
            "arbitrary_project_correctness_claimed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interpreter", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    mapping = {}
    for spec in args.interpreter:
        version, sep, path = spec.partition("=")
        if not sep or version not in MINORS or version in mapping:
            parser.error("exact seven unique minor=absolute-interpreter entries required")
        mapping[version] = Path(path)
    if len(mapping) != len(MINORS) or not args.output.parent.is_dir():
        parser.error("all seven CPython minors and existing output directory required")
    records = [measure_version(version, mapping[version]) for version in MINORS]
    report = {"schema_version": 1,
              "measured_utc": datetime.now(timezone.utc).isoformat(),
              "status": "PASS_BOUND_TO_TRUSTED_SYNTAX_DOMAIN_ONLY",
              "source_sha256": hashlib.sha256(ROUTER.read_bytes()).hexdigest(),
              "versions": records, "actual_real_compiler_training_cases": len(records)*120*2,
              "actual_heldout_model_inferences": len(records)*32*2,
              "external_auditor_verified": False,
              "all_functions_260_verified": False,
              "unknown_python_code_executed": False}
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print("CODE-MODEL {} actual train runs, {} heldout model runs, seven minors PASS".format(
        report["actual_real_compiler_training_cases"],
        report["actual_heldout_model_inferences"]))


if __name__ == "__main__":
    sys.exit(main())
