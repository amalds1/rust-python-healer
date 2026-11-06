"""Record real seven-minor, signed-oracle two-model calibration and feedback.

Runs the actual local CPython executables and writes evidence only after all
seven genuine model-learning, inference and feedback policy gates pass.
"""

import argparse
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PARENT = ROOT.parent
PYTHON_BIN = {minor: str(PARENT / ".python-bin" / ("python"+minor))
              for minor in ("3.9", "3.10", "3.11", "3.13", "3.14", "3.15")}
PYTHON_BIN["3.12"] = sys.executable

PROBE = r'''
import json, sys, tempfile
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root/"python"))
sys.path.insert(0, str(root/"tests"))
import real_model_router_v23 as r
import test_real_model_router_v23 as oracle
corpus = r.stdlib_corpus()
models = r.train_pair(corpus)
bench = r.calibrate_router(models, oracle.ORACLE, oracle.SIGNATURE, oracle.KEY)
reports = bench["model_reports"]
if len(models) != 2 or len(reports) != 2 or not all(x["eligible"] for x in reports.values()):
    raise ValueError("two_real_trained_models_quality_gate_failed")
before = r.route_query(models, bench, "arithmetic average of numeric data",
                       auditor_key=oracle.KEY)
with tempfile.TemporaryDirectory(prefix="rph-dual-real-feedback-") as folder:
    db = Path(folder)/"verified.sqlite"
    appended = r.append_measured_feedback(db, models, bench,
                "arithmetic average of numeric data", oracle.KEY)
    verified = r.verified_feedback(db, oracle.KEY)
    after = r.route_query(models, bench, "arithmetic average of numeric data",
                          auditor_key=oracle.KEY, feedback_db=db)
if before["selected_model"] == after["selected_model"]:
    raise ValueError("real_feedback_did_not_adapt_policy")
if appended["records"] != 2 or verified["verified_record_count"] != 2:
    raise ValueError("real_measured_model_feedback_missing")
out = {"python_minor": "{}.{}".format(*sys.version_info[:2]),
       "python_implementation": sys.implementation.name,
       "python_binary": sys.executable,
       "stdlib_corpus_sha256": corpus["corpus_sha256"],
       "real_installed_stdlib_docs": len(corpus["sources"]),
       "independent_signed_oracle_sha256": bench["oracle_sha256"],
       "independent_evaluation_queries": bench["evaluated_real_stdlib_queries"],
       "models": {family: {k: v for k,v in record.items()
                            if k != "per_query"} for family, record in reports.items()},
       "feedback_before_model": before["selected_model"],
       "feedback_after_model": after["selected_model"],
       "signed_real_inference_feedback_rows": verified["verified_record_count"],
       "runtime_feedback_policy_learned": after["online_policy_feedback_learning"],
       "source_code_executed": False,
       "model_remote_llm_attested": False,
       "full_python_bug_autofix_routing_attested": False}
print(json.dumps(out,sort_keys=True,allow_nan=False))
'''


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    rows = []
    for minor in ("3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15"):
        exe = PYTHON_BIN[minor]
        result = subprocess.run([exe, "-I", "-S", "-B", "-c", PROBE,
                                 str(ROOT)], capture_output=True,
                                text=True, check=False, timeout=45)
        if result.returncode:
            raise RuntimeError("{}: {}".format(minor, result.stderr[-1500:]))
        entry = json.loads(result.stdout)
        if (entry["python_minor"] != minor or
                entry["independent_evaluation_queries"] != 14 or
                len(entry["models"]) != 2 or
                any(not value["eligible"] or value["inference_p95_us"] <= 0
                    for value in entry["models"].values()) or
                not entry["runtime_feedback_policy_learned"] or
                entry["signed_real_inference_feedback_rows"] != 2):
            raise RuntimeError("{}: actual_inference_learning_gate_failed".format(minor))
        rows.append(entry)
    report = {"status": "SEVEN_REAL_PYTHON_DUAL_TRAINED_MODEL_GATES_PASS",
              "covered_minors": [item["python_minor"] for item in rows],
              "model_family_count": 2,
              "actual_independent_model_oracle_runs": len(rows)*14*2,
              "real_signed_feedback_records": len(rows)*2,
              "actual_runtime_feedback_policy_learning_all_seven": True,
              "remote_foundation_models_claimed": False,
              "general_python_bug_autofix_quality_claimed": False,
              "per_version": rows}
    path = Path(args.output)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise RuntimeError("unsafe_evidence_destination")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8")
    print(json.dumps({"status": report["status"],
                      "python_minors": len(rows),
                      "actual_model_evaluations":
                          report["actual_independent_model_oracle_runs"],
                      "signed_feedback_records":
                          report["real_signed_feedback_records"]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
