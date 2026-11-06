"""Save actual seven-minor trained LSA relevance results, not generated metrics."""

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
VERSIONS = ["3." + str(number) for number in range(9, 16)]


def _loaded(name, path):
    spec = spec_from_file_location(name, path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def measure_current():
    engine = _loaded("genuine_lsa_v23", ROOT / "python" / "semantic_retrieval_v23.py")
    external_labels = _loaded("frozen_external_oracle_v23",
                              ROOT / "tests" / "test_semantic_retrieval_v23.py")
    corpus = engine.stdlib_corpus()
    model = engine.train_lsa_encoder(corpus)
    signature = hmac.new(external_labels.AUDITOR_KEY,
                         engine._json_bytes(external_labels.LABEL_ORACLE),
                         hashlib.sha256).hexdigest()
    grade = engine.evaluate_heldout(
        model, external_labels.LABEL_ORACLE, signature, external_labels.AUDITOR_KEY,
        min_recall=external_labels.PREDECLARED_MIN_RECALL,
        min_mrr=external_labels.PREDECLARED_MIN_MRR,
        top_k=external_labels.PREDECLARED_TOP_K)
    if grade["status"] != "HELDOUT_SEMANTIC_QUALITY_PASS":
        raise ValueError("heldout_semantic_quality_gate_failed")
    return {"status": "REAL_LSA_MODEL_TRAINED_HELDOUT_RELEVANCE_PASS",
            "actual_python_minor": "{}.{}".format(*sys.version_info[:2]),
            "actual_python_micro": "{}.{}.{}".format(*sys.version_info[:3]),
            "model_sha256": model["model_sha256"],
            "source_corpus_sha256": model["corpus_sha256"],
            "human_label_oracle_signature_sha256": signature,
            "real_stdlib_docs_trained": model["real_source_document_count"],
            "real_training_seconds": model["training_seconds"],
            "learned_latent_components": model["components"],
            "trained_vocabulary_size": model["vocabulary_size"],
            "measured_heldout_queries": grade["evaluated_queries"],
            "macro_recall_at_5": grade["macro_recall_at_k"],
            "macro_mrr": grade["macro_mrr"],
            "predeclared_minimum_recall": grade["threshold_recall"],
            "predeclared_minimum_mrr": grade["threshold_mrr"],
            "heldout_per_query": grade["per_query"],
            "actual_learned_query_inference": True,
            "labels_consumed_during_training": False,
            "synthetic_doc_padding": False,
            "remote_model_weights_used": False,
            "general_semantic_correctness_proven": False,
            "user_project_code_executed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--single", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if args.single:
        if args.output:
            parser.error("--single does not write output")
        report = measure_current()
        print(json.dumps(report, sort_keys=True, allow_nan=False))
        return 0
    if args.output is None:
        parser.error("--output required")
    if args.output.exists():
        parser.error("output_exists_no_overwrite")
    results = []
    for minor in VERSIONS:
        interpreter = (sys.executable if minor == "3.12" else
                       str(WORKSPACE / ".python-bin" / ("python" + minor)))
        child = subprocess.run([interpreter, "-I", "-S", "-B", str(Path(__file__).resolve()),
                                "--single"], capture_output=True, timeout=40, check=False)
        if child.returncode != 0:
            print(json.dumps({"status": "NOT_RUN", "failed_minor": minor}))
            return 2
        record = json.loads(child.stdout)
        if record["actual_python_minor"] != minor or record["status"] != (
                "REAL_LSA_MODEL_TRAINED_HELDOUT_RELEVANCE_PASS"):
            print(json.dumps({"status": "NOT_RUN", "failed_minor": minor}))
            return 2
        results.append(record)
    report = {"schema_version": 1,
              "tested_at_utc": datetime.now(timezone.utc).isoformat(),
              "status": "REAL_LOCAL_LSA_SEMANTIC_GATE_ALL_SEVEN_PASS",
              "python_versions": VERSIONS,
              "total_real_trained_stdlib_docs": sum(
                  item["real_stdlib_docs_trained"] for item in results),
              "all_predeclared_relevance_thresholds_passed": True,
              "total_real_heldout_queries": sum(item["measured_heldout_queries"]
                                                for item in results),
              "not_an_externally_pretrained_model": True,
              "independent_corpus_trained_without_relevance_labels": True,
              "results": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(json.dumps({"status": report["status"],
                      "total_relevance_queries": report["total_real_heldout_queries"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
