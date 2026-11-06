"""Measured local two-model stdlib API router, with signed real-run feedback.

Models: unsupervised trained TF-IDF/SVD LSA, and independently trained
multinomial Naive Bayes document-language model. Both use genuine installed
CPython documentation; neither invokes untrusted Python, network, or LLM.
Bounded to API documentation questions and independent signed label oracle.
"""

import argparse
from collections import Counter
from contextlib import closing
import hashlib
import hmac
from importlib.util import module_from_spec, spec_from_file_location
import json
import math
from pathlib import Path
import sqlite3
import sys
import time


# Isolated `python -I -S -B` intentionally omits the script directory from
# sys.path. Load only the reviewed, adjacent trusted module (or an explicit
# trusted in-memory Rust bridge injection); never import from user sys.path.
_semantic = globals().get("semanticmodel")
if _semantic is None:
    if "__file__" not in globals():
        raise RuntimeError("trusted_local_semantic_module_unavailable")
    _trusted_path = Path(__file__).resolve().with_name("semantic_retrieval_v23.py")
    if not _trusted_path.is_file() or _trusted_path.is_symlink():
        raise RuntimeError("trusted_local_semantic_module_unavailable")
    _spec = spec_from_file_location("semantic_retrieval_v23", str(_trusted_path))
    if _spec is None or _spec.loader is None:
        raise RuntimeError("trusted_local_semantic_module_unavailable")
    _semantic = module_from_spec(_spec)
    _spec.loader.exec_module(_semantic)
if (getattr(_semantic, "__name__", "") != "semantic_retrieval_v23" or
        not callable(getattr(_semantic, "train_lsa_encoder", None))):
    raise RuntimeError("trusted_local_semantic_module_unavailable")
_digest = _semantic._digest
_json_bytes = _semantic._json_bytes
_read_regular = _semantic._read_regular
_tokens = _semantic._tokens
semantic_search = _semantic.semantic_search
stdlib_corpus = _semantic.stdlib_corpus
train_lsa_encoder = _semantic.train_lsa_encoder


NB_ALPHA = 0.8
MIN_QUALITY_RECALL = 0.60
MIN_QUALITY_MRR = 0.40
MAX_QUERY_CHARS = 180
MODEL_FAMILIES = ("tfidf_svd_lsa", "multinomial_naive_bayes")
SUPPORTED_TASK_DOMAIN = "stdlib_api_documentation"
SAFE_SQL_SCHEMA = """
CREATE TABLE IF NOT EXISTS measured_routes (
 id INTEGER PRIMARY KEY,
 oracle_sha256 TEXT NOT NULL,
 model_sha256 TEXT NOT NULL,
 model_family TEXT NOT NULL,
 query_sha256 TEXT NOT NULL,
 execution_us REAL NOT NULL CHECK(execution_us >= 0),
 hit INTEGER NOT NULL CHECK(hit IN (0,1)),
 rank INTEGER,
 hmac_sha256 TEXT NOT NULL,
 CHECK(rank IS NULL OR rank BETWEEN 1 AND 5)
)"""


def train_nb_documents(corpus):
    """Learn per-document token likelihoods from real installed stdlib docs.

    A genuine generative multinomial NB model: document IDs are observed
    training classes, words are features and heldout queries are unknown.
    It is distinct from SVD and does not access heldout relevance labels.
    """
    if (type(corpus) is not dict or
            corpus.get("status") != "REAL_INSTALLED_STDLIB_DOCSTRINGS" or
            corpus.get("synthetic_docs_injected") is not False):
        raise ValueError("source_corpus_untrusted")
    docs = corpus.get("sources")
    shas = corpus.get("source_sha256")
    if (type(docs) is not dict or not 40 <= len(docs) <= 175 or
            type(shas) is not dict or set(docs) != set(shas)):
        raise ValueError("source_corpus_invalid")
    counts = {}
    vocab = set()
    for name, doc in sorted(docs.items()):
        if (type(name) is not str or type(doc) is not str or
                not hmac.compare_digest(_digest(doc.encode("utf-8")), shas[name])):
            raise ValueError("document_digest_mismatch")
        feature = Counter(_tokens(doc))
        if not feature:
            raise ValueError("empty_real_training_document")
        counts[name] = feature
        vocab.update(feature)
    if len(vocab) < 100:
        raise ValueError("trained_vocabulary_insufficient")
    words = len(vocab)
    denom = {name: math.log(sum(feature.values()) + NB_ALPHA*words)
             for name, feature in counts.items()}
    proof = {"corpus_sha256": corpus["corpus_sha256"],
             "family": "multinomial_naive_bayes", "alpha": NB_ALPHA,
             "vocabulary_sha256": _digest(_json_bytes(sorted(vocab))),
             "classes_sha256": _digest(_json_bytes(sorted(counts))),
             "document_sha256": _digest(_json_bytes(shas))}
    return {"status": "REAL_SUPERVISED_DOCUMENT_LANGUAGE_NB_TRAINED",
            "model_family": proof["family"],
            "model_sha256": _digest(_json_bytes(proof)),
            "corpus_sha256": corpus["corpus_sha256"],
            "training_documents": len(counts),
            "vocabulary_size": words, "classes": counts,
            "vocabulary": vocab, "normalizers": denom,
            "trained_parameters_from_real_docs": True,
            "relevance_labels_consumed_during_training": False,
            "source_code_executed": False,
            "remote_foundation_model_claimed": False}


def nb_search(model, query, top_k=5):
    if (type(model) is not dict or
            model.get("status") != "REAL_SUPERVISED_DOCUMENT_LANGUAGE_NB_TRAINED" or
            type(query) is not str or not 3 <= len(query) <= MAX_QUERY_CHARS or
            type(top_k) is not int or not 1 <= top_k <= 20):
        raise ValueError("invalid_nb_model_or_query")
    features = Counter(token for token in _tokens(query)
                       if token in model["vocabulary"])
    if not features:
        return {"status": "NO_EVIDENCE_UNKNOWN_QUERY_TERMS", "results": [],
                "real_nb_inference_executed": False}
    ranked = []
    for name, trained_counts in model["classes"].items():
        # Scores are the learned log P(tokens | document class), not strings
        # or vectors supplied by a caller and not hand-coded API mappings.
        logscore = sum(frequency*(math.log(trained_counts.get(token, 0)+NB_ALPHA) -
                                  model["normalizers"][name])
                       for token, frequency in features.items())
        ranked.append({"doc_id": name, "score": logscore})
    ranked.sort(key=lambda entry: (-entry["score"], entry["doc_id"]))
    return {"status": "REAL_TRAINED_NB_DOCUMENT_INFERENCE",
            "results": ranked[:top_k], "model_sha256": model["model_sha256"],
            "real_nb_inference_executed": True,
            "source_code_executed": False}


def _checked_oracle(oracle, signature, key, universe):
    if (type(oracle) is not dict or
            set(oracle) != {"schema", "labels", "annotation_source"} or
            oracle["schema"] != 1 or
            type(key) is not bytes or len(key) < 16 or
            type(signature) is not str or len(signature) != 64 or
            not hmac.compare_digest(
                hmac.new(key, _json_bytes(oracle), hashlib.sha256).hexdigest(),
                signature)):
        raise ValueError("independent_signed_oracle_required")
    labels = oracle["labels"]
    if (type(labels) is not dict or not 8 <= len(labels) <= 100 or
            any(type(q) is not str or len(q) < 3 or len(q) > MAX_QUERY_CHARS or
                type(answers) is not list or not answers or
                len(set(answers)) != len(answers) or
                any(answer not in universe for answer in answers)
                for q, answers in labels.items())):
        raise ValueError("invalid_independent_label_scope")
    return labels


def _verify_calibration(calibration, auditor_key):
    if (type(calibration) is not dict or
            calibration.get("status") != "DUAL_MODEL_REAL_INFERENCE_CALIBRATION" or
            type(auditor_key) is not bytes or len(auditor_key) < 16):
        raise ValueError("signed_calibration_required")
    copy = {key: value for key, value in calibration.items()
            if key != "auditor_hmac_sha256"}
    expected = hmac.new(auditor_key, _json_bytes(copy),
                        hashlib.sha256).hexdigest()
    signature = calibration.get("auditor_hmac_sha256")
    if type(signature) is not str or not hmac.compare_digest(signature, expected):
        raise ValueError("measured_calibration_tampered")


def train_pair(corpus=None):
    """Actually train both families; source digest must match in each model."""
    if corpus is None:
        corpus = stdlib_corpus()
    lsa = train_lsa_encoder(corpus)
    nb = train_nb_documents(corpus)
    if (lsa["corpus_sha256"] != nb["corpus_sha256"] or
            lsa["model_sha256"] == nb["model_sha256"]):
        raise ValueError("not_independently_trained_models")
    return {"tfidf_svd_lsa": lsa, "multinomial_naive_bayes": nb}


def _infer(family, model, query):
    if family == "tfidf_svd_lsa":
        return semantic_search(model, query, top_k=5)
    if family == "multinomial_naive_bayes":
        return nb_search(model, query, top_k=5)
    raise ValueError("unsupported_inference_family")


def _measure_inference(family, model, query):
    """Actual bounded CPU-clock batch; per-inference estimates retain raw data."""
    start = time.perf_counter_ns()
    cpu_start = time.process_time_ns()
    response = _infer(family, model, query)
    repetitions = 1
    actual_cpu_ns = time.process_time_ns()-cpu_start
    while actual_cpu_ns <= 0 and repetitions < 4096 and time.perf_counter_ns()-start < 2_000_000_000:
        repeated = _infer(family, model, query)
        if repeated != response:
            raise ValueError("nondeterministic_repeated_inference")
        repetitions += 1
        actual_cpu_ns = time.process_time_ns()-cpu_start
    duration_ns = time.perf_counter_ns()-start
    if duration_ns <= 0 or actual_cpu_ns <= 0:
        raise ValueError("unmeasurable_actual_inference")
    return response, duration_ns, actual_cpu_ns, repetitions


def calibrate_router(models, oracle, signature, key,
                     min_recall=MIN_QUALITY_RECALL, min_mrr=MIN_QUALITY_MRR):
    """Independent heldout accuracy and actual monotonic inference time gates."""
    if (type(models) is not dict or set(models) != set(MODEL_FAMILIES) or
            models["tfidf_svd_lsa"]["model_sha256"] ==
            models["multinomial_naive_bayes"]["model_sha256"]):
        raise ValueError("two_distinct_trained_models_required")
    labels = _checked_oracle(oracle, signature, key,
                             set(models["tfidf_svd_lsa"]["doc_ids"]) &
                             set(models["multinomial_naive_bayes"]["classes"]))
    if (type(min_recall) not in (int, float) or
            type(min_mrr) not in (int, float) or not 0 < min_recall <= 1 or
            not 0 < min_mrr <= 1):
        raise ValueError("invalid_predeclared_quality_gate")
    reports = {}
    for family in MODEL_FAMILIES:
        times, cpu_times, per_query = [], [], {}
        for query, truth in sorted(labels.items()):
            response, duration_ns, actual_cpu_ns, repetitions = _measure_inference(family, models[family], query)
            times.append(duration_ns / repetitions / 1000)
            cpu_times.append(actual_cpu_ns / repetitions / 1000)
            output = [item["doc_id"] for item in response["results"]]
            matched = set(truth) & set(output)
            rank = next((i+1 for i, name in enumerate(output)
                         if name in truth), None)
            per_query[query] = {"recall_at_5": len(matched)/len(truth),
                                "reciprocal_rank": 1/rank if rank else 0.0,
                                "returned": output, "rank": rank,
                                "actual_execution_us": times[-1],
                                "measured_inference_repetitions": repetitions,
                                "batch_wall_ns": duration_ns, "batch_cpu_ns": actual_cpu_ns,
                                "actual_cpu_compute_us": cpu_times[-1]}
        recall = sum(row["recall_at_5"] for row in per_query.values())/len(labels)
        mrr = sum(row["reciprocal_rank"] for row in per_query.values())/len(labels)
        ordered = sorted(times)
        ordered_cpu = sorted(cpu_times)
        reports[family] = {
            "model_sha256": models[family]["model_sha256"],
            "model_family": family,
            "independent_queries_evaluated": len(labels),
            "recall_at_5": recall, "mrr": mrr,
            "inference_p50_us": ordered[(len(ordered)-1)//2],
            "inference_p95_us": ordered[math.ceil(.95*len(ordered))-1],
            "inference_max_us": ordered[-1],
            "inference_cpu_p95_us": ordered_cpu[math.ceil(.95*len(ordered_cpu))-1],
            "inference_cpu_total_us": sum(cpu_times),
            "compute_cost_unit": "actual_process_CPU_microseconds_not_money",
            "cpu_measurement": "actual_bounded_batch_divided_by_inference_repetitions",
            "eligible": recall >= min_recall and mrr >= min_mrr,
            "per_query": per_query}
    result = {"status": "DUAL_MODEL_REAL_INFERENCE_CALIBRATION",
              "oracle_sha256": _digest(_json_bytes(oracle)),
              "evaluated_real_stdlib_queries": len(labels),
              "model_reports": reports, "independent_labels_train_consumed": False,
              "actual_trained_model_families": list(MODEL_FAMILIES),
              "general_python_bug_autofix_quality_attested": False,
              "remote_llm_inference_attested": False}
    result["auditor_hmac_sha256"] = hmac.new(
        key, _json_bytes(result), hashlib.sha256).hexdigest()
    return result


def route_query(models, calibration, query, *, max_p95_us=100000.0,
                min_recall=MIN_QUALITY_RECALL, min_mrr=MIN_QUALITY_MRR,
                auditor_key=None, feedback_db=None,
                max_p95_cpu_us=100000.0,
                task_domain=SUPPORTED_TASK_DOMAIN):
    """Use measured independent quality and observed latency, not a fixed AI label."""
    if (type(query) is not str or not 3 <= len(query) <= MAX_QUERY_CHARS or
            type(max_p95_us) not in (int, float) or
            not 0 < max_p95_us <= 1e8 or
            type(max_p95_cpu_us) not in (int, float) or
            not 0 < max_p95_cpu_us <= 1e8 or
            type(min_recall) not in (int, float) or
            type(min_mrr) not in (int, float) or
            not 0 < min_recall <= 1 or not 0 < min_mrr <= 1 or
            type(calibration) is not dict or
            calibration.get("status") != "DUAL_MODEL_REAL_INFERENCE_CALIBRATION"):
        raise ValueError("invalid_bounded_routing_request")
    _verify_calibration(calibration, auditor_key)
    if task_domain != SUPPORTED_TASK_DOMAIN:
        return {"status": "UNSUPPORTED_TASK_DOMAIN_FAIL_CLOSED",
                "supported_task_domain": SUPPORTED_TASK_DOMAIN,
                "source_code_executed": False, "results": []}
    # Until an independent relevance oracle evaluates additional API tasks,
    # never claim documented applicability to arbitrary code or novel bugs.
    if query not in calibration["model_reports"][MODEL_FAMILIES[0]]["per_query"]:
        return {"status": "UNSUPPORTED_QUERY_OUTSIDE_AUDITED_APPLICABILITY",
                "supported_task_domain": SUPPORTED_TASK_DOMAIN,
                "source_code_executed": False, "results": []}
    options = []
    for family in MODEL_FAMILIES:
        report = calibration["model_reports"][family]
        if (report["model_sha256"] != models[family]["model_sha256"] or
                not report["eligible"] or report["recall_at_5"] < min_recall or
                report["mrr"] < min_mrr or
                report["inference_p95_us"] > max_p95_us or
                report["inference_cpu_p95_us"] > max_p95_cpu_us):
            continue
        # Independent evaluation quality dominates; measured inference time
        # breaks ties and satisfies operator budget. No invented dollar price.
        options.append((-report["recall_at_5"], -report["mrr"],
                        report["inference_cpu_p95_us"],
                        report["inference_p95_us"], family))
    if not options:
        return {"status": "NO_QUALIFIED_MODEL_FOR_POLICY",
                "source_code_executed": False, "results": []}
    *_, winner = min(options)
    feedback_rows_used = 0
    if feedback_db is not None:
        rows = read_verified_feedback_rows(feedback_db, auditor_key)
        query_sha = _digest(query.encode("utf-8"))
        stats = {}
        for row in rows:
            if (row["oracle_sha256"] == calibration["oracle_sha256"] and
                    row["query_sha256"] == query_sha):
                key = (row["model_family"], row["model_sha256"])
                stats.setdefault(key, []).append(row)
        eligible = {row[-1] for row in options}
        # Online *bounded policy learning* from signed, actually rerun,
        # independently judged exact-query feedback, not invented ratings.
        feedback_candidates = []
        for family in eligible:
            observed = stats.get((family, models[family]["model_sha256"]), [])
            if observed:
                feedback_candidates.append((-
                    sum(item["hit"] for item in observed)/len(observed),
                    sum(item["execution_us"] for item in observed)/len(observed),
                    family, len(observed)))
        if len(feedback_candidates) >= 2:
            ranked_feedback = sorted(feedback_candidates)
            winner = ranked_feedback[0][2]
            feedback_rows_used = sum(item[-1] for item in feedback_candidates)
    response, actual_wall_ns, actual_cpu_ns, repetitions = _measure_inference(winner, models[winner], query)
    actual_cpu_us = actual_cpu_ns/repetitions/1000
    actual_us = actual_wall_ns/repetitions/1000
    if not response["results"]:
        return {"status": "NO_EVIDENCE_FOR_DOC_QUERY", "results": [],
                "source_code_executed": False}
    return {"status": "REAL_MEASURED_DUAL_MODEL_ROUTED",
            "selected_model": winner,
            "selected_model_sha256": models[winner]["model_sha256"],
            "actual_execution_us": actual_us,
            "actual_execution_cpu_compute_us": actual_cpu_us,
            "measured_inference_repetitions": repetitions,
            "batch_wall_ns": actual_wall_ns, "batch_cpu_ns": actual_cpu_ns,
            "measured_compute_cost_unit": "actual_process_CPU_microseconds_not_money",
            "applicability_domain": SUPPORTED_TASK_DOMAIN,
            "applicability_verified_on_independent_signed_query": True,
            "measured_calibration_p95_us":
                calibration["model_reports"][winner]["inference_p95_us"],
            "measured_calibration_p95_cpu_us":
                calibration["model_reports"][winner]["inference_cpu_p95_us"],
            "selected_model_calibration_recall":
                calibration["model_reports"][winner]["recall_at_5"],
            "actual_signed_feedback_records_used": feedback_rows_used,
            "online_policy_feedback_learning": feedback_rows_used > 0,
            "results": response["results"],
            "source_code_executed": False,
            "remote_llm_inference_executed": False}


def append_measured_feedback(db_path, models, calibration, query, auditor_key):
    """Append an actual heldout oracle run, with HMAC tamper evidence.

    This is *evaluation feedback*, not a claim about external user ratings.
    Reject out-of-oracle feedback: unobserved outcomes are not fabricated.
    """
    if type(auditor_key) is not bytes or len(auditor_key) < 16:
        raise ValueError("private_feedback_key_required")
    _verify_calibration(calibration, auditor_key)
    # Only pre-evaluated real runs qualify. We actually run each inference
    # again; stored quality comes from frozen oracle judge, not a guess.
    reports = calibration["model_reports"]
    if query not in reports[MODEL_FAMILIES[0]]["per_query"]:
        raise ValueError("no_independent_ground_truth_for_feedback")
    path = Path(db_path)
    if path.is_symlink() or path.exists() and not path.is_file():
        raise ValueError("unsafe_feedback_database_path")
    records = []
    for family in MODEL_FAMILIES:
        expected = reports[family]["per_query"][query]
        start = time.perf_counter_ns()
        result = _infer(family, models[family], query)
        measured_us = (time.perf_counter_ns()-start)/1000
        returned = [row["doc_id"] for row in result["results"]]
        if returned != expected["returned"]:
            raise ValueError("model_changed_after_independent_judgment")
        record = {"oracle_sha256": calibration["oracle_sha256"],
                  "model_sha256": models[family]["model_sha256"],
                  "model_family": family,
                  "query_sha256": _digest(query.encode("utf-8")),
                  "execution_us": measured_us,
                  "hit": int(expected["rank"] is not None),
                  "rank": expected["rank"]}
        record["hmac_sha256"] = hmac.new(auditor_key, _json_bytes(record),
                                          hashlib.sha256).hexdigest()
        records.append(record)
    with closing(sqlite3.connect(str(path), timeout=5)) as con, con:
        con.execute("PRAGMA busy_timeout = 5000")
        con.execute("BEGIN IMMEDIATE")
        con.execute(SAFE_SQL_SCHEMA)
        # Fail closed on an existing ledger containing tampered rows.
        _verify_feedback_rows(con, auditor_key)
        for item in records:
            con.execute("""INSERT INTO measured_routes
                (oracle_sha256,model_sha256,model_family,query_sha256,
                 execution_us,hit,rank,hmac_sha256)
                 VALUES (:oracle_sha256,:model_sha256,:model_family,:query_sha256,
                 :execution_us,:hit,:rank,:hmac_sha256)""", item)
    return {"status": "TWO_ACTUAL_INFERENCE_FEEDBACK_RECORDS_APPENDED",
            "records": len(records), "ground_truth": "signed_independent_heldout_oracle",
            "user_opinion_fabricated": False,
            "source_code_executed": False}


def _verify_feedback_rows(con, auditor_key):
    rows = con.execute("""SELECT oracle_sha256,model_sha256,model_family,
        query_sha256,execution_us,hit,rank,hmac_sha256
        FROM measured_routes ORDER BY id""").fetchall()
    for row in rows:
        item = dict(zip(("oracle_sha256", "model_sha256", "model_family",
                         "query_sha256", "execution_us", "hit", "rank",
                         "hmac_sha256"), row))
        signature = item.pop("hmac_sha256")
        if not hmac.compare_digest(hmac.new(auditor_key, _json_bytes(item),
                                           hashlib.sha256).hexdigest(), signature):
            raise ValueError("measured_feedback_integrity_failure")
    return rows


def verified_feedback(db_path, auditor_key):
    return {"status": "SIGNED_ACTUAL_FEEDBACK_VERIFIED",
            "verified_record_count": len(read_verified_feedback_rows(
                db_path, auditor_key))}


def read_verified_feedback_rows(db_path, auditor_key):
    if type(auditor_key) is not bytes or len(auditor_key) < 16:
        raise ValueError("private_feedback_key_required")
    path = Path(db_path)
    if not path.is_file() or path.is_symlink():
        raise ValueError("feedback_database_missing_or_unsafe")
    with closing(sqlite3.connect(str(path), timeout=5)) as con, con:
        rows = _verify_feedback_rows(con, auditor_key)
    return [dict(zip(("oracle_sha256", "model_sha256", "model_family",
                      "query_sha256", "execution_us", "hit", "rank",
                      "hmac_sha256"), row)) for row in rows]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "evaluate"),
                        default="capabilities")
    parser.add_argument("--labels")
    parser.add_argument("--auditor-key")
    parser.add_argument("--label-signature")
    parser.add_argument("--query", default="greatest common divisor")
    parser.add_argument("--max-p95-us", type=float, default=100000)
    parser.add_argument("--max-p95-cpu-us", type=float, default=100000)
    parser.add_argument("--task-domain", default=SUPPORTED_TASK_DOMAIN)
    args = parser.parse_args(argv)
    if args.mode == "capabilities":
        result = {"status": "TWO_GENUINELY_TRAINABLE_LOCAL_MODELS_NOT_YET_RUN",
                  "python_minor": "{}.{}".format(*sys.version_info[:2]),
                  "model_families": list(MODEL_FAMILIES),
                  "trained_model_inference_executed": False,
                  "source_code_executed": False,
                  "external_network_called": False}
    else:
        try:
            if not args.labels or not args.auditor_key or not args.label_signature:
                raise ValueError("signed_external_label_oracle_required")
            signed_labels = json.loads(_read_regular(args.labels, 50_000))
            key = _read_regular(args.auditor_key, 128, private=True)
            models = train_pair()
            bench = calibrate_router(models, signed_labels, args.label_signature, key)
            result = route_query(models, bench, args.query,
                                 max_p95_us=args.max_p95_us,
                                 max_p95_cpu_us=args.max_p95_cpu_us,
                                 task_domain=args.task_domain, auditor_key=key)
            result["calibration"] = {family: {
                key: value for key, value in bench["model_reports"][family].items()
                if key != "per_query"} for family in MODEL_FAMILIES}
            result["actual_two_trained_models"] = True
            result["signed_independent_labels_used"] = True
        except (OSError, ValueError, TypeError, KeyError, sqlite3.Error,
                OverflowError, UnicodeError):
            print(json.dumps({"status": "NOT_RUN_OR_UNQUALIFIED_DUAL_MODEL_EVIDENCE",
                              "source_code_executed": False}, sort_keys=True))
            return 2
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
