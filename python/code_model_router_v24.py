"""F127: two genuinely trained local ML models route bounded Python repairs.

CPython itself supplies the real SyntaxError diagnostics. A multinomial Naive
Bayes model and a multiclass perceptron independently learn to classify them.
An independently HMAC-pinned held-out oracle gates model quality and actual
execution latency before routing. Only a one-character, compile-only proposal
is produced. No source is executed, installed, overwritten, or auto-approved.

This is *not* a general LLM or a proof of arbitrary-project correctness.
"""

import argparse
from collections import Counter
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time


KINDS = ("COLON", "PAREN", "BRACKET", "BRACE")
MODEL_FAMILIES = ("multinomial_nb", "multiclass_perceptron")
TASK_DOMAIN = "trusted_python_syntax_repair"
MAX_SOURCE_BYTES = 2048
MIN_QUALITY = 0.95
MAX_EVIDENCE_BYTES = 65536
OPENING = {"PAREN": "(", "BRACKET": "[", "BRACE": "{"}
CLOSING = {"PAREN": ")", "BRACKET": "]", "BRACE": "}"}
HEADERS = ("if", "for", "while", "def", "class")
SOURCE = re.compile(r"\A[\x09\x0a\x20-\x7e]{1,2048}\Z")


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def frozen_sources(train=True):
    """Disjoint, immutable fixture families; syntax checked by real CPython."""
    indices = range(1, 31) if train else (101, 103, 107, 109, 113, 127, 131, 137)
    cases = []
    for i in indices:
        if train:
            headers = ("if True", "for j in range(2)", "while False",
                       "def compute(j)", "class Shape")
            header = headers[i % len(headers)]
            if header.startswith("if "):
                header = "if {} > 0".format(i)
            elif header.startswith("for "):
                header = "for j in range({})".format(i)
            elif header.startswith("while "):
                header = "while {} < 0".format(i)
            elif header.startswith("def "):
                header = "def compute_{}(j)".format(i)
            else:
                header = "class Shape{}".format(i)
            body = "    return j" if header.startswith("def ") else "    result = 2"
            variable = "result"
        else:
            headers = ("if 2 > 1", "for k in range(3)", "while 0 < -1",
                       "def verify(k)", "class Archive")
            header = headers[i % len(headers)]
            if header.startswith("if "):
                header = "if {} >= 100".format(i)
            elif header.startswith("for "):
                header = "for k in range({})".format(i)
            elif header.startswith("while "):
                header = "while {} < 0".format(i)
            elif header.startswith("def "):
                header = "def verify_{}(k)".format(i)
            else:
                header = "class Archive{}".format(i)
            body = "    return k" if header.startswith("def ") else "    answer = 7"
            variable = "answer"
        canonical_source = header + ":\n" + body + "\n"
        cases.append({"kind": "COLON", "source": header + "\n" + body + "\n",
                      "expected_sha256": digest(canonical_source.encode())})
        clean = "{} = ({} + {})\n".format(variable, i, i + 1)
        cases.append({"kind": "PAREN", "source": clean.replace(")\n", "\n"),
                      "expected_sha256": digest(clean.encode())})
        clean = "{} = [{}, {}]\n".format(variable, i, i + 1)
        cases.append({"kind": "BRACKET", "source": clean.replace("]\n", "\n"),
                      "expected_sha256": digest(clean.encode())})
        clean = "{} = {{'key': {}}}\n".format(variable, i)
        cases.append({"kind": "BRACE", "source": clean.replace("}\n", "\n"),
                      "expected_sha256": digest(clean.encode())})
    return cases


def compiler_diagnostic(source):
    if (type(source) is not str or not SOURCE.fullmatch(source) or
            len(source.encode("ascii")) > MAX_SOURCE_BYTES or
            source.count("\n") > 8):
        raise ValueError("bounded_ascii_source_required")
    try:
        compile(source, "<compile-only>", "exec", dont_inherit=True)
    except SyntaxError as error:
        return {"status": "REAL_CPYTHON_SYNTAX_ERROR", "msg": error.msg,
                "line": error.lineno, "offset": error.offset,
                "python_minor": "{}.{}".format(*sys.version_info[:2]),
                "source_executed": False}
    return {"status": "NO_SYNTAX_ERROR", "source_executed": False}


def diagnostic_features(source, detail):
    if detail["status"] != "REAL_CPYTHON_SYNTAX_ERROR":
        raise ValueError("real_compiler_diagnostic_required")
    features = Counter("message:" + word for word in
                       re.findall(r"[a-z]+", detail["msg"].lower()))
    header = source.splitlines()[0].strip()
    for keyword in HEADERS:
        if header.startswith(keyword + " ") or header.startswith(keyword + "("):
            features["header:" + keyword] += 2
    for kind, opener in OPENING.items():
        if source.count(opener) - source.count(CLOSING[kind]) == 1:
            features["one_unclosed:" + kind] += 3
    if detail["line"] == 1:
        features["error_on_first_line"] += 1
    return features


def train_models():
    """Run the real compiler on 120 training samples, then learn parameters."""
    examples = []
    for row in frozen_sources(train=True):
        diagnostic = compiler_diagnostic(row["source"])
        if diagnostic["status"] != "REAL_CPYTHON_SYNTAX_ERROR":
            raise ValueError("real_training_case_did_not_fail_compile")
        examples.append((row["kind"], diagnostic_features(row["source"], diagnostic)))
    vocab = sorted(set(token for _, features in examples for token in features))
    if len(examples) != 120 or len(vocab) < 8:
        raise ValueError("insufficient_real_training_corpus")
    classes = {kind: Counter() for kind in KINDS}
    for kind, features in examples:
        classes[kind].update(features)
    alpha = 0.7
    nb = {"family": MODEL_FAMILIES[0], "counts": classes,
          "denominators": {kind: sum(classes[kind].values()) + alpha*len(vocab)
                           for kind in KINDS},
          "vocab": set(vocab), "alpha": alpha}
    weights = {kind: Counter() for kind in KINDS}
    for _ in range(18):
        for expected, features in examples:
            guessed = max(KINDS, key=lambda kind:
                          (sum(weights[kind][token]*count for token, count
                               in features.items()), -KINDS.index(kind)))
            if guessed != expected:
                for token, count in features.items():
                    weights[expected][token] += count
                    weights[guessed][token] -= count
    perceptron = {"family": MODEL_FAMILIES[1], "weights": weights}
    training_hashes = {digest(row["source"].encode())
                       for row in frozen_sources(train=True)}
    for model in (nb, perceptron):
        model["training_count"] = len(examples)
        model["training_source_sha256"] = training_hashes
        model["training_vocabulary"] = tuple(vocab)
        model["model_sha256"] = fingerprint_model(model)
    return {model["family"]: model for model in (nb, perceptron)}


def fingerprint_model(model):
    if model["family"] == "multinomial_nb":
        parameters = model["counts"]
    elif model["family"] == "multiclass_perceptron":
        parameters = model["weights"]
    else:
        raise ValueError("unknown_model_family_in_fingerprint")
    manifest = {"family": model["family"],
                "training_count": model["training_count"],
                "feature_vocabulary": model["training_vocabulary"],
                "parameters": parameters,
                "training_source_sha256": sorted(model["training_source_sha256"])}
    return digest(canonical(manifest))


def infer(model, features):
    if model["family"] == "multinomial_nb":
        alpha = model["alpha"]
        valid = {token: count for token, count in features.items()
                 if token in model["vocab"]}
        scores = {kind: sum(count*(math.log(model["counts"][kind][token]+alpha)
                                   - math.log(model["denominators"][kind]))
                            for token, count in valid.items()) for kind in KINDS}
    elif model["family"] == "multiclass_perceptron":
        scores = {kind: sum(model["weights"][kind][token]*count
                            for token, count in features.items()) for kind in KINDS}
    else:
        raise ValueError("unknown_learned_model_family")
    return max(KINDS, key=lambda kind: (scores[kind], -KINDS.index(kind)))


def safe_candidate(source, predicted):
    """Allow one deterministic punctuation insert; never run or apply code."""
    if predicted == "COLON":
        lines = source.splitlines(keepends=True)
        if (len(lines) != 2 or not any(
                lines[0].startswith(k + " ") or lines[0].startswith(k + "(")
                for k in HEADERS) or lines[0].rstrip().endswith(":") or
                not lines[0].endswith("\n") or not lines[1].startswith("    ")):
            return None
        candidate = lines[0][:-1] + ":\n" + lines[1]
        position = len(lines[0])
        inserted = ":"
    elif predicted in OPENING:
        opener, closer = OPENING[predicted], CLOSING[predicted]
        if (source.count(opener) - source.count(closer) != 1 or
                any(source.count(other) - source.count(CLOSING[kind]) != 0
                    for kind, other in OPENING.items() if kind != predicted) or
                source.count("\n") != 1 or not source.endswith("\n") or
                not source.splitlines()[0].strip().startswith(("result", "answer"))):
            return None
        candidate = source[:-1] + closer + "\n"
        position = len(source)
        inserted = closer
    else:
        return None
    if compiler_diagnostic(candidate)["status"] != "NO_SYNTAX_ERROR":
        return None
    return {"candidate_sha256": digest(candidate.encode()),
            "candidate_bytes": candidate, "insert": inserted,
            "column_one_based": position, "line": 1}


def verify_oracle(oracle, signature, key, training_sources):
    if (type(key) is not bytes or len(key) < 16 or
            type(signature) is not str or len(signature) != 64 or
            not hmac.compare_digest(
                hmac.new(key, canonical(oracle), hashlib.sha256).hexdigest(), signature)):
        raise ValueError("independent_signed_oracle_required")
    if type(oracle) is not dict or set(oracle) != {"schema", "domain", "cases"} or (
            oracle["schema"] != 1 or oracle["domain"] != TASK_DOMAIN or
            type(oracle["cases"]) is not list or len(oracle["cases"]) < 24):
        raise ValueError("invalid_independent_oracle")
    sources = set()
    for row in oracle["cases"]:
        if (type(row) is not dict or set(row) != {"kind", "source", "expected_sha256"} or
                row["kind"] not in KINDS or type(row["source"]) is not str or
                type(row["expected_sha256"]) is not str or
                not re.fullmatch(r"[0-9a-f]{64}", row["expected_sha256"])):
            raise ValueError("invalid_independent_oracle_case")
        identity = digest(row["source"].encode())
        if identity in sources or identity in training_sources:
            raise ValueError("heldout_train_overlap_or_duplicate")
        sources.add(identity)
    if any(sum(row["kind"] == kind for row in oracle["cases"]) < 4 for kind in KINDS):
        raise ValueError("independent_oracle_missing_error_family")
    return oracle["cases"]


TIMING_METHOD = "BOUNDED_PURE_INFERENCE_CASE_BATCH_MEANS_V1"
TIMING_SCHEMA = "CODE_MODEL_TIMING_V1"
TIMING_MAX_CALLS = 65536
TIMING_MAX_WALL_NS = 500_000_000
TIMING_MIN_CPU_NS = 1_000_000
TIMING_MIN_WALL_NS = 5_000_000
TIMING_LIMITS = {"maximum_calls": TIMING_MAX_CALLS, "maximum_wall_ns": TIMING_MAX_WALL_NS,
                 "minimum_cpu_ns": TIMING_MIN_CPU_NS, "minimum_wall_ns": TIMING_MIN_WALL_NS}


def measure_inference_batch(model, features):
    """Observe internal pure-inference repetitions, including loop/clock overhead.

    Clock checks occur at most64 calls apart; this is not an OS preemption
    guarantee. Scheduling overshoots are recorded and cannot qualify.
    """
    cpu_start, wall_start = time.process_time_ns(), time.perf_counter_ns()
    last_cpu, last_wall = cpu_start, wall_start
    repetitions = 0
    while repetitions < TIMING_MAX_CALLS:
        for _ in range(min(64, TIMING_MAX_CALLS - repetitions)):
            infer(model, features)
            repetitions += 1
        cpu_end, wall_end = time.process_time_ns(), time.perf_counter_ns()
        if cpu_end < last_cpu or wall_end < last_wall:
            raise ValueError("calibration_monotonic_clock_went_backwards")
        last_cpu, last_wall = cpu_end, wall_end
        cpu_ns, wall_ns = cpu_end - cpu_start, wall_end - wall_start
        if wall_ns > TIMING_MAX_WALL_NS:
            status = "NOT_RUN_SAMPLE_BUDGET"
            break
        if cpu_ns >= TIMING_MIN_CPU_NS and wall_ns >= TIMING_MIN_WALL_NS:
            status = "MEASURED"
            break
        if wall_ns == TIMING_MAX_WALL_NS:
            status = "NOT_RUN_TIMER_RESOLUTION"
            break
    else:
        status = "NOT_RUN_TIMER_RESOLUTION"
    return {"status": status, "repetitions": repetitions,
            "process_cpu_ns": cpu_ns, "wall_ns": wall_ns,
            "mean_cpu_us": cpu_ns / repetitions / 1000,
            "mean_wall_us": wall_ns / repetitions / 1000}


def qualified_case_batch_timing(report):
    """Require the new raw evidence, even for a correctly HMAC-signed receipt."""
    timing = report.get("timing")
    if (type(timing) is not dict or timing.get("schema") != TIMING_SCHEMA or
            timing.get("method") != TIMING_METHOD or timing.get("status") != "MEASURED" or
            timing.get("limits") != TIMING_LIMITS or
            timing.get("clock_and_loop_overhead_included") is not True or
            timing.get("single_call_p95_claimed") is not False or
            timing.get("timing_repetitions_are_additional_unique_oracles") is not False or
            timing.get("p95_statistic") != "NEAREST_RANK_P95_OF_CASE_BATCH_MEANS_US"):
        return False
    samples = timing.get("samples")
    count = report.get("actual_oracle_runs")
    if type(count) is not int or count < 24 or type(samples) is not list or len(samples) != count:
        return False
    identities, wall, cpu = set(), [], []
    for row in samples:
        if type(row) is not dict: return False
        identity = row.get("source_sha256")
        repetitions, wall_ns, cpu_ns = (row.get(name) for name in ("repetitions", "wall_ns", "process_cpu_ns"))
        if (row.get("status") != "MEASURED" or type(identity) is not str or
                re.fullmatch(r"[0-9a-f]{64}", identity) is None or identity in identities or
                type(repetitions) is not int or not 1 <= repetitions <= TIMING_MAX_CALLS or
                type(wall_ns) is not int or not TIMING_MIN_WALL_NS <= wall_ns <= TIMING_MAX_WALL_NS or
                type(cpu_ns) is not int or cpu_ns < TIMING_MIN_CPU_NS):
            return False
        identities.add(identity)
        mean_wall, mean_cpu = wall_ns / repetitions / 1000, cpu_ns / repetitions / 1000
        if (type(row.get("mean_wall_us")) not in (int, float) or
                type(row.get("mean_cpu_us")) not in (int, float) or
                row["mean_wall_us"] != mean_wall or row["mean_cpu_us"] != mean_cpu):
            return False
        wall.append(mean_wall); cpu.append(mean_cpu)
    rank = math.ceil(.95 * count) - 1
    return (type(report.get("p95_wall_us")) in (int, float) and
            type(report.get("p95_cpu_us")) in (int, float) and
            report["p95_wall_us"] == sorted(wall)[rank] and
            report["p95_cpu_us"] == sorted(cpu)[rank])


def calibrate(models, oracle, signature, key):
    training = next(iter(models.values()))["training_source_sha256"]
    cases = verify_oracle(oracle, signature, key, training)
    reports = {}
    for family in MODEL_FAMILIES:
        model = models[family]
        if fingerprint_model(model) != model["model_sha256"]:
            raise ValueError("trained_model_parameters_tampered")
        counts, samples = Counter(), []
        for row in cases:
            diagnostic = compiler_diagnostic(row["source"])
            features = diagnostic_features(row["source"], diagnostic)
            predicted = infer(model, features)
            candidate = safe_candidate(row["source"], predicted)
            if (predicted == row["kind"] and candidate is not None and
                    candidate["candidate_sha256"] == row["expected_sha256"]):
                counts[row["kind"]] += 1
            sample = measure_inference_batch(model, features)
            sample["source_sha256"] = digest(row["source"].encode())
            samples.append(sample)
        by_kind = {kind: counts[kind] / sum(row["kind"] == kind for row in cases)
                   for kind in KINDS}
        resolved = all(row["status"] == "MEASURED" for row in samples)
        reports[family] = {"model_sha256": model["model_sha256"],
                           "actual_oracle_runs": len(cases),
                           "exact_repair_rate": sum(counts.values())/len(cases),
                           "per_kind_repair_rate": by_kind,
                           "p95_wall_us": sorted(row["mean_wall_us"] for row in samples)[math.ceil(.95*len(samples))-1] if resolved else None,
                           "p95_cpu_us": sorted(row["mean_cpu_us"] for row in samples)[math.ceil(.95*len(samples))-1] if resolved else None,
                           "timing": {"schema": TIMING_SCHEMA, "method": TIMING_METHOD,
                                "limits": dict(TIMING_LIMITS),
                                "status": "MEASURED" if resolved else "NOT_RUN_TIMING_UNRESOLVED",
                                "p95_statistic": "NEAREST_RANK_P95_OF_CASE_BATCH_MEANS_US",
                                "clock_and_loop_overhead_included": True,
                                "single_call_p95_claimed": False,
                                "timing_repetitions_are_additional_unique_oracles": False,
                                "samples": samples},
                           "compute_cost_unit": "actual_process_CPU_microseconds_not_money"}
    result = {"status": ("TWO_ACTUALLY_TRAINED_CODE_MODELS_CALIBRATED" if all(
                  qualified_case_batch_timing(report) for report in reports.values())
                  else "NOT_RUN_CALIBRATION_TIMING_UNRESOLVED"),
              "task_domain": TASK_DOMAIN,
              "oracle_sha256": digest(canonical(oracle)),
              "reports": reports, "source_code_executed": False,
              "arbitrary_project_repair_verified": False}
    result["auditor_hmac_sha256"] = hmac.new(key, canonical(result), hashlib.sha256).hexdigest()
    return result


def route_task(models, calibration, source, key, *, min_quality=MIN_QUALITY,
               max_p95_wall_us=100_000.0, max_p95_cpu_us=100_000.0,
               task_domain=TASK_DOMAIN):
    if (task_domain != TASK_DOMAIN or type(calibration) is not dict or
            type(key) is not bytes or len(key) < 16 or
            type(min_quality) not in (float, int) or not 0 < min_quality <= 1 or
            type(max_p95_wall_us) not in (float, int) or
            not 0 < max_p95_wall_us <= 1e9 or
            type(max_p95_cpu_us) not in (float, int) or
            not 0 < max_p95_cpu_us <= 1e9):
        return {"status": "NO_QUALIFIED_MODEL_FOR_TASK_DOMAIN", "source_code_executed": False}
    receipt = dict(calibration)
    signature = receipt.pop("auditor_hmac_sha256", None)
    if (type(signature) is not str or not hmac.compare_digest(signature,
            hmac.new(key, canonical(receipt), hashlib.sha256).hexdigest())):
        raise ValueError("model_calibration_tampered")
    diagnostic = compiler_diagnostic(source)
    if diagnostic["status"] == "NO_SYNTAX_ERROR":
        return {"status": "NO_SYNTAX_ERROR_NO_REPAIR", "source_code_executed": False}
    features = diagnostic_features(source, diagnostic)
    selected = []
    for family in MODEL_FAMILIES:
        report = calibration["reports"][family]
        if fingerprint_model(models[family]) != models[family]["model_sha256"]:
            raise ValueError("trained_model_parameters_tampered")
        if report["model_sha256"] != models[family]["model_sha256"]:
            raise ValueError("model_sha256_mismatch")
        if (qualified_case_batch_timing(report) and report["exact_repair_rate"] >= min_quality and
                report["p95_wall_us"] <= max_p95_wall_us and
                report["p95_cpu_us"] <= max_p95_cpu_us):
            selected.append((-report["exact_repair_rate"],
                             report["p95_cpu_us"], family))
    if not selected:
        return {"status": "NO_QUALIFIED_MODEL_FOR_BUDGET", "source_code_executed": False}
    for _, _, family in sorted(selected):
        started = time.perf_counter_ns()
        predicted = infer(models[family], features)
        actual_ns = time.perf_counter_ns() - started
        if actual_ns < 0:
            raise ValueError("inference_monotonic_clock_went_backwards")
        actual_us = actual_ns / 1000
        candidate = safe_candidate(source, predicted)
        if candidate is not None:
            return {"status": "ACTUAL_TRAINED_CODE_MODEL_PROPOSED_COMPILE_ONLY",
                    "task_domain": TASK_DOMAIN, "model_family": family,
                    "model_sha256": models[family]["model_sha256"],
                    "model_inference_executed": True,
                    "candidate_sha256": candidate["candidate_sha256"],
                    "original_sha256": digest(source.encode()),
                    "edit": {"line": candidate["line"],
                             "column_one_based": candidate["column_one_based"],
                             "insert": candidate["insert"]},
                    "actual_inference_us": actual_us,
                    "actual_inference_wall_ns": actual_ns,
                    "actual_inference_timing_status": "MEASURED" if actual_ns else "NOT_RUN_TIMER_RESOLUTION",
                    "source_code_executed": False, "source_file_modified": False,
                    "candidate_auto_promoted": False,
                    "arbitrary_project_correctness_attested": False}
    return {"status": "NO_APPROVED_ONE_CHARACTER_REPAIR", "source_code_executed": False}


def _model_evidence_io():
    embedded = globals().get("_RPH_MODEL_EVIDENCE_IO")
    if embedded is None:
        import importlib.util
        spec = importlib.util.spec_from_file_location("rph_model_evidence_io", Path(__file__).resolve().with_name("model_evidence_io_v029.py"))
        embedded = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(embedded)
        globals()["_RPH_MODEL_EVIDENCE_IO"] = embedded
    return embedded


def read_regular(path, max_bytes=MAX_EVIDENCE_BYTES, private=False):
    if __import__("os").name == "nt":
        try:
            return _model_evidence_io().read_regular(path, max_bytes, private)
        except (OSError, ValueError) as error:
            raise ValueError("unsafe_model_evidence_file") from error
    file = Path(path)
    info = file.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            info.st_size <= 0 or info.st_size > max_bytes or
            (private and info.st_mode & 0o077)):
        raise ValueError("unsafe_model_evidence_file")
    fd = os.open(str(file), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(fd, "rb", closefd=False) as inp:
            opened = os.fstat(inp.fileno())
            if (opened.st_ino, opened.st_dev, opened.st_size) != (
                    info.st_ino, info.st_dev, info.st_size):
                raise ValueError("evidence_changed_before_open")
            raw = inp.read(max_bytes + 1)
            final = os.fstat(inp.fileno())
            if (final.st_size, final.st_ino, final.st_mtime_ns) != (
                    info.st_size, info.st_ino, info.st_mtime_ns):
                raise ValueError("evidence_changed_during_read")
    finally:
        os.close(fd)
    if len(raw) > max_bytes or digest(raw) == "":
        raise ValueError("invalid_model_evidence")
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "selftest", "route"),
                        default="capabilities")
    parser.add_argument("--source-file")
    parser.add_argument("--oracle-file")
    parser.add_argument("--signature")
    parser.add_argument("--key-file")
    args = parser.parse_args(argv)
    if args.mode == "capabilities":
        result = {"status": "ACTUAL_CODE_MODEL_ROUTER_ADAPTER_AVAILABLE",
                  "model_families": list(MODEL_FAMILIES),
                  "source_code_executed": False,
                  "training_or_model_inference_executed": False,
                  "general_python_bug_autofix_attested": False}
    else:
        try:
            models = train_models()
            if args.mode == "selftest":
                oracle = {"schema": 1, "domain": TASK_DOMAIN,
                          "cases": frozen_sources(train=False)}
                key = b"TRUSTED_LOCAL_DEMO_ONLY_NOT_OPERATOR_APPROVAL"
                signature = hmac.new(key, canonical(oracle), hashlib.sha256).hexdigest()
                calibration = calibrate(models, oracle, signature, key)
                result = {"status": "TRUSTED_CODE_MODEL_LOCAL_SELFTEST_NO_EXTERNAL_AUDIT",
                          "calibration": calibration,
                          "reports": calibration["reports"],
                          "external_independent_auditor_attested": False,
                          "source_code_executed": False}
                result["model_routing_demonstrated"] = route_task(
                    models, calibration, oracle["cases"][0]["source"], key)["status"] == (
                        "ACTUAL_TRAINED_CODE_MODEL_PROPOSED_COMPILE_ONLY")
            else:
                if not all((args.source_file, args.oracle_file, args.signature, args.key_file)):
                    raise ValueError("signed_operator_calibration_required")
                source = read_regular(args.source_file, MAX_SOURCE_BYTES).decode("ascii")
                oracle = json.loads(read_regular(args.oracle_file))
                key = read_regular(args.key_file, 128, private=True)
                proof = calibrate(models, oracle, args.signature, key)
                result = route_task(models, proof, source, key)
        except (OSError, ValueError, TypeError, KeyError, UnicodeError, SyntaxError):
            result = {"status": "NOT_RUN_OR_UNQUALIFIED_CODE_MODEL",
                      "source_code_executed": False}
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0 if not result["status"].startswith("NOT_RUN") else 2


if __name__ == "__main__":
    raise SystemExit(main())
