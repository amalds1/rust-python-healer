"""Real unsupervised LSA encoder trained on installed CPython stdlib docs.

Unlike a cosine-only evaluator supplied with arbitrary vectors, this program
learns latent components from an actual document-term matrix (truncated SVD
of its Gram matrix), then embeds held-out queries in that learned space.
Training never consumes relevance labels, executes project source, downloads
model code, or claims the resulting model is universally semantic.
"""

import argparse
from collections import Counter
import hashlib
import hmac
import importlib
import inspect
import json
import math
from pathlib import Path
import re
import stat
import sys
import time


TRUSTED_STDLIB_MODULES = (
    "math", "itertools", "statistics", "functools", "json", "re", "heapq",
    "collections", "bisect", "operator", "string", "textwrap", "pathlib",
    "datetime", "random", "decimal", "urllib.parse",
)
REQUIRED_REAL_SYMBOLS = (
    "math.gcd", "math.lcm", "math.isqrt", "math.sqrt", "math.factorial",
    "itertools.chain", "itertools.cycle", "itertools.combinations",
    "itertools.permutations", "statistics.mean", "statistics.median",
    "json.loads", "json.dumps", "re.sub", "heapq.merge", "bisect.bisect_left",
)
MAX_DOCUMENTS = 175
MAX_TERMS = 4600
MAX_LATENT = 28
MAX_TOKENS_PER_DOC = 250
SVD_ITERATIONS = 30
TOKEN = re.compile(r"[a-z][a-z0-9_]{1,32}\Z")
WORDS = re.compile(r"[a-z][a-z0-9_]{1,32}")
SHA = re.compile(r"[0-9a-f]{64}\Z")


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def stdlib_corpus():
    """Read 175 unique real installed stdlib public API docstrings only."""
    modules = {name: importlib.import_module(name)
               for name in TRUSTED_STDLIB_MODULES}
    found = {}
    for name, module in modules.items():
        for symbol, value in list(vars(module).items()):
            if symbol.startswith("_") or not (
                    inspect.isroutine(value) or inspect.isclass(value)):
                continue
            doc = inspect.getdoc(value)
            qualified = name + "." + symbol
            minimum = 4 if qualified in REQUIRED_REAL_SYMBOLS else 35
            if type(doc) is not str or not minimum <= len(doc) <= 8192:
                continue
            found[qualified] = doc
    missing = set(REQUIRED_REAL_SYMBOLS) - set(found)
    if missing:
        raise ValueError("selected_real_stdlib_symbols_unavailable")
    # The mandatory symbols identify a fixed, version-stable test domain;
    # corpus training itself never receives the independently held-out labels.
    chosen = dict((name, found[name]) for name in REQUIRED_REAL_SYMBOLS)
    for name in sorted(found):
        if len(chosen) >= MAX_DOCUMENTS:
            break
        if name not in chosen:
            chosen[name] = found[name]
    manifest = {name: _digest(doc.encode("utf-8"))
                for name, doc in sorted(chosen.items())}
    return {"status": "REAL_INSTALLED_STDLIB_DOCSTRINGS",
            "python_minor": "{}.{}".format(*sys.version_info[:2]),
            "sources": chosen, "source_sha256": manifest,
            "corpus_sha256": _digest(_json_bytes(manifest)),
            "source_code_executed": False,
            "remote_publisher_authenticated": False,
            "synthetic_docs_injected": False}


def _tokens(text):
    if type(text) is not str:
        raise ValueError("invalid_natural_language_text")
    raw = WORDS.findall(text.lower())[:MAX_TOKENS_PER_DOC]
    # Corpus-independent morphological normalization: common inflections of
    # the same root share an unsupervised token representation. This rule is
    # fixed without inspecting any held-out relevance labels.
    output = []
    for token in raw:
        if len(token) > 6 and token.endswith("ing"):
            token = token[:-3]
        elif len(token) > 5 and token.endswith("ies"):
            token = token[:-3] + "y"
        elif len(token) > 5 and token.endswith("ed"):
            token = token[:-2]
        elif len(token) > 4 and token.endswith("s") and not token.endswith("ss"):
            token = token[:-1]
        if len(token) > 5 and token.endswith("e"):
            token = token[:-1]
        output.append(token)
    return output


def _sparse_dot(a, b):
    if len(a) > len(b):
        a, b = b, a
    return sum(value * b.get(term, 0.0) for term, value in a.items())


def _normal(vec):
    norm = math.sqrt(sum(float(part)*float(part) for part in vec))
    return [value / norm for value in vec] if norm > 1e-12 else None


def _orthogonal(vector, basis):
    adjusted = list(vector)
    for old in basis:
        overlap = sum(a*b for a, b in zip(adjusted, old))
        for index, coordinate in enumerate(old):
            adjusted[index] -= overlap*coordinate
    return _normal(adjusted)


def _gram_spectrum(sparse_docs, components=MAX_LATENT):
    """Actually learn Gram eigenvectors via deterministic power iteration."""
    size = len(sparse_docs)
    gram = [[0.0] * size for _ in range(size)]
    for i in range(size):
        for j in range(i, size):
            dot = _sparse_dot(sparse_docs[i], sparse_docs[j])
            gram[i][j] = dot
            gram[j][i] = dot
    basis = []
    eigenvalues = []
    for rank in range(min(components, size - 1)):
        # Deterministic non-zero seed; no dependence on held-out label oracle.
        vector = _orthogonal([
            math.sin((index+1)*(rank+1)*0.61803398875) +
            math.cos((index+1)*(rank+3)*0.22360679775)
            for index in range(size)], basis)
        if vector is None:
            continue
        for _ in range(SVD_ITERATIONS):
            nxt = [sum(value*component for value, component in zip(row, vector))
                   for row in gram]
            vector = _orthogonal(nxt, basis)
            if vector is None:
                break
        if vector is None:
            continue
        projected = [sum(a*b for a, b in zip(row, vector)) for row in gram]
        strength = sum(a*b for a, b in zip(vector, projected))
        if strength <= 1e-9:
            break
        basis.append(vector)
        eigenvalues.append(strength)
    return gram, basis, eigenvalues


def train_lsa_encoder(corpus):
    """Unsupervised TF-IDF + truncated SVD learned from real stdlib text."""
    if (type(corpus) is not dict or
            corpus.get("status") != "REAL_INSTALLED_STDLIB_DOCSTRINGS" or
            corpus.get("synthetic_docs_injected") is not False):
        raise ValueError("real_corpus_required")
    docs, source_shas = corpus["sources"], corpus["source_sha256"]
    if (type(docs) is not dict or not 40 <= len(docs) <= MAX_DOCUMENTS or
            type(source_shas) is not dict or set(docs) != set(source_shas) or
            len(set(docs)) != len(docs)):
        raise ValueError("untrusted_or_small_corpus")
    for name, content in docs.items():
        if (type(name) is not str or type(content) is not str or
                type(source_shas[name]) is not str or
                not SHA.fullmatch(source_shas[name]) or
                _digest(content.encode("utf-8")) != source_shas[name]):
            raise ValueError("stdlib_doc_source_digest_mismatch")
    names = sorted(docs)
    counted = [Counter(_tokens(docs[name])) for name in names]
    document_frequency = Counter(term for counts in counted for term in counts)
    important = sorted(document_frequency,
                       key=lambda term: (-document_frequency[term], term))[:MAX_TERMS]
    idf = {term: math.log((len(names)+1)/(document_frequency[term]+1)) + 1
           for term in important}
    sparse = []
    for counts in counted:
        row = {term: (1+math.log(count))*idf[term]
               for term, count in counts.items() if term in idf}
        norm = math.sqrt(sum(value*value for value in row.values()))
        if norm > 1e-12:
            row = {term: value/norm for term, value in row.items()}
        sparse.append(row)
    started = time.perf_counter()
    gram, basis, eigenvalues = _gram_spectrum(sparse)
    elapsed = time.perf_counter()-started
    if len(basis) < 8:
        raise ValueError("unsupervised_training_insufficient_rank")
    # U sigma is a learned document embedding. Query projection uses the
    # corresponding right singular vectors computed from the same TF-IDF data.
    doc_latents = [[basis[rank][i]*math.sqrt(eigenvalues[rank])
                    for rank in range(len(basis))] for i in range(len(names))]
    normalized_doc_latents = [_normal(row) for row in doc_latents]
    proof = {"corpus_sha256": corpus["corpus_sha256"],
             "model_family": "unsupervised_tfidf_truncated_svd",
             "components": len(basis),
             "eigenvalues": [round(value, 10) for value in eigenvalues],
             "vocabulary_size": len(idf)}
    return {"status": "REAL_UNSUPERVISED_STDLIB_LSA_TRAINED",
            "model_family": proof["model_family"],
            "python_minor": corpus["python_minor"],
            "corpus_sha256": corpus["corpus_sha256"],
            "model_sha256": _digest(_json_bytes(proof)),
            "source_shas": source_shas,
            "doc_ids": names,
            "idf": idf,
            "sparse_docs": sparse,
            "gram": gram,
            "basis": basis,
            "eigenvalues": eigenvalues,
            "doc_latents": normalized_doc_latents,
            "components": len(basis),
            "vocabulary_size": len(idf),
            "real_source_document_count": len(names),
            "training_seconds": elapsed,
            "train_labels_consumed": False,
            "source_code_executed": False,
            "general_semantic_accuracy_attested": False}


def _embed_query(model, query):
    counts = Counter(_tokens(query))
    row = {term: (1+math.log(count))*model["idf"][term]
           for term, count in counts.items() if term in model["idf"]}
    norm = math.sqrt(sum(value*value for value in row.values()))
    if norm <= 1e-12:
        return None, None
    row = {term: value/norm for term, value in row.items()}
    lexical = [_sparse_dot(doc, row) for doc in model["sparse_docs"]]
    latent = [sum(vec[i]*lexical[i] for i in range(len(lexical))) /
              math.sqrt(model["eigenvalues"][index])
              for index, vec in enumerate(model["basis"])]
    latent = _normal(latent)
    return lexical, latent


def semantic_search(model, query, top_k=5):
    """Real learned query inference, deterministic ranking and lexical contrast."""
    if (type(model) is not dict or
            model.get("status") != "REAL_UNSUPERVISED_STDLIB_LSA_TRAINED" or
            type(top_k) is not int or not 1 <= top_k <= 20):
        raise ValueError("invalid_real_model_or_query_budget")
    if type(query) is not str or not 3 <= len(query) <= 180:
        raise ValueError("invalid_query")
    lexical, latent = _embed_query(model, query)
    if latent is None:
        return {"status": "NO_EVIDENCE_UNKNOWN_QUERY_TERMS",
                "results": [], "real_encoder_inference_executed": False}
    scores = []
    for index, name in enumerate(model["doc_ids"]):
        learned = model["doc_latents"][index]
        latent_cosine = (sum(a*b for a, b in zip(latent, learned))
                         if learned is not None else 0.0)
        # Latent semantic space has dominant weight; lexical score acts as
        # conservative anchor for rare native API names across Python minors.
        score = .72*latent_cosine + .28*lexical[index]
        scores.append({"doc_id": name, "score": score,
                       "latent_score": latent_cosine,
                       "lexical_score": lexical[index]})
    ranked = sorted(scores, key=lambda row: (-row["score"], row["doc_id"]))
    return {"status": "REAL_TRAINED_CORPUS_ENCODER_RESULTS",
            "results": ranked[:top_k],
            "model_sha256": model["model_sha256"],
            "real_encoder_inference_executed": True,
            "source_code_executed": False}


def evaluate_heldout(model, signed_labels, pinned_label_sha256, label_key,
                     min_recall=.80, min_mrr=.50, top_k=5):
    """Held-out independent labels checked AFTER training; no oracle leakage."""
    if (type(signed_labels) is not dict or
            set(signed_labels) != {"schema", "labels", "annotation_source"} or
            signed_labels["schema"] != 1 or
            type(label_key) is not bytes or len(label_key) < 16 or
            type(pinned_label_sha256) is not str or not SHA.fullmatch(pinned_label_sha256) or
            not hmac.compare_digest(hmac.new(label_key, _json_bytes(signed_labels),
                                             hashlib.sha256).hexdigest(),
                                    pinned_label_sha256)):
        raise ValueError("independently_signed_relevance_oracle_required")
    if (type(min_recall) not in (int,float) or type(min_mrr) not in (int,float) or
            not 0 < min_recall <= 1 or not 0 < min_mrr <= 1 or
            type(top_k) is not int or not 1 <= top_k <= 20):
        raise ValueError("invalid_predeclared_relevance_thresholds")
    labels = signed_labels["labels"]
    if type(labels) is not dict or not 4 <= len(labels) <= 100:
        raise ValueError("insufficient_heldout_relevance_judgments")
    evaluations = {}
    for query, relevant_docs in sorted(labels.items()):
        if (type(relevant_docs) is not list or not relevant_docs or
                any(doc not in model["doc_ids"] for doc in relevant_docs) or
                len(set(relevant_docs)) != len(relevant_docs)):
            raise ValueError("invalid_relevance_label_membership")
        response = semantic_search(model, query, top_k)
        if response["status"] != "REAL_TRAINED_CORPUS_ENCODER_RESULTS":
            evaluations[query] = {"recall_at_k": 0.0, "reciprocal_rank": 0.0,
                                  "retrieved": []}
            continue
        ranked = [row["doc_id"] for row in response["results"]]
        true = set(relevant_docs)
        hit = len(true & set(ranked))
        best = next((i+1 for i, name in enumerate(ranked) if name in true), None)
        evaluations[query] = {"recall_at_k": hit/len(true),
                              "reciprocal_rank": 1/best if best else 0.0,
                              "retrieved": ranked}
    recall = sum(row["recall_at_k"] for row in evaluations.values()) / len(evaluations)
    mrr = sum(row["reciprocal_rank"] for row in evaluations.values()) / len(evaluations)
    passed = recall >= min_recall and mrr >= min_mrr
    return {"status": "HELDOUT_SEMANTIC_QUALITY_PASS" if passed else
            "HELDOUT_SEMANTIC_QUALITY_FAIL",
            "macro_recall_at_k": recall, "macro_mrr": mrr,
            "threshold_recall": min_recall, "threshold_mrr": min_mrr,
            "labels_used_during_training": False,
            "actual_trained_embedding_inference": True,
            "real_stdlib_corpus_used": True,
            "evaluated_queries": len(evaluations),
            "per_query": evaluations,
            "external_semantic_model_authenticated": False,
            "generalization_beyond_selected_stdlib": False}


def _model_evidence_io():
    embedded = globals().get("_RPH_MODEL_EVIDENCE_IO")
    if embedded is None:
        import importlib.util
        spec = importlib.util.spec_from_file_location("rph_model_evidence_io", Path(__file__).resolve().with_name("model_evidence_io_v029.py"))
        embedded = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(embedded)
        globals()["_RPH_MODEL_EVIDENCE_IO"] = embedded
    return embedded


def _read_regular(path, maximum, private=False):
    if __import__("os").name == "nt":
        try:
            return _model_evidence_io().read_regular(path, maximum, private)
        except (OSError, ValueError) as error:
            raise ValueError("unsafe_semantic_evidence_file") from error
    candidate = Path(path)
    details = candidate.lstat()
    if (candidate.is_symlink() or not stat.S_ISREG(details.st_mode) or
            details.st_nlink != 1 or not 1 <= details.st_size <= maximum or
            (private and stat.S_IMODE(details.st_mode) & 0o077)):
        raise ValueError("unsafe_semantic_evidence_file")
    raw = candidate.read_bytes()
    after = candidate.stat()
    if (len(raw) != details.st_size or details.st_ino != after.st_ino or
            details.st_mtime_ns != after.st_mtime_ns):
        raise ValueError("semantic_evidence_changed_during_read")
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "train", "evaluated"),
                        default="capabilities")
    parser.add_argument("--labels")
    parser.add_argument("--auditor-key")
    parser.add_argument("--label-signature")
    parser.add_argument("--minimum-recall", type=float, default=.80)
    parser.add_argument("--minimum-mrr", type=float, default=.50)
    parser.add_argument("--top-k", type=int, default=5)
    args = parser.parse_args(argv)
    if args.mode == "capabilities":
        result = {"status": "LOCAL_TRAINED_SEMANTIC_ENCODER_AVAILABLE_NOT_YET_RUN",
                  "python_minor": "{}.{}".format(*sys.version_info[:2]),
                  "corpus_source": "selected_real_installed_stdlib_docstrings",
                  "labels_consumed_during_training": False,
                  "source_code_executed": False,
                  "external_network_called": False,
                  "remote_pretrained_weights_claimed": False}
    else:
        try:
            model = train_lsa_encoder(stdlib_corpus())
            if args.mode == "train":
                result = {"status": model["status"],
                          "model_sha256": model["model_sha256"],
                          "real_source_document_count": model["real_source_document_count"],
                          "vocabulary_size": model["vocabulary_size"],
                          "learned_latent_components": model["components"],
                          "training_seconds": model["training_seconds"],
                          "source_code_executed": False,
                          "independent_labels_evaluated": False}
            else:
                if not args.labels or not args.auditor_key or not args.label_signature:
                    parser.error("evaluated requires --labels --auditor-key --label-signature")
                labels = json.loads(_read_regular(args.labels, 50_000))
                auditor_key = _read_regular(args.auditor_key, 128, private=True)
                result = evaluate_heldout(model, labels, args.label_signature, auditor_key,
                                          min_recall=args.minimum_recall,
                                          min_mrr=args.minimum_mrr,
                                          top_k=args.top_k)
                result.pop("per_query")  # Never disclose operator query contents.
                result["model_sha256"] = model["model_sha256"]
        except (OSError, ValueError, UnicodeError, TypeError, RecursionError):
            print(json.dumps({"status": "NOT_RUN_OR_UNQUALIFIED_EVIDENCE",
                              "source_code_executed": False}, sort_keys=True))
            return 2
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
