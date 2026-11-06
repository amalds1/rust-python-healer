"""Bounded offline package API/advisory/distribution evidence and AST warnings.

Only a configured operator's HMAC is checked; upstream publisher identity,
current registry state and live CVE completeness are UNVERIFIED_EXTERNAL.
No network, imports of target packages, source execution or auto-upgrade.
"""

import ast
from contextlib import closing
from datetime import date
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import urlsplit


KINDS = ("api", "advisory", "distribution")
VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:(?:a|b|rc)[0-9]+|\.?(?:dev|post)[0-9]+)?$")
NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")
SYMBOL = re.compile(r"^[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*$")
MAX_DOC_BYTES = 100000


def exact_version(value):
    if type(value) is not str or not VERSION.fullmatch(value):
        raise ValueError("exact_package_or_python_version_required")
    return value


def _date(value):
    if type(value) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("invalid_observation_date")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise ValueError("invalid_observation_date") from None


def _small(value, length, label):
    if type(value) is not str or not value or len(value.encode("utf-8")) > length:
        raise ValueError("invalid_" + label)
    return value


def _safe_url(uri, hostname):
    try:
        parsed = urlsplit(_small(uri, 2048, "source_uri"))
        return (parsed.scheme == "https" and parsed.hostname == hostname and
                parsed.port in (None, 443) and parsed.username is None and
                parsed.password is None and not parsed.query and not parsed.fragment and
                bool(parsed.path))
    except ValueError:
        return False


def _trust(policy, trust):
    if (type(policy) is not dict or type(trust) is not dict or
            policy.get("schema_version") != 1 or trust.get("schema_version") != 1 or
            type(policy.get("sources")) is not dict or
            type(trust.get("authorities")) is not dict):
        raise ValueError("invalid_authority_policy")
    _small(policy.get("policy_id"), 128, "policy_id")
    unique = set()
    for authority, config in trust["authorities"].items():
        if type(authority) is not str or not NAME.fullmatch(authority):
            raise ValueError("invalid_authority_name")
        key = config.get("key_hex") if type(config) is dict else None
        if type(key) is not str or not re.fullmatch(r"[a-fA-F0-9]{64}", key):
            raise ValueError("invalid_operator_hmac_key")
        if key.lower() in unique:
            raise ValueError("duplicate_authority_key")
        unique.add(key.lower())


def sign_for_test(policy, record, key_hex):
    """Only an operator fixture signature; not publisher authenticity."""
    payload = {k: v for k, v in record.items() if k not in ("signature", "document_text")}
    canonical = json.dumps({"policy_id": policy["policy_id"], "entry": payload},
                           ensure_ascii=False, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
    return hmac.new(bytes.fromhex(key_hex), canonical, hashlib.sha256).hexdigest()


def _authorized(policy, trust, entry):
    authority = entry.get("authority")
    if type(authority) is not str:
        return False
    source = policy["sources"].get(authority)
    key = trust["authorities"].get(authority)
    return (type(source) is dict and type(key) is dict and
            source.get("ingest_allowed") is True and
            type(source.get("licenses")) is list and
            entry.get("license_id") in source["licenses"] and
            _safe_url(entry.get("source_uri"), source.get("hostname")))


def _validated(kind, entry, policy, trust):
    if type(entry) is not dict or entry.get("kind") != kind:
        raise ValueError("invalid_evidence_kind")
    base_fields = {"kind", "record_id", "authority", "source_uri", "license_id",
                   "document_text", "document_sha256", "observed_date",
                   "package", "package_version", "python_version", "signature"}
    specific = {
        "api": {"symbol", "signature_text", "deprecated_since", "removed_in",
                "changelog", "replacement"},
        "advisory": {"advisory_id", "severity", "fixed_version", "withdrawn"},
        "distribution": {"artifact_sha256", "yanked", "removed", "prerelease",
                         "repository_trust"},
    }[kind]
    if any(k not in base_fields | specific for k in entry):
        raise ValueError("unexpected_evidence_field")
    for field in base_fields:
        if field not in entry:
            raise ValueError("missing_evidence_field")
    _small(entry["record_id"], 128, "record_id")
    if not NAME.fullmatch(entry["record_id"]):
        raise ValueError("invalid_record_id")
    _small(entry["package"], 128, "package")
    if not NAME.fullmatch(entry["package"]):
        raise ValueError("invalid_package")
    exact_version(entry["package_version"])
    exact_version(entry["python_version"])
    _date(entry["observed_date"])
    doc = _small(entry["document_text"], MAX_DOC_BYTES, "document")
    digest = hashlib.sha256(doc.encode("utf-8")).hexdigest()
    if entry["document_sha256"] != digest:
        raise ValueError("document_sha256_mismatch")
    if kind == "api":
        for field in ("symbol", "signature_text", "changelog"):
            _small(entry.get(field), 1024 if field != "symbol" else 256, field)
        if not SYMBOL.fullmatch(entry["symbol"]):
            raise ValueError("invalid_api_symbol")
        for field in ("deprecated_since", "removed_in"):
            if entry.get(field) is not None:
                exact_version(entry[field])
        if entry.get("replacement") is not None:
            _small(entry["replacement"], 256, "replacement")
    if kind == "advisory":
        advisory_id = _small(entry.get("advisory_id"), 128, "advisory_id")
        if not (re.fullmatch(r"CVE-\d{4}-\d{4,}", advisory_id) or
                re.fullmatch(r"GHSA-[a-z0-9-]{14,}", advisory_id)):
            raise ValueError("invalid_advisory_identifier")
        if entry.get("severity") not in ("low", "medium", "high", "critical", "unknown"):
            raise ValueError("invalid_advisory_severity")
        if type(entry.get("withdrawn")) is not bool:
            raise ValueError("invalid_advisory_withdrawn")
        if entry.get("fixed_version") is not None:
            exact_version(entry["fixed_version"])
    if kind == "distribution":
        if (type(entry.get("artifact_sha256")) is not str or
                not re.fullmatch("[0-9a-f]{64}", entry["artifact_sha256"])):
            raise ValueError("invalid_distribution_artifact_digest")
        for name in ("yanked", "removed", "prerelease"):
            if type(entry.get(name)) is not bool:
                raise ValueError("invalid_distribution_state")
        if entry.get("repository_trust") not in ("trusted", "untrusted", "unknown"):
            raise ValueError("invalid_repository_trust")
    if not _authorized(policy, trust, entry):
        raise ValueError("unlicensed_or_untrusted_source")
    key = trust["authorities"][entry["authority"]]["key_hex"]
    signature = entry["signature"]
    if (type(signature) is not str or
            not hmac.compare_digest(sign_for_test(policy, entry, key), signature)):
        raise ValueError("operator_attestation_invalid")
    payload = {k: v for k, v in entry.items() if k not in ("signature", "document_text")}
    return (entry["record_id"], kind, entry["package"], entry["package_version"],
            entry["python_version"], entry["observed_date"],
            json.dumps(payload, sort_keys=True, ensure_ascii=False),
            signature, policy["policy_id"])


def ingest(database_path, policy, trust, manifest):
    """Atomically store immutable authorized evidence, never source code."""
    _trust(policy, trust)
    if (type(manifest) is not dict or manifest.get("schema_version") != 1 or
            any(type(manifest.get(kind, [])) is not list for kind in KINDS)):
        raise ValueError("invalid_evidence_manifest")
    entries = [(kind, record) for kind in KINDS for record in manifest.get(kind, [])]
    if not entries or len(entries) > 500:
        raise ValueError("invalid_evidence_batch_size")
    rows = [_validated(kind, record, policy, trust) for kind, record in entries]
    if len({row[0] for row in rows}) != len(rows):
        raise ValueError("duplicate_evidence_record_id")
    db = Path(database_path)
    db.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(str(db))) as conn:
        with conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS package_evidence (
              record_id TEXT PRIMARY KEY, kind TEXT NOT NULL, package TEXT NOT NULL,
              package_version TEXT NOT NULL, python_version TEXT NOT NULL,
              observed_date TEXT NOT NULL, payload TEXT NOT NULL,
              signature TEXT NOT NULL, policy_id TEXT NOT NULL)""")
            conn.execute("""CREATE INDEX IF NOT EXISTS package_evidence_exact_idx
              ON package_evidence(kind,package,package_version,python_version)""")
            try:
                conn.executemany("INSERT INTO package_evidence VALUES (?,?,?,?,?,?,?,?,?)", rows)
            except sqlite3.IntegrityError as error:
                raise ValueError("immutable_evidence_collision") from error
    return {"records_inserted": len(rows), "status": "UNVERIFIED_EXTERNAL",
            "operator_signature_checked": True, "publisher_authenticated": False,
            "network_used": False, "source_executed": False,
            "auto_upgrade": False, "document_text_stored": False}


def _records(db_path, kind, package, version, python_version, policy, trust,
             as_of, stale_days):
    _trust(policy, trust)
    if kind not in KINDS:
        raise ValueError("invalid_evidence_kind")
    _small(package, 128, "package")
    if not NAME.fullmatch(package):
        raise ValueError("invalid_package")
    exact_version(version)
    exact_version(python_version)
    now = _date(as_of)
    if type(stale_days) is not int or not 1 <= stale_days <= 3650:
        raise ValueError("invalid_staleness_window")
    with closing(sqlite3.connect(str(db_path))) as conn:
        rows = conn.execute("""SELECT record_id,observed_date,payload,signature,policy_id
          FROM package_evidence WHERE kind=? AND package=? AND package_version=?
          AND python_version=? ORDER BY record_id""",
          (kind, package, version, python_version)).fetchall()
    valid = []
    review = []
    for record_id, observed, serialized, signature, policy_id in rows:
        try:
            payload = json.loads(serialized)
            date_of_record = _date(observed)
            key = trust["authorities"].get(payload["authority"], {}).get("key_hex")
            authentic = (type(payload) is dict and key is not None and
                         payload.get("kind") == kind and
                         payload.get("record_id") == record_id and
                         payload.get("observed_date") == observed and
                         payload.get("package") == package and
                         payload.get("package_version") == version and
                         payload.get("python_version") == python_version and
                         policy_id == policy["policy_id"] and
                         _authorized(policy, trust, payload) and
                         type(signature) is str and
                         hmac.compare_digest(sign_for_test(policy, payload, key),
                                             signature))
            if not authentic:
                review.append({"record_id": record_id, "reason": "invalid_provenance"})
            elif date_of_record > now:
                review.append({"record_id": record_id, "reason": "future_dated"})
            elif (now - date_of_record).days > stale_days:
                review.append({"record_id": record_id, "reason": "stale_evidence"})
            else:
                valid.append(payload)
        except (ValueError, TypeError, KeyError, AttributeError):
            review.append({"record_id": record_id, "reason": "invalid_evidence"})
    return valid, review


def _api_conflicts(valid):
    by_symbol = {}
    for item in valid:
        by_symbol.setdefault(item["symbol"], []).append(item)
    conflicts = []
    for symbol, items in by_symbol.items():
        facts = {(item["signature_text"], item.get("deprecated_since"),
                  item.get("removed_in"), item["changelog"], item.get("replacement"))
                 for item in items}
        if len(facts) > 1:
            conflicts.append({"symbol": symbol, "reason": "conflicting_api_metadata",
                              "record_ids": sorted(item["record_id"] for item in items)})
    return conflicts


def lookup_api(db_path, package, package_version, python_version,
               policy, trust, as_of, stale_days=90):
    """Return exact-release API signatures, change notes and warnings only."""
    valid, review = _records(db_path, "api", package, package_version,
                             python_version, policy, trust, as_of, stale_days)
    review.extend(_api_conflicts(valid))
    return {"status": "REVIEW_REQUIRED" if review else
            "UNVERIFIED_EXTERNAL" if valid else "NO_EVIDENCE",
            "apis": valid, "needs_review": review,
            "publisher_authenticated": False, "network_used": False}


def check_advisories(db_path, dependencies, python_version, policy, trust,
                     as_of, stale_days=90):
    """Exact installed-version advisory correlation; NOT a live CVE scan."""
    if type(dependencies) is not dict or len(dependencies) > 500:
        raise ValueError("invalid_dependency_inventory")
    findings = []
    review = []
    withdrawn_records = []
    for package, version in sorted(dependencies.items()):
        valid, flagged = _records(db_path, "advisory", package, version,
                                  python_version, policy, trust, as_of, stale_days)
        findings.extend({"package": package, "version": version,
                         "advisory_id": item["advisory_id"],
                         "severity": item["severity"],
                         "fixed_version": item.get("fixed_version"),
                         "withdrawn": False,
                         "record_id": item["record_id"]} for item in valid
                        if not item["withdrawn"])
        withdrawn_records.extend({"record_id": item["record_id"],
                                  "advisory_id": item["advisory_id"]}
                                 for item in valid if item["withdrawn"])
        review.extend(flagged)
    return {"status": "REVIEW_REQUIRED" if review or withdrawn_records else
            "UNVERIFIED_EXTERNAL",
            "findings": findings, "needs_review": review,
            "withdrawn_advisory_records": withdrawn_records,
            "advisory_coverage_complete": False, "live_advisory_feed_checked": False,
            "automatic_upgrade": False, "network_used": False}


def check_distribution(db_path, package, version, python_version, policy,
                       trust, as_of, stale_days=90):
    valid, flagged = _records(db_path, "distribution", package, version,
                              python_version, policy, trust, as_of, stale_days)
    risks = []
    for record in valid:
        indicators = [name for name in ("yanked", "removed", "prerelease")
                      if record[name]]
        if re.search(r"(?:a|b|rc|dev)[0-9]+$", version):
            if not record["prerelease"]:
                indicators.append("prerelease_metadata_inconsistent")
            if "prerelease" not in indicators:
                indicators.append("prerelease")
        if record["repository_trust"] != "trusted":
            indicators.append("repository_not_confirmed_trusted")
        if indicators:
            risks.append({"record_id": record["record_id"],
                          "indicators": indicators})
    return {"status": "REVIEW_REQUIRED" if flagged or risks else
            "UNVERIFIED_EXTERNAL" if valid else "NO_EVIDENCE",
            "risks": risks, "needs_review": flagged,
            "records_checked": len(valid), "publisher_authenticated": False,
            "repository_state_live_verified": False, "automatic_install": False}


def _expr_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        root = _expr_name(node.value)
        return root + "." + node.attr if root else None
    return None


def locate_obsolete_calls(db_path, source, dependencies, python_version,
                          policy, trust, as_of, stale_days=90):
    """AST-only potential calls through module-level imports; no execution.

    Conservative lexical check: dynamic imports, re-exports and bound methods
    are NOT resolved. Findings require human review rather than auto-rewrites.
    """
    if type(source) is not str or len(source.encode("utf-8")) > 200000:
        raise ValueError("invalid_source_size")
    if type(dependencies) is not dict or len(dependencies) > 500:
        raise ValueError("invalid_dependency_inventory")
    tree = ast.parse(source)
    mapping = {}
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for item in statement.names:
                mapping[item.asname or item.name.split(".")[0]] = (
                    item.name if item.asname else item.name.split(".")[0])
        if isinstance(statement, ast.ImportFrom) and statement.level == 0:
            for item in statement.names:
                if item.name != "*":
                    mapping[item.asname or item.name] = statement.module + "." + item.name if statement.module else item.name
    known = {}
    review = []
    conflicted_symbols = set()
    for package, version in dependencies.items():
        valid, flagged = _records(db_path, "api", package, version,
                                  python_version, policy, trust, as_of, stale_days)
        review.extend(flagged)
        conflicts = _api_conflicts(valid)
        review.extend(conflicts)
        conflicted_symbols.update(item["symbol"] for item in conflicts)
        for row in valid:
            if (row["symbol"] not in conflicted_symbols and
                    (row.get("deprecated_since") is not None or
                     row.get("removed_in") is not None)):
                known[row["symbol"]] = row
    for symbol in conflicted_symbols:
        known.pop(symbol, None)
    # Fail conservatively on aliases that are assigned elsewhere at module
    # level or shadowed by local function variables/parameters. This avoids
    # presenting them as reliable imported-package symbols.
    global_shadowed = set()
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        global_shadowed.update(node.id for node in ast.walk(statement)
                               if isinstance(node, ast.Name) and
                               isinstance(node.ctx, ast.Store))
    locally_shadowed_calls = set()
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        local_names = {node.id for node in ast.walk(function)
                       if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)}
        arguments = function.args
        local_names.update(arg.arg for arg in
                           arguments.posonlyargs + arguments.args +
                           arguments.kwonlyargs)
        if arguments.vararg:
            local_names.add(arguments.vararg.arg)
        if arguments.kwarg:
            local_names.add(arguments.kwarg.arg)
        for call in ast.walk(function):
            if isinstance(call, ast.Call):
                expression = _expr_name(call.func)
                if expression and expression.split(".", 1)[0] in local_names:
                    locally_shadowed_calls.add(id(call))
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        expression = _expr_name(node.func)
        if not expression:
            continue
        root, _, tail = expression.partition(".")
        if root in global_shadowed or id(node) in locally_shadowed_calls:
            continue
        resolved = mapping.get(root)
        if resolved is None:
            continue
        symbol = resolved + ("." + tail if tail else "")
        row = known.get(symbol)
        if row is not None:
            findings.append({"symbol": symbol, "line": node.lineno,
                             "column": node.col_offset, "record_id": row["record_id"],
                             "deprecated_since": row.get("deprecated_since"),
                             "removed_in": row.get("removed_in"),
                             "confidence": "POTENTIAL_AST_ALIAS_MATCH"})
    return {"status": "REVIEW_REQUIRED" if findings or review else "NO_MATCH_IN_INDEX",
            "findings": findings, "needs_review": review,
            "static_analysis_only": True, "target_modules_imported": False,
            "source_executed": False, "automatic_rewrite": False,
            "unresolved_dynamic_calls_possible": True}
