"""Offline, operator-attested release/deprecation evidence and conflict audit.

Never downloads, executes or silently replaces release notes.  HMAC protects
locally configured/operator-controlled records; it does *not* prove a publisher
authored the document or establish copyright ownership.  Conflicting, stale
or future-dated evidence always needs review, regardless of source priority.
"""

from contextlib import closing
from datetime import date
import hashlib
import hmac
import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import urlsplit


VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:(?:a|b|rc)[0-9]+)?$")
IDENT_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.:-]{0,127}$")
CLAIM_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.:-]{0,199}$")
SCHEMA_VERSION = 1
MAX_DOCUMENT_BYTES = 100_000
SIGNED_FIELDS = ("record_id", "authority", "source_uri", "license_id",
                 "document_sha256", "package", "package_version",
                 "python_version", "topic", "claim", "deprecated_since",
                 "removal_not_before", "observed_date")


def _exact_version(value):
    if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
        raise ValueError("exact_version_required")
    return value


def _date(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
        raise ValueError("invalid_calendar_date")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise ValueError("invalid_calendar_date") from None


def _bounded(value, maximum, label):
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise ValueError("invalid_" + label)
    return value


def _canonical(policy_id, record):
    # Stable on both raw ingestion and a reconstructed SQLite row.
    signed = {field: record.get(field) for field in SIGNED_FIELDS}
    return json.dumps({"policy_id": policy_id, "record": signed}, sort_keys=True,
                      ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sign_for_test(policy, record, key_hex):
    """Produce *operator* signatures for trusted, locally constructed fixtures."""
    return hmac.new(bytes.fromhex(key_hex), _canonical(policy["policy_id"], record),
                    hashlib.sha256).hexdigest()


def _trust(policy, trust):
    if (type(policy) is not dict or type(trust) is not dict or
            policy.get("schema_version") != SCHEMA_VERSION or
            trust.get("schema_version") != SCHEMA_VERSION or
            not isinstance(policy.get("sources"), dict) or
            not isinstance(trust.get("authorities"), dict)):
        raise ValueError("invalid_source_policy")
    _bounded(policy.get("policy_id"), 128, "policy_id")
    if not policy["sources"]:
        raise ValueError("invalid_source_policy")
    keys = set()
    for authority, config in trust["authorities"].items():
        if not isinstance(authority, str) or not IDENT_RE.fullmatch(authority):
            raise ValueError("invalid_authority")
        key_hex = config.get("key_hex") if isinstance(config, dict) else None
        if not isinstance(key_hex, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", key_hex):
            raise ValueError("invalid_operator_key")
        normalized = key_hex.lower()
        if normalized in keys:
            raise ValueError("duplicate_operator_authority_key")
        keys.add(normalized)


def _verify_record(policy, trust, item):
    if type(item) is not dict:
        raise ValueError("invalid_release_record")
    required = ("record_id", "authority", "source_uri", "license_id", "document_sha256",
                "release_document", "package", "package_version", "python_version",
                "topic", "claim", "observed_date", "signature")
    if any(field not in item for field in required):
        raise ValueError("invalid_release_record")
    if any(field not in set(SIGNED_FIELDS) | {"release_document", "signature"}
           for field in item):
        raise ValueError("unexpected_release_record_field")
    if not IDENT_RE.fullmatch(_bounded(item["record_id"], 128, "record_id")):
        raise ValueError("invalid_record_id")
    authority = _bounded(item["authority"], 128, "authority")
    source = policy["sources"].get(authority)
    key = trust["authorities"].get(authority)
    if not isinstance(source, dict) or not isinstance(key, dict):
        raise ValueError("unknown_source_authority")
    if (source.get("allow_ingest") is not True or
            not isinstance(source.get("licenses"), list) or
            item["license_id"] not in source["licenses"]):
        raise ValueError("release_document_ingestion_denied")
    uri = _bounded(item["source_uri"], 2048, "source_uri")
    parsed = urlsplit(uri)
    if (parsed.scheme != "https" or parsed.username is not None or
            parsed.password is not None or parsed.query or parsed.fragment or
            parsed.hostname != source.get("hostname") or
            not parsed.path.startswith("/")):
        raise ValueError("source_uri_not_authorized_or_contains_credentials")
    _bounded(item["package"], 128, "package")
    if not IDENT_RE.fullmatch(item["package"]):
        raise ValueError("invalid_package")
    _exact_version(item["python_version"])
    _exact_version(item["package_version"])
    if not CLAIM_RE.fullmatch(_bounded(item["topic"], 200, "topic")):
        raise ValueError("invalid_topic")
    _bounded(item["claim"], 1024, "claim")
    _date(item["observed_date"])
    start, end = item.get("deprecated_since"), item.get("removal_not_before")
    if start is not None:
        _exact_version(start)
    if end is not None:
        _exact_version(end)
    if end is not None and start is None:
        raise ValueError("removal_window_requires_deprecation_start")
    if start is not None and item["topic"].startswith("deprecation:") is False:
        raise ValueError("deprecation_window_requires_deprecation_topic")
    if start is not None and end is not None:
        # The simple numeric version sequence makes no claims about PEP 440
        # prerelease ordering, so reject nonnumeric windows instead of guessing.
        if not start.replace(".", "").isdigit() or not end.replace(".", "").isdigit():
            raise ValueError("prerelease_window_needs_manual_review")
        a = tuple(int(p) for p in start.split("."))
        b = tuple(int(p) for p in end.split("."))
        if a > b:
            raise ValueError("inverted_deprecation_window")
    document = _bounded(item["release_document"], MAX_DOCUMENT_BYTES, "release_document")
    digest = hashlib.sha256(document.encode("utf-8")).hexdigest()
    if item["document_sha256"] != digest:
        raise ValueError("release_document_sha256_mismatch")
    signature = item["signature"]
    if (not isinstance(signature, str) or
            not hmac.compare_digest(sign_for_test(policy, item, key["key_hex"]), signature)):
        raise ValueError("operator_signature_invalid")
    return (item["record_id"], authority, uri, item["license_id"], digest,
            item["package"], item["package_version"], item["python_version"],
            item["topic"], item["claim"], start, end, item["observed_date"],
            policy["policy_id"], signature)


def ingest(database_path, policy, trust, manifest):
    """Verify entire batch before committing; immutable records, no override."""
    _trust(policy, trust)
    if (type(manifest) is not dict or manifest.get("schema_version") != SCHEMA_VERSION or
            not isinstance(manifest.get("entries"), list) or
            not manifest["entries"] or len(manifest["entries"]) > 1000):
        raise ValueError("invalid_release_manifest")
    records = [_verify_record(policy, trust, item) for item in manifest["entries"]]
    ids = [item[0] for item in records]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate_release_record_id")
    database = Path(database_path)
    database.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(str(database))) as connection:
        with connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS release_notes (
          record_id TEXT PRIMARY KEY, authority TEXT NOT NULL,
          source_uri TEXT NOT NULL, license_id TEXT NOT NULL,
          document_sha256 TEXT NOT NULL, package TEXT NOT NULL,
          package_version TEXT NOT NULL, python_version TEXT NOT NULL,
          topic TEXT NOT NULL, claim TEXT NOT NULL,
          deprecated_since TEXT, removal_not_before TEXT,
          observed_date TEXT NOT NULL, policy_id TEXT NOT NULL,
          operator_signature TEXT NOT NULL)""")
            connection.execute("""CREATE INDEX IF NOT EXISTS release_exact_idx
          ON release_notes(python_version,package,package_version,topic)""")
            try:
                connection.executemany("""INSERT INTO release_notes
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", records)
            except sqlite3.IntegrityError as error:
                raise ValueError("immutable_release_record_collision") from error
    return {"status": "OPERATOR_ATTESTED_NOT_PUBLISHER_VERIFIED",
            "entries_inserted": len(records), "network_used": False,
            "source_executed": False, "publisher_verified": False,
            "automatic_override": False, "source_document_text_stored": False}


def review(database_path, python_version, package, package_version, topic,
           as_of, stale_after_days=90, *, policy=None, trust=None):
    """Return all exact-match evidence and REVIEW_REQUIRED if any is unsafe.

    Identical facts from distinct authorities can coexist. Conflicts are not
    decided by source priority. No evidence is never an affirmative result.
    """
    _exact_version(python_version)
    _exact_version(package_version)
    if not IDENT_RE.fullmatch(_bounded(package, 128, "package")):
        raise ValueError("invalid_package")
    if not CLAIM_RE.fullmatch(_bounded(topic, 200, "topic")):
        raise ValueError("invalid_topic")
    today = _date(as_of)
    if type(stale_after_days) is not int or not 1 <= stale_after_days <= 3650:
        raise ValueError("invalid_stale_window")
    if (policy is None) != (trust is None):
        raise ValueError("policy_and_trust_required_together")
    if policy is not None:
        _trust(policy, trust)
    with closing(sqlite3.connect(str(database_path))) as connection:
        rows = connection.execute("""SELECT record_id,authority,source_uri,license_id,
           document_sha256,claim,deprecated_since,removal_not_before,observed_date,
           policy_id,operator_signature
           FROM release_notes WHERE python_version=? AND package=?
           AND package_version=? AND topic=? ORDER BY record_id""",
          (python_version, package, package_version, topic)).fetchall()
    records = [{"record_id": row[0], "authority": row[1], "source_uri": row[2],
                "license_id": row[3], "document_sha256": row[4], "claim": row[5],
                "deprecated_since": row[6], "removal_not_before": row[7],
                "observed_date": row[8]} for row in rows]
    invalid_provenance = []
    if policy is not None:
        for row in rows:
            authority = row[1]
            record = dict(zip(SIGNED_FIELDS, (
                row[0], row[1], row[2], row[3], row[4], package,
                package_version, python_version, topic, row[5], row[6],
                row[7], row[8])))
            source = policy["sources"].get(authority)
            key = trust["authorities"].get(authority)
            try:
                current_hostname = urlsplit(row[2]).hostname
            except ValueError:
                current_hostname = None
            authorized = (isinstance(source, dict) and
                          source.get("allow_ingest") is True and
                          isinstance(source.get("licenses"), list) and
                          row[3] in source["licenses"] and
                          current_hostname == source.get("hostname"))
            if (not isinstance(key, dict) or not authorized or
                    row[9] != policy["policy_id"] or
                    not isinstance(row[10], str) or
                    not hmac.compare_digest(
                        sign_for_test(policy, record, key["key_hex"]), row[10])):
                invalid_provenance.append(row[0])
    facts = {(r["claim"], r["deprecated_since"], r["removal_not_before"])
             for r in records}
    conflicting = len(facts) > 1
    stale = []
    future = []
    for record in records:
        try:
            observed = _date(record["observed_date"])
        except ValueError:
            if record["record_id"] not in invalid_provenance:
                invalid_provenance.append(record["record_id"])
            continue
        if (today - observed).days > stale_after_days:
            stale.append(record["record_id"])
        if observed > today:
            future.append(record["record_id"])
    flag = bool(conflicting or stale or future or invalid_provenance or policy is None)
    return {"status": "NO_EVIDENCE" if not records else
            "REVIEW_REQUIRED" if flag else "OPERATOR_ATTESTED_NOT_PUBLISHER_VERIFIED",
            "records": records, "conflicting_claims": conflicting,
            "stale_record_ids": stale, "future_dated_record_ids": future,
            "invalid_provenance_record_ids": invalid_provenance,
            "provenance_rechecked": policy is not None,
            "review_required": flag, "automatic_override": False,
            "publisher_verified": False, "network_used": False,
            "source_executed": False}


def main():
    """Bounded offline CLI; an operator must provide provenance and trust data."""
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    put = sub.add_parser("ingest")
    put.add_argument("--db", required=True)
    for key in ("policy", "trust", "manifest"):
        put.add_argument("--" + key, required=True)
    lookup = sub.add_parser("review")
    for key in ("db", "python-version", "package", "package-version", "topic", "as-of"):
        lookup.add_argument("--" + key, required=True)
    lookup.add_argument("--stale-after-days", type=int, default=90)
    lookup.add_argument("--policy", required=True)
    lookup.add_argument("--trust", required=True)
    args = parser.parse_args()
    def bounded_record(path):
        source = Path(path)
        if source.is_symlink() or not source.is_file() or source.stat().st_size > 500_000:
            raise ValueError("invalid_manifest_path_or_size")
        return json.loads(source.read_text(encoding="utf-8"))

    if args.action == "ingest":
        result = ingest(args.db, bounded_record(args.policy),
                        bounded_record(args.trust), bounded_record(args.manifest))
    else:
        result = review(args.db, args.python_version, args.package,
                        args.package_version, args.topic, args.as_of,
                        args.stale_after_days, policy=bounded_record(args.policy),
                        trust=bounded_record(args.trust))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
