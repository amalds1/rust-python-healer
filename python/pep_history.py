"""Offline PEP snapshots, status-change/supersession review and provenance.

The module accepts only locally reviewed source documents and operator HMAC
keys. A peps.python.org URL does NOT independently prove official authorship.
No network synchronization, publisher signature validation or Python imports.
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


STATUSES = ("Draft", "Active", "Accepted", "Final", "Rejected", "Withdrawn",
            "Deferred", "Provisional", "Superseded")
FIELDS = ("snapshot_id", "number", "title", "status", "supersedes",
          "source_uri", "license_id", "document_sha256", "observed_date",
          "authority", "change_summary")


def _date(value):
    if type(value) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("invalid_pep_observation_date")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise ValueError("invalid_pep_observation_date") from None


def _policy(policy, trust):
    if (type(policy) is not dict or type(trust) is not dict or
            policy.get("schema_version") != 1 or trust.get("schema_version") != 1 or
            type(policy.get("sources")) is not dict or
            type(trust.get("authorities")) is not dict or
            type(policy.get("policy_id")) is not str or
            not 1 <= len(policy["policy_id"]) <= 128):
        raise ValueError("invalid_pep_source_policy")
    seen = set()
    for authority, config in trust["authorities"].items():
        key = config.get("key_hex") if type(config) is dict else None
        if type(key) is not str or not re.fullmatch(r"[a-fA-F0-9]{64}", key):
            raise ValueError("invalid_pep_authority_key")
        if key.lower() in seen:
            raise ValueError("duplicate_pep_authority_key")
        seen.add(key.lower())


def sign_for_test(policy, entry, key_hex):
    """Operator fixture signature, never an upstream PEP publisher signature."""
    payload = {field: entry.get(field) for field in FIELDS}
    canonical = json.dumps({"policy_id": policy["policy_id"], "snapshot": payload},
                           sort_keys=True, ensure_ascii=False,
                           separators=(",", ":")).encode("utf-8")
    return hmac.new(bytes.fromhex(key_hex), canonical, hashlib.sha256).hexdigest()


def _allowed(policy, trust, item):
    authority = item.get("authority")
    source = policy["sources"].get(authority)
    key = trust["authorities"].get(authority)
    if type(source) is not dict or type(key) is not dict:
        return False
    try:
        uri = urlsplit(item["source_uri"])
        valid_uri = (uri.scheme == "https" and uri.hostname == "peps.python.org" and
                     uri.hostname == source.get("hostname") and
                     uri.port in (None, 443) and uri.username is None and
                     uri.password is None and not uri.query and not uri.fragment and
                     uri.path == "/pep-{0:04d}/".format(item["number"]))
    except (ValueError, TypeError, KeyError):
        valid_uri = False
    return (valid_uri and source.get("ingest_allowed") is True and
            type(source.get("licenses")) is list and
            item.get("license_id") in source["licenses"])


def _validate(policy, trust, record):
    if type(record) is not dict or not set(FIELDS).issubset(record) or any(
            k not in set(FIELDS) | {"document_text", "signature"} for k in record):
        raise ValueError("invalid_pep_snapshot_fields")
    snapshot_id = record["snapshot_id"]
    if (type(snapshot_id) is not str or
            not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}", snapshot_id)):
        raise ValueError("invalid_pep_snapshot_id")
    number = record["number"]
    if type(number) is not int or not 1 <= number <= 99999:
        raise ValueError("invalid_pep_number")
    for field, limit in (("title", 300), ("change_summary", 1000)):
        val = record.get(field)
        if type(val) is not str or not val or len(val.encode("utf-8")) > limit:
            raise ValueError("invalid_pep_" + field)
    if record["status"] not in STATUSES:
        raise ValueError("invalid_pep_status")
    supersedes = record["supersedes"]
    if (type(supersedes) is not list or len(supersedes) > 100 or
            any(type(ref) is not int or not 1 <= ref <= 99999 or ref == number
                for ref in supersedes) or len(supersedes) != len(set(supersedes))):
        raise ValueError("invalid_pep_supersedes_edges")
    _date(record["observed_date"])
    doc = record.get("document_text")
    if type(doc) is not str or not doc or len(doc.encode("utf-8")) > 100000:
        raise ValueError("invalid_pep_document")
    if hashlib.sha256(doc.encode("utf-8")).hexdigest() != record["document_sha256"]:
        raise ValueError("pep_document_sha256_mismatch")
    if not _allowed(policy, trust, record):
        raise ValueError("pep_source_authorization_denied")
    key = trust["authorities"][record["authority"]]["key_hex"]
    if (type(record.get("signature")) is not str or
            not hmac.compare_digest(sign_for_test(policy, record, key), record["signature"])):
        raise ValueError("pep_operator_signature_invalid")
    payload = {field: record.get(field) for field in FIELDS}
    return (snapshot_id, number, record["observed_date"],
            json.dumps(payload, sort_keys=True, ensure_ascii=False),
            record["signature"], policy["policy_id"])


def ingest(database_path, policy, trust, manifest):
    """Append-only PEP status snapshots, each checked before DB creation."""
    _policy(policy, trust)
    if (type(manifest) is not dict or manifest.get("schema_version") != 1 or
            type(manifest.get("snapshots")) is not list or
            not 1 <= len(manifest["snapshots"]) <= 500):
        raise ValueError("invalid_pep_manifest")
    rows = [_validate(policy, trust, snapshot) for snapshot in manifest["snapshots"]]
    if len(set(row[0] for row in rows)) != len(rows):
        raise ValueError("duplicate_pep_snapshot")
    db = Path(database_path)
    db.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(str(db))) as conn:
        with conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS pep_snapshots (
               snapshot_id TEXT PRIMARY KEY, pep_number INTEGER NOT NULL,
               observed_date TEXT NOT NULL, payload TEXT NOT NULL,
               signature TEXT NOT NULL, policy_id TEXT NOT NULL)""")
            conn.execute("""CREATE INDEX IF NOT EXISTS pep_history_num_date
               ON pep_snapshots(pep_number,observed_date)""")
            try:
                conn.executemany("INSERT INTO pep_snapshots VALUES (?,?,?,?,?,?)", rows)
            except sqlite3.IntegrityError as error:
                raise ValueError("immutable_pep_snapshot_collision") from error
    return {"snapshots_inserted": len(rows), "status": "UNVERIFIED_EXTERNAL",
            "operator_signature_checked": True, "publisher_authenticated": False,
            "network_synchronized": False, "automatic_override": False,
            "document_text_stored": False}


def review(database_path, number, as_of, policy, trust, stale_days=90):
    """Preserve entire PEP history; conflicts and unknown edges demand review."""
    _policy(policy, trust)
    if type(number) is not int or not 1 <= number <= 99999:
        raise ValueError("invalid_pep_number")
    today = _date(as_of)
    if type(stale_days) is not int or not 1 <= stale_days <= 3650:
        raise ValueError("invalid_pep_staleness_window")
    with closing(sqlite3.connect(str(database_path))) as conn:
        rows = conn.execute("""SELECT snapshot_id,observed_date,payload,
                   signature,policy_id FROM pep_snapshots
                   WHERE pep_number=? ORDER BY observed_date,snapshot_id""",
                   (number,)).fetchall()
        known_numbers = {x[0] for x in conn.execute("SELECT DISTINCT pep_number FROM pep_snapshots")}
        graph_rows = conn.execute("SELECT pep_number,payload FROM pep_snapshots LIMIT 20001").fetchall()
    snapshots = []
    flagged = []
    if len(graph_rows) > 20000:
        flagged.append({"reason": "supersession_graph_scan_limit_reached"})
    else:
        graph = {}
        for origin, blob in graph_rows:
            try:
                refs = json.loads(blob)["supersedes"]
                if type(refs) is list and all(type(ref) is int for ref in refs):
                    graph.setdefault(origin, set()).update(refs)
            except (ValueError, TypeError, KeyError):
                flagged.append({"reason": "corrupt_supersession_graph_evidence"})
        pending, visited = list(graph.get(number, ())), set()
        while pending:
            current = pending.pop()
            if current == number:
                flagged.append({"reason": "supersession_cycle"})
                break
            if current not in visited:
                visited.add(current)
                pending.extend(graph.get(current, ()))
    for snapshot_id, observed, blob, signature, policy_id in rows:
        try:
            item = json.loads(blob)
            observed_date = _date(observed)
            key = trust["authorities"].get(item["authority"], {}).get("key_hex")
            authentic = (type(item) is dict and key is not None and
                         item.get("snapshot_id") == snapshot_id and
                         item.get("number") == number and
                         item.get("observed_date") == observed and
                         policy_id == policy["policy_id"] and
                         _allowed(policy, trust, item) and
                         type(signature) is str and
                         hmac.compare_digest(sign_for_test(policy, item, key), signature))
            if not authentic:
                flagged.append({"snapshot_id": snapshot_id, "reason": "invalid_provenance"})
                continue
            if observed_date > today:
                flagged.append({"snapshot_id": snapshot_id, "reason": "future_dated"})
            elif (today - observed_date).days > stale_days:
                flagged.append({"snapshot_id": snapshot_id, "reason": "stale_snapshot"})
            snapshots.append(item)
            unknown = sorted(set(item["supersedes"]) - known_numbers)
            if unknown:
                flagged.append({"snapshot_id": snapshot_id,
                                "reason": "unresolved_supersedes_reference", "numbers": unknown})
        except (TypeError, KeyError, ValueError, AttributeError):
            flagged.append({"snapshot_id": snapshot_id, "reason": "corrupt_snapshot"})
    history = {(item["status"], tuple(item["supersedes"])) for item in snapshots}
    status_changed = len(history) > 1
    if status_changed:
        flagged.append({"reason": "status_or_supersession_changed_needs_review"})
    return {"status": "REVIEW_REQUIRED" if flagged else
            "UNVERIFIED_EXTERNAL" if snapshots else "NO_EVIDENCE",
            "snapshots": snapshots, "needs_review": flagged,
            "status_changed": status_changed, "automatic_override": False,
            "publisher_authenticated": False, "network_synchronized": False,
            "external_pep_feed_verified": False}
