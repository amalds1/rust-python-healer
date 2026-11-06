"""Offline documentation-section permission, citation and version binding.

An operator-controlled policy and HMAC-authorized source records are checked
before insertion.  This does NOT authenticate a publisher or legal ownership.
Untrusted source text is never imported, evaluated, executed or returned from
the default inventory/ingest response.
"""

import argparse
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from urllib.parse import urlsplit


MAX_BYTES = 1_048_576
MAX_SECTIONS = 64
MAX_CONTENT_BYTES = 32_768
MAX_SOURCES = 32
MAX_QUOTE_WORDS = 25
MAX_QUOTE_BYTES = 1_024
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z")
PACKAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
LICENSE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,63}\Z")
PY_VERSION = re.compile(r"3\.[0-9]{1,2}\.[0-9]{1,3}\Z")
EXACT_VERSION = re.compile(r"[0-9][A-Za-z0-9_.!+~-]{0,63}\Z")
PLATFORM = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{2,95}\Z")
HEX64 = re.compile(r"[a-f0-9]{64}\Z")


def canonical(value):
    """Stable bytes for deterministic metadata hashes and HMAC."""
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def bounded_json(path, private=False):
    """Read a unique regular file with no-follow and strict size/private mode."""
    location = Path(path)
    if location.is_symlink():
        raise ValueError("policy_input_symlink_refused")
    if private and os.name == "nt":
        privacy = globals().get("_RPH_WINDOWS_PRIVACY")
        if privacy is None:
            spec = importlib.util.spec_from_file_location("rph_source_privacy", Path(__file__).with_name("windows_private_paths.py"))
            privacy = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(privacy)
        try:
            descriptor = privacy.open_private_readonly(location.absolute())
        except ValueError as error:
            if str(error) == "windows_privacy_single_link_required":
                raise ValueError("policy_input_not_unique_bounded_file") from None
            raise ValueError("trust_file_must_be_owner_only") from None
    else:
        descriptor = os.open(str(location), os.O_RDONLY |
                             getattr(os, "O_NOFOLLOW", 0) |
                             getattr(os, "O_NONBLOCK", 0))
    try:
        stream = os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise
    with stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_size > MAX_BYTES):
            raise ValueError("policy_input_not_unique_bounded_file")
        if private and os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("trust_file_must_be_owner_only")
        content = stream.read(MAX_BYTES + 1)
        if private and os.name == "nt":
            try:
                privacy.assert_private_file_descriptor(stream.fileno())
            except ValueError:
                raise ValueError("trust_file_must_be_owner_only") from None
        after = os.fstat(stream.fileno())
        if (not stat.S_ISREG(after.st_mode) or after.st_nlink != 1
                or (private and os.name != "nt" and stat.S_IMODE(after.st_mode) & 0o077)
                or len(content) != info.st_size or len(content) > MAX_BYTES or
                (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise ValueError("policy_input_changed_or_oversized")
    try:
        return json.loads(content.decode("utf-8"), object_pairs_hook=unique_keys,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              ValueError("invalid_json_number")))
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("invalid_policy_json") from None


def validate_policy(policy):
    if not isinstance(policy, dict) or set(policy) != {
            "schema_version", "policy_id", "sources"} or type(policy["schema_version"]) is not int or policy["schema_version"] != 1:
        raise ValueError("invalid_source_policy")
    if not isinstance(policy["policy_id"], str) or not ID.fullmatch(policy["policy_id"]):
        raise ValueError("invalid_policy_id")
    sources = policy["sources"]
    if not isinstance(sources, dict) or not 0 < len(sources) <= MAX_SOURCES:
        raise ValueError("invalid_source_allowlist")
    for source_id, value in sources.items():
        if not isinstance(source_id, str) or not ID.fullmatch(source_id):
            raise ValueError("invalid_source_id")
        if not isinstance(value, dict) or set(value) != {
                "hostname", "licenses", "may_ingest", "max_citation_words",
                "max_citation_bytes"}:
            raise ValueError("invalid_source_constraints")
        host, licenses = value["hostname"], value["licenses"]
        if (not isinstance(host, str) or host.lower() != host or len(host) > 128 or
                not re.fullmatch(r"[a-z0-9][a-z0-9.-]+", host) or
                not isinstance(licenses, list) or not 0 < len(licenses) <= 24 or
                len(licenses) != len(set(str(x) for x in licenses)) or
                any(not isinstance(x, str) or not LICENSE.fullmatch(x) for x in licenses)):
            raise ValueError("invalid_source_host_or_license")
        if type(value["may_ingest"]) is not bool:
            raise ValueError("invalid_ingestion_permission")
        for key, limit in (("max_citation_words", MAX_QUOTE_WORDS),
                           ("max_citation_bytes", MAX_QUOTE_BYTES)):
            value_limit = value[key]
            if type(value_limit) is not int or not 0 <= value_limit <= limit:
                raise ValueError("invalid_source_citation_budget")
    return sources


def validate_trust(trust, sources):
    if (not isinstance(trust, dict) or set(trust) != {"schema_version", "authorities"}
            or type(trust["schema_version"]) is not int or trust["schema_version"] != 1):
        raise ValueError("invalid_trust")
    authorities = trust["authorities"]
    if (not isinstance(authorities, dict) or not authorities or
            set(authorities) != set(sources)):
        raise ValueError("trust_authorities_must_match_policy_sources")
    used = set()
    for authority, value in authorities.items():
        if (not isinstance(value, dict) or set(value) != {"key_hex"} or
                not isinstance(value["key_hex"], str) or
                not HEX64.fullmatch(value["key_hex"])):
            raise ValueError("invalid_operator_key")
        if value["key_hex"] in used:
            raise ValueError("duplicate_operator_key")
        used.add(value["key_hex"])
    return authorities


def normalize_section(section):
    """Validate exact-version metadata; never allow implied range/wildcard."""
    required = {"section_id", "source_id", "uri", "license", "python_version",
                "package", "package_version", "platform", "content",
                "ingest_authorized", "signature"}
    if not isinstance(section, dict) or set(section) != required:
        raise ValueError("invalid_document_section")
    for key, rule in (("section_id", ID), ("source_id", ID), ("license", LICENSE),
                      ("python_version", PY_VERSION), ("package", PACKAGE),
                      ("package_version", EXACT_VERSION), ("platform", PLATFORM),
                      ("signature", HEX64)):
        value = section[key]
        if not isinstance(value, str) or not rule.fullmatch(value):
            raise ValueError("invalid_exact_section_metadata")
    if type(section["ingest_authorized"]) is not bool:
        raise ValueError("invalid_section_permission")
    content = section["content"]
    if (not isinstance(content, str) or not content or "\x00" in content or
            len(content.encode("utf-8")) > MAX_CONTENT_BYTES):
        raise ValueError("invalid_section_content")
    uri = section["uri"]
    if not isinstance(uri, str) or len(uri) > 2048 or any(x in uri for x in "\r\n\0"):
        raise ValueError("invalid_source_uri")
    parts = urlsplit(uri)
    if (parts.scheme != "https" or not parts.hostname or parts.username or
            parts.password or parts.query or parts.fragment or parts.port not in (None, 443)):
        raise ValueError("unsafe_source_uri")
    return parts.hostname.lower()


def signed_payload(policy_hash, section):
    return {"policy_sha256": policy_hash,
            **{k: v for k, v in section.items() if k != "signature"}}


def sign_for_test(policy, section, key_hex):
    """Fixture signer only; the verifier never creates publisher signatures."""
    return hmac.new(bytes.fromhex(key_hex), canonical(signed_payload(
        digest(policy), section)), hashlib.sha256).hexdigest()


def validated_sections(policy, trust, manifest):
    sources = validate_policy(policy)
    authorities = validate_trust(trust, sources)
    if (not isinstance(manifest, dict) or set(manifest) != {"schema_version", "sections"}
            or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1 or
            not isinstance(manifest["sections"], list) or
            not 0 < len(manifest["sections"]) <= MAX_SECTIONS):
        raise ValueError("invalid_section_manifest")
    rows, seen = [], set()
    policy_hash = digest(policy)
    for section in manifest["sections"]:
        host = normalize_section(section)
        source_id = section["source_id"]
        section_id = section["section_id"]
        if section_id in seen:
            raise ValueError("duplicate_document_section")
        seen.add(section_id)
        source = sources.get(source_id)
        if source is None or host != source["hostname"]:
            raise ValueError("source_host_not_authorized")
        if (not source["may_ingest"] or not section["ingest_authorized"] or
                section["license"] not in source["licenses"]):
            raise ValueError("document_ingestion_or_license_denied")
        expected = hmac.new(bytes.fromhex(authorities[source_id]["key_hex"]),
                            canonical(signed_payload(policy_hash, section)),
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, section["signature"]):
            raise ValueError("operator_attestation_invalid")
        raw = section["content"].encode("utf-8")
        rows.append({
            "section_id": section_id,
            "source_id": source_id,
            "uri_sha256": hashlib.sha256(section["uri"].encode("utf-8")).hexdigest(),
            "license": section["license"],
            "python_version": section["python_version"],
            "package": re.sub(r"[-_.]+", "-", section["package"]).lower(),
            "package_version": section["package_version"],
            "platform": section["platform"],
            "content_sha256": hashlib.sha256(raw).hexdigest(),
            "record_sha256": digest(signed_payload(policy_hash, section)),
            "content": section["content"],
            "content_bytes": len(raw),
            "content_words": len(section["content"].split()),
            "citation_limit_words": source["max_citation_words"],
            "citation_limit_bytes": source["max_citation_bytes"],
            "policy_sha256": policy_hash,
            "operator_attestation": "HMAC_VERIFIED_PUBLISHER_NOT_VERIFIED",
        })
    return rows


def schema(connection):
    connection.execute("""CREATE TABLE IF NOT EXISTS sections(
        section_id TEXT PRIMARY KEY, source_id TEXT NOT NULL,
        uri_sha256 TEXT NOT NULL, license TEXT NOT NULL,
        python_version TEXT NOT NULL, package TEXT NOT NULL,
        package_version TEXT NOT NULL, platform TEXT NOT NULL,
        content_sha256 TEXT NOT NULL, record_sha256 TEXT NOT NULL,
        content TEXT NOT NULL,
        content_bytes INTEGER NOT NULL, content_words INTEGER NOT NULL,
        citation_limit_words INTEGER NOT NULL, citation_limit_bytes INTEGER NOT NULL,
        policy_sha256 TEXT NOT NULL, operator_attestation TEXT NOT NULL,
        UNIQUE(source_id, uri_sha256, content_sha256, python_version,
               package, package_version, platform)
    )""")
    connection.execute("""CREATE INDEX IF NOT EXISTS section_versions
        ON sections(python_version,package,package_version,platform)""")


def ingest(database, policy, trust, manifest):
    """Atomic import: all authorized+authenticated sections or none."""
    rows = validated_sections(policy, trust, manifest)
    path = Path(database)
    if path.is_symlink():
        raise ValueError("database_symlink_refused")
    if path.exists():
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("database_not_unique_regular_file")
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise ValueError("database_parent_not_directory")
    connection = sqlite3.connect(str(path), timeout=4)
    try:
        connection.execute("PRAGMA busy_timeout=4000")
        connection.execute("PRAGMA foreign_keys=ON")
        with connection:
            schema(connection)
            inserted = 0
            for row in rows:
                prior = connection.execute("SELECT record_sha256 FROM sections "
                                           "WHERE section_id=?", (row["section_id"],)).fetchone()
                if prior is not None:
                    if prior[0] != row["record_sha256"]:
                        raise ValueError("section_identity_changed_without_new_id")
                    continue
                columns = list(row)
                connection.execute("INSERT INTO sections(" + ",".join(columns) + ") VALUES (" +
                                   ",".join("?" for _ in columns) + ")",
                                   tuple(row[name] for name in columns))
                inserted += 1
            count = connection.execute("SELECT COUNT(*) FROM sections").fetchone()[0]
    finally:
        connection.close()
    return {"status": "OPERATOR_ATTESTED_NOT_PUBLISHER_VERIFIED",
            "sections_in_manifest": len(rows), "sections_inserted": inserted,
            "sections_recorded": count,
            "policy_sha256": digest(policy),
            "manifest_sha256": digest(manifest),
            "source_executed": False,
            "network_used": False,
            "publisher_verified": False,
            "full_license_authenticity": "NOT_VERIFIED",
            "content_disclosed": False,
            "note": "Operator HMAC checks ingestion policy, not legal ownership or publisher authenticity"}


def _readonly_database(database):
    path = Path(database).absolute()
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                getattr(info, "st_file_attributes", 0) & 0x400):
            raise ValueError("missing_or_linked_database")
    except OSError:
        raise ValueError("missing_or_linked_database") from None
    # Immutable prevents SQLite recovery/SHM writes; callers must checkpoint
    # first. Rust additionally queries its own bounded, held-handle snapshot.
    if any(Path(str(path) + suffix).exists() or Path(str(path) + suffix).is_symlink()
           for suffix in ("-wal", "-shm", "-journal")):
        raise ValueError("readonly_database_requires_checkpoint")
    connection = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
    except BaseException:
        connection.close()
        raise
    return connection


def lookup(database, python_version, package, package_version, platform):
    """Return exact-version metadata only, never source text by default."""
    for value, regex in ((python_version, PY_VERSION), (package, PACKAGE),
                         (package_version, EXACT_VERSION), (platform, PLATFORM)):
        if not isinstance(value, str) or not regex.fullmatch(value):
            raise ValueError("version_filter_must_be_exact")
    db_path = Path(database)
    if (db_path.is_symlink() or not db_path.is_file() or
            db_path.stat().st_nlink != 1):
        raise ValueError("missing_or_linked_database")
    connection = _readonly_database(database)
    try:
        query = """SELECT section_id,source_id,uri_sha256,license,python_version,
           package,package_version,platform,content_sha256,citation_limit_words,
           citation_limit_bytes,operator_attestation FROM sections
           WHERE python_version=? AND package=? AND package_version=? AND platform=?
           ORDER BY section_id LIMIT 65"""
        records = connection.execute(query, (python_version,
                                            re.sub(r"[-_.]+", "-", package).lower(),
                                            package_version, platform)).fetchall()
    finally:
        connection.close()
    if len(records) > 64:
        raise ValueError("query_result_limit")
    keys = ("section_id", "source_id", "uri_sha256", "license", "python_version",
            "package", "package_version", "platform", "content_sha256",
            "citation_limit_words", "citation_limit_bytes", "operator_attestation")
    return {"status": "EXACT_VERSION_METADATA_NOT_PUBLISHER_VERIFIED",
            "source_executed": False, "publisher_verified": False,
            "content_disclosed": False,
            "sections": [dict(zip(keys, row)) for row in records]}


def cite(database, section_id, max_words, max_bytes):
    """Explicitly requested excerpt, bounded by both operator citation quotas."""
    if not isinstance(section_id, str) or not ID.fullmatch(section_id):
        raise ValueError("invalid_section_id")
    if (type(max_words) is not int or type(max_bytes) is not int or
            not 0 <= max_words <= MAX_QUOTE_WORDS or
            not 0 <= max_bytes <= MAX_QUOTE_BYTES):
        raise ValueError("invalid_quote_budget")
    db_path = Path(database)
    if (db_path.is_symlink() or not db_path.is_file() or
            db_path.stat().st_nlink != 1):
        raise ValueError("missing_or_linked_database")
    connection = _readonly_database(database)
    try:
        row = connection.execute("""SELECT content,citation_limit_words,
                      citation_limit_bytes,content_sha256 FROM sections
                      WHERE section_id=?""", (section_id,)).fetchone()
    finally:
        connection.close()
    if row is None:
        raise ValueError("unknown_section_id")
    content, word_limit, byte_limit, fingerprint = row
    count, raw = 0, bytearray()
    for word in content.split():
        encoding = word.encode("utf-8")
        additional = encoding if not raw else b" " + encoding
        if (count >= min(max_words, word_limit) or
                len(raw) + len(additional) > min(max_bytes, byte_limit)):
            break
        raw.extend(additional)
        count += 1
    return {"status": "EXCERPT_WITHIN_CITATION_BUDGET",
            "source_executed": False, "section_id": section_id,
            "trust_level": "UNTRUSTED_SOURCE_DATA",
            "content_sha256": fingerprint,
            "excerpt": raw.decode("utf-8"),
            "excerpt_words": count, "excerpt_bytes": len(raw),
            "full_content_disclosed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("ingest")
    add.add_argument("--database", required=True)
    add.add_argument("--policy", required=True)
    add.add_argument("--trust", required=True)
    add.add_argument("--manifest", required=True)
    query = sub.add_parser("lookup")
    query.add_argument("--database", required=True)
    query.add_argument("--python-version", required=True)
    query.add_argument("--package", required=True)
    query.add_argument("--package-version", required=True)
    query.add_argument("--platform", required=True)
    quote = sub.add_parser("cite")
    quote.add_argument("--database", required=True)
    quote.add_argument("--section-id", required=True)
    quote.add_argument("--max-words", type=int, required=True)
    quote.add_argument("--max-bytes", type=int, required=True)
    args = parser.parse_args()
    if args.command == "ingest":
        report = ingest(args.database, bounded_json(args.policy),
                        bounded_json(args.trust, private=True),
                        bounded_json(args.manifest))
    elif args.command == "lookup":
        report = lookup(args.database, args.python_version, args.package,
                        args.package_version, args.platform)
    else:
        report = cite(args.database, args.section_id, args.max_words, args.max_bytes)
    print(json.dumps(report, sort_keys=True, ensure_ascii=False))


if __name__ == "__main__":
    main()
