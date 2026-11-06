"""Bounded provenance and PEP-index evidence. Never executes package code.

Supports v1 PEP 740 DSSE P-256 signature verification with *operator-pinned*
X.509 roots/identity, not automatic trust in arbitrary presented roots.
Full PyPI attestation qualification also needs authenticated Rekor inclusion
proofs and official Fulcio trust roots; local crypto success does NOT imply it.
PEP API import is data-only. Live HTTPS feed authenticity and completeness
are independently recorded and never inferred from a caller-supplied ETag.
"""

import argparse
import base64
import binascii
import csv
from contextlib import closing
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from email.parser import BytesParser


PEP_URL = "https://peps.python.org/api/peps.json"
INTEGRITY_ORIGIN = "https://pypi.org"
MAX_PEP_BYTES = 8_000_000
MAX_PROVENANCE_BYTES = 2_000_000
MAX_ARTIFACT_BYTES = 64_000_000
MAX_ADVISORIES = 1000
PEP_STATUS = frozenset(("Accepted", "Active", "Deferred", "Draft", "Final",
                       "Provisional", "Rejected", "Superseded", "Withdrawn"))
PEP_TYPES = frozenset(("Informational", "Process", "Standards Track"))
SHA = re.compile(r"[a-f0-9]{64}\Z")
WHEEL = re.compile(r"[A-Za-z0-9_.-]+\.whl\Z")
_DSSE_PAYLOAD = b"application/vnd.in-toto+json"
_SUBJECT_PREDICATES = frozenset((
    "https://slsa.dev/provenance/v1",
    "https://docs.pypi.org/attestations/publish/v1"))


def _safe_json(raw, limit):
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if type(raw) is not bytes or len(raw) > limit:
        raise ValueError("invalid_bounded_json")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("invalid_json_structure") from exc


def _read_regular(path, limit):
    path = Path(path)
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
            before.st_size > limit):
        raise ValueError("unsafe_file")
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("file_replaced")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            payload = stream.read(limit + 1)
        final = os.fstat(fd)
        if (len(payload) > limit or opened.st_size != final.st_size or
                opened.st_mtime_ns != final.st_mtime_ns):
            raise ValueError("file_changed_or_oversize")
        return payload
    finally:
        os.close(fd)


def _sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def _toml(raw):
    try:
        import tomllib as parser
    except ImportError:
        try:
            import tomli as parser
        except ImportError:
            try:
                from pip._vendor import tomli as parser
            except ImportError as exc:
                raise RuntimeError("trusted_toml_parser_unavailable") from exc
    try:
        return parser.loads(raw.decode("utf-8"))
    except (UnicodeError, parser.TOMLDecodeError) as exc:
        raise ValueError("invalid_cargo_lock_toml") from exc


def _base64(value, limit):
    if not isinstance(value, str) or len(value) > limit * 2:
        raise ValueError("invalid_base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid_base64") from exc
    if len(raw) > limit:
        raise ValueError("base64_size_limit")
    return raw


def dsse_pae(statement):
    """PEP 740 uses v1 DSSE PAE over opaque in-toto JSON bytes."""
    if type(statement) is not bytes or len(statement) > 256_000:
        raise ValueError("statement_size_limit")
    return (b"DSSEv1 " + str(len(_DSSE_PAYLOAD)).encode("ascii") + b" " +
            _DSSE_PAYLOAD + b" " + str(len(statement)).encode("ascii") +
            b" " + statement)


def integrity_endpoint(project, version, filename):
    """One exact host and safe path segments; no arbitrary supplied URLs."""
    segment = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
    if (not all(isinstance(x, str) and segment.fullmatch(x)
                for x in (project, version, filename)) or
            not (WHEEL.fullmatch(filename) or filename.endswith(".tar.gz"))):
        raise ValueError("invalid_integrity_route")
    return INTEGRITY_ORIGIN + "/integrity/" + project + "/" + version + "/" + filename + "/provenance"


def _openssl_executable():
    if os.name != "nt":
        return "openssl"
    # Query the OS installation directory, never CWD/PATH or a presented key.
    import ctypes
    from ctypes import wintypes
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.SHGetFolderPathW.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.HANDLE,
                                      wintypes.DWORD, wintypes.LPWSTR]
    shell.SHGetFolderPathW.restype = ctypes.c_long
    folder = ctypes.create_unicode_buffer(260)
    if shell.SHGetFolderPathW(None, 0x26, None, 0, folder) != 0:
        raise ValueError("trusted_openssl_installation_unavailable")
    path = Path(folder.value) / "Git/usr/bin/openssl.exe"
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("trusted_openssl_installation_unavailable")
    except OSError:
        raise ValueError("trusted_openssl_installation_unavailable") from None
    return str(path)


def _openssl(args, data=None, max_bytes=50_000):
    """Only caller-selected fixed openssl subcommands; no shell or plugins."""
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                   "OPENSSL_CONF": os.devnull}
    if os.name == "nt" and os.environ.get("SystemRoot"):
        environment["SystemRoot"] = os.environ["SystemRoot"]
    result = subprocess.run([_openssl_executable()] + list(args), input=data,
                            capture_output=True, timeout=8, check=False,
                            env=environment)
    if result.returncode != 0 or len(result.stdout) > max_bytes:
        raise ValueError("cryptographic_verification_failed")
    return result.stdout


def verify_pep740(provenance_raw, artifact_path, expected_project,
                  expected_version, pinned_root_pem, pinned_root_sha256,
                  expected_signing_identity, allow_unverified_log=False):
    """Verify real cryptography on local bytes under an external trust anchor.

    The caller must obtain/pin the CA root and signing identity independently.
    Transparency-log inclusion is NOT validated by this module.  Production
    policy therefore rejects by default, even after signature verification.
    """
    provenance = _safe_json(provenance_raw, MAX_PROVENANCE_BYTES)
    if type(provenance) is not dict or type(provenance.get("attestation_bundles")) is not list:
        raise ValueError("invalid_integrity_api_provenance")
    if not isinstance(expected_signing_identity, str) or not expected_signing_identity.startswith("https://"):
        raise ValueError("explicit_publisher_identity_required")
    if type(pinned_root_pem) is not bytes or type(pinned_root_sha256) is not str:
        raise ValueError("trusted_root_pin_required")
    if not SHA.fullmatch(pinned_root_sha256.lower()):
        raise ValueError("trusted_root_pin_invalid")
    artifact = _read_regular(artifact_path, MAX_ARTIFACT_BYTES)
    filename = Path(artifact_path).name
    integrity_endpoint(expected_project, expected_version, filename)
    if type(provenance["attestation_bundles"]) is not list or not 1 <= len(provenance["attestation_bundles"]) <= 20:
        raise ValueError("invalid_attestation_bundle_count")

    with tempfile.TemporaryDirectory(prefix="rph-v23-pep740-") as folder:
        base = Path(folder)
        root = base / "root.pem"
        root.write_bytes(pinned_root_pem)
        root_der = _openssl(["x509", "-in", str(root), "-outform", "DER"])
        if _sha_bytes(root_der) != pinned_root_sha256.lower():
            raise ValueError("trusted_root_hash_mismatch")
        for bundle in provenance["attestation_bundles"]:
            if type(bundle) is not dict or type(bundle.get("attestations")) is not list:
                raise ValueError("invalid_attestation_bundle")
            if not 1 <= len(bundle["attestations"]) <= 30:
                raise ValueError("invalid_attestation_count")
            for att in bundle["attestations"]:
                if type(att) is not dict or att.get("version") != 1:
                    raise ValueError("unsupported_attestation_version")
                material = att.get("verification_material")
                envelope = att.get("envelope")
                if type(material) is not dict or type(envelope) is not dict:
                    raise ValueError("invalid_signature_material")
                certificate = _base64(material.get("certificate"), 12_000)
                statement = _base64(envelope.get("statement"), 256_000)
                signature = _base64(envelope.get("signature"), 1000)
                leaf_der = base / "leaf.der"
                leaf_der.write_bytes(certificate)
                leaf = base / "leaf.pem"
                leaf.write_bytes(_openssl(["x509", "-inform", "DER", "-in",
                                           str(leaf_der), "-outform", "PEM"]))
                _openssl(["verify", "-CAfile", str(root), "-purpose", "any", str(leaf)])
                san = _openssl(["x509", "-in", str(leaf), "-noout", "-ext", "subjectAltName"])
                identities = re.findall(rb"URI:([^,\s]+)", san)
                if expected_signing_identity.encode("utf-8") not in identities:
                    raise ValueError("publisher_identity_mismatch")
                public = base / "leaf-public.pem"
                public.write_bytes(_openssl(["x509", "-in", str(leaf), "-pubkey", "-noout"]))
                description = _openssl(["pkey", "-pubin", "-in", str(public), "-text", "-noout"])
                if b"prime256v1" not in description and b"P-256" not in description:
                    raise ValueError("certificate_not_p256")
                signed = base / "dsse.bin"
                signed.write_bytes(dsse_pae(statement))
                sigfile = base / "dsse.sig"
                sigfile.write_bytes(signature)
                _openssl(["dgst", "-sha256", "-verify", str(public), "-signature",
                          str(sigfile), str(signed)])
                claim = _safe_json(statement, 256_000)
                if type(claim) is not dict or claim.get("_type") != "https://in-toto.io/Statement/v1":
                    raise ValueError("not_intoto_v1_statement")
                subject = claim.get("subject")
                if type(subject) is not list or len(subject) != 1:
                    raise ValueError("intoto_subject_not_unique")
                if type(subject[0]) is not dict or subject[0].get("name") != filename:
                    raise ValueError("intoto_artifact_filename_mismatch")
                digest = subject[0].get("digest")
                if type(digest) is not dict or digest.get("sha256") != _sha_bytes(artifact):
                    raise ValueError("intoto_artifact_sha_mismatch")
                if claim.get("predicateType") not in _SUBJECT_PREDICATES:
                    raise ValueError("unsupported_intoto_predicate")
                if not allow_unverified_log:
                    return {"status": "NOT_QUALIFIED_NO_AUTHENTICATED_LOG",
                            "p256_dsse_signature_valid": True,
                            "certificate_chain_valid_against_operator_pin": True,
                            "trusted_identity_exact_match": True,
                            "artifact_sha256_matches_statement": True,
                            "rekor_transparency_entry_authenticated": False,
                            "official_sigstore_trust_root_attested": False,
                            "production_install_authorized": False}
                return {"status": "LOCAL_PINNED_PEP740_CRYPTO_PASS_LOG_UNATTESTED",
                        "p256_dsse_signature_valid": True,
                        "certificate_chain_valid_against_operator_pin": True,
                        "trusted_identity_exact_match": True,
                        "artifact_sha256_matches_statement": True,
                        "rekor_transparency_entry_authenticated": False,
                        "official_sigstore_trust_root_attested": False,
                        "production_install_authorized": False,
                        "network_used": False, "user_source_executed": False}
    raise ValueError("no_attestation_matched")


def pep_api_snapshot(raw, source_sha256, source_url=PEP_URL):
    """Validate/index the complete official API data structure, not a subset."""
    if source_url != PEP_URL or type(source_sha256) is not str or not SHA.fullmatch(source_sha256):
        raise ValueError("untrusted_pep_source_or_digest")
    if _sha_bytes(raw if type(raw) is bytes else raw.encode("utf-8")) != source_sha256:
        raise ValueError("pep_api_sha_mismatch")
    source = _safe_json(raw, MAX_PEP_BYTES)
    if type(source) is not dict or not 1 <= len(source) <= 5000:
        raise ValueError("invalid_pep_count")
    records = []
    for key, item in source.items():
        if not (type(key) is str and key.isdecimal() and type(item) is dict and
                type(item.get("number")) is int and item["number"] == int(key) and
                item.get("status") in PEP_STATUS and item.get("type") in PEP_TYPES and
                isinstance(item.get("title"), str) and len(item["title"]) <= 512 and
                item.get("url") == "https://peps.python.org/pep-{:04d}/".format(int(key))):
            raise ValueError("invalid_official_pep_record")
        superseded = item.get("superseded_by")
        replaced = item.get("replaces")
        def numbers(raw_numbers):
            if raw_numbers is None:
                return []
            if type(raw_numbers) is not str or len(raw_numbers) > 1000:
                raise ValueError("invalid_pep_references")
            values = raw_numbers.split(",")
            if len(values) > 100 or any(not x.strip().isdigit() for x in values):
                raise ValueError("invalid_pep_references")
            return sorted({int(v.strip()) for v in values})
        records.append({"number": int(key), "title": item["title"],
                        "status": item["status"], "type": item["type"],
                        "topic": item.get("topic", ""),
                        "python_version": item.get("python_version"),
                        "superseded_by": numbers(superseded),
                        "replaces": numbers(replaced), "url": item["url"]})
    known = {item["number"] for item in records}
    for item in records:
        for target in item["superseded_by"] + item["replaces"]:
            if target not in known or target == item["number"]:
                raise ValueError("dangling_or_self_pep_reference")
    return {"status": "COMPLETE_CONSISTENT_PEP_API_SNAPSHOT",
            "records": sorted(records, key=lambda item: item["number"]),
            "source_uri": PEP_URL, "source_sha256": source_sha256,
            "official_publisher_authenticated_by_live_https": False,
            "supersedes_graph_validated": True,
            "python_source_executed": False}


def pep_snapshot_change(previous, current):
    """Version/status/replacement changes with source SHA binding."""
    old = {item["number"]: item for item in previous["records"]}
    new = {item["number"]: item for item in current["records"]}
    changes = []
    for number in sorted(set(old) | set(new)):
        before, after = old.get(number), new.get(number)
        if before != after:
            changes.append({"pep": number, "change":
                            "ADDED" if before is None else
                            "DELETED" if after is None else "UPDATED",
                            "old_status": before["status"] if before else None,
                            "new_status": after["status"] if after else None})
    return {"status": "PEP_CHANGESET_UNAUTHENTICATED_SOURCE",
            "old_sha256": previous["source_sha256"],
            "new_sha256": current["source_sha256"],
            "changes": changes, "download_authenticated": False}


def persist_pep_snapshot(database, parsed):
    """New SQLite PEP FTS index; never overwrite or silently downgrade DB."""
    path = Path(database)
    if path.exists() or path.is_symlink():
        raise ValueError("destination_already_exists")
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise ValueError("invalid_index_directory")
    with closing(sqlite3.connect(str(path))) as connection:
        with connection:
            connection.execute("PRAGMA user_version=1")
            connection.execute("CREATE TABLE peps(number INTEGER PRIMARY KEY, title TEXT NOT NULL, "
                               "status TEXT NOT NULL, type TEXT NOT NULL, topic TEXT, "
                               "python_version TEXT, superseded_by TEXT, replaces TEXT)")
            connection.execute("CREATE VIRTUAL TABLE pep_fts USING fts5(title, content='peps', content_rowid='number')")
            connection.execute("CREATE TABLE provenance(source_uri TEXT NOT NULL, sha256 TEXT NOT NULL)")
            for item in parsed["records"]:
                connection.execute("INSERT INTO peps VALUES (?,?,?,?,?,?,?,?)",
                                   (item["number"], item["title"], item["status"],
                                    item["type"], str(item["topic"]), str(item["python_version"]),
                                    json.dumps(item["superseded_by"]), json.dumps(item["replaces"])))
                connection.execute("INSERT INTO pep_fts(rowid,title) VALUES (?,?)",
                                   (item["number"], item["title"]))
            connection.execute("INSERT INTO provenance VALUES (?,?)",
                               (parsed["source_uri"], parsed["source_sha256"]))
            row = connection.execute("SELECT count(*) FROM peps").fetchone()[0]
    return {"status": "PEP_SQLITE_FTS_PERSISTED_LOCAL_ONLY", "count": row,
            "source_sha256": parsed["source_sha256"],
            "publisher_identity_authenticated": False}


def _etag_safe(etag):
    return type(etag) is str and 2 <= len(etag) <= 160 and bool(re.fullmatch(
        r'(?:W/)?"[\x21\x23-\x7e]{0,150}"', etag))


def fetch_official_peps(timeout=6, etag=None, include_raw=False):
    """Opt-in current PEP API fetch with default system TLS and no redirects.

    Network-dependent; tests must mock this exactly and mark live source
    authentication NOT_RUN when no actual HTTPS call was performed.
    """
    if type(timeout) not in (int, float) or not 1 <= timeout <= 12:
        raise ValueError("invalid_network_timeout")
    if etag is not None and not _etag_safe(etag):
        raise ValueError("untrusted_if_none_match_etag")
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ValueError("redirect_disallowed")
    opener = urllib.request.build_opener(NoRedirect())
    headers = {"Accept": "application/json",
               "User-Agent": "Rust-Python-Healer/0.23-PEP-reader"}
    if etag is not None:
        headers["If-None-Match"] = etag
    req = urllib.request.Request(PEP_URL, headers=headers)
    try:
        with opener.open(req, timeout=timeout) as response:
            if response.geturl() != PEP_URL or response.status != 200:
                raise ValueError("unexpected_pep_http_reply")
            response_etag = response.headers.get("ETag")
            payload = response.read(MAX_PEP_BYTES + 1)
            if len(payload) > MAX_PEP_BYTES:
                raise ValueError("pep_api_content_too_large")
    except urllib.error.HTTPError as exc:
        if exc.code == 304 and etag is not None and exc.url == PEP_URL:
            return {"status": "OFFICIAL_PEP_NOT_MODIFIED_TLS",
                    "etag": etag, "current_payload_unchanged": True,
                    "actual_network_call_performed": True}
        raise RuntimeError("unexpected_pep_feed_http_status") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError("offline_or_untrusted_pep_feed") from exc
    digest = _sha_bytes(payload)
    report = pep_api_snapshot(payload, digest)
    report["official_publisher_authenticated_by_live_https"] = True
    report["actual_network_call_performed"] = True
    report["etag"] = response_etag if _etag_safe(response_etag) else None
    if include_raw:
        report["raw_bytes"] = payload
    return report


def sync_pep_index(cache_dir, fetcher=None):
    """Atomic manifest-pointer update of content-addressed official PEP docs.

    A caller-supplied fetcher is for offline tests only, and can never mark
    the source as externally authenticated. On 304 the previous on-disk
    content's SHA256 is recalculated before accepting the result.
    """
    base = Path(cache_dir)
    if not base.is_dir() or base.is_symlink():
        raise ValueError("private_pep_cache_required")
    if os.name == "nt":
        privacy = globals().get("_RPH_WINDOWS_PRIVACY")
        if privacy is None:
            spec = importlib.util.spec_from_file_location("rph_pep_privacy", Path(__file__).with_name("windows_private_paths.py"))
            privacy = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(privacy)
        try:
            privacy.assert_private_directory(base.absolute())
        except (OSError, ValueError):
            raise ValueError("private_pep_cache_required") from None
    elif base.stat().st_mode & 0o077:
        raise ValueError("private_pep_cache_required")
    current = base / "current.json"
    previous = None
    if current.exists() or current.is_symlink():
        previous = _safe_json(_read_regular(current, 20_000), 20_000)
        if (type(previous) is not dict or not SHA.fullmatch(previous.get("sha256", "")) or
                not re.fullmatch(r"peps-[a-f0-9]{64}\.json", previous.get("source_file", "")) or
                not re.fullmatch(r"peps-[a-f0-9]{64}\.sqlite", previous.get("index_file", ""))):
            raise ValueError("corrupted_pep_cache_manifest")
        prior_bytes = _read_regular(base / previous["source_file"], MAX_PEP_BYTES)
        if _sha_bytes(prior_bytes) != previous["sha256"]:
            raise ValueError("stale_or_tampered_pep_cache")
        pep_api_snapshot(prior_bytes, previous["sha256"])
    conditional_etag = previous.get("etag") if previous and _etag_safe(previous.get("etag")) else None
    if fetcher is None:
        response = fetch_official_peps(timeout=12, etag=conditional_etag, include_raw=True)
        live_https = True
    else:
        response = fetcher(conditional_etag)
        live_https = False
    if type(response) is not dict:
        raise ValueError("invalid_pep_fetch_result")
    if response.get("status") == "OFFICIAL_PEP_NOT_MODIFIED_TLS":
        if previous is None or response.get("etag") != conditional_etag:
            raise ValueError("unverifiable_http_304")
        return {"status": "PEP_CACHE_SHA_VERIFIED_UNCHANGED",
                "sha256": previous["sha256"],
                "pep_count": previous["count"],
                "live_https_authenticated": live_https,
                "304_not_used_as_hash_replacement": True,
                "local_storage_cryptographically_signed": False}
    raw = response.get("raw_bytes")
    if type(raw) is not bytes:
        raise ValueError("pep_fetch_payload_missing")
    digest = _sha_bytes(raw)
    parsed = pep_api_snapshot(raw, digest)
    source_file = "peps-" + digest + ".json"
    index_file = "peps-" + digest + ".sqlite"
    if not (base / source_file).exists():
        with (base / source_file).open("xb") as out:
            out.write(raw)
    elif _read_regular(base / source_file, MAX_PEP_BYTES) != raw:
        raise ValueError("existing_content_address_broken")
    if not (base / index_file).exists():
        persist_pep_snapshot(base / index_file, parsed)
    else:
        with closing(sqlite3.connect(str(base / index_file))) as conn:
            if conn.execute("SELECT count(*) FROM peps").fetchone()[0] != len(parsed["records"]):
                raise ValueError("existing_index_count_mismatch")
    if previous and previous["sha256"] == digest:
        return {"status": "PEP_CACHE_CONTENT_IDENTICAL",
                "sha256": digest, "pep_count": len(parsed["records"]),
                "live_https_authenticated": live_https}
    if previous:
        old = pep_api_snapshot(_read_regular(base / previous["source_file"], MAX_PEP_BYTES),
                               previous["sha256"])
        changes = pep_snapshot_change(old, parsed)["changes"]
    else:
        changes = []
    etag = response.get("etag")
    meta = {"schema": 1, "sha256": digest, "source_file": source_file,
            "index_file": index_file, "count": len(parsed["records"]),
            "etag": etag if _etag_safe(etag) else None,
            "source_uri": PEP_URL,
            "live_https_authenticated": live_https}
    staged = base / (".current-" + digest + ".json")
    with staged.open("xb") as writer:
        writer.write((json.dumps(meta, sort_keys=True) + "\n").encode("utf-8"))
        writer.flush()
        os.fsync(writer.fileno())
    os.replace(str(staged), str(current))
    return {"status": "PEP_OFFICIAL_SOURCE_SYNCHRONIZED" if live_https
            else "PEP_MOCKED_SOURCE_SYNCHRONIZED_NOT_OFFICIAL",
            "sha256": digest, "pep_count": len(parsed["records"]),
            "changes": changes, "live_https_authenticated": live_https,
            "snapshots_retained": True,
            "local_storage_cryptographically_signed": False}


def watch_pep_index(cache_dir, cycles=2, interval_ms=20, fetcher=None):
    """Bounded explicit watch; no background daemon or unattended mutation."""
    if type(cycles) is not int or not 1 <= cycles <= 4 or type(interval_ms) is not int or not 0 <= interval_ms <= 1000:
        raise ValueError("unsafe_pep_watch_schedule")
    rows = []
    for index in range(cycles):
        rows.append(sync_pep_index(cache_dir, fetcher=fetcher))
        if index + 1 < cycles:
            time.sleep(interval_ms / 1000)
    return {"status": "BOUNDED_PEP_WATCH_COMPLETED",
            "cycles": rows,
            "all_live_https_authenticated": all(row["live_https_authenticated"] for row in rows),
            "automatic_future_interpreter_support_proven": False}


def audit_supply_chain(cargo_lock_path, python_wheel_path, rust_binary_path,
                       pinned_hashes, local_advisory_json):
    """Real Cargo.lock/wheel RECORD/binary SHA and pinned advisory comparison.

    This is a *local* pinned inventory, not an OSV/PyPI/CVE publisher audit.
    It deliberately refuses releases when evidence does not match pins.
    """
    expected = ("cargo_lock_sha256", "python_wheel_sha256", "rust_binary_sha256",
                "advisory_feed_sha256")
    if (type(pinned_hashes) is not dict or set(pinned_hashes) != set(expected) or
            any(type(pinned_hashes[key]) is not str or not SHA.fullmatch(pinned_hashes[key])
                for key in expected)):
        raise ValueError("full_operator_pins_required")
    lock = _read_regular(cargo_lock_path, 1_000_000)
    wheel = _read_regular(python_wheel_path, MAX_ARTIFACT_BYTES)
    binary = _read_regular(rust_binary_path, MAX_ARTIFACT_BYTES)
    if (type(local_advisory_json) not in (bytes, str) or
            _sha_bytes(local_advisory_json if type(local_advisory_json) is bytes
                       else local_advisory_json.encode("utf-8")) != pinned_hashes["advisory_feed_sha256"]):
        raise ValueError("advisory_source_pin_mismatch")
    if (_sha_bytes(lock) != pinned_hashes["cargo_lock_sha256"] or
            _sha_bytes(wheel) != pinned_hashes["python_wheel_sha256"] or
            _sha_bytes(binary) != pinned_hashes["rust_binary_sha256"]):
        raise ValueError("release_material_hash_mismatch")
    if not (binary.startswith(b"\x7fELF") or binary[:2] == b"MZ" or
            binary[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")):
        raise ValueError("not_executable_format")
    parsed = _toml(lock)
    packages = parsed.get("package")
    if type(packages) is not list or not 1 <= len(packages) <= 5000:
        raise ValueError("invalid_cargo_lock_packages")
    cargo = {}
    for record in packages:
        if type(record) is not dict or not isinstance(record.get("name"), str) or not isinstance(record.get("version"), str):
            raise ValueError("invalid_cargo_package")
        key = (record["name"], record["version"])
        if key in cargo:
            raise ValueError("duplicate_cargo_identity")
        source, checksum = record.get("source"), record.get("checksum")
        if source is not None and (type(source) is not str or not source.startswith("registry+")):
            raise ValueError("unknown_cargo_source_kind")
        if source is not None and (type(checksum) is not str or not SHA.fullmatch(checksum)):
            raise ValueError("cargo_registry_checksum_missing")
        cargo[key] = {"name": key[0], "version": key[1],
                      "declared_registry_checksum_present": bool(checksum)}
    try:
        with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
            infos = archive.infolist()
            if not 1 <= len(infos) <= 400 or sum(i.file_size for i in infos) > 60_000_000:
                raise ValueError("wheel_member_budget")
            names = [info.filename for info in infos]
            if (len(set(names)) != len(names) or any(
                    name.startswith("/") or "\\" in name or
                    any(part in ("", ".", "..") for part in name.split("/"))
                    for name in names)):
                raise ValueError("unsafe_wheel_member")
            metadata_files = [name for name in names if name.endswith(".dist-info/METADATA")]
            record_files = [name for name in names if name.endswith(".dist-info/RECORD")]
            if len(metadata_files) != 1 or len(record_files) != 1:
                raise ValueError("wheel_metadata_record_required")
            msg = BytesParser().parsebytes(archive.read(metadata_files[0]), headersonly=True)
            python_name, python_version = msg.get("Name"), msg.get("Version")
            if not isinstance(python_name, str) or not isinstance(python_version, str):
                raise ValueError("wheel_identity_missing")
            rows = list(csv.reader(io.StringIO(archive.read(record_files[0]).decode("utf-8"))))
            if len(rows) != len(infos) or len({row[0] for row in rows}) != len(rows):
                raise ValueError("wheel_record_incomplete")
            for row in rows:
                if len(row) != 3 or row[0] not in names:
                    raise ValueError("wheel_record_invalid_row")
                if row[0] == record_files[0] and row[1:] == ["", ""]:
                    continue
                if not row[1].startswith("sha256=") or not row[2].isdigit():
                    raise ValueError("wheel_record_hash_required")
                content = archive.read(row[0])
                actual = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode("ascii")
                if row[1][7:] != actual or int(row[2]) != len(content):
                    raise ValueError("wheel_record_content_mismatch")
    except (zipfile.BadZipFile, UnicodeError, KeyError, IndexError) as exc:
        raise ValueError("invalid_wheel_container") from exc
    snapshot = _safe_json(local_advisory_json, 2_000_000)
    if type(snapshot) is not dict or type(snapshot.get("advisories")) is not list or len(snapshot["advisories"]) > MAX_ADVISORIES:
        raise ValueError("invalid_advisory_snapshot")
    matched = []
    for item in snapshot["advisories"]:
        if (type(item) is not dict or item.get("ecosystem") not in ("cargo", "pypi") or
                not isinstance(item.get("id"), str) or
                not isinstance(item.get("name"), str) or
                not isinstance(item.get("version"), str) or
                not re.fullmatch(r"CVE-\d{4}-\d{4,}", item["id"])):
            raise ValueError("invalid_advisory_entry")
        affected = ((item["name"], item["version"]) in cargo if item["ecosystem"] == "cargo"
                    else item["name"].lower().replace("_", "-") == python_name.lower().replace("_", "-") and
                    item["version"] == python_version)
        if affected:
            matched.append({"id": item["id"], "ecosystem": item["ecosystem"]})
    return {"status": "LOCAL_SUPPLY_CHAIN_AUDIT_MATCHED_UNOFFICIAL_FEED",
            "cargo_packages_inventoried": len(cargo),
            "wheel_record_entries_verified": len(rows),
            "python_package": python_name, "python_version": python_version,
            "rust_binary_format_checked": True,
            "rust_binary_hash_matches_operator_pin": True,
            "local_advisories_matching": matched,
            "operator_pin_verified": True,
            "external_advisory_publisher_authenticated": False,
            "rust_crate_tarball_bytes_authenticated": False,
            "official_pypi_attestation_authenticated": False,
            "unknown_package_code_executed": False,
            "network_used": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "pep-index"),
                        default="capabilities")
    parser.add_argument("--source")
    parser.add_argument("--sha256")
    args = parser.parse_args(argv)
    try:
        if args.mode == "capabilities":
            report = {"status": "READ_ONLY_PROVENANCE_CAPABILITIES",
                      "capabilities": ["pep740_p256_dsse", "pep_api_index",
                                       "pep_status_diff", "operator_pinned_root"],
                      "network_used": False, "publisher_authenticated": False}
        else:
            payload = _read_regular(args.source, MAX_PEP_BYTES)
            data = pep_api_snapshot(payload, args.sha256)
            report = {"status": data["status"], "count": len(data["records"]),
                      "source_sha256": data["source_sha256"],
                      "publisher_authenticated": False, "network_used": False}
    except (OSError, ValueError, RuntimeError, TypeError, UnicodeError):
        report = {"status": "REFUSED", "network_used": False,
                  "publisher_authenticated": False}
    print(json.dumps(report, sort_keys=True))
    return 2 if report["status"] == "REFUSED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
