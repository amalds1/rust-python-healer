"""Operator-attested source policy, exact versions and citation quotas."""

from importlib.util import module_from_spec, spec_from_file_location
import copy
import json
import os
import sqlite3
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if os.name == "nt":
    from windows_privacy_fixtures import set_private_acl, set_public_read_acl


def trust_permissions(path, private=True):
    if os.name == "nt":
        (set_private_acl if private else set_public_read_acl)(path)
    else:
        path.chmod(0o600 if private else 0o644)


spec = spec_from_file_location("source_policy", ROOT / "python" / "source_policy.py")
module = module_from_spec(spec)
spec.loader.exec_module(module)


def fixture():
    policy = {"schema_version": 1, "policy_id": "P-source-license-1", "sources": {
        "python-docs": {"hostname": "docs.python.org", "licenses": ["PSF-2.0"],
                        "may_ingest": True, "max_citation_words": 12,
                        "max_citation_bytes": 100}}}
    trust = {"schema_version": 1, "authorities": {
        "python-docs": {"key_hex": "ef" * 32}}}
    section = {
        "section_id": "collections-v39-001", "source_id": "python-docs",
        "uri": "https://docs.python.org/3.9/library/collections.html",
        "license": "PSF-2.0", "python_version": "3.9.25",
        "package": "stdlib", "package_version": "3.9.25",
        "platform": "linux-x86_64-glibc",
        "content": "collections deque rotate efficiently with a bounded indexed buffer, preserving order",
        "ingest_authorized": True,
        "signature": "0" * 64,
    }
    section["signature"] = module.sign_for_test(
        policy, section, trust["authorities"]["python-docs"]["key_hex"])
    return policy, trust, {"schema_version": 1, "sections": [section]}


def signed(policy, trust, section):
    section["signature"] = module.sign_for_test(
        policy, section, trust["authorities"][section["source_id"]]["key_hex"])
    return section


class SourcePolicyTests(unittest.TestCase):
    def test_readonly_database_never_creates_missing_or_allows_write(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "source space.sqlite"
            with self.assertRaises(ValueError):
                module._readonly_database(path)
            self.assertFalse(path.exists())
            connection = sqlite3.connect(path)
            connection.execute("PRAGMA user_version=7")
            connection.close()
            before = path.read_bytes()
            names = sorted(p.name for p in path.parent.iterdir())
            connection = module._readonly_database(path)
            try:
                self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (7,))
                with self.assertRaises(sqlite3.OperationalError):
                    connection.execute("CREATE TABLE forbidden(value)")
            finally:
                connection.close()
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(sorted(p.name for p in path.parent.iterdir()), names)

    def test_readonly_database_requires_checkpoint_and_rejects_journal_alias(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "source.sqlite"
            sqlite3.connect(path).close()
            for suffix in ("-wal", "-shm", "-journal"):
                sidecar = Path(str(path) + suffix)
                sidecar.write_bytes(b"pending state")
                with self.assertRaisesRegex(ValueError, "requires_checkpoint"):
                    module._readonly_database(path)
                sidecar.unlink()
            Path(str(path) + "-journal").symlink_to(Path(folder) / "missing")
            with self.assertRaisesRegex(ValueError, "requires_checkpoint"):
                module._readonly_database(path)

    def test_private_reader_rechecks_hardlink_and_acl_changes_on_open_handle(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "private.json"
            alias = Path(folder) / "alias.json"
            path.write_bytes(b"{}")
            original_fdopen = module.os.fdopen
            for mutation in ("hardlink", "public_acl"):
                with self.subTest(mutation=mutation):
                    trust_permissions(path)
                    class Stream:
                        def __init__(inner, descriptor, mode):
                            inner.actual = original_fdopen(descriptor, mode)
                        def __enter__(inner): return inner
                        def __exit__(inner, *args): inner.actual.close()
                        def fileno(inner): return inner.actual.fileno()
                        def read(inner, maximum):
                            if mutation == "hardlink": os.link(path, alias)
                            else: trust_permissions(path, private=False)
                            return inner.actual.read(maximum)
                    try:
                        with mock.patch.object(module.os, "fdopen", side_effect=Stream):
                            with self.assertRaises(ValueError):
                                module.bounded_json(path, private=True)
                    finally:
                        if alias.exists(): alias.unlink()
                        trust_permissions(path)

    def test_private_reader_closes_actual_descriptor_if_fdopen_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "private.json"
            path.write_bytes(b"{}")
            trust_permissions(path)
            descriptors = []
            def refuse(descriptor, mode):
                descriptors.append(descriptor)
                raise OSError("fixed fdopen failure")
            with mock.patch.object(module.os, "fdopen", side_effect=refuse):
                with self.assertRaisesRegex(OSError, "fixed fdopen failure"):
                    module.bounded_json(path, private=True)
            self.assertEqual(len(descriptors), 1)
            with self.assertRaises(OSError):
                os.fstat(descriptors[0])
            path.unlink()

    def test_signed_ingestion_preserves_exact_version_and_no_source_leak(self):
        policy, trust, manifest = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "sections.sqlite"
            report = module.ingest(database, policy, trust, manifest)
            self.assertEqual(report["status"], "OPERATOR_ATTESTED_NOT_PUBLISHER_VERIFIED")
            self.assertEqual(report["sections_inserted"], 1)
            self.assertFalse(report["content_disclosed"])
            self.assertFalse(report["source_executed"])
            self.assertFalse(report["network_used"])
            self.assertFalse(report["publisher_verified"])
            self.assertNotIn("deque rotate", json.dumps(report))
            found = module.lookup(database, "3.9.25", "stdlib", "3.9.25",
                                  "linux-x86_64-glibc")
        self.assertEqual(len(found["sections"]), 1)
        self.assertEqual(found["sections"][0]["license"], "PSF-2.0")
        self.assertEqual(found["sections"][0]["section_id"], "collections-v39-001")
        self.assertFalse(found["content_disclosed"])
        self.assertNotIn("deque rotate", json.dumps(found))

    def test_version_lookup_is_exact_and_refuses_unbounded_filters(self):
        policy, trust, manifest = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "sections.sqlite"
            module.ingest(database, policy, trust, manifest)
            for args in (("3.9.24", "stdlib", "3.9.25", "linux-x86_64-glibc"),
                         ("3.9.25", "stdlib", "3.10.0", "linux-x86_64-glibc"),
                         ("3.9.25", "stdlib", "3.9.25", "win_amd64-msvc")):
                self.assertEqual(module.lookup(database, *args)["sections"], [])
            for python in ("3.9", "3.9.*", "3.9.25; import os"):
                with self.assertRaisesRegex(ValueError, "version_filter_must_be_exact"):
                    module.lookup(database, python, "stdlib", "3.9.25", "linux-x86_64-glibc")

    def test_per_section_citation_word_and_byte_limits(self):
        policy, trust, manifest = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "sections.sqlite"
            module.ingest(database, policy, trust, manifest)
            sample = module.cite(database, "collections-v39-001", 25, 1024)
            self.assertLessEqual(sample["excerpt_words"], 12)
            self.assertLessEqual(sample["excerpt_bytes"], 100)
            self.assertEqual(sample["excerpt"], manifest["sections"][0]["content"])
            few = module.cite(database, "collections-v39-001", 2, 20)
            self.assertEqual(few["excerpt"], "collections deque")
            for word_limit, byte_limit in ((26, 20), (1, 1025), (-1, 2)):
                with self.assertRaisesRegex(ValueError, "invalid_quote_budget"):
                    module.cite(database, "collections-v39-001", word_limit, byte_limit)

    def test_permission_denial_and_unlisted_license_rejected_before_writes(self):
        policy, trust, manifest = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "sections.sqlite"
            policy["sources"]["python-docs"]["may_ingest"] = False
            with self.assertRaisesRegex(ValueError, "document_ingestion_or_license_denied"):
                module.ingest(database, policy, trust, manifest)
            self.assertFalse(database.exists())
            policy["sources"]["python-docs"]["may_ingest"] = True
            manifest["sections"][0]["license"] = "Proprietary"
            signed(policy, trust, manifest["sections"][0])
            with self.assertRaisesRegex(ValueError, "document_ingestion_or_license_denied"):
                module.ingest(database, policy, trust, manifest)
            self.assertFalse(database.exists())

    def test_section_level_authorization_must_be_explicit(self):
        policy, trust, manifest = fixture()
        section = manifest["sections"][0]
        section["ingest_authorized"] = False
        signed(policy, trust, section)
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "document_ingestion_or_license_denied"):
                module.ingest(Path(temporary) / "db.sqlite", policy, trust, manifest)

    def test_hmac_tamper_and_policy_replay_are_refused_without_false_pass(self):
        policy, trust, manifest = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "db.sqlite"
            manifest["sections"][0]["content"] = "poisoned document injection"
            with self.assertRaisesRegex(ValueError, "operator_attestation_invalid"):
                module.ingest(database, policy, trust, manifest)
            self.assertFalse(database.exists())
            manifest["sections"][0]["content"] = fixture()[2]["sections"][0]["content"]
            policy["sources"]["python-docs"]["max_citation_words"] = 8
            with self.assertRaisesRegex(ValueError, "operator_attestation_invalid"):
                module.ingest(database, policy, trust, manifest)
            self.assertFalse(database.exists())

    def test_host_allowlist_disallows_credentials_query_and_unlisted_hosts(self):
        policy, trust, manifest = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "db.sqlite"
            for uri in ("http://docs.python.org/3.9/", "https://alice:pass@docs.python.org/a",
                        "https://docs.python.org/a?token=secret", "https://evil.example.org/a",
                        "https://docs.python.org/a#fragment"):
                sample = copy.deepcopy(manifest)
                sample["sections"][0]["uri"] = uri
                signed(policy, trust, sample["sections"][0])
                with self.assertRaises(ValueError):
                    module.ingest(database, policy, trust, sample)
                self.assertFalse(database.exists())

    def test_duplicate_ids_are_rejected_even_when_signed(self):
        policy, trust, manifest = fixture()
        section = copy.deepcopy(manifest["sections"][0])
        manifest["sections"].append(section)
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "duplicate_document_section"):
                module.ingest(Path(temporary) / "db.sqlite", policy, trust, manifest)

    def test_different_version_requires_new_signed_section_identity(self):
        policy, trust, manifest = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "db.sqlite"
            module.ingest(database, policy, trust, manifest)
            changed = copy.deepcopy(manifest)
            changed["sections"][0]["python_version"] = "3.10.22"
            changed["sections"][0]["package_version"] = "3.10.22"
            signed(policy, trust, changed["sections"][0])
            with self.assertRaisesRegex(ValueError, "section_identity_changed_without_new_id"):
                module.ingest(database, policy, trust, changed)
            self.assertEqual(len(module.lookup(database, "3.9.25", "stdlib", "3.9.25",
                                               "linux-x86_64-glibc")["sections"]), 1)

    def test_idempotent_ingestion_stores_exactly_once(self):
        policy, trust, manifest = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "db.sqlite"
            self.assertEqual(module.ingest(database, policy, trust, manifest)["sections_inserted"], 1)
            repeat = module.ingest(database, policy, trust, manifest)
            self.assertEqual(repeat["sections_inserted"], 0)
            self.assertEqual(repeat["sections_recorded"], 1)

    def test_atomic_rollback_on_database_uniqueness_conflict(self):
        policy, trust, manifest = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "db.sqlite"
            module.ingest(database, policy, trust, manifest)
            extra = copy.deepcopy(manifest["sections"][0])
            extra["section_id"] = "alias-identical-content"
            signed(policy, trust, extra)
            with self.assertRaises(Exception):
                module.ingest(database, policy, trust,
                              {"schema_version": 1, "sections": [extra]})
            self.assertEqual(len(module.lookup(database, "3.9.25", "stdlib", "3.9.25",
                                               "linux-x86_64-glibc")["sections"]), 1)

    def test_trust_file_must_be_private_and_regular(self):
        with tempfile.TemporaryDirectory() as temporary:
            trust = Path(temporary) / "operator-keys.json"
            trust.write_text(json.dumps(fixture()[1]))
            trust_permissions(trust, False)
            with self.assertRaisesRegex(ValueError, "trust_file_must_be_owner_only"):
                module.bounded_json(trust, private=True)
            trust_permissions(trust)
            self.assertEqual(module.bounded_json(trust, private=True)["schema_version"], 1)
            link = Path(temporary) / "keys-link.json"
            link.symlink_to(trust)
            with self.assertRaisesRegex(ValueError, "policy_input_symlink_refused"):
                module.bounded_json(link, private=True)
            hard = Path(temporary) / "keys-hard.json"
            os.link(str(trust), str(hard))
            with self.assertRaisesRegex(ValueError, "policy_input_not_unique_bounded_file"):
                module.bounded_json(trust, private=True)

    def test_duplicate_json_keys_and_oversized_inputs_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bad.json"
            path.write_text('{"schema_version":1,"sources":{},"sources":{}}')
            with self.assertRaisesRegex(ValueError, "invalid_policy_json"):
                module.bounded_json(path)
            path.write_bytes(b"x" * (module.MAX_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "policy_input_not_unique_bounded_file"):
                module.bounded_json(path)

    def test_non_standard_versions_and_wildcard_platforms_rejected(self):
        policy, trust, manifest = fixture()
        for key, value in (("python_version", "3.9"), ("python_version", "3.9.*"),
                           ("package_version", ">=3.9"), ("platform", "*"),
                           ("section_id", "../../passwd")):
            probe = copy.deepcopy(manifest)
            probe["sections"][0][key] = value
            signed(policy, trust, probe["sections"][0])
            with tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(ValueError):
                    module.ingest(Path(temporary) / "db.sqlite", policy, trust, probe)

    def test_cli_ingest_lookup_and_explicit_citation(self):
        policy, trust, manifest = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = [root / name for name in ("policy.json", "trust.json", "manifest.json")]
            for path, obj in zip(paths, (policy, trust, manifest)):
                path.write_text(json.dumps(obj))
            trust_permissions(paths[1])
            database = root / "db.sqlite"
            command = [sys.executable, "-I", "-S", "-B",
                       str(ROOT / "python/source_policy.py")]
            ingest = subprocess.run(command + ["ingest", "--database", str(database),
                                          "--policy", str(paths[0]), "--trust", str(paths[1]),
                                          "--manifest", str(paths[2])],
                                    capture_output=True, text=True)
            self.assertEqual(ingest.returncode, 0, ingest.stderr)
            self.assertEqual(json.loads(ingest.stdout)["sections_inserted"], 1)
            self.assertNotIn("deque rotate", ingest.stdout)
            lookup = subprocess.run(command + ["lookup", "--database", str(database),
                                          "--python-version", "3.9.25", "--package", "stdlib",
                                          "--package-version", "3.9.25", "--platform",
                                          "linux-x86_64-glibc"], capture_output=True, text=True)
            self.assertEqual(lookup.returncode, 0, lookup.stderr)
            self.assertEqual(len(json.loads(lookup.stdout)["sections"]), 1)
            citation = subprocess.run(command + ["cite", "--database", str(database),
                                            "--section-id", "collections-v39-001", "--max-words",
                                            "2", "--max-bytes", "30"],
                                      capture_output=True, text=True)
            self.assertEqual(citation.returncode, 0, citation.stderr)
            self.assertEqual(json.loads(citation.stdout)["excerpt"], "collections deque")

    def test_default_ingest_never_executes_pth_or_injected_document_text(self):
        policy, trust, manifest = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "would_execute.txt"
            manifest["sections"][0]["content"] = "INSTRUCTIONS: execute Python now. open({!r},'w')".format(str(marker))
            signed(policy, trust, manifest["sections"][0])
            (root / "danger.pth").write_text("import os;open({!r},'w').close()".format(str(marker)))
            result = module.ingest(root / "db.sqlite", policy, trust, manifest)
            self.assertEqual(result["sections_inserted"], 1)
            self.assertFalse(marker.exists())
            self.assertFalse(result["source_executed"])
            self.assertNotIn("INSTRUCTIONS:", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
