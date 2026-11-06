"""Actual Git bare/origin/clones + independently signed local merge approval."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "python" / "git_review_v23.py"
SPEC = importlib.util.spec_from_file_location("git_review_v23", SCRIPT)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class GitReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys_dir = tempfile.TemporaryDirectory(prefix="rph-v23-reviewer-keys-")
        folder = Path(cls.keys_dir.name)
        cls.private = folder / "reviewer.key"
        cls.public = folder / "reviewer.pub"
        cls.other_private = folder / "other.key"
        cls.other_public = folder / "other.pub"
        for priv, pub in ((cls.private, cls.public),
                          (cls.other_private, cls.other_public)):
            subprocess.run([mod.openssl_executable(), "genpkey", "-algorithm", "ED25519",
                            "-out", str(priv)], check=True, capture_output=True, timeout=5)
            priv.chmod(0o600)
            if os.name == "nt":
                import windows_privacy_fixtures
                windows_privacy_fixtures.set_private_acl(priv)
            subprocess.run([mod.openssl_executable(), "pkey", "-in", str(priv), "-pubout",
                            "-out", str(pub)], check=True, capture_output=True, timeout=5)
        cls.public_pin = mod.reviewer_public_key_pin(cls.public)

    @classmethod
    def tearDownClass(cls):
        cls.keys_dir.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rph-v23-git-review-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.folder.chmod(0o700)
        if os.name == "nt":
            import windows_privacy_fixtures
            windows_privacy_fixtures.set_private_acl(self.folder)
        self.fixture = mod.LocalGitFixture(self.folder)
        self.initial = self.fixture.initialize()

    def reviewed(self, manifest=None, private=None, approved=True):
        payload = manifest if manifest is not None else self.fixture.proposal()
        signature = mod.sign_review(payload, private or self.private, approved)
        return payload, signature

    def merge(self, manifest, signature, public=None, pin=None, now=None):
        return self.fixture.merge_if_approved(manifest, signature, public or self.public,
                                              pin or self.public_pin, now=now)

    def test_real_bare_repository_and_two_isolated_clones(self):
        self.assertTrue(self.initial["remote_bare_created"])
        self.assertTrue(self.initial["writer_clone_created"])
        self.assertTrue(self.initial["integrator_clone_created"])
        self.assertFalse(self.initial["source_executed"])
        self.assertNotEqual(self.initial["initial_sha"], self.initial["candidate_sha"])
        self.assertEqual((self.fixture.integrator / mod.FILE).read_text(), mod.BASE_FIXTURE)
        self.assertEqual((self.fixture.writer / mod.FILE).read_text(), mod.REPAIRED_FIXTURE)

    def test_real_merge_requires_distinct_ed25519_review_and_proves_parent_shas(self):
        manifest, signature = self.reviewed()
        report = self.merge(manifest, signature)
        self.assertEqual(report["status"], "LOCAL_MERGE_APPROVAL_VERIFIED_NOT_EXTERNAL_PR")
        self.assertTrue(report["independent_reviewer_ed25519_verified"])
        self.assertTrue(report["diff_sha256_verified"])
        self.assertNotEqual(report["real_merge_commit_sha"], manifest["head_sha"])
        self.assertEqual(self.fixture._remote_sha("main"), report["real_merge_commit_sha"])
        self.assertEqual((self.fixture.integrator / mod.FILE).read_text(), mod.REPAIRED_FIXTURE)
        self.assertFalse(report["external_github_pr_approved"])
        self.assertFalse(report["human_reviewer_identity_attested"])

    def test_signer_cannot_approve_without_explicit_reviewer_choice(self):
        manifest = self.fixture.proposal()
        with self.assertRaises(PermissionError):
            self.reviewed(manifest, approved=False)
        self.assertEqual(self.fixture._remote_sha("main"), self.fixture.base)

    def test_missing_signature_cannot_merge(self):
        manifest = self.fixture.proposal()
        with self.assertRaises(ValueError):
            self.merge(manifest, "")
        self.assertEqual(self.fixture._remote_sha("main"), self.fixture.base)

    def test_signature_from_wrong_reviewer_key_is_rejected(self):
        manifest, signature = self.reviewed(private=self.other_private)
        with self.assertRaises(ValueError):
            self.merge(manifest, signature)
        self.assertEqual(self.fixture._remote_sha("main"), self.fixture.base)

    def test_operator_pinned_public_key_mismatch_is_rejected(self):
        manifest, signature = self.reviewed()
        with self.assertRaisesRegex(ValueError, "reviewer_public_key_pin_mismatch"):
            self.merge(manifest, signature, pin="f" * 64)
        self.assertEqual(self.fixture._remote_sha("main"), self.fixture.base)

    def test_actual_separate_wrong_public_key_cannot_approve(self):
        manifest, signature = self.reviewed()
        wrong_pin = mod.reviewer_public_key_pin(self.other_public)
        with self.assertRaises(ValueError):
            self.merge(manifest, signature, public=self.other_public, pin=wrong_pin)

    def test_approval_expires_before_merge(self):
        manifest = self.fixture.proposal(now=1000)
        signature = mod.sign_review(manifest, self.private, True)
        with self.assertRaisesRegex(ValueError, "expired"):
            self.merge(manifest, signature, now=1201)
        self.assertEqual(self.fixture._remote_sha("main"), self.fixture.base)

    def test_future_dated_approval_is_not_yet_valid(self):
        manifest = self.fixture.proposal(now=int(time.time()) + 100)
        signature = mod.sign_review(manifest, self.private, True)
        with self.assertRaisesRegex(ValueError, "not_yet_valid"):
            self.merge(manifest, signature)

    def test_replayed_signed_review_fails_after_first_real_merge(self):
        manifest, signature = self.reviewed()
        self.merge(manifest, signature)
        with self.assertRaisesRegex(ValueError, "replay"):
            self.merge(manifest, signature)

    def test_approval_nonce_survives_new_integrator_instance(self):
        manifest, signature = self.reviewed()
        self.merge(manifest, signature)
        second = mod.LocalGitFixture(self.folder)
        with self.assertRaisesRegex(ValueError, "replay"):
            second.merge_if_approved(manifest, signature, self.public, self.public_pin)
        self.assertTrue((self.folder / "review_approvals.sqlite").is_file())

    def test_approval_ledger_symlink_rejected_fail_closed(self):
        wrong_target = self.folder / "private.txt"
        wrong_target.write_text("do not overwrite\n")
        (self.folder / "review_approvals.sqlite").symlink_to(wrong_target)
        manifest, signature = self.reviewed()
        with self.assertRaisesRegex(ValueError, "unsafe_approval_ledger_path"):
            self.merge(manifest, signature)
        self.assertEqual(wrong_target.read_text(), "do not overwrite\n")

    def test_modified_diff_hash_even_when_resigned_is_refused(self):
        manifest = self.fixture.proposal()
        manifest["diff_sha256"] = "f" * 64
        signature = mod.sign_review(manifest, self.private, True)
        with self.assertRaisesRegex(ValueError, "diff_changed"):
            self.merge(manifest, signature)
        self.assertEqual(self.fixture._remote_sha("main"), self.fixture.base)

    def test_tampered_manifest_cannot_reuse_old_signature(self):
        manifest, signature = self.reviewed()
        manifest["expires_epoch"] += 1
        with self.assertRaises(ValueError):
            self.merge(manifest, signature)
        self.assertEqual(self.fixture._remote_sha("main"), self.fixture.base)

    def test_stale_main_branch_is_rejected_even_with_valid_review_signature(self):
        manifest, signature = self.reviewed()
        mod.git(self.fixture.integrator, "checkout", "main")
        extra = self.fixture.integrator / "src" / "unrelated.py"
        extra.write_text("UNRELATED=1\n", encoding="utf-8")
        mod.git(self.fixture.integrator, "add", "--", "src/unrelated.py")
        mod.git(self.fixture.integrator, "commit", "-m", "trusted unrelated base change")
        mod.git(self.fixture.integrator, "push", "origin", "HEAD:refs/heads/main")
        with self.assertRaisesRegex(ValueError, "stale_base_branch_rejected"):
            self.merge(manifest, signature)

    def test_feature_head_changed_after_approval_is_refused(self):
        manifest, signature = self.reviewed()
        (self.fixture.writer / mod.FILE).write_text("def calculate():\n    return 3\n")
        mod.git(self.fixture.writer, "add", "--", mod.FILE)
        mod.git(self.fixture.writer, "commit", "-m", "unapproved head mutation")
        mod.git(self.fixture.writer, "push", "origin", "HEAD:refs/heads/" + mod.REVIEW_BRANCH)
        with self.assertRaisesRegex(ValueError, "unreviewed_feature_head"):
            self.merge(manifest, signature)

    def test_wrong_origin_identity_is_rejected_even_if_review_resigned(self):
        manifest = self.fixture.proposal()
        manifest["origin_id"] = hashlib.sha256(b"unknown-other-remote").hexdigest()
        signature = mod.sign_review(manifest, self.private, True)
        with self.assertRaisesRegex(ValueError, "wrong_git_remote_identity"):
            self.merge(manifest, signature)

    def test_source_branch_mismatch_or_unexpected_operation_rejected(self):
        manifest = self.fixture.proposal()
        for field, value in (("source_branch", "feature/unreviewed"),
                             ("base_branch", "production"),
                             ("operation", "force_push_without_review")):
            changed = dict(manifest, **{field: value})
            with self.assertRaisesRegex(ValueError, "unknown_git_operation"):
                mod.sign_review(changed, self.private, True)

    def test_reviewer_and_writer_must_be_separate_roles(self):
        manifest = self.fixture.proposal()
        manifest["reviewer"] = manifest["writer"]
        with self.assertRaisesRegex(ValueError, "independent_roles_invalid"):
            mod.sign_review(manifest, self.private, True)

    def test_approval_nonce_must_be_bounded_and_nontrivial(self):
        manifest = self.fixture.proposal()
        for invalid in ("", "short", "bad nonce", "a" * 200):
            changed = dict(manifest, nonce=invalid)
            with self.assertRaises(ValueError):
                mod.sign_review(changed, self.private, True)

    def test_approval_expiry_cannot_be_arbitrarily_extended(self):
        manifest = self.fixture.proposal()
        for ttl in (0, 601, -1):
            changed = dict(manifest, expires_epoch=manifest["created_epoch"] + ttl)
            with self.assertRaisesRegex(ValueError, "approval_ttl_invalid"):
                mod.sign_review(changed, self.private, True)

    def test_local_fixture_is_private_and_cannot_be_reinitialized(self):
        with self.assertRaisesRegex(ValueError, "already_exist"):
            self.fixture.initialize()
        self.folder.chmod(0o755)
        if os.name == "nt":
            import windows_privacy_fixtures
            windows_privacy_fixtures.set_public_read_acl(self.folder)
        with self.assertRaisesRegex(ValueError, "mode_0700"):
            mod.LocalGitFixture(self.folder)
        self.folder.chmod(0o700)

    def test_reviewer_private_key_must_not_be_world_readable(self):
        manifest = self.fixture.proposal()
        self.private.chmod(0o644)
        if os.name == "nt":
            import windows_privacy_fixtures
            windows_privacy_fixtures.set_public_read_acl(self.private)
        try:
            with self.assertRaisesRegex(ValueError, "private_reviewer_signing_key_required"):
                mod.sign_review(manifest, self.private, True)
        finally:
            self.private.chmod(0o600)
            if os.name == "nt":
                windows_privacy_fixtures.set_private_acl(self.private)

    def test_symlink_source_is_not_allowed_as_reviewed_file(self):
        candidate = self.fixture.writer / mod.FILE
        candidate.unlink()
        candidate.symlink_to("/etc/passwd")
        mod.git(self.fixture.writer, "add", "--", mod.FILE)
        mod.git(self.fixture.writer, "commit", "-m", "untrusted symlink replacement")
        mod.git(self.fixture.writer, "push", "origin", "HEAD:refs/heads/" + mod.REVIEW_BRANCH)
        with self.assertRaisesRegex(ValueError, "symlink_submodule_or_special_mode_rejected"):
            self.fixture._changed_files(self.fixture.base,
                      mod.git(self.fixture.writer, "rev-parse", "HEAD").decode().strip(),
                      self.fixture.writer)

    def test_disallowed_ordinary_file_change_outside_src_is_rejected(self):
        extra = self.fixture.writer / "README.md"
        extra.write_text("unreviewed unrelated data\n")
        mod.git(self.fixture.writer, "add", "--", "README.md")
        mod.git(self.fixture.writer, "commit", "-m", "unapproved README")
        with self.assertRaisesRegex(ValueError, "unsafe_or_disallowed_changed_path"):
            self.fixture._changed_files(self.fixture.base,
                      mod.git(self.fixture.writer, "rev-parse", "HEAD").decode().strip(),
                      self.fixture.writer)

    def test_git_review_status_cli_explicitly_does_not_claim_real_pr(self):
        completed = subprocess.run([sys.executable, "-I", "-S", "-B", str(SCRIPT),
                                    "--status"], capture_output=True, timeout=6,
                                   check=False)
        self.assertEqual(completed.returncode, 0)
        report = json.loads(completed.stdout)
        self.assertEqual(report["status"], "LOCAL_MERGE_APPROVAL_NOT_EXTERNAL_PR")
        self.assertFalse(report["external_github_pr_approved"])
        self.assertFalse(report["human_reviewer_identity_attested"])


if __name__ == "__main__":
    unittest.main()
