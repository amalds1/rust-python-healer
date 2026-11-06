"""Cryptographically approved local Git merge gate for a trusted fixture.

Creates a real bare repository and two separate real clones.  A reviewer with
an independent Ed25519 private key signs the exact source/base/head/diff SHA,
expiry and one-time nonce; the integrator holds only a pinned public key.
GitHub/GitLab PR APIs, real humans, arbitrary project code and external
publisher identity are NOT present or claimed.  This is F139 PARTIAL.
"""

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import time


BASE_BRANCH = "main"
REVIEW_BRANCH = "feature/reviewed"
MAX_DIFF_BYTES = 64_000
MAX_OUTPUT = 100_000
SHA1 = re.compile(r"[0-9a-f]{40}\Z", re.ASCII)
SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
NONCE = re.compile(r"[A-Za-z0-9_-]{12,96}\Z", re.ASCII)
FILE = "src/module.py"
BASE_FIXTURE = "def calculate():\n    return 1\n"
REPAIRED_FIXTURE = "def calculate():\n    return 2\n"


def _model_evidence_io():
    module = globals().get("_RPH_MODEL_EVIDENCE_IO")
    if module is None:
        import importlib.util
        spec = importlib.util.spec_from_file_location("rph_git_evidence_io", Path(__file__).resolve().with_name("model_evidence_io_v029.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        globals()["_RPH_MODEL_EVIDENCE_IO"] = module
    return module


def openssl_executable():
    installed = shutil.which("openssl")
    if installed is None and os.name == "nt":
        candidate = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/usr/bin/openssl.exe"
        if candidate.is_file():
            installed = str(candidate)
    if installed is None:
        raise ValueError("installed_openssl_required")
    return installed


def _run(command, cwd=None, input_bytes=None, extra_env=None):
    command = list(command)
    if command[0] == "openssl":
        command[0] = openssl_executable()
    env = dict(os.environ)
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_ALLOW_PROTOCOL": "file", "GIT_TERMINAL_PROMPT": "0",
                "GIT_AUTHOR_NAME": "Trusted Fixture Author",
                "GIT_AUTHOR_EMAIL": "writer@fixture.invalid",
                "GIT_COMMITTER_NAME": "Trusted Fixture Integrator",
                "GIT_COMMITTER_EMAIL": "integrator@fixture.invalid"})
    if extra_env:
        env.update(extra_env)
    process = subprocess.run(command, cwd=str(cwd) if cwd else None,
                             input=input_bytes, capture_output=True,
                             timeout=8, check=False, env=env)
    if len(process.stdout) > MAX_OUTPUT or len(process.stderr) > MAX_OUTPUT:
        raise ValueError("subprocess_output_limit")
    if process.returncode:
        raise ValueError("trusted_git_or_signature_command_failed")
    return process.stdout


def git(repository, *args):
    return _run(["git", "-c", "core.hooksPath=" + os.devnull, "-C",
                 str(repository)] + list(args))


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _sha_object(value, pattern):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def canonical_manifest(manifest):
    if not isinstance(manifest, dict):
        raise ValueError("approval_manifest_invalid")
    required = {"schema", "origin_id", "base_branch", "source_branch",
                "base_sha", "head_sha", "diff_sha256", "reviewer", "writer",
                "nonce", "created_epoch", "expires_epoch", "operation"}
    if set(manifest) != required or manifest["schema"] != 1:
        raise ValueError("approval_schema_invalid")
    if (manifest["base_branch"] != BASE_BRANCH
            or manifest["source_branch"] != REVIEW_BRANCH
            or manifest["operation"] != "local_git_merge_review"):
        raise ValueError("unknown_git_operation")
    if any(not _sha_object(manifest[field], SHA1) for field in
           ("base_sha", "head_sha")):
        raise ValueError("sha1_commit_shape_invalid")
    if not _sha_object(manifest["diff_sha256"], SHA256):
        raise ValueError("diff_sha256_invalid")
    if not _sha_object(manifest["origin_id"], SHA256):
        raise ValueError("origin_pin_invalid")
    if (manifest["writer"] != "trusted-fixture-writer"
            or manifest["reviewer"] != "independent-fixture-reviewer"):
        raise ValueError("independent_roles_invalid")
    if not isinstance(manifest["nonce"], str) or NONCE.fullmatch(manifest["nonce"]) is None:
        raise ValueError("nonce_invalid")
    created = manifest["created_epoch"]
    expires = manifest["expires_epoch"]
    if (type(created) is not int or type(expires) is not int
            or not 1 <= expires - created <= 600):
        raise ValueError("approval_ttl_invalid")
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _private_key(path):
    path = Path(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or (os.name != "nt" and info.st_mode & 0o077)
            or info.st_nlink != 1):
        raise ValueError("private_reviewer_signing_key_required")
    if os.name == "nt":
        try:
            _model_evidence_io().privacy().assert_private_file(path)
        except (OSError, ValueError) as problem:
            raise ValueError("private_reviewer_signing_key_required") from problem
    return path


def reviewer_public_key_pin(path):
    """Out-of-band operator pins exact public key PEM bytes, not filename."""
    raw = (_model_evidence_io().read_regular(Path(path),4096) if os.name == "nt" else Path(path).read_bytes())
    if len(raw) > 4096 or b"BEGIN PUBLIC KEY" not in raw:
        raise ValueError("invalid_reviewer_public_key")
    return _sha256(raw)


def sign_review(manifest, reviewer_private_key, approved):
    """Run an actual distinct Ed25519 signer process; no auto approval."""
    payload = canonical_manifest(manifest)
    if approved is not True:
        raise PermissionError("explicit_independent_reviewer_approval_required")
    key = _private_key(reviewer_private_key)
    with tempfile.TemporaryDirectory(prefix="rph-git-review-sign-") as folder:
        input_file = Path(folder) / "review.json"
        signature_file = Path(folder) / "approval.sig"
        input_file.write_bytes(payload)
        held_key = _model_evidence_io().privacy().open_private_readonly(key) if os.name == "nt" else None
        try:
            _run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey",
                  str(key), "-in", str(input_file), "-out", str(signature_file)])
        finally:
            if held_key is not None:
                os.close(held_key)
        signature = signature_file.read_bytes()
    if len(signature) != 64:
        raise ValueError("ed25519_signature_length_invalid")
    return signature.hex()


def verify_review(manifest, signature_hex, public_key_file, pinned_public_sha,
                  now=None):
    payload = canonical_manifest(manifest)
    if (not _sha_object(signature_hex, re.compile(r"[0-9a-f]{128}\Z", re.ASCII))
            or not _sha_object(pinned_public_sha, SHA256)
            or not isinstance(public_key_file, (str, Path))):
        raise ValueError("signature_or_public_key_pin_missing")
    if reviewer_public_key_pin(public_key_file) != pinned_public_sha:
        raise ValueError("reviewer_public_key_pin_mismatch")
    clock = int(time.time()) if now is None else now
    if type(clock) is not int or clock < manifest["created_epoch"] or clock > manifest["expires_epoch"]:
        raise ValueError("reviewer_approval_expired_or_not_yet_valid")
    with tempfile.TemporaryDirectory(prefix="rph-git-review-verify-") as folder:
        message = Path(folder) / "review.json"
        signature = Path(folder) / "signature.sig"
        message.write_bytes(payload)
        signature.write_bytes(bytes.fromhex(signature_hex))
        _run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
              "-inkey", str(public_key_file), "-in", str(message),
              "-sigfile", str(signature)])
    return True


class LocalGitFixture:
    """Independent writer and integrator clones from one offline bare origin."""

    def __init__(self, private_workspace):
        root = Path(private_workspace)
        meta = root.lstat()
        if not stat.S_ISDIR(meta.st_mode) or (os.name != "nt" and meta.st_mode & 0o077):
            raise ValueError("private_workspace_mode_0700_required")
        if os.name == "nt":
            try:
                _model_evidence_io().privacy().assert_private_directory(root)
            except (OSError, ValueError) as problem:
                raise ValueError("private_workspace_mode_0700_required") from problem
        self.root = root
        self.remote = root / "trusted-remote.git"
        self.writer = root / "writer-clone"
        self.integrator = root / "integrator-clone"
        self.ledger = root / "review_approvals.sqlite"
        self.origin_id = _sha256(str(self.remote.resolve()).encode("utf-8"))
        self.base = None
        self.head = None

    def _ledger_database(self):
        if self.ledger.exists() or self.ledger.is_symlink():
            info = self.ledger.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or (os.name != "nt" and info.st_mode & 0o077)):
                raise ValueError("unsafe_approval_ledger_path")
            if os.name == "nt":
                try:
                    _model_evidence_io().privacy().assert_private_file(self.ledger)
                except (OSError, ValueError) as problem:
                    raise ValueError("unsafe_approval_ledger_path") from problem
        connection = sqlite3.connect(str(self.ledger), timeout=3)
        self.ledger.chmod(0o600)
        connection.execute("CREATE TABLE IF NOT EXISTS used_approvals("
                           "nonce TEXT PRIMARY KEY, manifest_sha TEXT UNIQUE NOT NULL)")
        connection.commit()
        return connection

    def _approval_used(self, digest, nonce):
        connection = self._ledger_database()
        try:
            return connection.execute(
                "SELECT 1 FROM used_approvals WHERE nonce=? OR manifest_sha=? LIMIT 1",
                (nonce, digest)).fetchone() is not None
        finally:
            connection.close()

    def _reserve_approval(self, digest, nonce):
        connection = self._ledger_database()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("INSERT INTO used_approvals(nonce,manifest_sha) VALUES(?,?)",
                               (nonce, digest))
            connection.commit()
        except sqlite3.IntegrityError:
            connection.rollback()
            raise ValueError("review_approval_replay_detected") from None
        finally:
            connection.close()

    def initialize(self):
        if any(path.exists() for path in (self.remote, self.writer, self.integrator)):
            raise ValueError("fixture_repositories_already_exist")
        _run(["git", "-c", "core.hooksPath=" + os.devnull, "init", "--bare",
              "--initial-branch=main", str(self.remote)])
        git(self.remote, "config", "core.hooksPath", os.devnull)
        git(self.remote, "config", "receive.denyNonFastForwards", "true")
        _run(["git", "-c", "core.hooksPath=" + os.devnull, "clone",
              str(self.remote), str(self.writer)])
        source = self.writer / FILE
        source.parent.mkdir()
        source.write_text(BASE_FIXTURE, encoding="utf-8")
        git(self.writer, "add", "--", FILE)
        git(self.writer, "commit", "-m", "trusted initial fixture")
        git(self.writer, "push", "origin", "HEAD:refs/heads/main")
        _run(["git", "-c", "core.hooksPath=" + os.devnull, "clone",
              str(self.remote), str(self.integrator)])
        self.base = git(self.writer, "rev-parse", "HEAD").decode("ascii").strip()
        git(self.writer, "checkout", "-b", REVIEW_BRANCH)
        source.write_text(REPAIRED_FIXTURE, encoding="utf-8")
        git(self.writer, "add", "--", FILE)
        git(self.writer, "commit", "-m", "trusted reviewed repair fixture")
        git(self.writer, "push", "origin", "HEAD:refs/heads/" + REVIEW_BRANCH)
        self.head = git(self.writer, "rev-parse", "HEAD").decode("ascii").strip()
        if self.base == self.head:
            raise ValueError("repair_commit_not_distinct")
        return {"status": "TWO_REAL_ISOLATED_GIT_CLONES_CREATED",
                "remote_bare_created": self.remote.is_dir(),
                "writer_clone_created": self.writer.is_dir(),
                "integrator_clone_created": self.integrator.is_dir(),
                "initial_sha": self.base, "candidate_sha": self.head,
                "source_executed": False}

    def _diff_bytes(self, base, head, repository):
        diff = git(repository, "diff", "--no-ext-diff", "--binary", base, head)
        if not diff or len(diff) > MAX_DIFF_BYTES:
            raise ValueError("empty_or_oversized_review_diff")
        return diff

    def _changed_files(self, base, head, repository):
        raw = git(repository, "diff", "--name-only", base, head)
        files = raw.decode("utf-8").splitlines()
        if not files or len(files) > 50:
            raise ValueError("invalid_changed_file_inventory")
        for path in files:
            components = path.split("/")
            if (not path.startswith("src/") or not path.endswith(".py")
                    or any(x in ("", ".", "..") for x in components)
                    or any(x in path for x in ("\\", "\x00"))):
                raise ValueError("unsafe_or_disallowed_changed_path")
            tree = git(repository, "ls-tree", head, "--", path).decode("utf-8")
            if not tree.startswith(("100644 blob ", "100755 blob ")):
                raise ValueError("symlink_submodule_or_special_mode_rejected")
        return files

    def proposal(self, now=None):
        if self.base is None or self.head is None:
            raise ValueError("trusted_remote_not_initialized")
        self._changed_files(self.base, self.head, self.writer)
        raw = self._diff_bytes(self.base, self.head, self.writer)
        current = int(time.time()) if now is None else now
        return {"schema": 1, "operation": "local_git_merge_review",
                "origin_id": self.origin_id,
                "base_branch": BASE_BRANCH, "source_branch": REVIEW_BRANCH,
                "base_sha": self.base, "head_sha": self.head,
                "diff_sha256": _sha256(raw),
                "writer": "trusted-fixture-writer",
                "reviewer": "independent-fixture-reviewer",
                "nonce": secrets.token_urlsafe(18),
                "created_epoch": current, "expires_epoch": current + 120}

    def _remote_sha(self, branch):
        data = git(self.integrator, "ls-remote", "--heads", "origin",
                   "refs/heads/" + branch).decode("ascii").strip()
        if not data:
            raise ValueError("remote_branch_missing")
        return data.split("\t", 1)[0]

    def merge_if_approved(self, manifest, signature_hex, public_key_file,
                          pinned_public_sha, now=None):
        payload = canonical_manifest(manifest)
        digest = _sha256(payload)
        if self._approval_used(digest, manifest["nonce"]):
            raise ValueError("review_approval_replay_detected")
        verify_review(manifest, signature_hex, public_key_file, pinned_public_sha, now=now)
        if manifest["origin_id"] != self.origin_id:
            raise ValueError("wrong_git_remote_identity")
        if manifest["base_sha"] != self._remote_sha(BASE_BRANCH):
            raise ValueError("stale_base_branch_rejected")
        if manifest["head_sha"] != self._remote_sha(REVIEW_BRANCH):
            raise ValueError("unreviewed_feature_head_rejected")
        git(self.integrator, "fetch", "origin", BASE_BRANCH, REVIEW_BRANCH)
        observed_base = git(self.integrator, "rev-parse", "origin/main").decode().strip()
        observed_head = git(self.integrator, "rev-parse",
                            "origin/" + REVIEW_BRANCH).decode().strip()
        if observed_base != manifest["base_sha"] or observed_head != manifest["head_sha"]:
            raise ValueError("branch_sha_changed_during_fetch")
        self._changed_files(observed_base, observed_head, self.integrator)
        observed_diff = _sha256(self._diff_bytes(observed_base, observed_head, self.integrator))
        if not hmac.compare_digest(observed_diff, manifest["diff_sha256"]):
            raise ValueError("diff_changed_after_reviewer_approval")
        if git(self.integrator, "rev-parse", "main").decode().strip() != observed_base:
            raise ValueError("local_integrator_base_diverged")
        self._reserve_approval(digest, manifest["nonce"])
        git(self.integrator, "checkout", BASE_BRANCH)
        git(self.integrator, "merge", "--no-ff", "--no-edit", observed_head)
        merged = git(self.integrator, "rev-parse", "HEAD").decode().strip()
        parents = git(self.integrator, "rev-list", "--parents", "-n", "1",
                      merged).decode().split()
        if parents != [merged, observed_base, observed_head]:
            raise ValueError("merge_parents_not_verified")
        git(self.integrator, "push", "origin", "HEAD:refs/heads/main")
        if self._remote_sha(BASE_BRANCH) != merged:
            raise ValueError("remote_push_not_verifiably_committed")
        contents = (self.integrator / FILE).read_text(encoding="utf-8")
        if contents != REPAIRED_FIXTURE:
            raise ValueError("reviewed_diff_not_applied_as_expected")
        return {"status": "LOCAL_MERGE_APPROVAL_VERIFIED_NOT_EXTERNAL_PR",
                "base_sha": observed_base, "approved_head_sha": observed_head,
                "real_merge_commit_sha": merged,
                "independent_reviewer_ed25519_verified": True,
                "approval_nonce_replay_blocked": True,
                "approval_nonce_persisted_sqlite": True,
                "expiry_checked": True,
                "diff_sha256_verified": observed_diff,
                "two_real_git_clones_used": True,
                "source_code_executed": False,
                "external_github_pr_approved": False,
                "human_reviewer_identity_attested": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status", action="store_true")
    args = parser.parse_args(argv)
    if args.status:
        print(json.dumps({"status": "LOCAL_MERGE_APPROVAL_NOT_EXTERNAL_PR",
                          "external_github_pr_approved": False,
                          "human_reviewer_identity_attested": False,
                          "requires_private_fixture_workspace": True},
                         sort_keys=True))
        return 0
    parser.error("direct reviewer keys and private Git fixture paths are required in Python API")


if __name__ == "__main__":
    raise SystemExit(main())
