"""Read-only, bounded verification of installed distribution RECORD hashes.

Never imports installed package modules or executes a project's code.
This is content consistency, NOT an authentic wheel signature or safe sandbox.
"""

import argparse
import base64
import csv
import hashlib
import hmac
from importlib import metadata
import json
import os
from pathlib import Path
import re
import stat
import sysconfig


NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
MAX_RECORD_BYTES = 1_000_000
MAX_RECORD_ENTRIES = 3000
MAX_SINGLE_FILE = 64_000_000
MAX_TOTAL_BYTES = 256_000_000


def canonical(value):
    if not NAME.fullmatch(value):
        raise ValueError("invalid_package_name")
    return re.sub(r"[-_.]+", "-", value).lower()


def safe_target(root, relative):
    """Reject traversal and symlinks; a concurrent TOCTOU attack remains possible."""
    if (not relative or len(relative) > 4096 or relative.startswith("/")
            or "\\" in relative or "\0" in relative):
        raise ValueError("invalid_record_path")
    pieces = relative.split("/")
    if any(x in ("", ".", "..") for x in pieces):
        raise ValueError("record_path_traversal")
    target = root
    for piece in pieces:
        target = target / piece
        if target.is_symlink():
            raise ValueError("record_symlink_refused")
    return target


def hash_file(path, expected_bytes):
    """Read file with a strict per-file cap and refuse symlinks/hardlinks."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("record_not_plain_file")
    if before.st_size > MAX_SINGLE_FILE:
        raise ValueError("record_file_too_large")
    if expected_bytes is not None and before.st_size != expected_bytes:
        raise ValueError("record_size_mismatch")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(str(path), flags)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_ino, opened.st_dev) != (before.st_ino, before.st_dev):
            raise ValueError("file_changed_during_verification")
        digest = hashlib.sha256()
        while True:
            block = stream.read(65536)
            if not block:
                break
            digest.update(block)
        after = os.fstat(stream.fileno())
    if (before.st_ino, before.st_dev, before.st_size, before.st_mtime_ns) != (
            after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns):
        raise ValueError("file_changed_during_verification")
    return digest.digest(), before.st_size


def inspect_record(dist):
    base = getattr(dist, "_path", None)
    if base is None:
        return {"status": "UNKNOWN", "reason": "distribution_path_unavailable"}
    directory = Path(base)
    record = directory / "RECORD"
    if record.is_symlink():
        return {"status": "INVALID", "reason": "record_symlink_refused"}
    if not record.exists():
        return {"status": "NOT_DECLARED"}
    if not record.is_file() or record.stat().st_size > MAX_RECORD_BYTES:
        return {"status": "INVALID", "reason": "record_size_limit"}
    root = directory.parent
    counted, verified, skipped, total = 0, 0, 0, 0
    try:
        # Python's CSV parser handles quoting, commas and non-ASCII paths.
        with record.open("r", encoding="utf-8", newline="") as stream:
            for parts in csv.reader(stream):
                counted += 1
                if counted > MAX_RECORD_ENTRIES or len(parts) != 3:
                    raise ValueError("invalid_record_row")
                relative, encoded, size_string = parts
                candidate = safe_target(root, relative)
                if relative == directory.name + "/RECORD":
                    # Wheel RECORD cannot sign itself.
                    continue
                if not encoded:
                    skipped += 1
                    continue
                if not encoded.startswith("sha256="):
                    raise ValueError("unsupported_hash_algorithm")
                tag = encoded[len("sha256="):]
                if not re.fullmatch(r"[A-Za-z0-9_-]{43}", tag):
                    raise ValueError("bad_record_digest")
                expected = base64.urlsafe_b64decode(tag + "=")
                if len(expected) != 32:
                    raise ValueError("bad_record_digest")
                if size_string and not re.fullmatch(r"\d{1,12}", size_string):
                    raise ValueError("invalid_record_size")
                specified = int(size_string) if size_string else None
                actual, length = hash_file(candidate, specified)
                total += length
                if total > MAX_TOTAL_BYTES:
                    raise ValueError("total_record_budget_exceeded")
                if not hmac.compare_digest(expected, actual):
                    raise ValueError("record_sha256_mismatch")
                verified += 1
    except (OSError, UnicodeError, ValueError, csv.Error) as exc:
        # Only fixed enumerated reasons, never copy private paths or raw CSV.
        known = {
            "invalid_record_path", "record_path_traversal", "record_symlink_refused",
            "record_not_plain_file", "record_file_too_large", "record_size_mismatch",
            "file_changed_during_verification", "invalid_record_row",
            "unsupported_hash_algorithm", "bad_record_digest", "invalid_record_size",
            "total_record_budget_exceeded", "record_sha256_mismatch",
        }
        reason = str(exc) if isinstance(exc, ValueError) and str(exc) in known else "unreadable_record"
        return {"status": "INVALID", "reason": reason, "checked": counted, "verified": verified}
    return {
        "status": "RECORDED_HASHES_MATCH_NOT_PROVENANCE" if verified and skipped == 0
                  else "PARTIAL_UNVERIFIED",
        "checked": counted, "verified": verified, "unhashed": skipped,
        "bytes_hashed": total,
        "path_protection": "BEST_EFFORT_NO_SYMLINKS_NOT_TOCTOU_PROOF",
        "provenance_verified": False,
    }


def inspect(packages, extra_roots=None):
    names = [canonical(p) for p in packages]
    if not names or len(names) > 25:
        raise ValueError("expected_1_to_25_packages")
    roots = {str(Path(p).resolve()) for p in
             (sysconfig.get_path("purelib"), sysconfig.get_path("platlib")) if p}
    for directory in extra_roots or []:
        path = Path(directory).resolve()
        if not path.is_dir():
            raise ValueError("metadata_root_missing")
        roots.add(str(path))
    if len(roots) > 12:
        raise ValueError("too_many_metadata_roots")
    found = {name: [] for name in names}
    for dist in metadata.distributions(path=sorted(roots)):
        try:
            name = canonical(dist.metadata.get("Name", ""))
            if name not in found:
                continue
            found[name].append({"version": str(dist.version), "record": inspect_record(dist)})
        except (OSError, UnicodeError, ValueError):
            continue
    return {"status": "INSPECTED_NOT_INSTALLED", "packages": [
        {"name": name, "distributions": found[name],
         "status": "MISSING" if not found[name] else
                   "AMBIGUOUS" if len(found[name]) > 1 else "FOUND"}
        for name in dict.fromkeys(names)
    ], "modules_executed": False,
        "note": "Installed RECORD content hashes only; no cryptographic package provenance or installation performed"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", action="append", required=True)
    parser.add_argument("--metadata-dir", action="append", default=[])
    args = parser.parse_args()
    print(json.dumps(inspect(args.package, args.metadata_dir), ensure_ascii=False))


if __name__ == "__main__":
    main()
