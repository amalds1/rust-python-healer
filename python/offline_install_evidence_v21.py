"""Trusted fixed-wheel, actual installed RECORD and offline reproducibility test.

Only the exact source-reviewed ``rph_fixture_v21`` *pure-data* wheel is allowed.
No arbitrary user wheel is ever passed to pip; no setup.py, build backend,
network, dependency resolution, system installation or module import. This is
not a publisher-authenticity or native/ABI-compatibility verification.
"""

import base64
import csv
import hashlib
import importlib.metadata
import io
import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

WHEEL_FILENAME = "rph_fixture_v21-0.0.1-py3-none-any.whl"
DIST_INFO = "rph_fixture_v21-0.0.1.dist-info"
MODULE_NAME = "rph_fixture_v21.py"
MODULE_SOURCE = b"VALUE = 'trusted fixture v21'\n"
WHEEL_METADATA = b"Wheel-Version: 1.0\nGenerator: reviewed-local-v21\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
CORE_METADATA = b"Metadata-Version: 2.3\nName: rph-fixture-v21\nVersion: 0.0.1\n"
FILES = {
    MODULE_NAME: MODULE_SOURCE,
    DIST_INFO + "/METADATA": CORE_METADATA,
    DIST_INFO + "/WHEEL": WHEEL_METADATA,
}
RECORD_NAME = DIST_INFO + "/RECORD"
EXPECTED_WHEEL_MEMBERS = set(FILES) | {RECORD_NAME}
MAX_WHEEL_BYTES = 200000
MAX_RECORD_ROWS = 80


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _record_hash(data):
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")


def _safe_member(name):
    if (type(name) is not str or not name or name.startswith(("/", "\\")) or
            "\\" in name or "\x00" in name or ":" in name):
        return False
    return all(part not in ("", ".", "..") for part in name.split("/"))


def _expected_record():
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name, data in sorted(FILES.items()):
        writer.writerow((name, _record_hash(data), len(data)))
    writer.writerow((RECORD_NAME, "", ""))
    return output.getvalue().encode("utf-8")


def build_trusted_fixture_wheel(destination):
    """Build a byte-for-byte reproducible, reviewed local wheel (new file)."""
    directory = Path(destination)
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("fixture_directory_must_preexist_and_be_real")
    wheel = directory / WHEEL_FILENAME
    if wheel.exists() or wheel.is_symlink():
        raise ValueError("fixture_wheel_cannot_overwrite_existing_file")
    with wheel.open("xb") as fileobj, zipfile.ZipFile(fileobj, "w") as archive:
        for name, data in sorted(dict(FILES, **{RECORD_NAME: _expected_record()}).items()):
            info = zipfile.ZipInfo(name)
            info.date_time = (1980, 1, 1, 0, 0, 0)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(info, data)
    return {"wheel_path": str(wheel), "sha256": _digest(wheel.read_bytes()),
            "trusted_fixture_only": True, "build_backend_executed": False}


def audit_trusted_wheel(wheel_path, expected_sha256):
    """Allowlist every byte-level member and RECORD before invoking pip."""
    path = Path(wheel_path)
    if (path.name != WHEEL_FILENAME or path.is_symlink() or not path.is_file() or
            type(expected_sha256) is not str or len(expected_sha256) != 64):
        return {"status": "REJECTED", "reason": "wheel_identity_or_expectation_invalid"}
    if path.stat().st_size > MAX_WHEEL_BYTES:
        return {"status": "REJECTED", "reason": "wheel_size_limit"}
    raw = path.read_bytes()
    if _digest(raw) != expected_sha256:
        return {"status": "REJECTED", "reason": "wheel_archive_sha256_mismatch"}
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if len(names) != len(set(names)) or set(names) != EXPECTED_WHEEL_MEMBERS:
                return {"status": "REJECTED", "reason": "unexpected_wheel_members"}
            for info in entries:
                mode = (info.external_attr >> 16) & 0o170000
                if (not _safe_member(info.filename) or info.file_size > MAX_WHEEL_BYTES or
                        mode not in (0, stat.S_IFREG)):
                    return {"status": "REJECTED", "reason": "unsafe_wheel_member"}
                expected_data = FILES.get(info.filename, _expected_record())
                if archive.read(info) != expected_data:
                    return {"status": "REJECTED", "reason": "wheel_record_or_content_invalid"}
    except (OSError, zipfile.BadZipFile, ValueError, RuntimeError):
        return {"status": "REJECTED", "reason": "invalid_zip_archive"}
    return {"status": "VERIFIED_LOCAL_FIXTURE", "wheel_sha256": expected_sha256,
            "member_count": len(EXPECTED_WHEEL_MEMBERS),
            "publisher_authenticated": False, "native_wheel_tested": False,
            "untrusted_code_executed": False, "network_used": False}


def audit_installed_record(target):
    """Read real installed dist-info/RECORD and every private target file."""
    root = Path(target)
    dist = root / DIST_INFO
    if not root.is_dir() or root.is_symlink() or not dist.is_dir() or dist.is_symlink():
        return {"status": "NOT_INSTALLED_OR_UNSAFE_TARGET"}
    record_path = dist / "RECORD"
    if not record_path.is_file() or record_path.is_symlink():
        return {"status": "MISSING_OR_UNSAFE_RECORD"}
    try:
        with record_path.open("r", encoding="utf-8", newline="") as record_file:
            rows = list(csv.reader(record_file))
    except (OSError, UnicodeError, csv.Error):
        return {"status": "INVALID_INSTALLED_RECORD"}
    if len(rows) > MAX_RECORD_ROWS or len(rows) < len(FILES):
        return {"status": "INVALID_INSTALLED_RECORD"}
    listed, errors, measured = set(), [], {}
    for row in rows:
        if len(row) != 3 or not _safe_member(row[0]) or row[0] in listed:
            errors.append("invalid_record_entry")
            continue
        name, checksum, size = row
        listed.add(name)
        file = root.joinpath(*name.split("/"))
        if file.is_symlink() or not file.is_file():
            errors.append("missing_or_symlink_file:" + name)
            continue
        payload = file.read_bytes()
        measured[name] = _digest(payload)
        if name == RECORD_NAME and checksum == "" and size == "":
            continue
        if (not checksum.startswith("sha256=") or
                checksum != _record_hash(payload) or size != str(len(payload))):
            errors.append("sha256_or_size_mismatch:" + name)
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            errors.append("unsafe_symlink_in_install")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    extra = actual - listed
    missing = listed - actual
    if extra:
        errors.append("unrecorded_installed_files")
    if missing:
        errors.append("record_files_missing")
    try:
        distributions = list(importlib.metadata.distributions(path=[str(root)]))
        identity = (len(distributions) == 1 and
                    distributions[0].metadata["Name"].lower().replace("-", "_") == "rph_fixture_v21" and
                    distributions[0].version == "0.0.1")
    except (KeyError, OSError, ValueError):
        identity = False
    if not identity:
        errors.append("installed_distribution_identity_invalid")
    return {"status": "PASS" if not errors else "FAIL",
            "python_version": "{}.{}".format(*sys.version_info[:2]),
            "record_entries": len(rows), "verified_file_count": len(measured),
            "errors": errors, "file_sha256": measured,
            "installed_distribution_detected": identity,
            "system_site_packages_modified": False,
            "publisher_authenticated": False, "target_modules_imported": False}


def _install(wheel, target):
    env = os.environ.copy()
    env.update(PIP_NO_INDEX="1", PIP_DISABLE_PIP_VERSION_CHECK="1",
               PIP_NO_INPUT="1", PYTHONDONTWRITEBYTECODE="1")
    command = [sys.executable, "-m", "pip", "install", "--no-index", "--no-deps",
               "--no-compile", "--no-cache-dir", "--disable-pip-version-check",
               "--no-warn-script-location", "--target", str(target), str(wheel)]
    try:
        outcome = subprocess.run(command, env=env, capture_output=True,
                                 timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return outcome.returncode == 0


def reproducible_offline_install(wheel_path, expected_sha256, first_target, second_target):
    """Run two actual trusted wheel pip installs into independent empty dirs."""
    wheel_ok = audit_trusted_wheel(wheel_path, expected_sha256)
    if wheel_ok["status"] != "VERIFIED_LOCAL_FIXTURE":
        return {"status": "REJECTED_BEFORE_INSTALL", "wheel": wheel_ok,
                "network_used": False, "untrusted_wheel_installed": False}
    first, second = Path(first_target), Path(second_target)
    if (first == second or any(path.is_symlink() or not path.is_dir() or
                               next(path.iterdir(), None) is not None
                               for path in (first, second))):
        raise ValueError("two_distinct_empty_private_targets_required")
    if not _install(wheel_path, first) or not _install(wheel_path, second):
        return {"status": "NOT_RUN_PIP_ENVIRONMENT", "network_used": False,
                "untrusted_wheel_installed": False}
    first_audit = audit_installed_record(first)
    second_audit = audit_installed_record(second)
    same = (first_audit.get("status") == "PASS" and
            second_audit.get("status") == "PASS" and
            first_audit["file_sha256"] == second_audit["file_sha256"])
    return {"status": "PASS" if same else "FAIL",
            "first": first_audit, "second": second_audit,
            "identical_installed_file_hashes": same,
            "used_flags": ["--no-index", "--no-deps", "--no-compile", "--target"],
            "two_independent_targets": True, "network_used": False,
            "system_install_performed": False, "publisher_authenticated": False,
            "untrusted_wheel_installed": False}
