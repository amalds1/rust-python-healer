"""Check-time private fixed-wheel identity; no install or sandbox guarantee.

The trusted caller supplies a reviewed manifest SHA. A metadata version is
never an archive authentication substitute. A same-user later mutation is
outside this read-only check; this API does not promise immutable imports.
"""
import hashlib
from functools import lru_cache
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import stat


@lru_cache(maxsize=1)
def _windows_privacy():
    injected = globals().get("_RPH_WINDOWS_PRIVACY")
    if injected is not None:
        return injected
    path = Path(__file__).with_name("windows_private_paths.py")
    spec = importlib.util.spec_from_file_location("_fixed_wheel_windows_privacy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assert_private_directory(path):
    path = Path(path)
    if os.name == "nt":
        _windows_privacy().assert_private_directory(path)
    else:
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077
                or info.st_uid != os.getuid()):
            raise ValueError("private_pinned_wheel_directory_required")


def _read_private(path, maximum):
    if os.name == "nt":
        privacy = _windows_privacy()
        descriptor = privacy.open_private_readonly(path)
    else:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > maximum):
            raise ValueError("invalid_private_wheel_file")
        if os.name == "nt":
            privacy.assert_private_file_descriptor(descriptor)
        elif before.st_mode & 0o077 or before.st_uid != os.getuid():
            raise ValueError("private_wheel_file_required")
        digest = hashlib.sha256()
        count = 0
        chunks = [] if maximum <= 16_000_000 else None
        while True:
            raw = os.read(descriptor, min(1024 * 1024, maximum + 1 - count))
            if not raw:
                break
            count += len(raw)
            if count > maximum:
                raise ValueError("private_wheel_file_unbounded")
            digest.update(raw)
            if chunks is not None:
                chunks.append(raw)
        after = os.fstat(descriptor)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("wheel_file_changed_during_verification")
        return digest.hexdigest(), b"".join(chunks) if chunks is not None else None
    finally:
        os.close(descriptor)


def verify_private_target(target, expected_manifest_sha256, manifest_path=None):
    """Validate a complete reviewed byte map before adding a target to sys.path."""
    if (type(expected_manifest_sha256) is not str
            or len(expected_manifest_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_manifest_sha256)):
        raise ValueError("reviewed_wheel_manifest_sha_required")
    target = Path(target)
    if not target.is_absolute():
        raise ValueError("absolute_private_wheel_target_required")
    assert_private_directory(target)
    manifest = Path(manifest_path) if manifest_path else target.parent / "installed-byte-manifest.json"
    try:
        manifest.lstat()
    except FileNotFoundError as error:
        raise ValueError("reviewed_wheel_manifest_missing") from error
    digest, raw = _read_private(manifest, 16_000_000)
    if digest != expected_manifest_sha256:
        raise ValueError("reviewed_wheel_manifest_hash_mismatch")
    data = json.loads(raw)
    expected = data.get("all_installed_file_sha256")
    if type(expected) is not dict or not 1 <= len(expected) <= 100000:
        raise ValueError("invalid_wheel_manifest_file_map")
    for name, digest in expected.items():
        if type(name) is not str:
            raise ValueError("invalid_wheel_manifest_member")
        parts = PurePosixPath(name)
        if (not name or parts.is_absolute()
                or any(p in ("", ".", "..") for p in name.split("/"))
                or "\\" in name or ":" in name
                or type(digest) is not str or len(digest) != 64
                or any(c not in "0123456789abcdef" for c in digest)):
            raise ValueError("invalid_wheel_manifest_member")
    actual = set()
    for folder, directories, files in os.walk(target, followlinks=False):
        for name in directories:
            assert_private_directory(Path(folder) / name)
        for name in files:
            path = Path(folder) / name
            relative = path.relative_to(target).as_posix()
            if relative not in expected:
                raise ValueError("unreviewed_installed_wheel_file")
            digest, _ = _read_private(path, 180_000_000)
            if digest != expected[relative]:
                raise ValueError("installed_wheel_byte_mismatch")
            actual.add(relative)
    if actual != set(expected):
        raise ValueError("reviewed_installed_wheel_file_missing")
    return {"manifest_sha256": expected_manifest_sha256,
            "verified_files": len(actual), "runtime": data.get("runtime"),
            "scope": "CHECK_TIME_REVIEWED_PRIVATE_FIXED_WHEEL_BYTES"}
