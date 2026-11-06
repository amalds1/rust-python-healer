"""Run an offline release without pip, network, or global installation.

Trust boundary: SHA256 checks *local consistency* against a colocated manifest.
Neither the manifest nor the executable is authenticated or code-signed.
The operator must obtain the entire bundle from a trusted channel.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import zipfile


MAX_MANIFEST_BYTES = 16_000
MAX_ARCHIVE_BYTES = 70_000_000
MAX_RUST_BINARY_BYTES = 64_000_000
MAX_WHEEL_BYTES = 32_000_000
_ARTIFACT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,150}\Z", re.ASCII)
_SHA256 = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)


class BundleError(Exception):
    """Fixed-code launcher error; never displays untrusted paths or payload."""


def read_plain(path, limit):
    try:
        before = path.lstat()
    except OSError:
        raise BundleError("missing_artifact") from None
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise BundleError("artifact_not_private_regular_file")
    if before.st_size > limit:
        raise BundleError("artifact_size_limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(str(path), flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise BundleError("artifact_changed_during_read")
            content = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
    except OSError:
        raise BundleError("artifact_unreadable") from None
    if len(content) > limit or (before.st_size, before.st_mtime_ns, before.st_ino) != (
            after.st_size, after.st_mtime_ns, after.st_ino):
        raise BundleError("artifact_changed_during_read")
    return content


def _unique_pairs(pairs):
    items = {}
    for name, value in pairs:
        if name in items:
            raise BundleError("duplicate_manifest_field")
        items[name] = value
    return items


def verify_bundle(folder):
    folder = Path(folder)
    try:
        mode = folder.lstat().st_mode
    except OSError:
        raise BundleError("bundle_directory_missing") from None
    if not stat.S_ISDIR(mode):
        raise BundleError("bundle_directory_not_plain")
    raw = read_plain(folder / "release_manifest.json", MAX_MANIFEST_BYTES)
    try:
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError, TypeError):
        raise BundleError("invalid_release_manifest") from None
    if (not isinstance(manifest, dict) or manifest.get("schema") != 1
            or manifest.get("offline") is not True
            or manifest.get("provenance_authenticated") is not False
            or not isinstance(manifest.get("sha256"), dict)):
        raise BundleError("invalid_release_manifest")
    names = [manifest.get("python_wheel"), manifest.get("rust_archive"),
             manifest.get("launcher")]
    if (any(not isinstance(n, str) or not _ARTIFACT.fullmatch(n) for n in names)
            or len(set(names)) != len(names) or names[2] != "run_bundle.py"
            or not names[0].endswith(".whl") or not names[1].endswith(".zip")):
        raise BundleError("invalid_artifact_names")
    checksums = manifest["sha256"]
    if (set(checksums) != set(names)
            or any(not isinstance(checksums[n], str) or not _SHA256.fullmatch(checksums[n])
                   for n in names)):
        raise BundleError("invalid_release_checksums")
    outputs = {}
    for name in names:
        limit = MAX_WHEEL_BYTES if name.endswith(".whl") else MAX_ARCHIVE_BYTES
        if name == "run_bundle.py":
            limit = 2_000_000
        content = read_plain(folder / name, limit)
        if hashlib.sha256(content).hexdigest() != checksums[name]:
            raise BundleError("artifact_checksum_mismatch")
        outputs[name] = content
    expected_sums = "".join("{}  {}\n".format(checksums[name], name)
                            for name in sorted(names)).encode("ascii")
    if read_plain(folder / "SHA256SUMS", 1_000) != expected_sums:
        raise BundleError("checksum_file_mismatch")
    return manifest, outputs


def rust_executable(content):
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            members = archive.namelist()
            if len(members) != 2 or set(members) not in ({"NOTICE.txt", "bin/rust-python-healer"}, {"NOTICE.txt", "bin/rust-python-healer.exe"}):
                raise BundleError("invalid_rust_archive_members")
            member = "bin/rust-python-healer.exe" if "bin/rust-python-healer.exe" in members else "bin/rust-python-healer"
            binary = archive.getinfo(member)
            if binary.file_size > MAX_RUST_BINARY_BYTES:
                raise BundleError("rust_binary_size_limit")
            if (binary.external_attr >> 16) & 0o170000 != 0o100000:
                raise BundleError("rust_archive_member_not_regular_file")
            executable = archive.read(binary)
            if len(executable) > MAX_RUST_BINARY_BYTES:
                raise BundleError("rust_binary_size_limit")
            if not (executable.startswith(b"\x7fELF") or executable[:2] == b"MZ"
                    or executable[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                                         b"\xca\xfe\xba\xbe")):
                raise BundleError("unknown_executable_format")
            if member.endswith(".exe") != (executable[:2] == b"MZ"):
                raise BundleError("rust_archive_filename_format_mismatch")
            return executable
    except (OSError, KeyError, zipfile.BadZipFile, RuntimeError, EOFError):
        raise BundleError("invalid_rust_archive") from None


def launch(bundle, command, arguments):
    manifest, artifacts = verify_bundle(bundle)
    with tempfile.TemporaryDirectory(prefix="rph-bundle-") as directory:
        if command == "python":
            wheel_name = manifest["python_wheel"]
            wheel_path = Path(bundle) / wheel_name
            # Isolated cwd and no user site; Python imports the vetted wheel
            # directly from the zip sys.path, without pip installation.
            env = os.environ.copy()
            env["PYTHONPATH"] = str(wheel_path.resolve())
            env["PYTHONNOUSERSITE"] = "1"
            argv = [sys.executable, "-S", "-B", "-m", "rust_python_healer_cli"] + arguments
        else:
            binary = rust_executable(artifacts[manifest["rust_archive"]])
            if os.name == "nt" and binary[:2] != b"MZ":
                raise BundleError("native_windows_pe_required")
            binary_path = Path(directory) / ("rust-python-healer.exe" if binary[:2] == b"MZ" else "rust-python-healer")
            with binary_path.open("xb") as output:
                output.write(binary)
            binary_path.chmod(0o700)
            argv = [str(binary_path)] + arguments
            env = os.environ.copy()
            # Rust's tempfile crate otherwise assumes /tmp exists, which is
            # false in some restricted runners. Use our scoped writable dir.
            env["TMPDIR"] = directory
        try:
            result = subprocess.run(argv, cwd=directory, env=env, check=False,
                                    timeout=90)
        except (OSError, subprocess.TimeoutExpired):
            raise BundleError("subprocess_launch_failed") from None
        return result.returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline checksum-checked Python/Rust launch")
    parser.add_argument("--dist-dir", required=True)
    parser.add_argument("command", choices=("python", "rust"))
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    forwarded = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    if not forwarded:
        parser.error("one or more CLI arguments required")
    try:
        return launch(args.dist_dir, args.command, forwarded)
    except BundleError as error:
        print(json.dumps({"status": "NOT_LAUNCHED", "reason": str(error)}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
