"""Offline, deterministic distribution of existing read-only Python helpers.

Builds a PEP 427 pure-Python wheel plus a separately distributable existing
Rust executable archive. Does NOT compile Rust or verify a binary's source,
sign a release, install packages, use the network, or overwrite artifacts.
"""

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import zipfile


ROOT = Path(__file__).resolve().parents[1]
MAX_HELPER_BYTES = 2_000_000
MAX_TOTAL_PY_BYTES = 32_000_000
MAX_RUST_BYTES = 64_000_000
WHEEL_TAG = "py3-none-any"
_VERSION = re.compile(r'(?m)^version\s*=\s*"(\d+\.\d+\.\d+)"\s*$')
_NAME = re.compile(r"[a-z][a-z0-9_]*\.py\Z", re.ASCII)
_STAMP = (2020, 1, 1, 0, 0, 0)


def read_regular(path, limit):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("input_not_regular_file")
    if before.st_size > limit:
        raise ValueError("input_size_limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(str(path), flags)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("input_changed_during_read")
        content = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if len(content) > limit:
        raise ValueError("input_size_limit")
    if (after.st_size, after.st_mtime_ns, after.st_ino, after.st_dev) != (
            before.st_size, before.st_mtime_ns, before.st_ino, before.st_dev):
        raise ValueError("input_changed_during_read")
    return content


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _zip_write(archive, name, content, executable=False):
    entry = zipfile.ZipInfo(name, _STAMP)
    entry.create_system = 3
    entry.external_attr = ((0o100755 if executable else 0o100644) << 16)
    entry.compress_type = zipfile.ZIP_STORED
    archive.writestr(entry, content)


def _record_line(name, content):
    encoded = base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode("ascii")
    return "{},sha256={},{}\n".format(name, encoded, len(content))


def project_version():
    raw = read_regular(ROOT / "Cargo.toml", 100_000).decode("utf-8")
    match = _VERSION.search(raw)
    if not match:
        raise ValueError("project_version_unavailable")
    return match.group(1)


def collect_helpers():
    sources = {}
    total = 0
    folder = ROOT / "python"
    for candidate in sorted(folder.iterdir(), key=lambda p: p.name):
        if not _NAME.fullmatch(candidate.name):
            continue
        content = read_regular(candidate, MAX_HELPER_BYTES)
        total += len(content)
        if total > MAX_TOTAL_PY_BYTES:
            raise ValueError("python_source_budget_exceeded")
        sources[candidate.stem] = content
    if "abi_tags" not in sources or "static_quality" not in sources:
        raise ValueError("required_helpers_missing")
    if len(sources) > 128:
        raise ValueError("helper_count_limit")
    return sources


def build_wheel(version, sources):
    name = "rust_python_healer_helpers-{}-{}.whl".format(version, WHEEL_TAG)
    metadata = "rust_python_healer_helpers-{}.dist-info".format(version)
    records = {}
    records["rust_python_healer_helpers/__init__.py"] = (
        "\"\"\"Read-only Rust Python Healer helper collection.\"\"\"\n"
        "HELPER_MODULES = {}\n".format(repr(sorted(sources))).encode("utf-8"))
    for stem, content in sources.items():
        records["rust_python_healer_helpers/{}.py".format(stem)] = content
    records["rust_python_healer_cli/__init__.py"] = b"\"\"\"Rust Python Healer command entrypoint.\"\"\"\n"
    command = read_regular(ROOT / "packaging" / "wheel_cli.py", MAX_HELPER_BYTES)
    records["rust_python_healer_cli/__main__.py"] = command
    records["{}/WHEEL".format(metadata)] = (
        "Wheel-Version: 1.0\nGenerator: rust-python-healer-stdlib-offline\n"
        "Root-Is-Purelib: true\nTag: {}\n".format(WHEEL_TAG)).encode("utf-8")
    records["{}/METADATA".format(metadata)] = (
        "Metadata-Version: 2.1\nName: rust-python-healer-helpers\n"
        "Version: {}\nSummary: Offline CPython diagnostics helper collection\n"
        "Requires-Python: >=3.9, <3.16\n".format(version)).encode("utf-8")
    records["{}/entry_points.txt".format(metadata)] = (
        "[console_scripts]\nrph-python = rust_python_healer_cli.__main__:main\n"
    ).encode("utf-8")
    record_name = "{}/RECORD".format(metadata)
    record = "".join(_record_line(filename, content) for filename, content in sorted(records.items()))
    record += "{},,\n".format(record_name)
    records[record_name] = record.encode("ascii")
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED,
                         allowZip64=False) as output:
        for filename, content in sorted(records.items()):
            _zip_write(output, filename, content)
    return name, stream.getvalue(), len(sources)


def build_rust_archive(version, rust_binary):
    content = read_regular(rust_binary, MAX_RUST_BYTES)
    if not (content.startswith(b"\x7fELF") or content[:2] == b"MZ"
            or content[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
                                b"\xca\xfe\xba\xbe")):
        raise ValueError("rust_binary_format_unrecognized")
    # ELF is not synonymous with Linux. Only label the structure/architecture
    # we can infer from the header; never claim executable OS compatibility.
    label = ("elf_x86_64" if len(content) >= 20 and content[:6] == b"\x7fELF\x02\x01"
             and content[18:20] == b"\x3e\x00" else "platform_unverified")
    filename = "rust_python_healer-{}-{}.zip".format(version, label)
    notice = (
        "Existing Rust executable; NOT compiled or provenance-authenticated by this builder.\n"
        "Only run on compatible operating systems and architectures.\n"
    ).encode("ascii")
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED,
                         allowZip64=False) as output:
        _zip_write(output, "NOTICE.txt", notice)
        _zip_write(output, "bin/rust-python-healer.exe" if content[:2] == b"MZ" else "bin/rust-python-healer", content, executable=True)
    return filename, stream.getvalue()


def _write_unique(destination, content):
    with destination.open("xb") as stream:
        stream.write(content)


def build_release(output_directory, rust_binary):
    output = Path(output_directory)
    info = output.lstat()
    if not stat.S_ISDIR(info.st_mode):
        raise ValueError("output_not_real_directory")
    version = project_version()
    sources = collect_helpers()
    wheel_name, wheel_data, count = build_wheel(version, sources)
    rust_name, rust_data = build_rust_archive(version, rust_binary)
    launcher_data = read_regular(ROOT / "packaging" / "run_bundle.py", MAX_HELPER_BYTES)
    launcher_name = "run_bundle.py"
    hashes = {wheel_name: sha256(wheel_data), rust_name: sha256(rust_data),
              launcher_name: sha256(launcher_data)}
    manifest = {
        "schema": 1, "version": version,
        "python_wheel": wheel_name, "rust_archive": rust_name,
        "launcher": launcher_name, "sha256": hashes,
        "python_helper_modules": count,
        "offline": True, "global_install_performed": False,
        "rust_compiled_in_this_build": False,
        "provenance_authenticated": False, "native_compatibility_verified": False,
    }
    generated = {
        wheel_name: wheel_data, rust_name: rust_data,
        launcher_name: launcher_data,
        "release_manifest.json": (json.dumps(manifest, sort_keys=True,
                                             separators=(",", ":")) + "\n").encode("utf-8"),
        "SHA256SUMS": "".join("{}  {}\n".format(hashes[name], name)
                               for name in sorted(hashes)).encode("ascii"),
    }
    # Atomic non-clobbering creation. An existing output is a stop condition.
    if any((output / name).exists() or (output / name).is_symlink() for name in generated):
        raise ValueError("output_file_exists")
    for name, content in generated.items():
        _write_unique(output / name, content)
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline wheel + existing Rust executable release")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--rust-binary", required=True)
    args = parser.parse_args(argv)
    try:
        result = build_release(args.output_dir, args.rust_binary)
    except (OSError, UnicodeError, ValueError, zipfile.BadZipFile):
        print(json.dumps({"status": "NOT_BUILT", "reason": "invalid_input_or_output"}))
        return 2
    print(json.dumps({"status": "BUILT_OFFLINE_NOT_SIGNED", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
