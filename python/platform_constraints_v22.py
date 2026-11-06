"""Measured, fail-closed *local* platform checks on immutable trusted inputs.

This module is NOT an OS sandbox for arbitrary Python source and does not
claim to execute Windows, PowerShell, musl, or other CPU architectures.
F109 covers resource caps for fixed child fixtures only. F176 checks a
strict Windows path/PowerShell literal subset. F178 probes the running
Linux libc and ELF headers, and evaluates declared wheel platform policy.
"""

import argparse
import ctypes
import json
import ntpath
import os
from pathlib import Path, PureWindowsPath
import platform
import re
import selectors
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time


MAX_PATH_CHARS = 1024
MAX_ELF_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_BYTES = 4096
_WINDOWS_RESERVED = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?\Z",
                               flags=re.IGNORECASE)
_MANYLINUX = re.compile(r"manylinux_(\d{1,3})_(\d{1,3})_(x86_64|aarch64|i686)\Z")
_MUSLLINUX = re.compile(r"musllinux_(\d{1,3})_(\d{1,3})_(x86_64|aarch64|i686)\Z")
_ALIAS = {"manylinux2014_x86_64": (2, 17, "x86_64"),
          "manylinux2010_x86_64": (2, 12, "x86_64"),
          "manylinux1_x86_64": (2, 5, "x86_64")}
_ARCH_MACHINE = {3: "i686", 62: "x86_64", 183: "aarch64"}


def _strict_text(value, reason="invalid_text"):
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_PATH_CHARS:
        raise ValueError(reason)
    if any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF
           for c in value):
        raise ValueError(reason)
    return value


def inspect_windows_path(value):
    """Classify strict absolute paths lexically; no Windows filesystem claim."""
    raw = _strict_text(value, "unsafe_windows_path")
    if "/" in raw or raw.startswith(("\\\\?\\", "\\\\.\\")):
        raise ValueError("windows_namespace_or_separator_not_supported")
    if any(part in (".", "..") for part in raw.split("\\")):
        raise ValueError("original_windows_path_contains_traversal")
    pure = PureWindowsPath(raw)
    drive = pure.drive
    if raw.startswith("\\\\"):
        components = [part for part in raw.split("\\") if part]
        if len(components) < 3 or not pure.is_absolute() or not drive.startswith("\\\\"):
            raise ValueError("invalid_unc_share_or_path")
        kind = "UNC"
        if any(not part.strip(" .") for part in components):
            raise ValueError("empty_unc_component")
    else:
        if not re.fullmatch(r"[A-Za-z]:", drive) or not pure.is_absolute():
            raise ValueError("absolute_drive_path_required")
        kind = "DRIVE"
    if not raw.endswith("\\") and "\\\\" in raw[2:]:
        raise ValueError("duplicate_separator_rejected")
    parts = pure.parts[1:]
    if not parts:
        raise ValueError("file_component_required")
    for item in parts:
        if item in (".", "..") or item.endswith((" ", ".")) or ":" in item:
            raise ValueError("unsafe_windows_component")
        if _WINDOWS_RESERVED.fullmatch(item):
            raise ValueError("reserved_windows_device_name")
    # Two independent stdlib parsers must agree on drive and canonical form.
    normalized = ntpath.normpath(raw)
    if normalized != str(pure):
        raise ValueError("conflicting_windows_path_oracle")
    return {"status": "WINDOWS_PATH_LEXICALLY_VALIDATED_NOT_EXECUTED",
            "kind": kind, "normalized_path": normalized,
            "drive": drive, "file_components": len(parts),
            "powershell_or_windows_executed": False,
            "windows_filesystem_case_semantics_proven": False}


def quote_powershell_single_literal(value):
    """Encode one data literal, never construct a shell command or script."""
    raw = _strict_text(value, "unsafe_powershell_literal")
    if len(raw.replace("'", "''")) > MAX_PATH_CHARS:
        raise ValueError("powershell_literal_size_limit")
    return "'" + raw.replace("'", "''") + "'"


def decode_powershell_single_literal(literal):
    """Independent conservative PowerShell literal parser for round-trip tests."""
    raw = _strict_text(literal, "invalid_powershell_literal")
    if len(raw) < 2 or not raw.startswith("'") or not raw.endswith("'"):
        raise ValueError("invalid_powershell_literal")
    content = []
    position = 1
    while position < len(raw) - 1:
        if raw[position] == "'":
            if position + 1 >= len(raw) - 1 or raw[position + 1] != "'":
                raise ValueError("unescaped_powershell_quote")
            content.append("'")
            position += 2
        else:
            content.append(raw[position])
            position += 1
    return "".join(content)


def inspect_linux_libc():
    """Read the actual local Linux libc version, no native package import."""
    if sys.platform != "linux":
        return {"status": "NOT_SUPPORTED_NON_LINUX", "libc_verified": False}
    family = "UNKNOWN"
    version = None
    detection = "UNVERIFIED"
    try:
        library = ctypes.CDLL("libc.so.6")
        routine = library.gnu_get_libc_version
        routine.restype = ctypes.c_char_p
        raw = routine()
        if isinstance(raw, bytes) and re.fullmatch(rb"\d{1,3}\.\d{1,3}", raw):
            family, version, detection = "glibc", raw.decode("ascii"), "ACTUAL_GNU_LIBC_CALL"
    except (AttributeError, OSError, ValueError):
        name, discovered = platform.libc_ver()
        if name == "musl" and re.fullmatch(r"\d{1,3}\.\d{1,3}(?:\.\d+)?", discovered):
            family, version, detection = "musl", discovered, "RUNTIME_METADATA_NOT_ABI_PROOF"
    return {"status": "LOCAL_LIBC_PROBED" if version else "UNKNOWN_LIBC",
            "libc_family": family, "libc_version": version,
            "evidence": detection, "architecture": platform.machine().lower(),
            "local_runtime_only": True, "foreign_musl_execution_proven": False}


def compare_linux_wheel_policy(tag, runtime=None):
    """PEP600/656 local policy comparison; never import an extension."""
    tag = _strict_text(tag, "invalid_linux_wheel_tag")
    observed_locally = runtime is None
    if runtime is None:
        runtime = inspect_linux_libc()
    if not isinstance(runtime, dict) or runtime.get("status") not in (
            "LOCAL_LIBC_PROBED", "UNKNOWN_LIBC", "NOT_SUPPORTED_NON_LINUX"):
        return {"status": "INVALID_RUNTIME_METADATA", "compatibility": "UNKNOWN"}
    if tag in _ALIAS:
        major, minor, arch = _ALIAS[tag]
        family = "glibc"
    else:
        match = _MANYLINUX.fullmatch(tag)
        if match:
            major, minor, arch = int(match.group(1)), int(match.group(2)), match.group(3)
            family = "glibc"
        else:
            match = _MUSLLINUX.fullmatch(tag)
            if not match:
                return {"status": "INVALID_OR_UNSUPPORTED_LINUX_WHEEL_POLICY",
                        "compatibility": "UNKNOWN"}
            major, minor, arch = int(match.group(1)), int(match.group(2)), match.group(3)
            family = "musl"
    if runtime.get("status") != "LOCAL_LIBC_PROBED":
        match_result = "UNKNOWN"
    elif arch != runtime.get("architecture") or family != runtime.get("libc_family"):
        match_result = "MISMATCH"
    else:
        try:
            current = tuple(int(part) for part in runtime["libc_version"].split(".")[:2])
        except (ValueError, AttributeError, KeyError):
            current = None
        match_result = ("MATCH_LOCAL_POLICY_ONLY" if current is not None and
                        current >= (major, minor) else "MISMATCH" if current is not None
                        else "UNKNOWN")
    return {"status": "LOCAL_WHEEL_POLICY_COMPARED" if observed_locally else
            "CALLER_SUPPLIED_POLICY_HYPOTHESIS_NOT_ATTESTED",
            "compatibility": match_result,
            "tag": tag, "declared_family": family, "declared_min_libc": "{}.{}".format(major, minor),
            "declared_arch": arch, "runtime_evidence": runtime.get("evidence"),
            "native_import_verified": False, "artifact_attested": False,
            "musl_runtime_actually_tested": observed_locally and
            runtime.get("libc_family") == "musl" and
            runtime.get("status") == "LOCAL_LIBC_PROBED"}


def inspect_local_elf(path):
    """Bounded descriptor-bound ELF64 read; never loads the supplied binary."""
    supplied = Path(path)
    before = supplied.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_ELF_BYTES:
        raise ValueError("unsafe_elf_input_type_or_size")
    fd = os.open(str(supplied), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        after = os.fstat(fd)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            raise ValueError("elf_changed_between_check_and_open")
        header = os.read(fd, 64)
        if len(header) < 64 or not header.startswith(b"\x7fELF"):
            return {"status": "NOT_ELF", "binary_executed": False}
        if header[4] != 2 or header[5] not in (1, 2) or header[6] != 1:
            return {"status": "UNSUPPORTED_ELF_FORMAT", "binary_executed": False}
        endian = "<" if header[5] == 1 else ">"
        machine = struct.unpack(endian + "H", header[18:20])[0]
        e_type = struct.unpack(endian + "H", header[16:18])[0]
        architecture = _ARCH_MACHINE.get(machine, "UNKNOWN_MACHINE")
        runtime_arch = platform.machine().lower()
        if runtime_arch == "amd64":
            runtime_arch = "x86_64"
        return {"status": "ELF64_HEADER_INSPECTED_NOT_LOADED",
                "architecture": architecture, "runtime_architecture": runtime_arch,
                "compatible_architecture": architecture == runtime_arch,
                "elf_type": e_type, "machine_id": machine,
                "sha256_authenticated": False, "binary_executed": False,
                "dynamic_deps_verified": False, "libc_abi_verified": False}
    finally:
        os.close(fd)


_GUARDED_SCRIPT = r'''
import os, resource, sys
resource.setrlimit(resource.RLIMIT_CPU, (1, 2))
resource.setrlimit(resource.RLIMIT_AS, (96 * 1024 * 1024, 96 * 1024 * 1024))
resource.setrlimit(resource.RLIMIT_FSIZE, (512, 512))
resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
mode = sys.argv[1]
if mode == "safe":
    sys.stdout.write("SAFE_FIXED_WORKLOAD")
elif mode == "cpu":
    while True:
        pass
elif mode == "ram":
    try:
        chunk = bytearray(512 * 1024 * 1024)
        sys.exit(71)
    except MemoryError:
        sys.exit(43)
elif mode == "file":
    try:
        with open(sys.argv[2], "wb") as target:
            target.write(b"x" * 4096)
        sys.exit(71)
    except OSError:
        sys.exit(44)
elif mode == "fd":
    holders = []
    try:
        for _ in range(128):
            holders.append(open(os.devnull, "rb"))
        sys.exit(71)
    except OSError:
        sys.exit(45)
elif mode == "stdout":
    while True:
        sys.stdout.buffer.write(b"Q" * 1024)
        sys.stdout.flush()
'''


def run_guarded_fixture(mode, timeout_seconds=4, output_quota=MAX_OUTPUT_BYTES):
    """Real Linux RLIMIT/pipe quotas for fixed program, not arbitrary source."""
    if mode not in ("safe", "cpu", "ram", "file", "fd", "stdout"):
        raise ValueError("unknown_trusted_fixture_not_executed")
    if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool) or not (
            2 <= timeout_seconds <= 8):
        raise ValueError("invalid_fixture_timeout")
    if not isinstance(output_quota, int) or isinstance(output_quota, bool) or not (
            128 <= output_quota <= MAX_OUTPUT_BYTES):
        raise ValueError("invalid_output_quota")
    if sys.platform != "linux":
        return {"status": "NOT_SUPPORTED_NON_LINUX", "unknown_source_executed": False}
    with tempfile.TemporaryDirectory(prefix="rph-fixed-limits-") as folder:
        outfile = str(Path(folder) / "fixture.bin")
        process = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c",
                                    _GUARDED_SCRIPT, mode, outfile],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, close_fds=True,
                                   cwd=folder)
        caught = bytearray()
        watched = selectors.DefaultSelector()
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            watched.register(stream, selectors.EVENT_READ)
        observed_bytes = 0
        quota_exceeded = False
        deadline = time.monotonic() + float(timeout_seconds)
        try:
            while watched.get_map() and time.monotonic() < deadline:
                for event, _ in watched.select(timeout=0.05):
                    chunk = os.read(event.fileobj.fileno(), max(1, output_quota + 1))
                    if not chunk:
                        watched.unregister(event.fileobj)
                        continue
                    observed_bytes += len(chunk)
                    if len(caught) < output_quota:
                        caught.extend(chunk[:output_quota - len(caught)])
                    if observed_bytes > output_quota:
                        quota_exceeded = True
                        process.kill()
                        break
                if quota_exceeded:
                    break
            if process.poll() is None and time.monotonic() >= deadline:
                process.kill()
                timed_out = True
            else:
                timed_out = False
            process.wait(timeout=2)
        finally:
            watched.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            process.stdout.close()
            process.stderr.close()
        code = process.returncode
        if mode == "safe":
            triggered = code == 0 and b"SAFE_FIXED_WORKLOAD" in caught
        elif mode == "cpu":
            triggered = code in (-signal.SIGXCPU, -signal.SIGKILL) and not timed_out
        elif mode == "ram":
            triggered = code == 43
        elif mode == "file":
            triggered = code in (44, -signal.SIGXFSZ)
        else:
            triggered = quota_exceeded and code in (-signal.SIGKILL, -signal.SIGTERM)
        if mode == "fd":
            triggered = code == 45
        written_size = os.path.getsize(outfile) if os.path.exists(outfile) else 0
        return {"status": "FIXED_LINUX_RESOURCE_GATE_VERIFIED" if triggered else
                "NOT_VERIFIED_RESOURCE_GATE",
                "mode": mode, "returncode": code,
                "limit_tripped_or_safe_completed": triggered,
                "stdout_stderr_total_observed_bytes": observed_bytes,
                "output_quota_exceeded": quota_exceeded,
                "timeout_kill_used": timed_out,
                "rlimit_cpu_seconds": 1, "rlimit_address_space_mib": 96,
                "rlimit_file_bytes": 512, "stdout_stderr_quota_bytes": output_quota,
                "fixture_disk_bytes_written": written_size,
                "rlimit_open_file_descriptors": 32,
                "network_isolation_proven": False,
                "arbitrary_user_source_sandboxed": False,
                "unknown_source_executed": False,
                "full_disk_read_io_limit_proven": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("limits", "windows", "linux"), required=True)
    parser.add_argument("--fixture", choices=("safe", "cpu", "ram", "file", "fd", "stdout"),
                        default="safe")
    parser.add_argument("--path")
    parser.add_argument("--platform-tag")
    args = parser.parse_args(argv)
    try:
        if args.mode == "limits":
            result = run_guarded_fixture(args.fixture)
        elif args.mode == "windows":
            result = inspect_windows_path(args.path)
            result["powershell_quoted_data"] = quote_powershell_single_literal(args.path)
        else:
            result = {"status": "LOCAL_LINUX_PLATFORM_DIAGNOSTICS",
                      "runtime": inspect_linux_libc()}
            if args.platform_tag:
                result["wheel_policy"] = compare_linux_wheel_policy(args.platform_tag)
            if args.path:
                result["elf_header"] = inspect_local_elf(args.path)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "REFUSED", "reason": str(error),
                          "unknown_source_executed": False}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
