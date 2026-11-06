"""Real, SHA-pinned PowerShell 7.5.13 fixed-fixture parser validation.

Only fixed benign fixtures are sent to official ``pwsh -NoProfile
-NonInteractive -Command``. Windows drive/UNC classification is lexical via
Python's two independent Windows-path parsers. Native Windows parser execution
is reported separately from actual drive/UNC filesystem access.
"""

import argparse
from contextlib import contextmanager, ExitStack
from functools import lru_cache
import importlib.util
import hashlib
import json
import ntpath
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import subprocess
import zipfile


POWER_SHELL_VERSION = "7.5.13"
OFFICIAL_ARCHIVE_SHA256 = "e9256bfc6ac98fcbec97270e8a986577a7346a587837cc80d30595eef3c2546b"
PINNED_RUNTIME_FILES = {
    "pwsh": "4fe2bf099c8d2678c0c144d198d1e4a8eb725231469988705eab9d0b5ca88a2a",
    "libcoreclr.so": "af38137cef9decdf8376cc520366245df44ad4b6050d17c13e9baba63ac3ef3d",
    "libhostpolicy.so": "3026f009e1e37bd54170105d3b9c0c7e966b5996f374805bd348b50c26232056",
    "System.Management.Automation.dll": "58f5532afecba0f5ca1e9d24c373db20241135c95551059efb0d436621d610e7",
}
WINDOWS_ARCHIVE_SHA256 = "120b8f0b04f3b3f6e8c351ddbe568bf596cdca15eeb2ecb7e724060051a36d65"
WINDOWS_RUNTIME_FILES = {
    "pwsh.exe": "be1a0cbecd77c913c364b8d9319e2a91cfedcf476efc219c2c5d864abe1e726b",
    "coreclr.dll": "03a85b6ba7087b41ac63f5c23c534074a4be81eaa23ac5aae9ed252c2c28dd1c",
    "hostpolicy.dll": "b60b311bd86d705fbd6f2a28c05f31f108833f467d3e7d99b5943e979c538c36",
    "System.Management.Automation.dll": "a8652d1b60502606e9214e709230f732d33366295d6063adf809f2eec249b63e",
}
MAX_SCRIPT_CHARS = 4096
MAX_OUTPUT_BYTES = 16_384
MAX_LITERAL = 1024
_RESERVED = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?\Z", re.I)

# No outside code, credentials, paths, arbitrary shell fragments or scripts
# are accepted. These intentionally contain PowerShell metacharacters.
TRUSTED_LITERAL_FIXTURES = {
    "ordinary": "literal-data-123",
    "nested_quotes": "O'Brien's file; 'do not execute'",
    "dollar_substitution": "$(throw 'INJECTION_NOT_ALLOWED')",
    "backtick_dollar": "`n $env:PATH ${user} # literal only",
    "pipe_semicolon": "Write-Output BAD; Get-Process | Out-Host",
    "unicode": "één été 你好 ♥",
    "drive_path": r"C:\Program Files\Python\python.exe",
    "unc_path": r"\\server\share\folder\file name.ps1",
}


def _runtime_root(root=None):
    if root is not None:
        return Path(root)
    override = os.environ.get("RPH_PINNED_POWERSHELL_ROOT")
    if override:
        return Path(override)
    location = globals().get("__file__")
    return Path(location).resolve().parents[2] / ("powershell-v23-win-x64" if os.name == "nt" else "powershell-v23") if isinstance(location, str) else None


@lru_cache(maxsize=1)
def _windows_privacy():
    injected = globals().get("_RPH_WINDOWS_PRIVACY")
    if injected is not None:
        return injected
    spec = importlib.util.spec_from_file_location("rph_pwsh_privacy", Path(__file__).with_name("windows_private_paths.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha_regular(path, max_bytes):
    previous = path.lstat()
    if not stat.S_ISREG(previous.st_mode) or previous.st_nlink != 1 or not (
            0 < previous.st_size <= max_bytes):
        raise ValueError("pinned_runtime_file_not_safe_regular")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = (_windows_privacy().open_private_readonly(path.absolute())
                  if os.name == "nt" else os.open(str(path), flags))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                previous.st_dev, previous.st_ino, previous.st_size, previous.st_mtime_ns):
            raise ValueError("pinned_runtime_file_changed")
        digest = hashlib.sha256()
        total = 0
        while True:
            part = os.read(descriptor, 1024 * 1024)
            if not part:
                break
            total += len(part)
            if total > max_bytes:
                raise ValueError("pinned_runtime_file_too_large")
            digest.update(part)
        after = os.fstat(descriptor)
        if (after.st_nlink != 1 or total != opened.st_size or
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise ValueError("pinned_runtime_file_changed")
        if os.name == "nt":
            _windows_privacy().assert_private_file_descriptor(descriptor)
        return digest.hexdigest()
    finally:
        os.close(descriptor)


@contextmanager
def _checked_windows_runtime(home):
    """Pin all ZIP members on read-only handles until child completion.

    Archive SHA is independently published by the official release. Every
    extracted member is compared to that authenticated archive. Leaf handles
    deny write/delete sharing; no ancestor or hostile-owner sandbox claimed.
    """
    privacy = _windows_privacy()
    import ctypes
    from ctypes import wintypes
    import msvcrt
    kernel, _security = privacy._libraries()
    kernel.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
        wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
        wintypes.BOOL, wintypes.DWORD]
    kernel.DuplicateHandle.restype = wintypes.BOOL
    privacy.assert_private_directory(home.absolute())
    privacy.assert_private_directory((home / "bin").absolute())
    for name, expected in WINDOWS_RUNTIME_FILES.items():
        if _sha_regular(home / "bin" / name, 128_000_000) != expected:
            raise ValueError("official_powershell_runtime_hash_mismatch")
    with ExitStack() as stack:
        held_directories = set()
        def hold_directory(path):
            location = str(path.absolute())
            if location in held_directories: return
            handle = kernel.CreateFileW(location, 0x00020080, 1, None, 3,
                                        0x02000000 | 0x00200000, None)
            if not handle or handle == ctypes.c_void_p(-1).value:
                raise ValueError("official_runtime_directory_pin_failed")
            stack.callback(kernel.CloseHandle, handle)
            privacy._inspect_private_handle(handle, True, kernel, _security)
            held_directories.add(location)
        hold_directory(home)
        hold_directory(home / "bin")
        def stream(path):
            descriptor = privacy.open_private_readonly(path.absolute())
            try:
                opened = os.fdopen(descriptor, "rb")
            except BaseException:
                os.close(descriptor)
                raise
            return stack.enter_context(opened)
        archive = stream(home / "PowerShell-7.5.13-win-x64.zip")
        if os.fstat(archive.fileno()).st_size > 160_000_000:
            raise ValueError("official_release_archive_size_rejected")
        digest = hashlib.sha256()
        while True:
            chunk = archive.read(1024 * 1024)
            if not chunk: break
            digest.update(chunk)
        if digest.hexdigest() != WINDOWS_ARCHIVE_SHA256:
            raise ValueError("official_release_archive_sha256_mismatch")
        archive.seek(0)
        package = stack.enter_context(zipfile.ZipFile(archive))
        members = [member for member in package.infolist() if not member.is_dir()]
        if not 1 <= len(members) <= 2048 or sum(member.file_size for member in members) > 1_000_000_000:
            raise ValueError("official_runtime_member_budget")
        expected_names = {member.filename for member in members}
        if len(expected_names) != len(members):
            raise ValueError("official_runtime_duplicate_member")
        actual_names = set()
        for folder, directories, files in os.walk(home / "bin", followlinks=False):
            hold_directory(Path(folder))
            for directory in directories:
                hold_directory(Path(folder) / directory)
            actual_names.update((Path(folder) / name).relative_to(home / "bin").as_posix() for name in files)
        if actual_names != expected_names:
            raise ValueError("official_runtime_member_set_mismatch")
        for member in members:
            parts = member.filename.split("/")
            if any(part in ("", ".", "..") or ":" in part or "\\" in part for part in parts):
                raise ValueError("official_runtime_member_name_invalid")
            target = stream(home / "bin" / member.filename)
            if os.fstat(target.fileno()).st_size != member.file_size:
                raise ValueError("official_powershell_runtime_hash_mismatch")
            observed, expected = hashlib.sha256(), hashlib.sha256()
            source = package.open(member)
            with source:
                while True:
                    left, right = target.read(1024 * 1024), source.read(1024 * 1024)
                    observed.update(left); expected.update(right)
                    if not left and not right: break
            if observed.digest() != expected.digest():
                raise ValueError("official_powershell_runtime_hash_mismatch")
            privacy.assert_private_file_descriptor(target.fileno())
            # Native duplicates preserve share locks without exhausting the
            # CRT's process-local fd limit on this 930-member distribution.
            held = wintypes.HANDLE()
            if not kernel.DuplicateHandle(wintypes.HANDLE(-1),
                    msvcrt.get_osfhandle(target.fileno()), wintypes.HANDLE(-1),
                    ctypes.byref(held), 0, False, 2):
                raise ValueError("official_runtime_handle_pin_failed")
            stack.callback(kernel.CloseHandle, held)
            target.close()
        yield {"status": "OFFICIAL_WINDOWS_POWERSHELL_COMPONENT_SHA256_VERIFIED",
               "pwsh_version": POWER_SHELL_VERSION,
               "trusted_official_binary_verified": True,
               "official_archive_sha256": WINDOWS_ARCHIVE_SHA256,
               "official_archive_rechecked": True,
               "runtime_component_hashes": dict(WINDOWS_RUNTIME_FILES),
               "all_archive_members_verified_and_held": len(members),
               "actual_windows_host": True,
               "publisher_signature_cryptographically_verified": False,
               "ancestor_sandbox_proven": False,
               "source_code_or_unknown_shell_script_executed": False}


def verify_official_pwsh(root=None, verify_archive=False):
    """Pin extracted binary+managed host/runtime and optional official tar."""
    home = _runtime_root(root)
    if home is None or not home.is_dir() or home.is_symlink():
        return {"status": "NOT_RUN_OFFICIAL_POWERSHELL_UNAVAILABLE",
                "trusted_official_binary_verified": False}
    bin_dir = home / "bin"
    if not bin_dir.is_dir() or bin_dir.is_symlink():
        raise ValueError("pinned_binary_directory_invalid")
    if os.name == "nt":
        with _checked_windows_runtime(home) as report:
            return report
    verified = {}
    for name, expected in PINNED_RUNTIME_FILES.items():
        candidate = bin_dir / name
        observed = _sha_regular(candidate, 128_000_000)
        if observed != expected:
            raise ValueError("official_powershell_runtime_hash_mismatch")
        verified[name] = observed
    archive_verified = False
    if verify_archive:
        archive = home / "powershell-7.5.13-linux-x64.tar.gz"
        archive_verified = _sha_regular(archive, 120_000_000) == OFFICIAL_ARCHIVE_SHA256
        if not archive_verified:
            raise ValueError("official_release_archive_sha256_mismatch")
    return {"status": "OFFICIAL_LINUX_POWERSHELL_COMPONENT_SHA256_VERIFIED",
            "pwsh_version": POWER_SHELL_VERSION,
            "trusted_official_binary_verified": True,
            "official_archive_sha256": OFFICIAL_ARCHIVE_SHA256,
            "official_archive_rechecked": archive_verified,
            "runtime_component_hashes": verified,
            "actual_windows_host": False,
            "publisher_signature_cryptographically_verified": False,
            "source_code_or_unknown_shell_script_executed": False}


def quote_ps_literal(value):
    """PowerShell single-quoted scalar data, not a script or command."""
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_LITERAL or any(
            ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError("unsafe_or_oversized_powershell_literal")
    encoded = value.replace("'", "''")
    if len(encoded) > MAX_LITERAL:
        raise ValueError("escaped_powershell_literal_quota")
    return "'" + encoded + "'"


def windows_lexical_oracles(value):
    """PureWindowsPath and ntpath must agree; never touch the Windows FS."""
    raw = value
    quote_ps_literal(raw)
    if "/" in raw or raw.startswith(("\\\\?\\", "\\\\.\\")) or any(
            part in (".", "..") for part in raw.split("\\")):
        raise ValueError("unsafe_windows_namespace_or_traversal")
    obj = PureWindowsPath(raw)
    if not obj.is_absolute() or not obj.drive or obj.name in ("", ".", ".."):
        raise ValueError("absolute_windows_file_path_required")
    expected = ntpath.normpath(raw)
    if expected != str(obj):
        raise ValueError("conflicting_windows_lexical_oracles")
    for part in obj.parts[1:]:
        if part.endswith((" ", ".")) or ":" in part or _RESERVED.fullmatch(part):
            raise ValueError("reserved_or_ambiguous_windows_filename")
    kind = "UNC" if obj.drive.startswith("\\\\") else "DRIVE"
    return {"status": "TWO_WINDOWS_LEXICAL_ORACLES_AGREE",
            "kind": kind, "drive": obj.drive,
            "independent_ntpath_and_purewindows_agree": True,
            "native_windows_path_executed": False,
            "real_windows_filesystem_verified": False}


def _fixed_runtime_process(script, root=None):
    if not isinstance(script, str) or len(script) > MAX_SCRIPT_CHARS:
        raise ValueError("fixed_script_size_rejected")
    fixed_scripts = {"[Console]::Out.Write($PSVersionTable.PSVersion.ToString())",
                     "$value = 'UNTERMINATED"}
    fixed_scripts.update(_literal_digest_script(key) for key in TRUSTED_LITERAL_FIXTURES)
    if script not in fixed_scripts:
        raise ValueError("unknown_powershell_script_never_executed")
    if os.name == "nt":
        home = _runtime_root(root)
        if home is None or not home.is_dir() or home.is_symlink():
            return {"status": "NOT_RUN_POWERSHELL_RUNTIME_UNAVAILABLE"}
        with _checked_windows_runtime(home):
            return _execute_fixed(script, home, "pwsh.exe")
    verified = verify_official_pwsh(root)
    if verified["status"] != "OFFICIAL_LINUX_POWERSHELL_COMPONENT_SHA256_VERIFIED":
        return {"status": "NOT_RUN_POWERSHELL_RUNTIME_UNAVAILABLE"}
    home = _runtime_root(root)
    return _execute_fixed(script, home, "pwsh")


def _execute_fixed(script, home, executable):
    args = [str(home / "bin" / executable), "-NoLogo", "-NoProfile", "-NonInteractive",
            "-Command", script]
    environment = None
    if os.name == "nt":
        # No inherited .NET startup hooks, extra dependency paths or profiles.
        environment = {"SystemRoot": os.environ["SystemRoot"], "PATH": os.defpath,
                       "PSModulePath": str(home / "bin" / "Modules"),
                       "POWERSHELL_TELEMETRY_OPTOUT": "1", "DOTNET_EnableDiagnostics": "0"}
    executed = subprocess.run(args, cwd=str(home / "bin"), stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=15, check=False, env=environment)
    if len(executed.stdout) > MAX_OUTPUT_BYTES or len(executed.stderr) > MAX_OUTPUT_BYTES:
        return {"status": "OUTPUT_QUOTA_EXCEEDED", "powershell_executed": True}
    return {"status": "REAL_POWERSHELL_PROCESS_OBSERVED",
            "returncode": executed.returncode,
            "stdout": executed.stdout.decode("utf-8", "replace").strip(),
            "stderr_type": "PARSE_OR_RUNTIME_ERROR" if executed.returncode else "NONE",
            "powershell_executed": True,
            "profile_loaded": False, "interactive": False,
            "untrusted_user_script_executed": False}


def probe_real_pwsh_version(root=None):
    script = "[Console]::Out.Write($PSVersionTable.PSVersion.ToString())"
    report = _fixed_runtime_process(script, root)
    ok = report.get("returncode") == 0 and report.get("stdout") == POWER_SHELL_VERSION
    return {"status": "REAL_OFFICIAL_POWERSHELL_7_5_13_EXECUTED" if ok else
            "NOT_VERIFIED_POWERSHELL_VERSION_OR_EXECUTION",
            "actual_pwsh_version": report.get("stdout") if ok else None,
            "powershell_child_executed": report.get("powershell_executed", False),
            "profile_loaded": False, "interactive": False,
            "real_windows_host": os.name == "nt" and ok}


def _literal_digest_script(fixture_id):
    if fixture_id not in TRUSTED_LITERAL_FIXTURES:
        raise ValueError("only_curated_powershell_fixture_allowed")
    literal = quote_ps_literal(TRUSTED_LITERAL_FIXTURES[fixture_id])
    return ("$v = " + literal + "; "
            "$bytes = [Text.Encoding]::UTF8.GetBytes($v); "
            "$digest = [Security.Cryptography.SHA256]::HashData($bytes); "
            "[Console]::Out.Write([Convert]::ToHexString($digest).ToLowerInvariant())")


def verify_real_literal(fixture_id, root=None):
    script = _literal_digest_script(fixture_id)
    observed = _fixed_runtime_process(script, root)
    target_sha = hashlib.sha256(TRUSTED_LITERAL_FIXTURES[fixture_id].encode("utf-8")).hexdigest()
    valid = observed.get("returncode") == 0 and observed.get("stdout") == target_sha
    return {"status": "REAL_POWERSHELL_LITERAL_PARSER_PROVED" if valid else
            "NOT_VERIFIED_POWERSHELL_LITERAL",
            "fixture_id": fixture_id,
            "sha256_match": bool(valid),
            "power_shell_engine_executed": observed.get("powershell_executed", False),
            "unknown_user_literal_or_script_executed": False,
            "actual_windows_host": os.name == "nt" and bool(valid),
            "original_data_echoed": False}


def verify_real_windows_path_fixture(fixture_id, root=None):
    if fixture_id not in ("drive_path", "unc_path"):
        raise ValueError("only_curated_windows_path_fixture_allowed")
    windows = windows_lexical_oracles(TRUSTED_LITERAL_FIXTURES[fixture_id])
    literal = verify_real_literal(fixture_id, root)
    success = literal["status"] == "REAL_POWERSHELL_LITERAL_PARSER_PROVED" and \
        windows["status"] == "TWO_WINDOWS_LEXICAL_ORACLES_AGREE"
    return {"status": "LOCAL_POWERSHELL_WINDOWS_LEXICAL_FIXTURE_PASS" if success else
            "INSUFFICIENT_WINDOWS_PATH_PARSER_EVIDENCE",
            "fixture_id": fixture_id, "windows_path_kind": windows["kind"],
            "real_powershell_quoting_parser_verified": literal["sha256_match"],
            "two_python_windows_path_oracles_agree": True,
            "actual_windows_filesystem_tested": False}


def parser_negative_unterminated_quote(root=None):
    """Real PowerShell must refuse a fixed malformed literal, execute nothing."""
    observed = _fixed_runtime_process("$value = 'UNTERMINATED", root)
    refused = observed.get("returncode") not in (0, None) and \
        observed.get("stdout") == ""
    return {"status": "REAL_POWERSHELL_UNTERMINATED_QUOTE_REJECTED" if refused else
            "PARSER_NEGATIVE_NOT_VERIFIED",
            "actual_powershell_parser_invoked": observed.get("powershell_executed", False),
            "malicious_script_executed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "version", "verify", "literal",
                                           "windows", "negative"), default="capabilities")
    parser.add_argument("--fixture", choices=sorted(TRUSTED_LITERAL_FIXTURES))
    parser.add_argument("--verify-archive", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.mode == "capabilities":
            result = {"status": "REAL_POWERSHELL_OPTIONAL_PINNED_ADAPTER",
                      "actual_powershell_parser_invoked": False,
                      "native_windows_host_verified": False,
                      "pwsh_runtime_required_for_capabilities": False,
                      "user_shell_script_executed": False,
                      "supported_real_parser_modes": ["version", "literal", "windows", "negative"],
                      "separate_live_sha256_verification_available": True}
        elif args.mode == "version":
            result = probe_real_pwsh_version()
        elif args.mode == "verify":
            result = verify_official_pwsh(verify_archive=args.verify_archive)
        elif args.mode == "literal":
            result = verify_real_literal(args.fixture)
        elif args.mode == "windows":
            result = verify_real_windows_path_fixture(args.fixture)
        else:
            result = parser_negative_unterminated_quote()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        result = {"status": "NOT_VERIFIED_OR_UNSAFE_INPUT_REFUSED",
                  "user_script_executed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"].endswith(("PASS", "VERIFIED", "PROVED", "REJECTED",
                                             "EXECUTED", "ADAPTER")) else 2


if __name__ == "__main__":
    raise SystemExit(main())
