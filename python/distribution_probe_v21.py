"""F245: actually install a preverified OWN wheel offline and check split artifacts.

Only the explicitly selected, built project release is touched; never install
packages from the internet or into global/site Python. Does not attest a real
publisher, other architectures, or macOS/Windows compatibility.
"""

import argparse
from contextlib import ExitStack
from functools import lru_cache
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile


MAX_MANIFEST = 16_000
MAX_WHEEL = 12 * 1024 * 1024
MAX_RUST_ARCHIVE = 64 * 1024 * 1024
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
WINDOWS_PIP_WHEEL_SHA256 = "9655943313a94722b7774661c21049070f6bbb0a1516bf02f7c8d5d9201514cd"


@lru_cache(maxsize=2)
def _windows_helper(kind):
    injection, filename = {"privacy": ("_RPH_WINDOWS_PRIVACY", "windows_private_paths.py"),
        "source": ("_RPH_WINDOWS_SECURITY", "windows_descriptor_security_v029.py")}[kind]
    module = globals().get(injection)
    if module is None:
        spec = importlib.util.spec_from_file_location("rph_distribution_" + kind, Path(__file__).with_name(filename))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


def _windows_pip_bootstrap(interpreter):
    configured = globals().get("_RPH_PINNED_PIP_WHEEL")
    wheel = Path(configured) if configured else Path(__file__).absolute().parents[1] / ".r6-pip-tools/pip-25.3-py3-none-any.whl"
    if _digest(_read_owned(wheel, MAX_WHEEL)) != WINDOWS_PIP_WHEEL_SHA256:
        raise ValueError("private_pip_tool_wheel_pin_mismatch")
    bootstrap = ("import sys,runpy;sys.path.insert(0,sys.argv.pop(1));"
                 "runpy.run_module('pip',run_name='__main__')")
    return [str(interpreter), "-I", "-S", "-B", "-c", bootstrap, str(wheel)]


def _read_owned(path, limit):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
        raise ValueError("unsafe_or_unbounded_release_item")
    if os.name == "nt":
        security = _windows_helper("source")
        opened = security.Root(path.absolute().parent)
        try:
            handle = security._open(opened.handles[0], path.name, False)
            opened.handles.append(handle)
            current = opened.blob._information(handle, False, limit)
            if current[0] != opened.identity[0]:
                raise ValueError("release_item_changed")
            return opened.read(handle, limit)
        finally:
            opened.close()
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        content = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if len(content) > limit or (before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError("release_item_changed")
    return content


def _digest(value):
    return hashlib.sha256(value).hexdigest()


def inspect_split_bundle(folder):
    folder = Path(folder)
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError("unsafe_release_directory")
    manifest = json.loads(_read_owned(folder / "release_manifest.json", MAX_MANIFEST))
    if not isinstance(manifest, dict) or not VERSION.fullmatch(str(manifest.get("version", ""))):
        raise ValueError("bad_release_manifest")
    if manifest.get("offline") is not True or manifest.get("global_install_performed") is not False:
        raise ValueError("release_is_not_offline")
    names = (manifest.get("python_wheel"), manifest.get("rust_archive"),
             manifest.get("launcher"))
    if not all(isinstance(name, str) and name == Path(name).name and name not in ("", ".")
               for name in names) or len(set(names)) != 3:
        raise ValueError("release_filenames_invalid")
    expected = manifest.get("sha256")
    if not isinstance(expected, dict) or set(expected) != set(names):
        raise ValueError("release_digests_missing")
    contents = {}
    for name, limit in zip(names, (MAX_WHEEL, MAX_RUST_ARCHIVE, 1_000_000)):
        if not isinstance(expected[name], str) or not HASH.fullmatch(expected[name]):
            raise ValueError("malformed_release_hash")
        content = _read_owned(folder / name, limit)
        if _digest(content) != expected[name]:
            raise ValueError("release_sha256_mismatch")
        contents[name] = content
    wheel, rust, launcher = names
    if (not wheel.endswith("-py3-none-any.whl") or
            manifest["version"] not in wheel or
            not rust.endswith("-elf_x86_64.zip") or
            launcher != "run_bundle.py"):
        raise ValueError("release_component_types_invalid")
    with zipfile.ZipFile(io.BytesIO(contents[wheel])) as archive:
        entries = archive.namelist()
        if len(entries) > 128 or sum(item.file_size for item in archive.infolist()) > 32_000_000:
            raise ValueError("unsafe_wheel_archive_quota")
        if not any(item.endswith(".dist-info/RECORD") for item in entries) or \
                "rust_python_healer_cli/__main__.py" not in entries:
            raise ValueError("invalid_python_wheel")
        if any(item.startswith("/") or ".." in Path(item).parts or
               entry.file_size > 2_000_000 for item, entry in (
                   (entry.filename, entry) for entry in archive.infolist())):
            raise ValueError("unsafe_wheel_members")
    with zipfile.ZipFile(io.BytesIO(contents[rust])) as archive:
        entries = archive.namelist()
        if set(entries) != {"NOTICE.txt", "bin/rust-python-healer"}:
            raise ValueError("unsafe_rust_archive_members")
        binary = archive.read("bin/rust-python-healer")
        if not binary.startswith(b"\x7fELF") or len(binary) > MAX_RUST_ARCHIVE:
            raise ValueError("not_verified_elf_release")
    return {"status": "SPLIT_OFFLINE_RELEASE_HASHES_VERIFIED",
            "version": manifest["version"], "wheel": wheel, "rust_archive": rust,
            "launcher": launcher, "rust_sha256": _digest(binary),
            "publisher_authenticated": False, "python_wheel_installed": False,
            "native_rust_execution_verified": False,
            "artifact_scope": "FROZEN_LOCAL_0_27_ELF_INSPECTION_ONLY" if os.name == "nt" else "LEGACY_SPLIT_LOCAL_ARTIFACTS",
            "source_executed": False}


def verify_offline_install(folder, interpreter, trusted_wheel_sha256):
    """Run pip offline only for an *independently pinned* own wheel digest."""
    report = inspect_split_bundle(folder)
    folder = Path(folder)
    if not isinstance(trusted_wheel_sha256, str) or not HASH.fullmatch(trusted_wheel_sha256):
        raise ValueError("out_of_band_trusted_wheel_sha256_required")
    if _digest(_read_owned(folder / report["wheel"], MAX_WHEEL)) != trusted_wheel_sha256:
        raise ValueError("wheel_does_not_match_independent_trust_pin")
    selected = str(interpreter)
    if not os.path.isabs(selected):
        selected = shutil.which(selected) or selected
    interpreter = Path(selected).resolve(strict=True)
    if not interpreter.is_file():
        raise ValueError("explicit_real_interpreter_required")
    with tempfile.TemporaryDirectory(prefix="rph-wheel-target-") as temp:
        destination = Path(temp) / "site"
        destination.mkdir()
        if os.name == "nt":
            _windows_helper("privacy").assert_private_directory(Path(temp).absolute())
            _windows_helper("privacy").assert_private_directory(destination.absolute())
        clean_env = {"PATH": os.environ.get("PATH", ""),
                     "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                     "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C", "TZ": "UTC"}
        if os.name == "nt":clean_env["SystemRoot"] = os.environ["SystemRoot"]
        pip = _windows_pip_bootstrap(interpreter) if os.name == "nt" else [str(interpreter), "-m", "pip"]
        staged = Path(temp) / report["wheel"]
        code = _read_owned(folder / report["wheel"], MAX_WHEEL)
        if _digest(code) != trusted_wheel_sha256:
            raise ValueError("wheel_does_not_match_independent_trust_pin")
        with staged.open("xb") as output:
            output.write(code); output.flush(); os.fsync(output.fileno())
        with ExitStack() as held:
            if os.name == "nt":
                descriptor = _windows_helper("privacy").open_private_readonly(staged.absolute())
                held.callback(os.close, descriptor)
                if _digest(_read_owned(staged, MAX_WHEEL)) != trusted_wheel_sha256:
                    raise ValueError("wheel_does_not_match_independent_trust_pin")
                pip_wheel = Path(pip[-1])
                descriptor = _windows_helper("privacy").open_private_readonly(pip_wheel.absolute())
                held.callback(os.close, descriptor)
                if _digest(_read_owned(pip_wheel, MAX_WHEEL)) != WINDOWS_PIP_WHEEL_SHA256:
                    raise ValueError("private_pip_tool_wheel_pin_mismatch")
            install = subprocess.run(pip + ["--isolated", "install",
                     "--no-index", "--no-deps", "--disable-pip-version-check",
                     "--no-compile", "--target", str(destination), str(staged)],
                     capture_output=True, timeout=45, env=clean_env, check=False)
        if install.returncode or len(install.stdout) > 50_000 or len(install.stderr) > 50_000:
            return {**report, "status": "NOT_RUN_OR_FAILED_OFFLINE_WHEEL_INSTALL",
                    "install_exit_code": install.returncode}
        target = destination / "rust_python_healer_helpers"
        if not target.is_dir() or not (destination / "rust_python_healer_cli").is_dir():
            raise ValueError("missing_split_python_components")
        checker = ("import sys;sys.path.insert(0,sys.argv[1]);"
                   "import rust_python_healer_helpers as h;"
                   "import rust_python_healer_cli.__main__ as c;"
                   "assert 'static_quality' in h.HELPER_MODULES;"
                   "assert callable(c.main);print('%d.%d'%sys.version_info[:2])")
        witness = subprocess.run([str(interpreter), "-I", "-S", "-B", "-c", checker,
                                  str(destination)], capture_output=True, timeout=15,
                                 env=clean_env, check=False)
        if witness.returncode or witness.stderr:
            raise ValueError("isolated_installed_cli_import_failed")
        minor = witness.stdout.decode("ascii").strip()
        report.update({"status": "OFFLINE_WHEEL_INSTALLED_TO_PRIVATE_TARGET",
                       "python_minor": minor, "python_wheel_installed": True,
                       "global_install_performed": False, "installer_used_network": False,
                       "owned_python_cli_imported": True,
                       "publisher_authenticated": False})
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", type=Path, required=True)
    parser.add_argument("--python", type=Path)
    parser.add_argument("--trusted-wheel-sha256")
    args = parser.parse_args()
    result = (verify_offline_install(args.release_dir, args.python,
                                     args.trusted_wheel_sha256)
              if args.python else inspect_split_bundle(args.release_dir))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
