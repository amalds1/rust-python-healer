"""Offline verification of *actual* PyPI/Sigstore PEP 740 and OSV evidence.

The original sampleproject wheel was downloaded from PyPI only after obtaining
its SHA256 from the PyPI JSON API, and its provenance from the PyPI Integrity
API. Sigstore's production TUF root was fetched by the official verifier.
All evidence hashes are now pinned. Runtime NEVER downloads, installs, imports
project code, contacts OSV, or treats unsigned metadata as publisher trust.

The SBOM inventories bounded *local* Python/Cargo dependency metadata; the
OSV snapshot is for a deliberately vulnerable **fixture**, urllib3 1.25.8,
not a complete vulnerability audit of every SBOM component. Publisher
verification is genuine but applies only to the pinned sampleproject wheel.
"""

import argparse
from contextlib import ExitStack
from functools import lru_cache
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess


PINNED = {
    "wheel": "c23e447ea90d796d1e645c35c4b2de125040add12a845825546f91c93f391b6b",
    "provenance": "418da7504bfb4e28f8ec2bdbbea158f785ffc4746fe48b87c7407e252e74c441",
    "tuf_root": "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66",
    "osv": "3085865a57bc29c2f4bc33bc4fc714f1b802d48a03fa2571a070a499907ca112",
}
OFFICIAL_REPOSITORY = "https://github.com/pypa/sampleproject"
WHEEL_FILE = "sampleproject-4.0.0-py3-none-any.whl"
PROVENANCE_FILE = "sampleproject-4.0.0.provenance.json"
OSV_FILE = "osv-urllib3-1.25.8.json"
TRUSTED_ROOT_RELATIVE = ("cache/sigstore-python/tuf/"
                         "https%3A%2F%2Ftuf-repo-cdn.sigstore.dev/trusted_root.json")
MAX_EVIDENCE_BYTES = 2_000_000
MAX_CARGO_BYTES = 4_000_000
MAX_SBOM_COMPONENTS = 2_000
MAX_STDOUT_BYTES = 100_000
WINDOWS_R6_PROFILE_FILE = "windows-r6-supply-profile.json"
WINDOWS_R6_PROFILE_SHA256 = "cebfe72eb4832a376e0021e6ae4f7761941f6f8b8ca60d16ad35a6db75d81c96"
WINDOWS_VERIFIER_MANIFEST = "r6-primary-verifier-manifest.json"
WINDOWS_VERIFIER_MANIFEST_SHA256 = "02ca92e928144934748695b995beaa9185e2fb31c4b8206489828b39968cc343"


def _hold_verified_windows_verifier(tools, root, stack):
    """Authenticate and retain SDK files; this does not authenticate the Python executable."""
    import ctypes
    from ctypes import wintypes
    import msvcrt
    privacy = _windows_helper("privacy")
    security = _windows_helper("source")
    kernel, _ = privacy._libraries()
    kernel.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
        wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
        wintypes.BOOL, wintypes.DWORD]
    kernel.DuplicateHandle.restype = wintypes.BOOL
    directories = set()

    def hold_directory(directory):
        if directory in directories:
            return
        privacy.assert_private_directory(directory.absolute())
        opened = security.Root(directory)
        stack.callback(opened.close)
        directories.add(directory)

    def hold_file(path, expected):
        hold_directory(path.parent)
        fd = privacy.open_private_readonly(path.absolute())
        try:
            with os.fdopen(fd, "rb", closefd=False) as stream:
                digest = hashlib.sha256()
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk: break
                    digest.update(chunk)
            privacy.assert_private_file_descriptor(fd)
            if digest.hexdigest() != expected:
                raise ValueError("official_verifier_component_sha256_mismatch")
            handle = wintypes.HANDLE()
            if not kernel.DuplicateHandle(wintypes.HANDLE(-1), msvcrt.get_osfhandle(fd),
                    wintypes.HANDLE(-1), ctypes.byref(handle), 0, False, 2):
                raise ValueError("official_verifier_handle_pin_failed")
            stack.callback(kernel.CloseHandle, handle)
        finally:
            os.close(fd)

    hold_directory(tools)
    manifest = tools / WINDOWS_VERIFIER_MANIFEST
    hold_file(manifest, WINDOWS_VERIFIER_MANIFEST_SHA256)
    expected = json.loads(_hashed(manifest, WINDOWS_VERIFIER_MANIFEST_SHA256))["all_installed_file_sha256"]
    if len(expected) != 1542:
        raise ValueError("official_verifier_manifest_count_mismatch")
    for name, digest in expected.items():
        pieces = name.split("/")
        if any(piece in ("", ".", "..") or ":" in piece or "\\" in piece for piece in pieces):
            raise ValueError("official_verifier_manifest_path_invalid")
        for count in range(1, len(pieces)):
            hold_directory(tools.joinpath(*pieces[:count]))
        hold_file(tools.joinpath(*pieces), digest)
    actual = {p.relative_to(tools).as_posix() for p in tools.rglob("*") if not p.is_dir()}
    if actual != set(expected) | {WINDOWS_VERIFIER_MANIFEST}:
        raise ValueError("official_verifier_unexpected_file")
    actual_directories = {p for p in tools.rglob("*") if p.is_dir()}
    if actual_directories != directories - {tools}:
        raise ValueError("official_verifier_unexpected_directory")
    # Bind the *actual* Windows SDK cache, not the historical XDG-only path.
    cache = root / "cache/windows-local/sigstore/sigstore-python/Cache/tuf/https%3A%2F%2Ftuf-repo-cdn.sigstore.dev"
    for directory in reversed([cache] + list(cache.parents)[:7]):
        if directory == root: continue
        if not directory.exists(): directory.mkdir()
        hold_directory(directory)
    for name in ("trusted_root.json", "signing_config.v0.2.json"):
        source = tools / "sigstore/_store/https%3A%2F%2Ftuf-repo-cdn.sigstore.dev" / name
        raw = _read_file(source, MAX_EVIDENCE_BYTES)
        target = cache / name
        if not target.exists():
            with target.open("xb") as stream:
                stream.write(raw)
        hold_file(target, hashlib.sha256(raw).hexdigest())


@lru_cache(maxsize=2)
def _windows_helper(kind):
    injected, filename = {"privacy": ("_RPH_WINDOWS_PRIVACY", "windows_private_paths.py"),
        "source": ("_RPH_WINDOWS_SECURITY", "windows_descriptor_security_v029.py")}[kind]
    module = globals().get(injected)
    if module is None:
        spec = importlib.util.spec_from_file_location("rph_supply_" + kind, Path(__file__).with_name(filename))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


def windows_r6_profile(evidence_root):
    raw = _hashed(Path(evidence_root) / WINDOWS_R6_PROFILE_FILE, WINDOWS_R6_PROFILE_SHA256)
    profile = json.loads(raw)
    if (profile.get("schema") != "WINDOWS_R6_SUPPLY_SCOPE_V1" or
            profile.get("legacy_snapshot_replay_status") != "HOLD_ORIGINAL_OSV_BYTES_UNAVAILABLE"):
        raise ValueError("wrong_windows_r6_supply_scope")
    return profile


def active_pins(evidence_root):
    return windows_r6_profile(evidence_root)["artifact_pins"] if os.name == "nt" else dict(PINNED)


def active_osv_file(evidence_root):
    return windows_r6_profile(evidence_root)["osv_fixture_file"] if os.name == "nt" else OSV_FILE


def _private_dir(p):
    path = Path(p)
    if not path.is_dir() or path.is_symlink():
        raise ValueError("private_evidence_or_tool_root_required")
    if os.name == "nt":
        try:
            _windows_helper("privacy").assert_private_directory(path.absolute())
        except (ValueError, OSError):
            raise ValueError("private_evidence_or_tool_root_required") from None
    elif path.stat().st_mode & 0o077:
        raise ValueError("private_evidence_or_tool_root_required")
    return path.absolute()


def _read_file(p, limit):
    file = Path(p)
    info = file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
        raise ValueError("unsafe_or_oversize_evidence_file")
    if os.name == "nt":
        security = _windows_helper("source")
        opened = security.Root(file.absolute().parent)
        try:
            handle = security._open(opened.handles[0], file.name, False)
            opened.handles.append(handle)
            current = opened.blob._information(handle, False, limit)
            if current[0] != opened.identity[0]:
                raise ValueError("evidence_file_changed_during_read")
            return opened.read(handle, limit)
        finally:
            opened.close()
    fd = os.open(str(file), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        if os.fstat(fd).st_ino != info.st_ino:
            raise ValueError("evidence_file_changed_during_read")
        with os.fdopen(fd, "rb", closefd=False) as data:
            value = data.read(limit + 1)
        if len(value) > limit:
            raise ValueError("evidence_file_exceeds_budget")
        return value
    finally:
        os.close(fd)


def _hashed(p, digest, limit=MAX_EVIDENCE_BYTES):
    value = _read_file(p, limit)
    if hashlib.sha256(value).hexdigest() != digest:
        raise ValueError("official_evidence_sha256_mismatch")
    return value


def _tool_preflight(tool_root):
    root = _private_dir(tool_root)
    for package, version in (("pypi_attestations", "0.0.30"), ("sigstore", "4.5.1")):
        folders = list(root.glob(package + "-*.dist-info"))
        if len(folders) != 1 or folders[0].is_symlink():
            raise ValueError("official_verifier_installed_metadata_missing")
        meta = _read_file(folders[0] / "METADATA", 500_000)
        pkg_name = package.replace("_", "-")
        if (len(re.findall(rb"(?m)^Name: " + pkg_name.encode() + rb"\r?$", meta, re.I)) != 1 or
                len(re.findall(rb"(?m)^Version: " + version.encode() + rb"\r?$", meta)) != 1):
            raise ValueError("official_verifier_version_pin_mismatch")
    # The actual offline verifier bootstraps this packaged production anchor.
    # Its exact bytes also match the separately fetched official root-signing source.
    _hashed(root / "sigstore/_store/https%3A%2F%2Ftuf-repo-cdn.sigstore.dev/trusted_root.json", PINNED["tuf_root"])
    return root


def _check_evidence(evidence_root):
    root = _private_dir(evidence_root)
    pins = active_pins(root)
    wheel = root / WHEEL_FILE
    provenance = root / PROVENANCE_FILE
    _hashed(wheel, pins["wheel"])
    raw_provenance = _hashed(provenance, pins["provenance"])
    _hashed(root / TRUSTED_ROOT_RELATIVE, pins["tuf_root"])
    osv = json.loads(_hashed(root / active_osv_file(root), pins["osv"]))
    attestation = json.loads(raw_provenance)
    bundles = attestation.get("attestation_bundles")
    if type(bundles) is not list or len(bundles) != 1:
        raise ValueError("pypi_attestation_bundle_count_mismatch")
    bundle = bundles[0]
    if (bundle.get("publisher", {}).get("repository") != "pypa/sampleproject" or
            bundle.get("publisher", {}).get("kind") != "GitHub"):
        raise ValueError("pypi_trusted_publisher_identity_mismatch")
    attestations = bundle.get("attestations")
    if type(attestations) is not list or len(attestations) != 1:
        raise ValueError("pypi_pep740_attestation_missing")
    attestation = attestations[0]
    material = attestation.get("verification_material", {})
    if ("certificate" not in material or
            not material.get("transparency_entries") or
            "envelope" not in attestation):
        raise ValueError("dsse_fulcio_rekor_material_missing")
    vulns = osv.get("vulns")
    if type(vulns) is not list or not vulns:
        raise ValueError("osv_official_advisory_snapshot_missing")
    ids = set()
    for vuln in vulns:
        if type(vuln) is not dict or not re.fullmatch(r"[A-Za-z0-9-]{6,100}", vuln.get("id", "")):
            raise ValueError("invalid_official_osv_vulnerability_id")
        if not any(type(a) is dict and type(a.get("package")) is dict and
                   a["package"].get("name") == "urllib3" and
                   a["package"].get("ecosystem") == "PyPI"
                   for a in vuln.get("affected", [])):
            raise ValueError("osv_advisory_for_unexpected_package")
        ids.add(vuln["id"])
    if len(ids) != len(vulns):
        raise ValueError("duplicate_official_osv_vulnerability_id")
    return {"root": root, "wheel": wheel, "provenance": provenance,
            "osv_advisory_ids": sorted(ids), "osv_advisory_count": len(ids)}


def _verify_official_offline(evidence_root, tool_root, checker_python, *,
                             wheel=None, provenance=None,
                             repository=OFFICIAL_REPOSITORY):
    """Execute the official Sigstore production verifier, not a homegrown ECDSA check."""
    root = _private_dir(evidence_root)
    tools = _tool_preflight(tool_root)
    command = [str(checker_python), "-B", "-m", "pypi_attestations", "verify", "pypi",
               "--offline", "--repository", repository, "--provenance-file",
               str(Path(provenance or (root / PROVENANCE_FILE)).absolute()),
               str(Path(wheel or (root / WHEEL_FILE)).absolute())]
    bootstrap = "import sys,runpy;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('pypi_attestations',run_name='__main__')"
    command = [str(checker_python), "-I", "-S", "-B", "-c", bootstrap, str(tools)] + command[4:]
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "PYTHONPATH": str(tools),
           "XDG_CACHE_HOME": str(root / "cache"),
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}
    if os.name == "nt":
        env["SystemRoot"] = os.environ["SystemRoot"]
        env["LOCALAPPDATA"] = str(root / "cache/windows-local")
        env["APPDATA"] = str(root / "cache/windows-roaming")
        env["WIN_PD_OVERRIDE_LOCAL_APPDATA"] = env["LOCALAPPDATA"]
    try:
        with ExitStack() as held:
            if os.name == "nt":
                _hold_verified_windows_verifier(tools, root, held)
                for path in (Path(wheel or (root / WHEEL_FILE)), Path(provenance or (root / PROVENANCE_FILE)), root / TRUSTED_ROOT_RELATIVE):
                    descriptor = _windows_helper("privacy").open_private_readonly(path.absolute())
                    held.callback(os.close, descriptor)
                if wheel is None: _hashed(root / WHEEL_FILE, PINNED["wheel"])
                if provenance is None: _hashed(root / PROVENANCE_FILE, PINNED["provenance"])
                _hashed(root / TRUSTED_ROOT_RELATIVE, PINNED["tuf_root"])
            result = subprocess.run(command, env=env, cwd=str(root),
                                    capture_output=True, check=False, timeout=25)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("official_sigstore_verifier_failed_to_run") from exc
    if len(result.stdout) + len(result.stderr) > MAX_STDOUT_BYTES:
        raise ValueError("official_sigstore_verifier_output_too_large")
    # The official CLI sends human verification messages to stderr via its
    # logging layer, even on success; both streams are bounded and checked.
    accepted = (result.returncode == 0 and
                b"OK: " + WHEEL_FILE.encode() in result.stdout + result.stderr)
    return {"accepted": accepted, "exit_code": result.returncode,
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
            "real_official_sigstore_cli_executed": True,
            "sigstore_production_tuf_offline": True}


def _parse_cargo(raw):
    try:
        import tomllib as toml
    except ImportError:
        try:
            import tomli as toml
        except ImportError:
            try:
                from pip._vendor import tomli as toml
            except ImportError:
                # Python 3.9/3.10 with -I -S has no tomllib, tomli, or pip.
                # The fixed Cargo.lock v4 subset has unquoted section markers
                # and simple string fields. Parse *only* name/version/source/
                # checksum, rejecting duplicate or incomplete records; ignore
                # dependency arrays rather than implementing arbitrary TOML.
                source = raw.decode("utf-8")
                chunks = re.split(r"(?m)^\[\[package\]\]\s*$", source)
                if len(chunks) < 2 or not re.search(r"(?m)^version\s*=\s*4\s*$", chunks[0]):
                    raise ValueError("unsupported_cargo_lock_format_without_toml")
                packages = []
                for chunk in chunks[1:]:
                    fields = re.findall(
                        r'(?m)^(name|version|source|checksum)\s*=\s*"([^"\r\n]{1,250})"\s*$',
                        chunk)
                    if len(set(k for k, _ in fields)) != len(fields):
                        raise ValueError("duplicate_cargo_package_field")
                    record = dict(fields)
                    if not all(key in record for key in ("name", "version")):
                        raise ValueError("cargo_package_identity_required")
                    packages.append(record)
                return {"package": packages}
    return toml.loads(raw.decode("utf-8"))


def _sbom(repository_root, tool_root):
    project = Path(repository_root)
    if not project.is_dir() or project.is_symlink():
        raise ValueError("repository_root_unavailable")
    cargo = _parse_cargo(_read_file(project / "Cargo.lock", MAX_CARGO_BYTES))
    crates = cargo.get("package")
    if type(crates) is not list or not crates:
        raise ValueError("cargo_lock_has_no_dependencies")
    components = []
    for record in crates:
        if type(record) is not dict or not all(
                isinstance(record.get(k), str) for k in ("name", "version")):
            raise ValueError("invalid_cargo_lock_package_metadata")
        if record.get("source", "").startswith("registry+"):
            checksum = record.get("checksum")
            if not isinstance(checksum, str) or re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
                raise ValueError("unverified_cargo_registry_checksum")
        components.append({"ecosystem": "crates.io", "name": record["name"],
                           "version": record["version"],
                           "package_digest": record.get("checksum"),
                           "provenance_verified": False})
    tools = _tool_preflight(tool_root)
    for folder in sorted(tools.glob("*.dist-info")):
        metadata = _read_file(folder / "METADATA", 500_000).decode("utf-8")
        names = re.findall(r"(?m)^Name:[ \t]*(\S+)\r?$", metadata)
        versions = re.findall(r"(?m)^Version:[ \t]*(\S+)\r?$", metadata)
        if len(names) != 1 or len(versions) != 1:
            raise ValueError("invalid_installed_python_wheel_metadata")
        components.append({"ecosystem": "PyPI", "name": names[0],
                           "version": versions[0],
                           "metadata_sha256": hashlib.sha256(metadata.encode()).hexdigest(),
                           "provenance_verified": False})
    if not 1 <= len(components) <= MAX_SBOM_COMPONENTS:
        raise ValueError("sbom_component_budget")
    return sorted(components, key=lambda c: (c["ecosystem"], c["name"], c["version"]))


def verify_pinned_evidence(repository_root, evidence_root, verifier_tool_root,
                           verifier_python):
    evidence = _check_evidence(evidence_root)
    pins = active_pins(evidence_root)
    verification = _verify_official_offline(evidence_root, verifier_tool_root, verifier_python)
    if not verification["accepted"]:
        raise ValueError("official_fulcio_rekor_verifier_rejected")
    components = _sbom(repository_root, verifier_tool_root)
    return {"status": "OFFICIAL_PYPI_SIGSTORE_AND_BOUNDED_OSV_SBOM_VERIFIED",
            "pypi_attestation_verification": verification,
            "attested_wheel": WHEEL_FILE,
            "expected_trusted_publisher": OFFICIAL_REPOSITORY,
            "verified_official_root_sha256": PINNED["tuf_root"],
            "wheel_sha256": PINNED["wheel"],
            "provenance_sha256": PINNED["provenance"],
            "osv_snapshot_sha256": pins["osv"],
            "evidence_scope": "WINDOWS_R6_RESTORED_PYPI_NEW_OSV" if os.name == "nt" else "LEGACY_V23_PINNED_LINUX",
            "legacy_osv_snapshot_replayed": False if os.name == "nt" else True,
            "osv_fixture": "PyPI urllib3==1.25.8",
            "osv_fixture_advisory_count": evidence["osv_advisory_count"],
            "osv_fixture_advisory_ids": evidence["osv_advisory_ids"],
            "sbom_components": components,
            "sbom_count": len(components),
            "sbom_covers_all_rust_python_dependencies": False,
            "full_independent_cve_audit_proven": False,
            "verified_other_package_publishers": False,
            "project_or_package_code_executed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "verify"), default="capabilities")
    parser.add_argument("--project")
    parser.add_argument("--evidence")
    parser.add_argument("--tool-root")
    parser.add_argument("--verifier-python")
    args = parser.parse_args(argv)
    try:
        if args.mode == "capabilities":
            result = {"status": "OFFICIAL_SUPPLY_CHAIN_VERIFIER_ADAPTER_AVAILABLE",
                      "network_performed": False, "external_verifier_executed": False}
        else:
            result = verify_pinned_evidence(args.project, args.evidence,
                                            args.tool_root, args.verifier_python)
    except (ValueError, TypeError, OSError, UnicodeError, RuntimeError):
        result = {"status": "REFUSED_OFFICIAL_SUPPLY_CHAIN_EVIDENCE",
                  "false_publisher_acceptance": False, "package_code_executed": False}
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 2 if result["status"].startswith("REFUSED") else 0


if __name__ == "__main__":
    raise SystemExit(main())
