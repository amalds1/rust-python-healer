"""Fail-closed local packaging policy, lock graph and source-origin inspection.

Only bounded data is read.  No package/source import, pip installation, VCS
checkout, registry request, executable code evaluation, or system mutation.
The input is not a sandbox and a locally self-reported commit is not a
publisher attestation.  The implemented adapters intentionally reject unknown
lock shapes instead of claiming cross-tool schema completeness.
"""

import ast
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname


MAX_DOCUMENT = 300_000
MAX_SOURCE = 200_000
MAX_FILES = 300
MAX_PACKAGES = 600
MAX_ITEMS = 2500
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
HEX64 = re.compile(r"[a-fA-F0-9]{64}\Z")
HEX40 = re.compile(r"[a-fA-F0-9]{40}\Z")
_KNOWN_VCS = frozenset(("git", "hg", "svn", "bzr"))


def _windows_private_directory(path):
    privacy = globals().get("_RPH_WINDOWS_PRIVACY")
    if privacy is None:
        spec = importlib.util.spec_from_file_location("rph_package_privacy", Path(__file__).with_name("windows_private_paths.py"))
        privacy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(privacy)
    return privacy.assert_private_directory(Path(path).absolute())


def _pypa():
    try:
        from packaging.markers import Marker, default_environment
        from packaging.requirements import Requirement
        from packaging.version import Version
        from packaging.utils import canonicalize_name, parse_wheel_filename
    except ImportError:
        try:
            from pip._vendor.packaging.markers import Marker, default_environment
            from pip._vendor.packaging.requirements import Requirement
            from pip._vendor.packaging.version import Version
            from pip._vendor.packaging.utils import canonicalize_name, parse_wheel_filename
        except ImportError as exc:
            raise RuntimeError("trusted_pypa_reference_unavailable") from exc
    return Marker, default_environment, Requirement, Version, canonicalize_name, parse_wheel_filename


def _toml(text):
    if type(text) is not str or len(text.encode("utf-8")) > MAX_DOCUMENT:
        raise ValueError("invalid_bounded_toml")
    try:
        import tomllib as parser
    except ImportError:
        try:
            import tomli as parser
        except ImportError:
            from pip._vendor import tomli as parser
    try:
        result = parser.loads(text)
    except parser.TOMLDecodeError as exc:
        raise ValueError("invalid_toml") from exc
    if type(result) is not dict:
        raise ValueError("invalid_toml_root")
    return result


def _read_regular(path, limit=MAX_DOCUMENT):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
        raise ValueError("unsafe_nonregular_or_hardlinked_file")
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_NONBLOCK", 0))
    try:
        after = os.fstat(fd)
        if not stat.S_ISREG(after.st_mode) or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("file_replaced_during_open")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            content = stream.read(limit + 1)
        if len(content) > limit:
            raise ValueError("file_size_limit")
        final = os.fstat(fd)
        if (after.st_ino, after.st_size, after.st_mtime_ns) != (final.st_ino, final.st_size, final.st_mtime_ns):
            raise ValueError("file_changed_during_read")
        return content
    finally:
        os.close(fd)


def _normalized(name):
    if type(name) is not str or not NAME.fullmatch(name):
        raise ValueError("invalid_package_name")
    return _pypa()[4](name)


def _version(text):
    if type(text) is not str or len(text) > 256:
        raise ValueError("invalid_package_version")
    try:
        return str(_pypa()[3](text))
    except Exception as exc:
        raise ValueError("invalid_package_version") from exc


def _environment(python_version, platform):
    if not re.fullmatch(r"3\.(?:9|1[0-9])(?:\.\d+)?", python_version) or type(platform) is not str or not re.fullmatch(r"[a-z0-9_]+", platform):
        raise ValueError("invalid_target_environment")
    Marker, default_environment, _, _, _, _ = _pypa()
    env = default_environment()
    pieces = python_version.split(".")
    env["python_full_version"] = python_version if len(pieces) == 3 else python_version + ".0"
    env["python_version"] = ".".join(pieces[:2])
    env["sys_platform"] = platform
    env["os_name"] = "nt" if platform == "win32" else "posix"
    env["extra"] = ""
    return env


def _marker_applies(marker, env):
    if not isinstance(marker, str) or len(marker) > 2000:
        raise ValueError("invalid_environment_marker")
    try:
        return bool(_pypa()[0](marker).evaluate(environment=env))
    except Exception as exc:
        raise ValueError("invalid_environment_marker") from exc


def _sha256_valid(value):
    return type(value) is str and bool(HEX64.fullmatch(value))


def _validate_wheel(record, name, version, kind):
    if type(record) is not dict:
        raise ValueError("invalid_wheel_record")
    label = record.get("name" if kind == "pylock" else
                       "filename" if kind == "uv" else "file")
    if type(label) is not str or len(label) > 180 or "/" in label or "\\" in label or not label.endswith(".whl"):
        raise ValueError("invalid_wheel_filename")
    try:
        distribution, wheel_version, _, _ = _pypa()[5](label)
    except Exception as exc:
        raise ValueError("wheel_tag_or_filename_invalid") from exc
    if _normalized(distribution) != name or str(wheel_version) != version:
        raise ValueError("wheel_identity_mismatch")
    if kind == "pylock":
        hashes = record.get("hashes")
        digest = hashes.get("sha256") if type(hashes) is dict else None
    else:
        value = record.get("hash")
        digest = value[7:] if isinstance(value, str) and value.startswith("sha256:") else None
    if not _sha256_valid(digest):
        raise ValueError("wheel_unpinned_sha256")
    return {"filename": label, "sha256": digest.lower()}


def _graph_validate(rows, links):
    """Require every local dependency link to resolve unambiguously."""
    available = {}
    for row in rows:
        key = (row["name"], row["version"])
        if key in available:
            raise ValueError("ambiguous_package_identity")
        available[key] = row
    normalized = []
    for src, names in links:
        for name, version in names:
            matches = [key for key in available if key[0] == name and
                       (version is None or key[1] == version)]
            if len(matches) != 1:
                raise ValueError("dependency_missing_or_ambiguous")
            normalized.append({"from": src, "to": [matches[0][0], matches[0][1]]})
    if len(normalized) > MAX_ITEMS:
        raise ValueError("dependency_graph_too_large")
    return normalized


def validate_pylock_graph(text, python_version, platform="linux", filename="pylock.toml"):
    """PEP 751 v1.0 wheel-only lock with marker and dependency audit.

    Non-wheel sources, unrecognised kinds and unsupported marker constructs
    fail closed.  PEP 751 dependency links are informational and MUST NOT be
    used as an installation plan; this function never installs anything.
    """
    if type(filename) is not str or not re.fullmatch(r"pylock(?:\.[a-zA-Z0-9_-]+)?\.toml", filename):
        raise ValueError("invalid_pylock_filename")
    env = _environment(python_version, platform)
    parsed = _toml(text)
    if parsed.get("lock-version") != "1.0":
        return {"status": "NOT_SUPPORTED_LOCK_VERSION", "installed": False}
    if not isinstance(parsed.get("created-by"), str) or not parsed["created-by"].strip():
        raise ValueError("missing_pylock_creator")
    optional_envs = parsed.get("environments", [])
    if type(optional_envs) is not list or len(optional_envs) > 100:
        raise ValueError("invalid_pylock_environments")
    if optional_envs and not any(_marker_applies(marker, env) for marker in optional_envs):
        return {"status": "TARGET_NOT_INCLUDED", "installed": False}
    if "requires-python" in parsed:
        _, _, _, _, _, _ = _pypa()
        try:
            from packaging.specifiers import SpecifierSet
        except ImportError:
            from pip._vendor.packaging.specifiers import SpecifierSet
        try:
            matched = SpecifierSet(parsed["requires-python"]).contains(env["python_full_version"])
        except Exception as exc:
            raise ValueError("invalid_requires_python") from exc
        if not matched:
            return {"status": "TARGET_NOT_INCLUDED", "installed": False}
    raw = parsed.get("packages")
    if type(raw) is not list or len(raw) > MAX_PACKAGES:
        raise ValueError("invalid_pylock_packages")
    rows = []
    links = []
    for record in raw:
        if type(record) is not dict:
            raise ValueError("invalid_pylock_package")
        name = _normalized(record.get("name"))
        version = _version(record.get("version"))
        if any(x in record for x in ("vcs", "directory", "archive", "sdist")):
            return {"status": "UNSUPPORTED_NONWHEEL_SOURCE", "installed": False}
        if "marker" in record and not _marker_applies(record["marker"], env):
            continue
        if "requires-python" in record:
            try:
                from packaging.specifiers import SpecifierSet
            except ImportError:
                from pip._vendor.packaging.specifiers import SpecifierSet
            if not SpecifierSet(record["requires-python"]).contains(env["python_full_version"]):
                continue
        wheels = record.get("wheels")
        if type(wheels) is not list or not 1 <= len(wheels) <= 100:
            raise ValueError("pylock_wheels_required")
        checked = [_validate_wheel(wheel, name, version, "pylock") for wheel in wheels]
        rows.append({"name": name, "version": version, "wheels": checked})
        deps = record.get("dependencies", [])
        if type(deps) is not list or len(deps) > 256:
            raise ValueError("invalid_pylock_dependencies")
        destinations = []
        for dep in deps:
            if type(dep) is not dict or not isinstance(dep.get("name"), str):
                raise ValueError("invalid_pylock_dependency")
            destinations.append((_normalized(dep["name"]),
                                 _version(dep["version"]) if "version" in dep else None))
        links.append(([name, version], destinations))
    graph = _graph_validate(rows, links)
    return {"status": "PEP751_V1_WHEEL_GRAPH_VALIDATED_LOCAL_ONLY",
            "python_minor": env["python_version"], "packages": rows,
            "dependency_audit_edges": graph,
            "dependencies_not_used_for_installation": True,
            "artifact_contents_authenticated": False,
            "installation_performed": False, "network_used": False,
            "user_code_executed": False, "full_pep751_schema_attestation": False}


def import_tool_lock(kind, text):
    """Validated, normalized local subgraph from uv, Poetry or PDM lockfiles."""
    if kind not in ("uv", "poetry", "pdm"):
        raise ValueError("unknown_tool_lock_format")
    root = _toml(text)
    if kind == "uv":
        if type(root.get("version")) is not int or root["version"] < 1:
            raise ValueError("missing_uv_format_version")
    elif type(root.get("metadata")) is not dict or not isinstance(root["metadata"].get("lock-version", root["metadata"].get("lock_version")), (str, int)):
        raise ValueError("missing_lock_metadata_version")
    raw = root.get("package")
    if type(raw) is not list or len(raw) > MAX_PACKAGES:
        raise ValueError("invalid_package_records")
    rows, links = [], []
    Requirement = _pypa()[2]
    for record in raw:
        if type(record) is not dict:
            raise ValueError("invalid_package_entry")
        name, version = _normalized(record.get("name")), _version(record.get("version"))
        files = record.get("wheels" if kind == "uv" else "files", [])
        if type(files) is not list or len(files) > 150:
            raise ValueError("invalid_tool_lock_wheels")
        checked = [_validate_wheel(w, name, version, kind) for w in files]
        if not checked:
            return {"status": "NONWHEEL_TOOL_SOURCE_NOT_AUDITED", "tool": kind,
                    "installation_performed": False}
        deps = record.get("dependencies", {} if kind == "poetry" else [])
        next_nodes = []
        if kind == "uv":
            if type(deps) is not list:
                raise ValueError("invalid_uv_dependencies")
            for dep in deps:
                if type(dep) is not dict or "name" not in dep:
                    raise ValueError("invalid_uv_dependency")
                next_nodes.append((_normalized(dep["name"]),
                                   _version(dep["version"]) if "version" in dep else None))
        elif kind == "poetry":
            if type(deps) is not dict:
                raise ValueError("invalid_poetry_dependencies")
            for dependency in deps:
                next_nodes.append((_normalized(dependency), None))
        else:
            if type(deps) is not list:
                raise ValueError("invalid_pdm_dependencies")
            for dep in deps:
                try:
                    next_nodes.append((_normalized(Requirement(dep).name), None))
                except Exception as exc:
                    raise ValueError("invalid_pdm_dependency_requirement") from exc
        rows.append({"name": name, "version": version, "wheels": checked})
        links.append(([name, version], next_nodes))
    graph = _graph_validate(rows, links)
    return {"status": "THREE_TOOL_LOCK_SUBGRAPH_VALIDATED_LOCAL_ONLY",
            "tool": kind, "packages": rows,
            "dependency_audit_edges": graph,
            "unknown_platform_variants_still_possible": True,
            "full_tool_schema_conformance_attested": False,
            "artifact_contents_authenticated": False,
            "installation_performed": False, "network_used": False,
            "user_code_executed": False}


def inspect_direct_url(data, artifact=None):
    """PEP 610 shape, local artifact hash and VCS commit syntax checks.

    VCS entries remain UNATTESTED unless an independent trusted clone
    and transport/identity are checked elsewhere; commits are never fetched.
    """
    if type(data) is bytes:
        if len(data) > 30_000:
            raise ValueError("direct_url_size_limit")
        data = data.decode("utf-8")
    if type(data) is not str or len(data.encode("utf-8")) > 30_000:
        raise ValueError("direct_url_size_limit")
    try:
        obj = json.loads(data, object_pairs_hook=_reject_duplicate_json)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid_direct_url_json") from exc
    if type(obj) is not dict or type(obj.get("url")) is not str:
        raise ValueError("invalid_direct_url_shape")
    keys = [key for key in ("vcs_info", "archive_info", "dir_info") if key in obj]
    if len(keys) != 1:
        raise ValueError("exactly_one_origin_kind_required")
    parsed = urlsplit(obj["url"])
    if not parsed.scheme or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("credential_or_query_in_origin")
    if parsed.scheme not in ("https", "file", "ssh"):
        raise ValueError("untrusted_url_scheme")
    if "subdirectory" in obj:
        _safe_relative(obj["subdirectory"])
    origin = obj[keys[0]]
    if type(origin) is not dict:
        raise ValueError("invalid_origin_data")
    if keys[0] == "vcs_info":
        if parsed.scheme not in ("https", "ssh") or origin.get("vcs") not in _KNOWN_VCS:
            raise ValueError("invalid_vcs_origin")
        commit = origin.get("commit_id")
        if origin["vcs"] == "git" and (not isinstance(commit, str) or not HEX40.fullmatch(commit)):
            raise ValueError("nonimmutable_git_revision")
        if type(commit) is not str or not commit:
            raise ValueError("missing_vcs_commit_id")
        return {"status": "VCS_COMMIT_METADATA_VALIDATED_BUT_UNATTESTED",
                "kind": "vcs", "commit_sha256": hashlib.sha256(commit.encode()).hexdigest(),
                "publisher_identity_authenticated": False, "network_used": False,
                "user_code_executed": False}
    if parsed.scheme != "file" or parsed.netloc not in ("", "localhost"):
        raise ValueError("only_local_artifact_or_directory_allowed")
    if os.name == "nt":
        # Only local drive URIs, never UNC, device paths or alternate streams.
        if (not re.match(r"^/[A-Za-z]:/", parsed.path) or "\\" in parsed.path or
                re.search(r"%(?:2f|5c|00)", parsed.path, re.I)):
            raise ValueError("unsafe_file_url_target")
        recorded_path = Path(url2pathname(parsed.path))
        drive, tail = os.path.splitdrive(str(recorded_path))
        if len(drive) != 2 or ":" in tail or "\x00" in tail:
            raise ValueError("unsafe_file_url_target")
        if recorded_path.exists() and getattr(recorded_path.lstat(), "st_file_attributes", 0) & 0x400:
            raise ValueError("unsafe_file_url_target")
    else:
        recorded_path = Path(unquote(parsed.path))
    if not recorded_path.is_absolute() or recorded_path.is_symlink():
        raise ValueError("unsafe_file_url_target")
    if keys[0] == "dir_info":
        if "editable" in origin and type(origin["editable"]) is not bool:
            raise ValueError("invalid_editable_flag")
        if not recorded_path.is_dir():
            raise ValueError("local_directory_missing")
        return {"status": "LOCAL_EDITABLE_ORIGIN_CLASSIFIED" if origin.get("editable")
                else "LOCAL_DIRECTORY_ORIGIN_CLASSIFIED", "kind": "directory",
                "editable": origin.get("editable", False),
                "location_disclosed": False, "source_executed": False,
                "publisher_identity_authenticated": False}
    hashes = origin.get("hashes")
    if type(hashes) is not dict or not _sha256_valid(hashes.get("sha256")):
        raise ValueError("archive_source_sha256_required")
    if artifact is None:
        return {"status": "ARCHIVE_PIN_DECLARED_BYTES_NOT_VERIFIED",
                "kind": "archive", "artifact_authenticated": False}
    if Path(artifact).absolute() != recorded_path:
        raise ValueError("supplied_artifact_differs_from_declared_origin")
    payload = _read_regular(artifact, 20_000_000)
    if hashlib.sha256(payload).hexdigest() != hashes["sha256"].lower():
        raise ValueError("archive_sha256_mismatch")
    return {"status": "LOCAL_ARCHIVE_BYTES_VERIFIED", "kind": "archive",
            "artifact_authenticated": True, "bytes_verified": len(payload),
            "publisher_identity_authenticated": False, "network_used": False,
            "user_code_executed": False}


def _reject_duplicate_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _safe_relative(name):
    if (type(name) is not str or len(name) > 256 or name.startswith("/") or
            "\\" in name or any(ord(ch) < 32 or ord(ch) == 127 for ch in name) or
            any(part in ("", ".", "..") for part in name.split("/"))):
        raise ValueError("unsafe_source_path")
    return name


def externally_managed_guard(prefix, base_prefix, stdlib_dir, target_directory=None):
    """Actual marker probe and fail-closed install preflight; never calls pip."""
    if any(type(x) is not str or not x or len(x) > 4096
           for x in (prefix, base_prefix, stdlib_dir)):
        raise ValueError("invalid_runtime_paths")
    stdlib = Path(stdlib_dir)
    if not stdlib.is_dir() or stdlib.is_symlink():
        raise ValueError("invalid_stdlib_root")
    marker = stdlib / "EXTERNALLY-MANAGED"
    exists = False
    try:
        before = marker.lstat()
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("unsafe_managed_marker")
        _read_regular(marker, 16_384)
        exists = True
    base_env = prefix == base_prefix
    managed = base_env and exists
    # Never authorize global paths.  Only permit an explicitly scoped private
    # target; the independent offline installer must perform later checks.
    target_approved = False
    if not managed and target_directory is not None:
        target = Path(target_directory)
        if (target.is_dir() and not target.is_symlink() and
                str(target.resolve()) not in (prefix, base_prefix, "/", stdlib_dir)):
            if os.name == "nt":
                try:
                    _windows_private_directory(target)
                    target_approved = True
                except (OSError, ValueError):
                    target_approved = False
            else:
                target_approved = target.stat().st_mode & 0o077 == 0
    return {"status": "EXTERNALLY_MANAGED_DENIED" if managed else
            "VENV_PRIVATE_TARGET_ALLOWED" if target_approved else "INSTALL_NOT_AUTHORIZED",
            "virtual_environment": not base_env,
            "externally_managed_marker_detected": exists,
            "global_install_allowed": False,
            "private_target_preflight_only": bool(target_approved),
            "system_packages_mutated": False, "pip_executed": False}


def analyze_project(root):
    """Bounded AST import graph + parsed pyproject and lock metadata.

    Static import edges are *possible* runtime imports, not actual imports.
    Directory race resistance is partial; no project file is executed.
    """
    base = Path(root)
    if not base.is_dir() or base.is_symlink():
        raise ValueError("unsafe_project_root")
    files = []
    scanned_dirs = 0
    for current, dirs, names in os.walk(str(base), followlinks=False):
        scanned_dirs += 1
        if scanned_dirs > 1000 or len(dirs) + len(names) > 2000:
            raise ValueError("project_directory_budget")
        dirs[:] = sorted(directory for directory in dirs
                         if directory not in (".venv", "venv", "__pycache__", "build", "dist"))
        if any((Path(current) / dirname).is_symlink() for dirname in dirs):
            raise ValueError("symlink_directory_rejected")
        for name in names:
            if name.endswith(".py"):
                files.append(Path(current) / name)
                if len(files) > MAX_FILES:
                    raise ValueError("project_file_budget")
    nodes = {}
    for file in files:
        relative = file.relative_to(base)
        if any((base / Path(*relative.parts[:depth])).is_symlink()
               for depth in range(1, len(relative.parts))):
            raise ValueError("symlink_directory_rejected")
        raw = _read_regular(file, MAX_SOURCE)
        module = ".".join(relative.with_suffix("").parts)
        if module.endswith(".__init__"):
            module = module[:-9]
        try:
            tree = ast.parse(raw.decode("utf-8"), filename="<untrusted-static>" )
        except (SyntaxError, UnicodeError) as exc:
            raise ValueError("unparseable_python_source") from exc
        nodes[module] = tree
    edges, unknown = set(), set()
    for module, tree in nodes.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for imported in node.names:
                    name = imported.name
                    if name in nodes:
                        edges.add((module, name))
                    elif name.split(".")[0] in nodes:
                        edges.add((module, name.split(".")[0]))
                    else:
                        unknown.add(name)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    ancestry = module.split(".")[:-1]
                    base_parts = ancestry[:max(0, len(ancestry) - (node.level - 1))]
                    candidate = ".".join(base_parts + ([node.module] if node.module else []))
                else:
                    candidate = node.module or ""
                if candidate in nodes:
                    edges.add((module, candidate))
                elif candidate:
                    unknown.add(candidate)
                for alias in node.names:
                    submodule = candidate + "." + alias.name
                    if submodule in nodes:
                        edges.add((module, submodule))
    manifest = base / "pyproject.toml"
    requirements = []
    if manifest.exists() or manifest.is_symlink():
        project = _toml(_read_regular(manifest).decode("utf-8"))
        project_table = project.get("project", {})
        if type(project_table) is not dict:
            raise ValueError("invalid_pyproject_table")
        direct = project_table.get("dependencies", [])
        if type(direct) is not list or len(direct) > MAX_PACKAGES:
            raise ValueError("invalid_project_dependencies")
        for value in direct:
            try:
                requirement = _pypa()[2](value)
            except Exception as exc:
                raise ValueError("invalid_pyproject_pep508_dependency") from exc
            requirements.append(_normalized(requirement.name))
    local_locks = {}
    for candidate in ("pylock.toml", "uv.lock", "poetry.lock", "pdm.lock"):
        path = base / candidate
        if path.exists() or path.is_symlink():
            record = _toml(_read_regular(path).decode("utf-8"))
            local_locks[candidate] = len(record.get("packages", record.get("package", [])))
    return {"status": "PROJECT_STATIC_IMPORT_AND_PACKAGE_GRAPH",
            "modules": sorted(nodes), "possible_import_edges": [list(e) for e in sorted(edges)],
            "external_or_unresolved_imports": sorted(unknown),
            "pyproject_dependencies": requirements,
            "local_lock_package_counts": local_locks,
            "unknown_source_executed": False, "imports_observed_at_runtime": False,
            "filesystem_race_resistance_complete": False}


def main(argv=None):
    """Read-only JSON CLI for the Rust `lab package-policy` adapter."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "project", "pylock",
                                            "tool-lock", "direct-url", "managed"),
                        default="capabilities")
    parser.add_argument("--path")
    parser.add_argument("--kind", choices=("uv", "poetry", "pdm"))
    parser.add_argument("--python-version", default="3.12")
    parser.add_argument("--platform", default="linux")
    parser.add_argument("--prefix")
    parser.add_argument("--base-prefix")
    parser.add_argument("--stdlib-dir")
    args = parser.parse_args(argv)
    try:
        if args.mode == "capabilities":
            result = {"status": "READ_ONLY_PACKAGE_POLICY_AVAILABLE",
                      "capabilities": ["static_import_graph", "pylock_wheel_graph",
                                       "uv_poetry_pdm_wheel_graph", "pep610_origin",
                                       "pep668_managed_guard"],
                      "network_used": False, "user_code_executed": False,
                      "install_performed": False}
        elif args.mode == "managed":
            result = externally_managed_guard(args.prefix, args.base_prefix,
                                              args.stdlib_dir)
        elif args.mode == "project":
            result = analyze_project(args.path)
        elif args.mode in ("pylock", "tool-lock", "direct-url"):
            if not args.path:
                raise ValueError("path_required")
            data = _read_regular(args.path).decode("utf-8")
            if args.mode == "pylock":
                result = validate_pylock_graph(data, args.python_version,
                                               args.platform, Path(args.path).name)
            elif args.mode == "tool-lock":
                result = import_tool_lock(args.kind, data)
            else:
                result = inspect_direct_url(data)
        else:
            raise ValueError("unknown_mode")
    except (OSError, ValueError, UnicodeError, TypeError, RuntimeError):
        result = {"status": "REFUSED", "reason": "invalid_or_untrusted_input",
                  "network_used": False, "user_code_executed": False,
                  "install_performed": False}
    print(json.dumps(result, sort_keys=True, allow_nan=False))
    return 2 if result.get("status") == "REFUSED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
