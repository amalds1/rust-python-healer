"""Offline CPython 3.9--3.15 Python packaging and Windows lexical inspection.

Data-only parsing. Target distributions are never imported/installed/executed,
no lockfile sources are fetched, and no PowerShell command is launched.
``packaging`` supplies the PEP 440/508 reference implementation; TOML uses
tomllib or an installed tomli-compatible parser. Absence is an explicit error.
Tool-specific lockfile schemas are *not* claimed fully certified.
"""

import re
from pathlib import PureWindowsPath

MAX_TEXT = 256_000
MAX_PKGS = 500
MAX_REQUIREMENT = 4096
REQUIRED_MARKER_ENV = frozenset((
    "implementation_name", "implementation_version", "os_name",
    "platform_machine", "platform_python_implementation", "platform_release",
    "platform_system", "platform_version", "python_full_version",
    "python_version", "sys_platform"))
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
WHEEL = re.compile(r"^[A-Za-z0-9_.-]+\.whl$")


def _packaging():
    try:
        from packaging.markers import Marker
        from packaging.requirements import Requirement
        from packaging.specifiers import SpecifierSet
        from packaging.utils import canonicalize_name, parse_wheel_filename
        from packaging.version import InvalidVersion, Version
    except ImportError:
        # This repository has a different local ``packaging/`` directory that
        # can shadow PyPA packaging. pip bundles a trusted PyPA implementation.
        try:
            from pip._vendor.packaging.markers import Marker
            from pip._vendor.packaging.requirements import Requirement
            from pip._vendor.packaging.specifiers import SpecifierSet
            from pip._vendor.packaging.utils import (
                canonicalize_name,
                parse_wheel_filename,
            )
            from pip._vendor.packaging.version import InvalidVersion, Version
        except ImportError as exc:
            raise RuntimeError("packaging_reference_library_not_available") from exc
    return Version, InvalidVersion, SpecifierSet, Requirement, Marker, canonicalize_name, parse_wheel_filename


def _text(value, length, label):
    if type(value) is not str or not value or len(value.encode("utf-8")) > length:
        raise ValueError("invalid_" + label)
    return value


def _toml(raw):
    _text(raw, MAX_TEXT, "toml_size")
    try:
        import tomllib as parser
        parser_name = "tomllib"
    except ImportError:
        try:
            import tomli as parser
            parser_name = "tomli"
        except ImportError:
            try:
                from pip._vendor import tomli as parser
                parser_name = "pip-vendored-tomli"
            except ImportError as exc:
                raise RuntimeError("toml_parser_unavailable_on_this_interpreter") from exc
    try:
        parsed = parser.loads(raw)
    except parser.TOMLDecodeError as exc:
        raise ValueError("invalid_toml_document") from exc
    if type(parsed) is not dict:
        raise ValueError("invalid_toml_structure")
    return parsed, parser_name


def pep440(version, specifier=None):
    """Full PEP 440 parsing/comparison via PyPA's reference implementation."""
    Version, InvalidVersion, SpecifierSet, _, _, _, _ = _packaging()
    _text(version, 256, "pep440_version")
    try:
        obj = Version(version)
    except InvalidVersion as exc:
        raise ValueError("invalid_pep440_version") from exc
    match = None
    if specifier is not None:
        if type(specifier) is not str or len(specifier) > 2048:
            raise ValueError("invalid_pep440_specifier")
        try:
            match = obj in SpecifierSet(specifier)
        except Exception as exc:
            raise ValueError("invalid_pep440_specifier") from exc
    return {"status": "PARSED_BY_PYPA_REFERENCE", "canonical": str(obj),
            "epoch": obj.epoch, "release": list(obj.release),
            "pre": list(obj.pre) if obj.pre is not None else None,
            "post": obj.post, "dev": obj.dev, "local": obj.local,
            "is_prerelease": obj.is_prerelease, "is_postrelease": obj.is_postrelease,
            "specifier_matches": match, "source_executed": False,
            "external_registry_verified": False}


def _marker_env(environment):
    if (type(environment) is not dict or set(environment) != REQUIRED_MARKER_ENV or
            any(type(value) is not str or len(value) > 256 for value in environment.values())):
        raise ValueError("full_explicit_marker_environment_required")
    Version = _packaging()[0]
    try:
        parsed = Version(environment["python_full_version"])
        if environment["python_version"] != ".".join(str(v) for v in parsed.release[:2]):
            raise ValueError("marker_python_minor_full_version_mismatch")
        Version(environment["implementation_version"])
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("invalid_marker_python_version") from exc
    return dict(environment)


def pep508(requirement, environment, selected_extras=()):
    """Evaluate a PEP 508 string against a full *explicit* target environment.

    URL requirements are parsed but not authenticated/fetched; marker evaluation
    is per selected extra. An empty extra is always evaluated if none selected.
    """
    _, _, _, Requirement, _, canonicalize_name, _ = _packaging()
    _text(requirement, MAX_REQUIREMENT, "pep508_requirement")
    env = _marker_env(environment)
    if (type(selected_extras) not in (list, tuple) or len(selected_extras) > 64 or
            any(type(x) is not str or not NAME.fullmatch(x) for x in selected_extras)):
        raise ValueError("invalid_selected_extras")
    try:
        obj = Requirement(requirement)
    except Exception as exc:
        raise ValueError("invalid_pep508_requirement") from exc
    evaluations = []
    for extra in selected_extras or ("",):
        evaluated_env = dict(env, extra=canonicalize_name(extra) if extra else "")
        try:
            match = obj.marker.evaluate(environment=evaluated_env) if obj.marker else True
        except Exception as exc:
            raise ValueError("unsupported_marker_for_reference_library") from exc
        evaluations.append({"extra": extra, "applies": bool(match)})
    return {"status": "PARSED_BY_PYPA_REFERENCE",
            "name": canonicalize_name(obj.name), "requested_extras": sorted(obj.extras),
            "specifier": str(obj.specifier), "marker": str(obj.marker) if obj.marker else None,
            "applies_any_selected_extra": any(item["applies"] for item in evaluations),
            "evaluations": evaluations, "direct_url_present": obj.url is not None,
            "direct_url_authorized": False, "source_executed": False,
            "target_package_imported": False}


def _requires_python(specifier, environment):
    _, _, SpecifierSet, _, _, _, _ = _packaging()
    try:
        return SpecifierSet(specifier).contains(environment["python_full_version"])
    except Exception as exc:
        raise ValueError("invalid_requires_python_specifier") from exc


def _pylock_filename(name):
    return type(name) is str and bool(re.fullmatch(r"pylock(?:\.[^.]+)?\.toml", name))


def pylock(text, environment, filename="pylock.toml"):
    """Conservative PEP 751 / pylock.toml version 1.0 wheel-only audit.

    Result never means the full lock is installable, its graph resolved, its
    artifact bytes authenticated, or the target OS compatible.
    """
    if not _pylock_filename(filename):
        raise ValueError("invalid_pylock_filename")
    env = _marker_env(environment)
    parsed, parser_name = _toml(text)
    if parsed.get("lock-version") != "1.0":
        return {"status": "UNSUPPORTED_LOCK_VERSION", "install_verified": False,
                "network_used": False}
    if type(parsed.get("created-by")) is not str or not parsed["created-by"]:
        raise ValueError("pylock_creator_required")
    if "requires-python" in parsed and not _requires_python(parsed["requires-python"], env):
        return {"status": "TARGET_MISMATCH", "reason": "python_requires_mismatch",
                "install_verified": False}
    if "environments" in parsed:
        markers = parsed["environments"]
        if type(markers) is not list or not 1 <= len(markers) <= 100:
            raise ValueError("invalid_pylock_environments")
        _, _, _, _, Marker, _, _ = _packaging()
        try:
            match = any(Marker(marker).evaluate(environment=dict(env, extra=""))
                        for marker in markers)
        except Exception as exc:
            raise ValueError("invalid_pylock_environment_marker") from exc
        if not match:
            return {"status": "TARGET_MISMATCH", "reason": "environment_marker_mismatch",
                    "install_verified": False}
    if "packages" not in parsed:
        raise ValueError("pylock_packages_required")
    packages = parsed["packages"]
    if type(packages) is not list or len(packages) > MAX_PKGS:
        raise ValueError("invalid_pylock_package_count")
    Version, _, _, _, _, canonicalize_name, parse_wheel_filename = _packaging()
    rows, issues = [], []
    for index, pkg in enumerate(packages):
        if type(pkg) is not dict or type(pkg.get("name")) is not str:
            raise ValueError("invalid_pylock_package_record")
        _text(pkg["name"], 128, "package_name")
        if not NAME.fullmatch(pkg["name"]):
            raise ValueError("invalid_pylock_package_name")
        name = canonicalize_name(pkg["name"])
        try:
            version = (str(Version(_text(pkg["version"], 256, "package_version")))
                       if "version" in pkg else None)
        except Exception as exc:
            raise ValueError("invalid_pylock_package_version") from exc
        sources = [key for key in ("vcs", "directory", "archive") if key in pkg]
        if sources:
            issues.append({"package_index": index, "reason": "unsupported_nonwheel_source"})
        if version is None:
            issues.append({"package_index": index, "reason": "nonpinned_source_or_version"})
        if "marker" in pkg or "requires-python" in pkg:
            issues.append({"package_index": index,
                           "reason": "package_specific_conditions_not_evaluated"})
        wheels = pkg.get("wheels", [])
        if type(wheels) is not list or len(wheels) > 100:
            raise ValueError("invalid_pylock_wheels")
        wheel_names = []
        for wheel in wheels:
            if type(wheel) is not dict:
                raise ValueError("invalid_pylock_wheel")
            filename_value = wheel.get("name")
            if type(filename_value) is not str or not WHEEL.fullmatch(filename_value):
                issues.append({"package_index": index, "reason": "wheel_filename_not_explicit"})
                continue
            try:
                distribution, wheel_version, _, _ = parse_wheel_filename(filename_value)
                if canonicalize_name(distribution) != name or str(wheel_version) != version:
                    raise ValueError("wheel_identity_mismatch")
            except (ValueError, TypeError):
                issues.append({"package_index": index, "reason": "wheel_identity_invalid"})
                continue
            digest = wheel.get("hashes", {}).get("sha256") if type(wheel.get("hashes")) is dict else None
            if type(digest) is not str or not SHA256.fullmatch(digest):
                issues.append({"package_index": index, "reason": "wheel_digest_missing_or_invalid"})
            wheel_names.append(filename_value)
        if not wheels:
            issues.append({"package_index": index, "reason": "no_wheel_for_offline_audit"})
        rows.append({"name": name, "version": version, "wheels": wheel_names})
    return {"status": "REVIEW_REQUIRED" if issues else "PARSED_WHEEL_SUBSET_ONLY",
            "lock_version": "1.0", "created_by": parsed["created-by"],
            "parser": parser_name, "packages": rows, "issues": issues,
            "full_pep751_conformance_verified": False, "wheels_imported": False,
            "wheel_tag_compatibility_verified": False,
            "install_verified": False, "artifact_bytes_verified": False,
            "source_executed": False, "network_used": False}


def dependency_group(text, group_name):
    """PEP 735 recursive include expansion: order/duplicates are preserved."""
    _text(group_name, 128, "group_name")
    parsed, parser_name = _toml(text)
    groups = parsed.get("dependency-groups")
    if type(groups) is not dict or len(groups) > 100:
        raise ValueError("invalid_dependency_groups_table")
    _, _, _, Requirement, _, canonicalize_name, _ = _packaging()
    indexed = {}
    for original in groups:
        if type(original) is not str or not NAME.fullmatch(original):
            raise ValueError("invalid_group_identifier")
        normalized = canonicalize_name(original)
        if normalized in indexed:
            raise ValueError("duplicate_normalized_group_name")
        indexed[normalized] = original
    wanted = canonicalize_name(group_name)
    if wanted not in indexed:
        raise ValueError("unknown_dependency_group")
    seen_steps = [0]

    def expand(name, stack):
        if name in stack:
            raise ValueError("dependency_group_cycle")
        if name not in indexed:
            raise ValueError("unknown_included_dependency_group")
        values = groups[indexed[name]]
        if type(values) is not list or len(values) > 500:
            raise ValueError("invalid_dependency_group_items")
        expanded = []
        for item in values:
            seen_steps[0] += 1
            if seen_steps[0] > 2000:
                raise ValueError("dependency_group_expansion_limit")
            if type(item) is str:
                _text(item, MAX_REQUIREMENT, "group_requirement")
                try:
                    Requirement(item)
                except Exception as exc:
                    raise ValueError("invalid_group_pep508_requirement") from exc
                expanded.append(item)
            elif type(item) is dict and set(item) == {"include-group"} and type(item["include-group"]) is str:
                expanded.extend(expand(canonicalize_name(item["include-group"]), stack | {name}))
            else:
                raise ValueError("invalid_dependency_group_include")
        return expanded

    expanded = expand(wanted, set())
    return {"status": "EXPANDED_PEP735_SUBSET", "group": wanted,
            "requirements": expanded, "parser": parser_name,
            "duplicates_preserved": True, "target_imports_executed": False,
            "network_used": False}


def inspect_tool_lock(kind, text):
    """Safe version/package inventory only for uv/Poetry/PDM TOML locks.

    No dependency resolution, transitive graph verification, artifact fetch,
    package installation or claim of cross-tool lock schema conformance.
    """
    if kind not in ("uv", "poetry", "pdm"):
        raise ValueError("unsupported_lock_tool")
    parsed, parser_name = _toml(text)
    packages = parsed.get("package", [])
    if type(packages) is not list or len(packages) > MAX_PKGS:
        raise ValueError("invalid_tool_lock_package_list")
    Version, _, _, _, _, canonicalize_name, _ = _packaging()
    if kind == "uv":
        metadata_version = parsed.get("version")
        if type(metadata_version) is not int or metadata_version < 1:
            raise ValueError("invalid_uv_lock_version")
    else:
        metadata = parsed.get("metadata")
        if type(metadata) is not dict:
            raise ValueError("missing_lock_metadata")
        metadata_version = metadata.get("lock-version", metadata.get("lock_version"))
        if type(metadata_version) not in (int, str):
            raise ValueError("missing_lock_format_version")
    entries = []
    for index, item in enumerate(packages):
        if type(item) is not dict or not isinstance(item.get("name"), str) or not isinstance(item.get("version"), str):
            raise ValueError("invalid_tool_lock_package")
        _text(item["name"], 128, "package_name")
        if not NAME.fullmatch(item["name"]):
            raise ValueError("invalid_tool_lock_package_name")
        normalized = canonicalize_name(item["name"])
        try:
            ver = str(Version(_text(item["version"], 256, "package_version")))
        except Exception as exc:
            raise ValueError("invalid_tool_lock_package_version") from exc
        entries.append({"package_index": index, "name": normalized, "version": ver})
    return {"status": "PARSED_PARTIAL_TOOL_SCHEMA", "tool": kind,
            "tool_lock_version": metadata_version, "parser": parser_name,
            "packages": entries, "schema_fully_supported": False,
            "resolution_verified": False, "artifact_integrity_verified": False,
            "installation_performed": False, "network_used": False,
            "package_code_executed": False}


def windows_relative_path(value):
    """Windows path traversal/ADS/device rejection, lexical only (no FS)."""
    _text(value, 4096, "windows_path")
    if any(ord(char) < 32 for char in value) or "\x7f" in value:
        raise ValueError("unsafe_windows_control_character")
    path = PureWindowsPath(value)
    if path.drive or path.root or value.startswith(("\\\\?\\", "\\\\.\\")):
        raise ValueError("absolute_device_or_drive_path_denied")
    components = re.split(r"[\\/]", value)
    if any(part in ("", "..") for part in components):
        raise ValueError("windows_traversal_or_empty_segment")
    reserved = re.compile(r"^(?:CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|"
                          r"COM[1-9¹²³]|LPT[1-9¹²³])(?:\..*)?$", re.IGNORECASE)
    for part in components:
        if (part.endswith((" ", ".")) or ":" in part or reserved.fullmatch(part) or
                re.search(r"[<>\"|?*]", part)):
            raise ValueError("unsafe_windows_component")
    return {"status": "SAFE_RELATIVE_LEXICAL", "canonical_windows": "\\".join(components),
            "filesystem_checked": False, "junction_or_symlink_checked": False,
            "path_executed": False}


def powershell_literal(value):
    """Only a PowerShell single-quoted string *literal*, not a command line."""
    _text(value, 4096, "powershell_literal")
    if any(ord(char) < 32 for char in value) or "\x7f" in value:
        raise ValueError("unsafe_powershell_control_character")
    return {"literal": "'" + value.replace("'", "''") + "'",
            "quoted_as": "POWERSHELL_SINGLE_QUOTED_DATA_LITERAL",
            "command_escaped": False, "command_executed": False}
