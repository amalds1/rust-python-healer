"""Read-only, bounded Python project/lockfile inventory for CPython 3.9+.

No setup.py execution, no package imports and no dependency installation.
Python 3.11+ has tomllib; older interpreters only extract *candidates* from a
strict subset of TOML and never claim complete parsing or dependency solving.
This is metadata collection, not a filesystem sandbox or trust attestation.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat


# Fixed root filenames only: no recursive or attacker-directed directory scan.
MANIFEST_NAMES = (
    "pyproject.toml", "requirements.txt", "requirements-dev.txt",
    "requirements-test.txt", "setup.cfg", "setup.py", "Pipfile",
    "Pipfile.lock", "poetry.lock", "uv.lock", "pdm.lock", "pylock.toml",
    "requirements.lock",
)
MAX_FILE_BYTES = 1_048_576
MAX_TOML_BYTES = 262_144
SIMPLE_STRING = re.compile(r'^\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*"([^"\\\r\n]{1,256})"\s*(?:#.*)?$')
SECTION = re.compile(r'^\s*\[([^\[\]\r\n]{1,128})\]\s*(?:#.*)?$')
EXTRA_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


def bounded_file(root, name):
    """Read only a fixed root-level regular file, without following symlinks."""
    target = root / name
    try:
        if target.is_symlink():
            return {"status": "REFUSED_SYMLINK"}, None
        descriptor = os.open(str(target), os.O_RDONLY |
                             getattr(os, "O_NOFOLLOW", 0) |
                             getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None, None
    except OSError:
        return {"status": "NOT_RUN", "reason": "open_refused"}, None
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            return {"status": "REFUSED_NON_REGULAR"}, None
        if info.st_size > MAX_FILE_BYTES:
            return {"status": "TOO_LARGE", "size_bytes": info.st_size}, None
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(MAX_FILE_BYTES + 1)
        if len(content) > MAX_FILE_BYTES:
            return {"status": "TOO_LARGE", "size_bytes": len(content)}, None
        return {
            "status": "HASHED_NOT_VERIFIED",
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "content_executed": False,
            "content_parsed": False,
        }, content
    except OSError:
        return {"status": "NOT_RUN", "reason": "read_failed"}, None
    finally:
        os.close(descriptor)


def conservative_toml_candidates(text):
    """Cross-version text hints only; not a TOML parser and never a PASS."""
    values = {}
    section = None
    for line in text.splitlines():
        match = SECTION.fullmatch(line)
        if match:
            section = match.group(1)
            continue
        if section != "project":
            continue
        match = SIMPLE_STRING.fullmatch(line)
        if match and match.group(1) in ("name", "requires-python"):
            key = match.group(1)
            if key in values:
                # Duplicate TOML keys are invalid; omit ambiguous hints.
                values.pop(key, None)
                section = None
            else:
                values[key] = match.group(2)
    return {
        "status": "PARTIAL",
        "parser": "CONSERVATIVE_TEXT_HINTS_NOT_TOML_VALIDATED",
        "name_candidate": values.get("name"),
        "requires_python_candidate": values.get("requires-python"),
        "dependencies": "NOT_RUN",
        "dependency_groups": "NOT_RUN",
        "optional_dependencies": "NOT_RUN",
        "build_requires": "NOT_RUN",
    }


def normalized_group_name(name):
    """Normalize only validated PEP 685-shaped identifiers, never paths."""
    if not isinstance(name, str) or not EXTRA_NAME.fullmatch(name):
        raise ValueError("invalid_dependency_group_name")
    return re.sub(r"[-_.]+", "-", name).lower()


def dependency_sections(project, build, document):
    """Count structured requirements and includes; do NOT resolve packages.

    Requirement strings are not executable and are deliberately not copied to
    the diagnostic response: they may contain tokens in VCS direct URLs.
    This validates a bounded TOML *shape*, not full PEP 508 syntax.
    """
    def checked_strings(items, maximum):
        if not isinstance(items, list) or len(items) > maximum:
            raise ValueError("dependency_list_limit")
        if any(not isinstance(x, str) or not x or len(x) > 1024 for x in items):
            raise ValueError("invalid_dependency_entry")
        return len(items)

    raw_extras = project.get("optional-dependencies", {})
    if not isinstance(raw_extras, dict) or len(raw_extras) > 64:
        raise ValueError("invalid_optional_dependencies")
    extras = []
    seen = set()
    for original, requirements in raw_extras.items():
        name = normalized_group_name(original)
        if name in seen:
            raise ValueError("duplicate_normalized_extra")
        seen.add(name)
        count = checked_strings(requirements, 200)
        extras.append({"name": name, "direct_requirements": count})

    raw_groups = document.get("dependency-groups", {})
    if not isinstance(raw_groups, dict) or len(raw_groups) > 64:
        raise ValueError("invalid_dependency_groups")
    groups = {}
    for original, requirements in raw_groups.items():
        name = normalized_group_name(original)
        if name in groups:
            raise ValueError("duplicate_normalized_dependency_group")
        if not isinstance(requirements, list) or len(requirements) > 200:
            raise ValueError("dependency_group_size_limit")
        direct = 0
        includes = []
        for item in requirements:
            if isinstance(item, str) and item and len(item) <= 1024:
                direct += 1
            elif isinstance(item, dict) and list(item) == ["include-group"]:
                includes.append(normalized_group_name(item["include-group"]))
            else:
                raise ValueError("invalid_dependency_group_entry")
        groups[name] = {"name": name, "direct_requirements": direct,
                        "includes": includes}

    cache = {}

    def expanded_count(name, parents=()):
        if name in cache:
            return cache[name]
        if name in parents:
            raise ValueError("dependency_group_include_cycle")
        if name not in groups:
            raise ValueError("dependency_group_include_unknown")
        if len(parents) >= 32:
            raise ValueError("dependency_group_include_too_deep")
        group = groups[name]
        count = group["direct_requirements"]
        for included in group["includes"]:
            count += expanded_count(included, parents + (name,))
            if count > 5000:
                raise ValueError("dependency_group_expansion_limit")
        cache[name] = count
        return count

    summaries = []
    for name in sorted(groups):
        group = groups[name]
        summaries.append({"name": name,
                          "direct_requirements": group["direct_requirements"],
                          "includes": group["includes"],
                          "expanded_requirements_count": expanded_count(name)})

    build_requirements = build.get("requires")
    build_count = (checked_strings(build_requirements, 200)
                   if build_requirements is not None else None)
    return {
        "optional_dependencies": sorted(extras, key=lambda item: item["name"]),
        "optional_dependencies_dynamic": "optional-dependencies" in project.get("dynamic", []),
        "dependency_groups": summaries,
        "build_requires_count": build_count,
        "requirements_syntax": "NOT_VERIFIED",
        "dependency_versions_resolved": False,
        "dependency_group_includes": "COUNTS_ONLY_NOT_INSTALLABLE",
    }


def parse_pyproject(content):
    if len(content) > MAX_TOML_BYTES:
        return {"status": "TOO_LARGE", "reason": "toml_limit_256k"}
    try:
        text = content.decode("utf-8")
    except UnicodeError:
        return {"status": "INVALID_UTF8"}
    try:
        import tomllib
    except ImportError:
        # No optional third-party parser is imported or installed on 3.9/3.10.
        return conservative_toml_candidates(text)
    try:
        parsed = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return {"status": "INVALID_TOML", "parser": "tomllib"}
    project = parsed.get("project", {})
    build = parsed.get("build-system", {})
    if not isinstance(project, dict) or not isinstance(build, dict):
        return {"status": "INVALID_STRUCTURE", "parser": "tomllib"}
    name = project.get("name")
    version = project.get("version")
    python = project.get("requires-python")
    for value, length in ((name, 128), (version, 128), (python, 256)):
        if value is not None and (not isinstance(value, str) or len(value) > length):
            return {"status": "INVALID_STRUCTURE", "parser": "tomllib"}
    dependencies = project.get("dependencies")
    if dependencies is not None and (
        not isinstance(dependencies, list) or len(dependencies) > 200 or
        any(not isinstance(item, str) or len(item) > 1024 for item in dependencies)
    ):
        return {"status": "INVALID_STRUCTURE", "parser": "tomllib"}
    backend = build.get("build-backend")
    if backend is not None and (not isinstance(backend, str) or len(backend) > 256):
        return {"status": "INVALID_STRUCTURE", "parser": "tomllib"}
    dynamic = project.get("dynamic", [])
    if (not isinstance(dynamic, list) or len(dynamic) > 64 or
            any(not isinstance(x, str) or len(x) > 128 for x in dynamic)):
        return {"status": "INVALID_STRUCTURE", "parser": "tomllib"}
    if ("dependencies" in dynamic and "dependencies" in project or
            "optional-dependencies" in dynamic and "optional-dependencies" in project):
        # PEP 621 forbids specifying the same metadata field statically and
        # declaring it dynamic. Do not pretend to have resolved either side.
        return {"status": "INVALID_STRUCTURE", "parser": "tomllib",
                "reason": "static_and_dynamic_dependency_conflict"}
    try:
        sections = dependency_sections(project, build, parsed)
    except ValueError as exc:
        # Fixed, context-free reason strings: no token-bearing values leaked.
        return {"status": "INVALID_STRUCTURE", "parser": "tomllib", "reason": str(exc)}
    return {
        "status": "INSPECTED_NOT_RESOLVED",
        "parser": "tomllib",
        "project_section_present": "project" in parsed,
        "name": name,
        "version": version,
        "requires_python": python,
        "dependency_count": len(dependencies) if dependencies is not None else None,
        "dynamic_dependencies": "dependencies" in dynamic,
        "dependency_resolution": "NOT_RUN",
        "build_backend_recorded": bool(backend),
        "build_backend_executed": False,
        **sections,
    }


def inspect(root):
    """Inventory fixed project files and parse TOML only when stdlib permits."""
    root = Path(root)
    if root.is_symlink():
        raise ValueError("symlink_project_root_refused")
    if not root.is_dir():
        raise ValueError("project_root_not_directory")
    records = []
    pyproject = {"status": "NOT_FOUND"}
    for name in dict.fromkeys(MANIFEST_NAMES):
        info, content = bounded_file(root, name)
        if info is None:
            continue
        record = {"filename": name, **info}
        if name == "pyproject.toml":
            pyproject = parse_pyproject(content) if content is not None else {
                "status": info["status"], "reason": "not_parsed"
            }
            record["content_parsed"] = pyproject.get("parser") == "tomllib"
        records.append(record)
    status = "NOT_FOUND" if not records else "INSPECTED_PARTIAL"
    return {
        "status": status,
        "pyproject": pyproject,
        "manifests": records,
        "files_present": len(records),
        "source_executed": False,
        "packages_imported": False,
        "install_performed": False,
        "dependency_resolution": "NOT_RUN",
        "import_graph": "NOT_RUN",
        "lockfile_verification": "NOT_RUN",
        "path_protection": "BEST_EFFORT_NO_ROOT_SWAP_GUARANTEE",
        "note": "Hashes are observations, not signed or verified dependency locks",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project_root", type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.project_root), ensure_ascii=False))


if __name__ == "__main__":
    main()
