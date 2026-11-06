"""Bounded, read-only inventory of installed Python distribution metadata.

This is an SBOM *candidate* with versioned observations, not an authenticated
SBOM, vulnerability scan, signature validation, dependency solver or sandbox.
Never import a package's module, execute package code or install anything.
"""

import argparse
import hashlib
from email import policy
from email.parser import BytesParser
from importlib import metadata
import json
import os
from pathlib import Path
import re
import stat
import sysconfig


MAX_DISTRIBUTIONS = 1000
MAX_METADATA_BYTES = 262_144
MAX_DIRECT_URL_BYTES = 32_768
MAX_REQUIREMENTS = 1000
MAX_ROOTS = 12
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.!+~-]{0,127}\Z")
PYTHON_SPEC_RE = re.compile(r"[0-9\s,.<>!=~*+\-]{0,256}\Z")


def bounded_regular(path, limit):
    """Use a no-follow file descriptor; do not disclose raw path on failure."""
    if path.is_symlink():
        raise ValueError("symlink_refused")
    descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("not_regular_unique_file")
        if info.st_size > limit:
            raise ValueError("size_limit")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("size_limit")
        after = os.fstat(stream.fileno())
        if (info.st_ino, info.st_dev, info.st_size, info.st_mtime_ns) != (
                after.st_ino, after.st_dev, after.st_size, after.st_mtime_ns):
            raise ValueError("file_changed_during_read")
        return data


def direct_origin(info_dir):
    """Expose only SHA256 of a URL, never credentials, path or query params."""
    location = info_dir / "direct_url.json"
    try:
        content = bounded_regular(location, MAX_DIRECT_URL_BYTES)
    except FileNotFoundError:
        return {"status": "NOT_DECLARED"}
    except (OSError, ValueError):
        return {"status": "INVALID_NOT_VERIFIED"}
    try:
        obj = json.loads(content.decode("utf-8"))
        if not isinstance(obj, dict) or not isinstance(obj.get("url"), str):
            return {"status": "INVALID_NOT_VERIFIED"}
        url = obj["url"]
        if not url or len(url) > 8192 or "\0" in url:
            return {"status": "INVALID_NOT_VERIFIED"}
        return {"status": "RECORDED_NOT_VERIFIED",
                "url_sha256": hashlib.sha256(url.encode("utf-8")).hexdigest(),
                "credentials_or_path_exposed": False}
    except (ValueError, UnicodeError, TypeError):
        return {"status": "INVALID_NOT_VERIFIED"}


def read_distribution(dist):
    """Read bounded METADATA/PKG-INFO via paths; no dist module import."""
    base = getattr(dist, "_path", None)
    if base is None:
        return None
    info_dir = Path(base)
    if info_dir.is_symlink() or not info_dir.is_dir():
        return None
    candidates = [info_dir / "METADATA", info_dir / "PKG-INFO"]
    content = None
    for candidate in candidates:
        try:
            content = bounded_regular(candidate, MAX_METADATA_BYTES)
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            return None
        break
    if content is None or b"\0" in content:
        return None
    try:
        parsed = BytesParser(policy=policy.compat32).parsebytes(content)
        names = parsed.get_all("Name") or []
        versions = parsed.get_all("Version") or []
        if len(names) != 1 or len(versions) != 1:
            return None
        name, version = str(names[0]), str(versions[0])
        if not NAME_RE.fullmatch(name) or not VERSION_RE.fullmatch(version):
            return None
        requirements = parsed.get_all("Requires-Dist") or []
        if len(requirements) > MAX_REQUIREMENTS:
            return None
        requirement_bytes = "\n".join(str(req) for req in requirements).encode("utf-8")
        python_requirements = parsed.get_all("Requires-Python") or []
        if len(python_requirements) > 1:
            return None
        python_spec = str(python_requirements[0]) if python_requirements else None
        if python_spec is not None and not PYTHON_SPEC_RE.fullmatch(python_spec):
            # A nonstandard untrusted value should never appear verbatim.
            python_spec = None
        return {
            "name": re.sub(r"[-_.]+", "-", name).lower(),
            "version": version,
            "requires_python": python_spec,
            "requires_dist_count": len(requirements),
            "requires_dist_sha256": hashlib.sha256(requirement_bytes).hexdigest(),
            "metadata_sha256": hashlib.sha256(content).hexdigest(),
            "origin": direct_origin(info_dir),
            "source": "LOCAL_INSTALLED_METADATA_NOT_AUTHENTICATED",
        }
    except (UnicodeError, ValueError, TypeError):
        return None


def inspect(extra_roots=None, include_installed=True):
    """Produce deterministic, bounded observations; never claim completeness."""
    roots = set()
    if include_installed:
        for entry in (sysconfig.get_path("purelib"), sysconfig.get_path("platlib")):
            if entry:
                roots.add(str(Path(entry).resolve()))
    for entry in extra_roots or []:
        path = Path(entry)
        if path.is_symlink() or not path.is_dir():
            raise ValueError("invalid_metadata_directory")
        roots.add(str(path.resolve()))
    if not roots or len(roots) > MAX_ROOTS:
        raise ValueError("missing_or_too_many_roots")

    entries, visited, refused, limited = [], 0, 0, False
    for dist in metadata.distributions(path=sorted(roots)):
        visited += 1
        if visited > MAX_DISTRIBUTIONS:
            limited = True
            break
        record = read_distribution(dist)
        if record is None:
            refused += 1
        else:
            entries.append(record)
    entries.sort(key=lambda item: (item["name"], item["version"], item["metadata_sha256"]))
    duplicates = set()
    previous = None
    for entry in entries:
        if entry["name"] == previous:
            duplicates.add(previous)
        previous = entry["name"]
    return {
        "schema_version": 1,
        "status": "PARTIAL_UNVERIFIED" if limited or refused else
                  "INVENTORIED_UNVERIFIED" if entries else "NO_METADATA_FOUND",
        "packages": entries,
        "packages_recorded": len(entries),
        "distributions_seen": visited,
        "metadata_refused": refused,
        "limit_hit": limited,
        "ambiguous_names": sorted(duplicates),
        "modules_executed": False,
        "source_executed": False,
        "installation_performed": False,
        "network_used": False,
        "vulnerabilities_scanned": False,
        "publisher_verified": False,
        "dependency_resolution": "NOT_RUN",
        "note": "Read-only SBOM candidate; neither authoritative inventory nor vulnerability/provenance attestation",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata-dir", action="append", default=[])
    parser.add_argument("--only-metadata-dir", action="store_true")
    args = parser.parse_args()
    print(json.dumps(inspect(args.metadata_dir, not args.only_metadata_dir), ensure_ascii=False))


if __name__ == "__main__":
    main()
