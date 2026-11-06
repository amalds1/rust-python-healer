"""Bounded, read-only CPython wheel-tag/ABI comparison for Python 3.9--3.15.

This compares *declared tags* with interpreter metadata; it does not load a
native library, execute a wheel, install a package, verify wheel provenance, or
prove that an extension imports. Non-exact OS policy (manylinux, musllinux,
macOS deployment versions) intentionally remains UNKNOWN.

Version-sensitive rules: CPython debug builds since 3.8 can also accept the
normal same-version ABI; free-threaded CPython 3.13+ has the ``t`` ABI and
does not accept ``abi3``; ``abi3t`` is supported only from CPython 3.15.
"""

import argparse
import importlib.machinery
import json
import platform
import re
import sys
import sysconfig


MAX_FILENAME_LENGTH = 512
MAX_TAG_ALTERNATIVES = 24
MAX_TAG_COMBINATIONS = 256
MIN_SUPPORTED_MINOR = 9
MAX_SUPPORTED_MINOR = 15

_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.]*\Z", re.ASCII)
_VERSION = re.compile(r"[0-9][A-Za-z0-9._!+]*\Z", re.ASCII)
_BUILD = re.compile(r"[0-9][A-Za-z0-9_]*\Z", re.ASCII)
_TAG = re.compile(r"[a-z][a-z0-9_]*\Z", re.ASCII)
_ABI = re.compile(r"cp(3)(\d{1,2})(td|t|d)?\Z", re.ASCII)
_CPYTHON = re.compile(r"cp3(\d{1,2})\Z", re.ASCII)
_PYTHON = re.compile(r"py3(\d{1,2})\Z", re.ASCII)
_SOABI = re.compile(r"cpython-(3)(\d{1,2})(td|t|d)?(?:-|\Z)", re.ASCII)
_WINDOWS_SOABI = re.compile(r"cp(3)(\d{1,2})(td|t|d)?-(win_amd64|win32|win_arm64)\Z", re.ASCII)


def _candidate_tags(text):
    tags = text.split(".")
    if not tags or len(tags) > MAX_TAG_ALTERNATIVES:
        raise ValueError("wheel_tag_count_limit")
    if any(not _TAG.fullmatch(tag) for tag in tags) or len(set(tags)) != len(tags):
        raise ValueError("invalid_wheel_tag")
    return tuple(sorted(tags))


def parse_wheel_filename(filename):
    """Parse a *basename*, not a path; never touch the filesystem.

    Supports PEP 427's five-/six-field filename and dot-compressed tags.
    This is a syntactic parser; it does not authenticate distributions or
    independently validate the entire PEP 440 version grammar.
    """
    if not isinstance(filename, str) or not 1 <= len(filename) <= MAX_FILENAME_LENGTH:
        raise ValueError("invalid_wheel_filename")
    if not filename.isascii() or "\\" in filename or "/" in filename or "\x00" in filename:
        raise ValueError("invalid_wheel_filename")
    if not filename.endswith(".whl"):
        raise ValueError("invalid_wheel_filename")
    fields = filename[:-4].split("-")
    if len(fields) == 5:
        distribution, version, python, abi, platform = fields
        build = None
    elif len(fields) == 6:
        distribution, version, build, python, abi, platform = fields
        if not _BUILD.fullmatch(build):
            raise ValueError("invalid_wheel_build_tag")
    else:
        raise ValueError("invalid_wheel_filename")
    if not _NAME.fullmatch(distribution) or not _VERSION.fullmatch(version):
        raise ValueError("invalid_wheel_name_or_version")
    pythons = _candidate_tags(python)
    abis = _candidate_tags(abi)
    platforms = _candidate_tags(platform)
    if len(pythons) * len(abis) * len(platforms) > MAX_TAG_COMBINATIONS:
        raise ValueError("wheel_tag_combination_limit")
    return {
        "distribution": distribution, "version": version, "build": build,
        "python_tags": pythons, "abi_tags": abis, "platform_tags": platforms,
    }


def inspect_runtime():
    """Collect only this CPython's own stdlib ABI metadata."""
    version = sys.version_info
    free_threaded = bool(sysconfig.get_config_var("Py_GIL_DISABLED")) if version[:2] >= (3, 13) else False
    py_debug = sysconfig.get_config_var("Py_DEBUG")
    if py_debug is None:
        debug = hasattr(sys, "gettotalrefcount") or "_d.pyd" in importlib.machinery.EXTENSION_SUFFIXES
        debug_known = debug
        if sys.platform == "win32" and not debug and sys.implementation.name == "cpython":
            actual_platform = sysconfig.get_platform().replace("-", "_").lower()
            machine = platform.machine().lower()
            bits = 64 if sys.maxsize > 2 ** 32 else 32
            architecture_matches = (
                actual_platform == "win_amd64" and bits == 64 and machine in ("amd64", "x86_64") or
                actual_platform == "win_arm64" and bits == 64 and machine in ("arm64", "aarch64") or
                actual_platform == "win32" and bits == 32 and machine in ("x86", "i386", "i686", "amd64", "x86_64")
            )
            expected = ".cp{}{}{}-{}.pyd".format(version.major, version.minor,
                "t" if free_threaded else "", actual_platform)
            debug_known = bool(architecture_matches and sysconfig.get_config_var("EXT_SUFFIX") == expected and
                expected in importlib.machinery.EXTENSION_SUFFIXES and
                sys.implementation.cache_tag == "cpython-{}{}".format(version.major, version.minor))
    else:
        debug = bool(py_debug)
        debug_known = True
    soabi = sysconfig.get_config_var("SOABI")
    if not isinstance(soabi, str) or len(soabi) > 128 or not soabi.isascii():
        soabi = None
    return {
        "implementation": sys.implementation.name,
        "major": version.major,
        "minor": version.minor,
        "debug": debug,
        "debug_known": debug_known,
        "free_threaded": free_threaded,
        "soabi": soabi,
        "platform": sysconfig.get_platform().replace("-", "_").replace(".", "_").lower(),
        "metadata_source": "ACTUAL_RUNNING_INTERPRETER",
    }


def _supported(runtime):
    return (runtime.get("implementation") == "cpython" and runtime.get("major") == 3
            and MIN_SUPPORTED_MINOR <= runtime.get("minor", -1) <= MAX_SUPPORTED_MINOR)


def _abi_metadata_consistent(runtime):
    """An identifiable SOABI that contradicts interpreter flags is not safe."""
    soabi = runtime.get("soabi")
    if soabi is None:
        return True  # SOABI may be absent on Windows.
    match = _SOABI.match(soabi)
    if not match and runtime.get("platform", "").startswith("win"):
        match = _WINDOWS_SOABI.fullmatch(soabi)
        if match and match.group(4) != runtime["platform"]:
            return False
        if not match and soabi.startswith("cp"):
            return False
    if not match:
        return True  # Platform-specific SOABI grammar not audited here.
    if int(match.group(2)) != runtime["minor"]:
        return False
    flags = match.group(3) or ""
    if ("t" in flags) != runtime["free_threaded"]:
        return False
    # Debug builds may have an SOABI without an explicit d suffix on Windows.
    if "d" in flags and not runtime["debug"]:
        return False
    return True


def _python_match(tag, abi, runtime):
    minor = runtime["minor"]
    if abi != "none" and not _CPYTHON.fullmatch(tag):
        # CPython publishes native/Stable-ABI wheel tags with a cpXY Python
        # tag, not py3/py3XY generic interpreter tags.
        return "MISMATCH"
    if tag == "py3":
        return "MATCH"
    match = _PYTHON.fullmatch(tag)
    if match:
        declared = int(match.group(1))
        # packaging.tags includes earlier py3XY-none-* tags on later Python 3
        # runtimes; py39 pure wheels can match Python 3.10--3.15 as well.
        return "MATCH" if 0 <= declared <= minor else "MISMATCH"
    match = _CPYTHON.fullmatch(tag)
    if match:
        declared = int(match.group(1))
        if abi in ("abi3", "abi3t"):
            return "MATCH" if 2 <= declared <= minor else "MISMATCH"
        return "MATCH" if declared == minor else "MISMATCH"
    if tag == "cp3":
        return "UNKNOWN"
    if tag.startswith(("cp2", "py2", "pp", "ip", "jy")):
        return "MISMATCH"
    return "UNKNOWN"


def _abi_match(tag, runtime):
    minor = runtime["minor"]
    threaded = runtime["free_threaded"]
    if tag == "none":
        return "MATCH"
    if tag == "abi3":
        return "MATCH" if not threaded else "MISMATCH"
    if tag == "abi3t":
        return "MATCH" if threaded and minor >= 15 else "MISMATCH"
    match = _ABI.fullmatch(tag)
    if not match:
        return "UNKNOWN"
    if int(match.group(2)) != minor:
        return "MISMATCH"
    flags = match.group(3) or ""
    if ("t" in flags) != threaded:
        return "MISMATCH"
    if not runtime["debug_known"]:
        return "UNKNOWN"
    if "d" in flags and not runtime["debug"]:
        return "MISMATCH"
    # Since CPython 3.8, debug builds also accept non-debug extensions.
    return "MATCH"


def _platform_family(value):
    if value.startswith("win"):
        return "win"
    if value.startswith("macosx"):
        return "macosx"
    if value.startswith(("linux", "manylinux", "musllinux")):
        return "linux"
    return None


def _platform_match(tag, runtime):
    if tag == "any" or tag == runtime["platform"]:
        return "MATCH"
    declared_family = _platform_family(tag)
    actual_family = _platform_family(runtime["platform"])
    if declared_family and actual_family and declared_family != actual_family:
        return "MISMATCH"
    # Unknown platform policies deliberately do not assert wheel portability.
    return "UNKNOWN"


def compare_wheel(filename, runtime=None):
    """Compare one wheel basename; no filesystem access and no native imports."""
    result = {
        "status": "NOT_RUN", "compatibility": "UNKNOWN_NOT_VERIFIED",
        "source_executed": False, "native_extensions_loaded": False,
        "installation_performed": False, "artifact_authenticated": False,
        "native_import_verified": False, "platform_policy_verified": False,
    }
    try:
        wheel = parse_wheel_filename(filename)
    except ValueError as exc:
        result.update(status="INVALID_WHEEL_FILENAME", reason=str(exc))
        return result
    if runtime is None:
        runtime = inspect_runtime()
    # Only bounded, typed data produced by inspect_runtime or caller's synthetic
    # test fixture is accepted; never let corrupt metadata masquerade as a pass.
    if (not isinstance(runtime, dict) or not isinstance(runtime.get("minor"), int)
            or not isinstance(runtime.get("major"), int)
            or not isinstance(runtime.get("platform"), str)
            or not isinstance(runtime.get("debug"), bool)
            or not isinstance(runtime.get("debug_known"), bool)
            or not isinstance(runtime.get("free_threaded"), bool)
            or not isinstance(runtime.get("implementation"), str)):
        result.update(status="INVALID_RUNTIME_METADATA")
        return result
    result.update(
        status="INSPECTED_TAGS", implementation=runtime["implementation"],
        python_version="{}.{}".format(runtime["major"], runtime["minor"]),
        runtime_abi=("cp3{}{}{}".format(runtime["minor"],
                      "t" if runtime["free_threaded"] else "",
                      "d" if runtime["debug"] else "")),
        soabi=runtime.get("soabi"),
        source=runtime.get("metadata_source", "CALLER_SUPPLIED_NOT_PROBED"),
        evaluated_combinations=(len(wheel["python_tags"]) * len(wheel["abi_tags"])
                                * len(wheel["platform_tags"])),
    )
    if not _supported(runtime):
        result.update(compatibility="UNKNOWN_NOT_VERIFIED", reason="runtime_version_not_supported")
        return result
    if runtime["free_threaded"] and runtime["minor"] < 13:
        result.update(compatibility="UNKNOWN_NOT_VERIFIED", reason="impossible_runtime_abi_flags")
        return result
    if not _abi_metadata_consistent(runtime):
        result.update(compatibility="UNKNOWN_NOT_VERIFIED", reason="runtime_abi_metadata_inconsistent")
        return result
    unknown = False
    for py_tag in wheel["python_tags"]:
        for abi_tag in wheel["abi_tags"]:
            for platform_tag in wheel["platform_tags"]:
                a = _python_match(py_tag, abi_tag, runtime)
                b = _abi_match(abi_tag, runtime)
                c = _platform_match(platform_tag, runtime)
                if abi_tag != "none" and platform_tag == "any":
                    # Native ABI tags require a concrete platform tag.
                    c = "MISMATCH"
                if a == b == c == "MATCH":
                    result.update(compatibility="POSSIBLE_TAG_MATCH_NOT_INSTALLED",
                                  matching_tag="{}-{}-{}".format(py_tag, abi_tag, platform_tag))
                    return result
                if "MISMATCH" not in (a, b, c):
                    unknown = True
    result["compatibility"] = "UNKNOWN_NOT_VERIFIED" if unknown else "INCOMPATIBLE_TAG"
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only CPython wheel ABI/tag comparator")
    parser.add_argument("--wheel", required=True, help="Wheel filename only, not a path")
    args = parser.parse_args(argv)
    print(json.dumps(compare_wheel(args.wheel), ensure_ascii=True, sort_keys=True))


if __name__ == "__main__":
    main()
