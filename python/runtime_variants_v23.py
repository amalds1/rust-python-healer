"""Actual CPython versus PyPy identity: do not transfer one runtime's PASS.

F174 is evidenced by running this fixed metadata-only script *under the
interpreter under test*. Input strings cannot change sys.implementation.
No virtual machine, arbitrary project import or third-party code executes.
"""

import argparse
import importlib.machinery
import json
import platform
import struct
import sys
import sysconfig


VALID_IMPLEMENTATIONS = frozenset(("cpython", "pypy"))


def actual_runtime_identity():
    name = sys.implementation.name
    abi = sysconfig.get_config_var("SOABI")
    if not isinstance(abi, str) or not 0 < len(abi) <= 128:
        abi = None
    pypy_version = getattr(sys, "pypy_version_info", None)
    if pypy_version is not None:
        pypy_version = "{}.{}.{}".format(*pypy_version[:3])
    tag = getattr(sys.implementation, "cache_tag", None)
    suffix = sysconfig.get_config_var("EXT_SUFFIX")
    platform_tag = sysconfig.get_platform().lower().replace("-", "_")
    machine = platform.machine().lower()
    pointer_bits = struct.calcsize("P") * 8
    soabi_consistent = (bool(abi) and abi.startswith("pypy") if name == "pypy" else
                        bool(abi) and abi.startswith("cpython-") if name == "cpython" else
                        False)
    basis = "SOABI_IMPLEMENTATION_PREFIX"
    if name == "cpython" and sys.platform == "win32":
        # Older Windows CPython deliberately has no SOABI. Its tagged .pyd
        # suffix, cache tag and actual process architecture carry the ABI.
        # Keep the observed None; never synthesize an allegedly observed SOABI.
        expected_tag = "cpython-{}{}".format(*sys.version_info[:2])
        abi_tag = "cp{}{}{}".format(*sys.version_info[:2],
                                    "t" if sysconfig.get_config_var("Py_GIL_DISABLED") else "")
        expected_abi = abi_tag + "-" + platform_tag
        architecture_consistent = (
            platform_tag == "win_amd64" and machine in ("amd64", "x86_64") and pointer_bits == 64 or
            platform_tag == "win_arm64" and machine in ("arm64", "aarch64") and pointer_bits == 64 or
            platform_tag == "win32" and pointer_bits == 32 and machine in ("x86", "i386", "i686", "amd64", "x86_64")
        )
        soabi_consistent = bool(architecture_consistent and tag == expected_tag and
            suffix == "." + expected_abi + ".pyd" and
            suffix in importlib.machinery.EXTENSION_SUFFIXES and
            (abi is None or abi == expected_abi))
        basis = "WINDOWS_EXT_SUFFIX_CACHE_TAG_PLATFORM_PROCESS_ARCHITECTURE"
    return {"status": "ACTUAL_PYPY_RUNTIME_OBSERVED" if name == "pypy" and soabi_consistent
            else "ACTUAL_CPYTHON_RUNTIME_OBSERVED" if name == "cpython" and soabi_consistent
            else "UNSUPPORTED_OR_CONTRADICTORY_INTERPRETER_IDENTITY",
            "implementation": name,
            "python_version": "{}.{}.{}".format(*sys.version_info[:3]),
            "runtime_platform": platform.system().lower(),
            "runtime_machine": platform.machine().lower(),
            "soabi": abi, "soabi_consistent_with_implementation": soabi_consistent,
            "abi_metadata_basis": basis, "configured_extension_suffix": suffix,
            "configured_platform_tag": platform_tag, "process_pointer_bits": pointer_bits,
            "extension_suffixes": list(importlib.machinery.EXTENSION_SUFFIXES),
            "cache_tag": tag,
            "pypy_implementation_version": pypy_version,
            "actual_sys_implementation_inspected": True,
            "python_project_source_executed": False,
            "cpython_native_extension_result_reused_for_pypy": False,
            "native_package_compatibility_proven": False}


def require_runtime_identity(expected):
    """Refuse CPython-only evidence under PyPy and vice versa."""
    if not isinstance(expected, str) or expected not in VALID_IMPLEMENTATIONS:
        raise ValueError("unsupported_expected_implementation")
    actual = actual_runtime_identity()
    matched = actual["implementation"] == expected and \
        actual["soabi_consistent_with_implementation"]
    return {"status": "REAL_RUNTIME_IMPLEMENTATION_MATCH" if matched else
            "CROSS_IMPLEMENTATION_EVIDENCE_REJECTED",
            "required_implementation": expected,
            "actual_implementation": actual["implementation"],
            "actual_soabi": actual["soabi"],
            "soabi_consistent": actual["soabi_consistent_with_implementation"],
            "compatible_evidence_reusable": bool(matched),
            "runtime_metadata_source": "ACTUAL_RUNNING_INTERPRETER",
            "other_implementation_executed_in_this_process": False}


def native_wheel_abi_family_for_runtime():
    """Never say a CPython ABI binary can be imported into PyPy."""
    actual = actual_runtime_identity()
    implementation = actual["implementation"]
    if implementation == "pypy":
        native_tag = "pp3{}".format(sys.version_info.minor)
    elif implementation == "cpython":
        native_tag = "cp3{}".format(sys.version_info.minor)
    else:
        native_tag = None
    return {"status": "NATIVE_ABI_FAMILY_SEPARATED" if native_tag else
            "UNSUPPORTED_IMPLEMENTATION_NO_NATIVE_PASS",
            "implementation": implementation,
            "expected_native_wheel_python_tag": native_tag,
            "actual_soabi": actual["soabi"],
            "foreign_cpython_binary_imported": False,
            "pypy_native_compilation_or_import_proven": False,
            "abi_tag_wheel_compatibility_fully_verified": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("identity", "gate", "abi"), default="identity")
    parser.add_argument("--expected", choices=("cpython", "pypy"))
    args = parser.parse_args(argv)
    try:
        if args.mode == "identity":
            report = actual_runtime_identity()
        elif args.mode == "gate":
            report = require_runtime_identity(args.expected)
        else:
            report = native_wheel_abi_family_for_runtime()
    except ValueError:
        report = {"status": "REJECTED_INVALID_IMPLEMENTATION_POLICY",
                  "python_project_source_executed": False}
    print(json.dumps(report, sort_keys=True))
    return 0 if not report["status"].startswith(("UNSUPPORTED", "REJECTED_INVALID")) else 2


if __name__ == "__main__":
    raise SystemExit(main())
