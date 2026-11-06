"""Read-only interpreter build identification for CPython 3.9+ and other VMs.

Executed by Rust with -I -S -B; does not import any target project module.
"""

import json
from datetime import date, datetime, timezone
from pathlib import Path
import platform
import sys
import sysconfig


# Python Developer's Guide, https://devguide.python.org/versions/.
# Future dates are scheduled, not a guarantee. Unknown minors deliberately
# remain UNKNOWN until this table is independently verified and refreshed.
_LIFECYCLE = {
    9: (date(2025, 10, 31), date(2022, 5, 1)),
    10: (date(2026, 10, 1), date(2023, 4, 1)),
    11: (date(2027, 10, 31), date(2024, 4, 1)),
    12: (date(2028, 10, 31), date(2025, 4, 1)),
    13: (date(2029, 10, 31), date(2026, 10, 1)),
    14: (date(2030, 10, 31), date(2027, 10, 1)),
    15: (date(2031, 10, 31), date(2028, 10, 1)),
}


def support_status(major, minor, today=None):
    """Report upstream CPython lifecycle, never infer support for new minors.

    Month-only planned lifecycle boundaries are intentionally conservative;
    an update of the official Devguide may supersede these local dates.
    """
    today = today if today is not None else datetime.now(timezone.utc).date()
    result = {
        "source": "https://devguide.python.org/versions/",
        "schedule_checked_utc": "2026-11-01",
        "as_of_utc": today.isoformat(),
        "schedule_may_change": True,
        "status": "UNKNOWN",
        "end_of_life": None,
        "warning": "Geen geverifieerde CPython-ondersteuningsplanning voor deze versie.",
    }
    if major != 3 or minor not in _LIFECYCLE:
        return result
    eol, security_start = _LIFECYCLE[minor]
    result["end_of_life"] = eol.isoformat()
    if today > eol:
        result["status"] = "END_OF_LIFE"
        result["warning"] = "Deze CPython-versie ontvangt upstream geen beveiligingsupdates meer."
    elif today >= security_start:
        result["status"] = "SECURITY_ONLY"
        result["warning"] = "Deze CPython-versie ontvangt upstream alleen nog beveiligingsfixes."
    else:
        result["status"] = "BUGFIX_AND_SECURITY"
        result["warning"] = None
    return result


def classify(implementation, minor, gil_disabled, gil_enabled):
    """Distinguish build configuration from dynamically enabled GIL state."""
    if implementation != "cpython":
        return "OTHER_INTERPRETER"
    if minor < (3, 13):
        return "LEGACY_GIL_BUILD"
    if gil_disabled in (1, "1", True):
        return "FREE_THREADED_BUILD"
    if gil_disabled in (0, "0", False, None):
        return "STANDARD_GIL_BUILD"
    return "UNKNOWN_BUILD"


def installation_policy(in_virtual_environment, externally_managed_marker):
    """A read-only PEP 668 policy; this helper never installs packages."""
    if in_virtual_environment:
        return "VIRTUAL_ENV_NO_INSTALL_PERFORMED"
    if externally_managed_marker:
        return "EXTERNALLY_MANAGED_INSTALL_FORBIDDEN"
    return "UNMARKED_NO_INSTALL_PERFORMED"


def probe():
    impl = sys.implementation.name
    version = (sys.version_info.major, sys.version_info.minor)
    is_gil_enabled = getattr(sys, "_is_gil_enabled", None)
    actual_gil = is_gil_enabled() if callable(is_gil_enabled) else None
    free_threaded_flag = sysconfig.get_config_var("Py_GIL_DISABLED")
    executable = Path(sys.executable)
    # CPython <3.14 may not set sys.prefix to the venv when using -S.
    possible_configs = (executable.parent / "pyvenv.cfg",
                        executable.parent.parent / "pyvenv.cfg")
    in_venv = (sys.prefix != sys.base_prefix or
               any(path.is_file() for path in possible_configs))
    # get_default_scheme() is absent on Python 3.9; get_path() already uses it.
    stdlib = sysconfig.get_path("stdlib")
    marker_exists = bool(stdlib and (Path(stdlib) / "EXTERNALLY-MANAGED").is_file())
    return {
        "status": "INSPECTED",
        "implementation": impl,
        "version": list(sys.version_info[:3]),
        "support": support_status(*version),
        "build": classify(impl, version, free_threaded_flag, actual_gil),
        "gil_enabled_runtime": actual_gil,
        "py_gil_disabled_build_flag": free_threaded_flag,
        "soabi": sysconfig.get_config_var("SOABI"),
        "abi_flags": getattr(sys, "abiflags", ""),
        "platform": sys.platform,
        "machine": platform.machine(),
        "packaging_environment": {
            "virtual_environment_detected": in_venv,
            "externally_managed_marker": marker_exists,
            "policy": installation_policy(in_venv, marker_exists),
        },
        "note": "Metadata only: no free-threaded concurrency or native ABI tests performed",
    }


if __name__ == "__main__":
    print(json.dumps(probe(), sort_keys=True))
