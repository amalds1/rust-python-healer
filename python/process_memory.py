"""Actual process-lifetime peak resident memory, normalized to KiB.

Windows PeakWorkingSetSize and macOS ru_maxrss are bytes; Linux ru_maxrss is
already KiB. A sample at benchmark start is a prior high-water mark, not the
current resident set. Unsupported APIs raise instead of reporting fake zeros.
"""

import os
import sys


def rss_basis():
    if os.name == "nt":
        return "windows_peak_working_set_process_high_water"
    if sys.platform == "darwin":
        return "macos_ru_maxrss_process_high_water_bytes_to_kib"
    return "linux_ru_maxrss_process_high_water"


def _windows_peak_working_set_bytes():
    import ctypes
    from ctypes import wintypes

    class ProcessMemoryCounters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
            (name, ctypes.c_size_t) for name in (
                "PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.K32GetProcessMemoryInfo.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(ProcessMemoryCounters), wintypes.DWORD]
    kernel.K32GetProcessMemoryInfo.restype = wintypes.BOOL
    counters = ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    # GetCurrentProcess returns a pseudo-handle; it must not be closed.
    if not kernel.K32GetProcessMemoryInfo(
            kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
        raise ctypes.WinError(ctypes.get_last_error())
    if counters.PeakWorkingSetSize <= 0:
        raise RuntimeError("process_peak_working_set_unavailable")
    return counters.PeakWorkingSetSize


def peak_rss_kib():
    if os.name == "nt":
        return _windows_peak_working_set_bytes() / 1024.0
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if peak <= 0:
        raise RuntimeError("process_peak_rss_unavailable")
    return peak / 1024.0 if sys.platform == "darwin" else peak
