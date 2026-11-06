"""Bounded Windows read beneath a pinned directory, with no reparse traversal.

Each child name is opened relative to its live parent HANDLE by NtCreateFile.
Only existing local disk files may be read; no file is created or executed.
"""

import ctypes
from ctypes import wintypes
from functools import lru_cache
import importlib.util
import os
from pathlib import Path
import re

COMPONENT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z")


class UnicodeString(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.USHORT),
        ("maximum", wintypes.USHORT),
        ("buffer", wintypes.LPWSTR),
    ]


class ObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.ULONG),
        ("root", wintypes.HANDLE),
        ("name", ctypes.POINTER(UnicodeString)),
        ("attributes", wintypes.ULONG),
        ("security", ctypes.c_void_p),
        ("quality", ctypes.c_void_p),
    ]


class IoStatus(ctypes.Structure):
    _fields_ = [
        ("status_or_pointer", ctypes.c_void_p),
        ("information", ctypes.c_size_t),
    ]


@lru_cache(maxsize=1)
def _libraries():
    if os.name != "nt":
        raise ValueError("windows_blob_platform_required")
    privacy = globals().get("_RPH_WINDOWS_PRIVACY")
    if privacy is None:
        spec = importlib.util.spec_from_file_location(
            "rph_blob_privacy", Path(__file__).with_name("windows_private_paths.py")
        )
        privacy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(privacy)
    kernel, _ = privacy._libraries()
    native = ctypes.WinDLL("ntdll", use_last_error=True)
    native.NtCreateFile.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(ObjectAttributes),
        ctypes.POINTER(IoStatus),
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    native.NtCreateFile.restype = wintypes.LONG
    kernel.GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel.ReadFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    kernel.ReadFile.restype = wintypes.BOOL
    return privacy, kernel, native


def _information(handle, directory, limit):
    privacy, kernel, _ = _libraries()
    info = privacy._FileInformation()
    if kernel.GetFileType(handle) != 1 or not kernel.GetFileInformationByHandle(
        handle, ctypes.byref(info)
    ):
        raise ValueError("blob_handle_metadata_unavailable")
    if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory:
        raise ValueError("blob_reparse_or_type_refused")
    size = (info.size_high << 32) | info.size_low
    if not directory and (info.links != 1 or size > limit):
        raise ValueError("blob_not_unique_regular_bounded_file")
    return (
        info.volume,
        info.index_high,
        info.index_low,
        size,
        info.write.dwHighDateTime,
        info.write.dwLowDateTime,
        info.links,
    )


def _relative_open(parent, name, directory):
    _, kernel, native = _libraries()
    if (
        type(name) is not str
        or not COMPONENT.fullmatch(name)
        or name.endswith(".")
        or name.split(".")[0].upper()
        in {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            *("COM" + str(i) for i in range(1, 10)),
            *("LPT" + str(i) for i in range(1, 10)),
        }
    ):
        raise ValueError("unsafe_windows_blob_component")
    text = ctypes.create_unicode_buffer(name)
    u = UnicodeString(
        len(name) * 2, (len(name) + 1) * 2, ctypes.cast(text, wintypes.LPWSTR)
    )
    attributes = ObjectAttributes(
        ctypes.sizeof(ObjectAttributes), parent, ctypes.pointer(u), 0x40, None, None
    )
    status = IoStatus()
    handle = wintypes.HANDLE()
    # SYNCHRONIZE+GENERIC_READ; share READ only; OPEN existing; synchronous,
    # OPEN_REPARSE_POINT on every single relative component (never a path).
    options = 0x00200000 | 0x20 | (0x1 if directory else 0x40)
    rc = native.NtCreateFile(
        ctypes.byref(handle),
        0x80100000,
        ctypes.byref(attributes),
        ctypes.byref(status),
        None,
        0,
        1,
        1,
        options,
        None,
        0,
    )
    if rc < 0:
        if handle.value:
            kernel.CloseHandle(handle)
        raise ValueError("blob_relative_handle_open_refused")
    if not handle.value:
        raise ValueError("blob_relative_handle_invalid")
    return handle


def read_blob_beneath(root, components, limit):
    if (
        type(limit) is not int
        or not 1 <= limit <= 1048576
        or type(components) is not list
        or not 1 <= len(components) <= 32
    ):
        raise ValueError("invalid_windows_blob_budget")
    raw = os.fspath(root)
    if type(raw) is not str or "\x00" in raw:
        raise ValueError("invalid_windows_blob_root")
    absolute = os.path.abspath(raw)
    drive, tail = os.path.splitdrive(absolute)
    if len(drive) != 2 or drive[1] != ":" or not tail.startswith(("\\", "/")):
        raise ValueError("local_windows_blob_root_required")
    _, kernel, _ = _libraries()
    handles = []
    try:
        handle = kernel.CreateFileW(
            absolute, 0x80100000, 1, None, 3, 0x02000000 | 0x00200000, None
        )
        if handle == ctypes.c_void_p(-1).value:
            raise ValueError("blob_root_open_refused")
        handles.append(handle)
        _information(handle, True, limit)
        final = ctypes.create_unicode_buffer(32768)
        length = kernel.GetFinalPathNameByHandleW(handle, final, len(final), 0)
        if not 0 < length < len(final):
            raise ValueError("blob_root_identity_unavailable")
        normalized = final.value
        if normalized.startswith("\\\\?\\"):
            normalized = normalized[4:]
        if os.path.normcase(os.path.normpath(normalized)) != os.path.normcase(
            os.path.normpath(absolute)
        ):
            raise ValueError("blob_root_ancestor_alias_refused")
        for i, name in enumerate(components):
            directory = i < len(components) - 1
            handle = _relative_open(handles[-1], name, directory)
            handles.append(handle)
            before = _information(handle, directory, limit)
        data = ctypes.create_string_buffer(limit + 1)
        read = wintypes.DWORD()
        if not kernel.ReadFile(handle, data, len(data), ctypes.byref(read), None):
            raise ValueError("blob_read_failed")
        after = _information(handle, False, limit)
        if before != after or read.value > limit or read.value != before[3]:
            raise ValueError("blob_changed_during_read")
        return data.raw[: read.value]
    finally:
        for handle in reversed(handles):
            kernel.CloseHandle(handle)
