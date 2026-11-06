"""Bounded Windows HANDLE reads, enumeration and private create-only snapshots.

Only trusted fixed JSON snapshots may be written. Source bytes are never run.
This is local filesystem checking, not an execution or network sandbox.
"""

import ctypes
from ctypes import wintypes
import importlib.util
import os
from pathlib import Path
import re


def _blob():
    module = globals().get("_RPH_WINDOWS_BLOB_READER")
    if module is None:
        spec = importlib.util.spec_from_file_location(
            "rph_security_blob", Path(__file__).with_name("windows_blob_reader_v029.py")
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        privacy = globals().get("_RPH_WINDOWS_PRIVACY")
        if privacy is not None:
            module._RPH_WINDOWS_PRIVACY = privacy
        globals()["_RPH_WINDOWS_BLOB_READER"] = module
    return module


def _name(name):
    if (
        type(name) is not str
        or not 1 <= len(name) <= 190
        or name in (".", "..")
        or name.endswith((".", " "))
        or any(c in name for c in "/\\:\x00")
        or any(ord(c) < 32 or 0xD800 <= ord(c) <= 0xDFFF for c in name)
        or re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", name, re.I)
    ):
        raise ValueError("UNSAFE_RELATIVE_COMPONENT")
    return name


def _open(parent, name, directory, create=False):
    blob = _blob()
    _, kernel, native = blob._libraries()
    _name(name)
    text = ctypes.create_unicode_buffer(name)
    size = len(name.encode("utf-16-le"))
    unicode = blob.UnicodeString(size, size + 2, ctypes.cast(text, wintypes.LPWSTR))
    attrs = blob.ObjectAttributes(
        ctypes.sizeof(blob.ObjectAttributes),
        parent,
        ctypes.pointer(unicode),
        0x40,
        None,
        None,
    )
    status, handle = blob.IoStatus(), wintypes.HANDLE()
    rc = native.NtCreateFile(
        ctypes.byref(handle),
        0xC0110000 if create else 0x80100000,
        ctypes.byref(attrs),
        ctypes.byref(status),
        None,
        0,
        0 if create else 1,
        2 if create else 1,
        0x200000 | 0x20 | (1 if directory else 0x40) | (2 if create else 0),
        None,
        0,
    )
    if rc < 0 or not handle.value:
        if handle.value:
            kernel.CloseHandle(handle)
        raise ValueError("FILE_OPEN_OR_EXCLUSIVE_CREATE_REJECTED")
    return handle


class Root:
    def __init__(self, path):
        self.blob = _blob()
        self.privacy, self.kernel, _ = self.blob._libraries()
        self.handles = []
        absolute = os.path.abspath(os.fspath(path))
        drive, tail = os.path.splitdrive(absolute)
        if (
            len(drive) != 2
            or drive[1] != ":"
            or not tail.startswith("\\")
            or "\x00" in absolute
        ):
            raise ValueError("LOCAL_ROOT_REQUIRED")
        handle = self.kernel.CreateFileW(
            absolute, 0x80100000, 1, None, 3, 0x02000000 | 0x00200000, None
        )
        if not handle or handle == ctypes.c_void_p(-1).value:
            raise ValueError("UNSAFE_PROJECT_ROOT")
        self.handles.append(handle)
        try:
            self.identity = self.blob._information(handle, True, 1048576)
            text = ctypes.create_unicode_buffer(32768)
            length = self.kernel.GetFinalPathNameByHandleW(handle, text, len(text), 0)
            if not 0 < length < len(text):
                raise ValueError("ROOT_IDENTITY_UNAVAILABLE")
            actual = text.value
            if actual.startswith("\\\\?\\"):
                actual = actual[4:]
            if os.path.normcase(os.path.normpath(actual)) != os.path.normcase(
                os.path.normpath(absolute)
            ):
                raise ValueError("ROOT_ANCESTOR_ALIAS_REJECTED")
        except BaseException:
            self.close()
            raise

    def close(self):
        for handle in reversed(self.handles):
            self.kernel.CloseHandle(handle)
        self.handles.clear()

    def child(self, parent, name, directory):
        handle = _open(parent, name, directory)
        self.handles.append(handle)
        info = self.blob._information(handle, directory, 1048576)
        if info[0] != self.identity[0]:
            raise ValueError("CROSS_DEVICE_REJECTED")
        return handle

    def read(self, handle, limit):
        before = self.blob._information(handle, False, limit)
        data, count = ctypes.create_string_buffer(limit + 1), wintypes.DWORD()
        if not self.kernel.ReadFile(handle, data, len(data), ctypes.byref(count), None):
            raise ValueError("FILE_READ_REJECTED")
        after = self.blob._information(handle, False, limit)
        if before != after or count.value != before[3] or count.value > limit:
            raise ValueError("FILE_CHANGED_DURING_READ")
        return data.raw[: count.value]


def read_project_file(root, pieces, limit, race_hook=None):
    opened = Root(root)
    try:
        parent = opened.handles[0]
        for part in pieces[:-1]:
            parent = opened.child(parent, part, True)
        handle = opened.child(parent, pieces[-1], False)
        if race_hook is not None:
            try:
                race_hook()
            except OSError as error:
                reason = (
                    "ROOT_REPLACED"
                    if error.filename
                    and os.path.normcase(os.path.abspath(error.filename))
                    == os.path.normcase(os.path.abspath(root))
                    else "FILE_REPLACED"
                )
                raise ValueError(reason + "_ATTEMPT_BLOCKED_BY_HELD_HANDLE") from None
        return opened.read(handle, limit)
    finally:
        opened.close()


class DirectoryEntry(ctypes.Structure):
    _fields_ = [
        ("next", wintypes.DWORD),
        ("index", wintypes.DWORD),
        ("created", ctypes.c_longlong),
        ("accessed", ctypes.c_longlong),
        ("written", ctypes.c_longlong),
        ("changed", ctypes.c_longlong),
        ("size", ctypes.c_longlong),
        ("allocation", ctypes.c_longlong),
        ("attributes", wintypes.DWORD),
        ("name_bytes", wintypes.DWORD),
        ("ea", wintypes.DWORD),
        ("short_bytes", ctypes.c_byte),
        ("short_name", wintypes.WCHAR * 12),
        ("file_id", ctypes.c_ulonglong),
        ("name", wintypes.WCHAR * 1),
    ]


def _entries(opened, handle, budget):
    kernel = opened.kernel
    kernel.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    rows = []
    while True:
        buffer = ctypes.create_string_buffer(65536)
        if not kernel.GetFileInformationByHandleEx(handle, 10, buffer, len(buffer)):
            if ctypes.get_last_error() == 18:  # ERROR_NO_MORE_FILES
                return rows
            raise ValueError("DIRECTORY_ENUMERATION_REJECTED")
        offset = 0
        while True:
            if offset + ctypes.sizeof(DirectoryEntry) > len(buffer):
                raise ValueError("DIRECTORY_RECORD_BOUNDS")
            row = DirectoryEntry.from_buffer(buffer, offset)
            start = offset + DirectoryEntry.name.offset
            if (
                row.name_bytes % 2
                or not 0 < row.name_bytes <= 380
                or start + row.name_bytes > len(buffer)
            ):
                raise ValueError("DIRECTORY_NAME_BOUNDS")
            name = buffer.raw[start : start + row.name_bytes].decode(
                "utf-16-le", "strict"
            )
            if name not in (".", ".."):
                _name(name)
                rows.append((name, row.attributes, row.file_id))
                if len(rows) > budget:
                    raise ValueError("SCAN_ENTRY_BUDGET")
            if row.next == 0:
                break
            if (row.next % 8 or row.next < ctypes.sizeof(DirectoryEntry) or
                    row.next < DirectoryEntry.name.offset + row.name_bytes or
                    offset + row.next > len(buffer)):
                raise ValueError("DIRECTORY_NEXT_BOUNDS")
            offset += row.next


def scan_project(root, max_files, max_bytes, max_depth):
    opened = Root(root)
    summary = {
        "status": "SAFE_DESCRIPTOR_SCAN_LOCAL_ONLY",
        "python_files": 0,
        "bytes_scanned": 0,
        "skipped_symlinks": 0,
        "no_external_symlink_followed": True,
        "unknown_source_executed": False,
        "cross_platform_proven": False,
        "enumeration_origin": "GetFileInformationByHandleEx",
        "network_isolation_proven": False,
        "sandbox_proven": False,
    }
    visited = 0

    def walk(handle, depth):
        nonlocal visited
        if depth > max_depth:
            raise ValueError("PATH_DEPTH_LIMIT")
        for name, attributes, identity in sorted(
            _entries(opened, handle, max_files * 4)
        ):
            visited += 1
            if visited > max_files * 4:
                raise ValueError("SCAN_ENTRY_BUDGET")
            if name in (".git", ".venv", "venv", "__pycache__", "build", "target"):
                continue
            if attributes & 0x400:
                summary["skipped_symlinks"] += 1
                continue
            directory = bool(attributes & 0x10)
            if not directory and not name.endswith(".py"):
                continue
            child = opened.child(handle, name, directory)
            info = opened.blob._information(child, directory, 1048576)
            if (info[1] << 32 | info[2]) != identity:
                raise ValueError("FILE_REPLACED_SINCE_ENUMERATION")
            try:
                if directory:
                    walk(child, depth + 1)
                else:
                    summary["python_files"] += 1
                    if summary["python_files"] > max_files:
                        raise ValueError("SCAN_FILE_BUDGET")
                    data = opened.read(
                        child, min(1000000, max_bytes - summary["bytes_scanned"])
                    )
                    summary["bytes_scanned"] += len(data)
            finally:
                opened.kernel.CloseHandle(opened.handles.pop())

    try:
        walk(opened.handles[0], 0)
        return summary
    finally:
        opened.close()


def write_private_snapshot(folder, name, payload):
    opened = Root(folder)
    handle = None
    committed = False
    try:
        opened.privacy._inspect_private_handle(
            opened.handles[0], True, *opened.privacy._libraries()
        )
        if type(payload) is not bytes or len(payload) > 64000:
            raise ValueError("THREAT_SNAPSHOT_SIZE_BUDGET")
        handle = _open(opened.handles[0], name, False, create=True)
        opened.privacy._inspect_private_handle(
            handle, False, *opened.privacy._libraries()
        )
        kernel = opened.kernel
        kernel.WriteFile.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        kernel.WriteFile.restype = wintypes.BOOL
        kernel.FlushFileBuffers.argtypes = [wintypes.HANDLE]
        kernel.FlushFileBuffers.restype = wintypes.BOOL
        count = wintypes.DWORD()
        if not kernel.WriteFile(
            handle, payload, len(payload), ctypes.byref(count), None
        ) or count.value != len(payload):
            raise ValueError("THREAT_WRITE_FAILED")
        opened.privacy._inspect_private_handle(
            handle, False, *opened.privacy._libraries()
        )
        opened.privacy._inspect_private_handle(
            opened.handles[0], True, *opened.privacy._libraries()
        )
        if not kernel.FlushFileBuffers(handle):
            raise ValueError("THREAT_FILE_FLUSH_FAILED")
        committed = True
        return {"file_data_flushed": True, "directory_durability_verified": False}
    finally:
        cleanup_failed = False
        if handle is not None:
            if not committed:
                # Delete only the exact, still-exclusively-held file we created.
                kernel = opened.kernel
                kernel.SetFileInformationByHandle.argtypes = [
                    wintypes.HANDLE,
                    ctypes.c_int,
                    ctypes.c_void_p,
                    wintypes.DWORD,
                ]
                kernel.SetFileInformationByHandle.restype = wintypes.BOOL
                delete = ctypes.c_ubyte(1)  # FILE_DISPOSITION_INFO.BOOLEAN
                cleanup_failed = not kernel.SetFileInformationByHandle(
                    handle, 4, ctypes.byref(delete), ctypes.sizeof(delete)
                )
            opened.kernel.CloseHandle(handle)
        opened.close()
        if cleanup_failed:
            raise ValueError("THREAT_PARTIAL_FILE_CLEANUP_FAILED")
