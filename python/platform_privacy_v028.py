"""Scoped platform adapters; no ACL repair or production durability claim."""
import ctypes
from contextlib import contextmanager
from ctypes import wintypes
from functools import lru_cache
import importlib.util
import os
from pathlib import Path


@lru_cache(maxsize=1)
def windows_privacy():
    embedded = globals().get("_RPH_WINDOWS_PRIVACY")
    if embedded is not None:
        return embedded
    path = Path(__file__).resolve().parent / "windows_private_paths.py"
    spec = importlib.util.spec_from_file_location("rph_windows_private_paths", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private_directory(path, label):
    try:
        return windows_privacy().assert_private_directory(path)
    except (OSError, ValueError) as problem:
        raise ValueError(label) from problem


def private_descriptor(descriptor, label):
    try:
        return windows_privacy().assert_private_file_descriptor(descriptor)
    except (OSError, ValueError) as problem:
        raise ValueError(label) from problem


def flush_file(descriptor):
    """Real open file data flush; Windows os.fsync uses _commit/FlushFileBuffers."""
    os.fsync(descriptor)


def replace_file(source, target):
    if os.name != "nt":
        os.replace(str(source), str(target))
        return
    source, target = Path(source), Path(target)
    if source.parent.resolve() != target.parent.resolve():
        raise ValueError("windows_same_directory_swap_required")
    private_directory(source.parent, "windows_swap_directory_not_private")
    windows_privacy().assert_private_file(source)
    if target.exists():
        windows_privacy().assert_private_file(target)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    kernel.MoveFileExW.restype = wintypes.BOOL
    if not kernel.MoveFileExW(str(source), str(target), 0x00000001 | 0x00000008):
        raise OSError(ctypes.get_last_error(), "windows_write_through_rename_failed")


def sync_directory_scope(folder):
    if os.name == "nt":
        private_directory(folder, "windows_sync_directory_not_private")
        return {"file_data_flush": "os.fsync_file_descriptors",
                "rename": "MOVEFILE_WRITE_THROUGH",
                "directory_metadata_flush_verified": False,
                "power_loss_durability_qualified": False}
    descriptor = os.open(str(folder), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {"directory_metadata_flush_verified": True,
            "power_loss_durability_qualified": False}



class _PrivateSecurityAttributes(ctypes.Structure):
    _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p),
                ("inherit_handle", wintypes.BOOL)]


@contextmanager
def _private_creation_attributes():
    """Explicit owner and protected DACL on new objects, never owner repair."""
    privacy = windows_privacy()
    kernel, security = privacy._libraries()
    security.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    security.ConvertSidToStringSidW.restype = wintypes.BOOL
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    sid = ctypes.create_string_buffer(privacy._current_user_sid(kernel, security))
    text, descriptor = wintypes.LPWSTR(), ctypes.c_void_p()
    if not security.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        raise OSError(ctypes.get_last_error(), "private_create_sid_unavailable")
    try:
        # OI/CI only for the explicit private subtree. No creator-owner alias.
        sddl = ("O:" + text.value + "D:P(A;OICI;FA;;;" + text.value
                + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
        if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, ctypes.byref(descriptor), None):
            raise OSError(ctypes.get_last_error(), "private_create_descriptor_unavailable")
        try:
            yield _PrivateSecurityAttributes(ctypes.sizeof(_PrivateSecurityAttributes), descriptor, False)
        finally:
            kernel.LocalFree(descriptor)
    finally:
        kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def _private_new_path(path):
    privacy = windows_privacy()
    value = privacy._local_absolute_path(path)
    leaf = Path(value).name
    # No alternate stream/device aliases or Windows component normalization.
    if (not leaf or leaf in (".", "..") or leaf.endswith((".", " "))
            or any(c in leaf for c in ':<>"|?*')
            or any(ord(c) < 32 for c in leaf)
            or leaf.split('.')[0].upper() in (
                'CON', 'PRN', 'AUX', 'NUL',
                *('COM' + str(i) for i in range(1, 10)),
                *('LPT' + str(i) for i in range(1, 10)))):
        raise ValueError("private_create_unsafe_leaf")
    return value


def _discard_created_handle(handle, kernel):
    """Delete exactly our still-open new object on failed validation/transfer."""
    kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                 ctypes.c_void_p, wintypes.DWORD]
    kernel.SetFileInformationByHandle.restype = wintypes.BOOL
    delete = ctypes.c_ubyte(1)  # FILE_DISPOSITION_INFO.DeleteFile is BOOLEAN.
    if not kernel.SetFileInformationByHandle(handle, 4, ctypes.byref(delete), ctypes.sizeof(delete)):
        raise OSError(ctypes.get_last_error(), "private_create_owned_handle_cleanup_failed")


def create_private_file(path):
    """Return owning CRT write fd for a CREATE_NEW, checked private leaf.

    No existing object is modified. Checks and transfer use the same HANDLE.
    Parent is checked separately; this is not ancestor/path confinement.
    """
    if os.name != "nt":
        raise ValueError("windows_native_private_creation_required")
    privacy = windows_privacy()
    value = _private_new_path(path)
    privacy.assert_private_directory(Path(value).parent)
    kernel, security = privacy._libraries()
    # A fresh DLL function binding avoids changing the read-only checker's ABI.
    native = ctypes.WinDLL("kernel32", use_last_error=True)
    native.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(_PrivateSecurityAttributes), wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    native.CreateFileW.restype = wintypes.HANDLE
    with _private_creation_attributes() as attributes:
        # GENERIC_READ|WRITE|DELETE, share none, CREATE_NEW, OPEN_REPARSE_POINT.
        handle = native.CreateFileW(value, 0xC0010000, 0, ctypes.byref(attributes),
                                    1, 0x00200080, None)
        error = ctypes.get_last_error() if not handle or handle == ctypes.c_void_p(-1).value else 0
    if not handle or handle == ctypes.c_void_p(-1).value:
        if error in (80, 183):
            raise FileExistsError(error, "private_create_target_exists")
        raise OSError(error, "private_create_new_file_failed")
    owned = True
    try:
        privacy._inspect_private_handle(handle, False, kernel, security)
        import msvcrt
        descriptor = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY | os.O_NOINHERIT)
        if descriptor < 0:
            raise ValueError("windows_private_descriptor_transfer_failed")
        owned = False
        return descriptor
    except BaseException:
        _discard_created_handle(handle, kernel)
        raise
    finally:
        if owned:
            kernel.CloseHandle(handle)


def create_private_directory(path):
    """Create only a new caller-selected directory with explicit owner/DACL.

    Does not require its enclosing temporary fixture parent to be private.
    On post-create validation failure it never removes/replaces a path; the
    caller retains its own temporary subtree for inspection/cleanup.
    """
    if os.name != "nt":
        raise ValueError("windows_native_private_creation_required")
    value = _private_new_path(path)
    native = ctypes.WinDLL("kernel32", use_last_error=True)
    native.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_PrivateSecurityAttributes)]
    native.CreateDirectoryW.restype = wintypes.BOOL
    with _private_creation_attributes() as attributes:
        created = native.CreateDirectoryW(value, ctypes.byref(attributes))
        error = ctypes.get_last_error() if not created else 0
    if not created:
        if error in (80, 183):
            raise FileExistsError(error, "private_create_target_exists")
        raise OSError(error, "private_create_new_directory_failed")
    windows_privacy().assert_private_directory(value)
    return Path(value)
