"""Real Windows ACL fixtures, restricted to explicitly supplied test paths.

No production code imports this module. Callers own their temporary fixture
roots; these helpers never enumerate or repair unrelated paths.
"""
import ctypes
import importlib.util
import os
from ctypes import wintypes
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
import windows_private_paths as privacy


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", wintypes.DWORD), ("descriptor", ctypes.c_void_p),
                ("inherit_handle", wintypes.BOOL)]


def _fixture_libraries():
    kernel, security = privacy._libraries()
    security.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    security.ConvertSidToStringSidW.restype = wintypes.BOOL
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD)]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    security.GetSecurityDescriptorDacl.argtypes = [ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL)]
    security.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    security.SetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int,
        wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    security.SetNamedSecurityInfoW.restype = wintypes.DWORD
    kernel.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_SecurityAttributes)]
    kernel.CreateDirectoryW.restype = wintypes.BOOL
    return kernel, security


def current_user_sid_string():
    kernel, security = _fixture_libraries()
    raw = privacy._current_user_sid(kernel, security)
    sid = ctypes.create_string_buffer(raw)
    text = wintypes.LPWSTR()
    if not security.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return text.value
    finally:
        kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def private_sddl(extra=""):
    sid = current_user_sid_string()
    return ("O:" + sid + "D:P(A;OICI;FA;;;" + sid + ")"
            "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" + extra)


def _descriptor(sddl, security):
    descriptor = ctypes.c_void_p()
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    return descriptor


def create_private_directory(path):
    """Create a new fixture directory with protected, explicit private DACL."""
    path = Path(path)
    kernel, security = _fixture_libraries()
    descriptor = _descriptor(private_sddl(), security)
    attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
    try:
        if not kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.LocalFree(descriptor)
    return path


def set_test_sddl(path, sddl):
    """Apply fixture ACL only; never called by the read-only production checker."""
    kernel, security = _fixture_libraries()
    descriptor = _descriptor(sddl, security)
    try:
        present, defaulted, dacl = wintypes.BOOL(), wintypes.BOOL(), ctypes.c_void_p()
        if not security.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present),
                ctypes.byref(dacl), ctypes.byref(defaulted)) or not present:
            raise RuntimeError("fixture_dacl_missing")
        status = security.SetNamedSecurityInfoW(str(path), 1, 0x80000004,
                                               None, None, dacl, None)
        if status:
            raise ctypes.WinError(status)
    finally:
        kernel.LocalFree(descriptor)


def set_private_acl(path):
    set_test_sddl(path, private_sddl())


def set_public_read_acl(path):
    """Even Everyone read-only access is intentionally not private."""
    set_test_sddl(path, private_sddl("(A;OICI;FR;;;WD)"))


def set_null_dacl(path):
    """Own fixture only: NULL DACL grants access to everyone and must fail."""
    _kernel, security = _fixture_libraries()
    status = security.SetNamedSecurityInfoW(str(path), 1, 0x80000004,
                                           None, None, None, None)
    if status:
        raise ctypes.WinError(status)


def create_test_junction(path, target):
    """Own fixture junction via native reparse IOCTL; no script-policy changes."""
    path, target = Path(path), Path(target).resolve(strict=True)
    if not target.is_relative_to(path.parent.resolve(strict=True)):
        raise ValueError("junction_target_must_stay_inside_fixture_parent")
    path.mkdir()  # No overwrite of any existing path.
    kernel, _security = _fixture_libraries()
    kernel.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD,
        ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel.DeviceIoControl.restype = wintypes.BOOL
    substitute = ("\\??\\" + str(target)).encode("utf-16-le")
    printed = str(target).encode("utf-16-le")
    names = substitute + b"\0\0" + printed + b"\0\0"
    mount = struct.pack("<HHHH", 0, len(substitute), len(substitute) + 2, len(printed)) + names
    raw = struct.pack("<IHH", 0xA0000003, len(mount), 0) + mount
    buffer = ctypes.create_string_buffer(raw)
    handle = kernel.CreateFileW(str(path), 0x40000000, 0, None, 3,
                                0x00200000 | 0x02000000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        written = wintypes.DWORD()
        if not kernel.DeviceIoControl(handle, 0x000900A4, buffer, len(raw), None, 0,
                                       ctypes.byref(written), None):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.CloseHandle(handle)


def _creation_platform():
    path = Path(__file__).resolve().parents[1] / "python" / "platform_privacy_v028.py"
    spec = importlib.util.spec_from_file_location("fixture_explicit_creation_platform", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private_fixture_root(folder):
    """New child of this test's own temp root; no existing owner/DACL repair."""
    if os.name == "nt":
        return _creation_platform().create_private_directory(Path(folder) / "private-fixture")
    return Path(folder)


def write_new_private_fixture(path, payload=b""):
    """Create only a new fixed test leaf; existing content never overwritten."""
    if os.name == "nt":
        fd = _creation_platform().create_private_file(path)
    else:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(payload)
