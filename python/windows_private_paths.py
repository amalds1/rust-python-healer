"""Read-only, fail-closed privacy checks of a held Windows leaf HANDLE.

Only the current effective user, LocalSystem and Builtin Administrators may
have effective allow ACEs. This is not a sandbox, ancestor path confinement,
or a promise that a later reopen has the checked identity or permissions.
No existing ACL or Windows setting is changed by this module.
"""

import ctypes
from ctypes import wintypes
from functools import lru_cache
import os
import struct


MAX_ACES = 512
MAX_TOKEN_BYTES = 65536
SYSTEM_SID = b"\x01\x01\x00\x00\x00\x00\x00\x05" + struct.pack("<I", 18)
ADMINISTRATORS_SID = b"\x01\x02\x00\x00\x00\x00\x00\x05" + struct.pack("<II", 32, 544)
OWNER_RIGHTS_SID = b"\x01\x01\x00\x00\x00\x00\x00\x03" + struct.pack("<I", 4)


class WindowsPrivacyRejected(ValueError):
    """The exact checked leaf could not meet the conservative privacy policy."""


class _FileInformation(ctypes.Structure):
    _fields_ = [("attributes", wintypes.DWORD), ("creation", wintypes.FILETIME),
                ("access", wintypes.FILETIME), ("write", wintypes.FILETIME),
                ("volume", wintypes.DWORD), ("size_high", wintypes.DWORD),
                ("size_low", wintypes.DWORD), ("links", wintypes.DWORD),
                ("index_high", wintypes.DWORD), ("index_low", wintypes.DWORD)]


class _Acl(ctypes.Structure):
    _fields_ = [("revision", wintypes.BYTE), ("reserved", wintypes.BYTE),
                ("size", wintypes.WORD), ("ace_count", wintypes.WORD),
                ("reserved2", wintypes.WORD)]


@lru_cache(maxsize=1)
def _libraries():
    if os.name != "nt":
        raise WindowsPrivacyRejected("windows_native_privacy_api_required")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    security = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(_FileInformation)]
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel.GetFileType.argtypes = [wintypes.HANDLE]
    kernel.GetFileType.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetCurrentThread.restype = wintypes.HANDLE
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    security.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    security.OpenProcessToken.restype = wintypes.BOOL
    security.OpenThreadToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL,
                                        ctypes.POINTER(wintypes.HANDLE)]
    security.OpenThreadToken.restype = wintypes.BOOL
    security.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                            ctypes.c_void_p, wintypes.DWORD,
                                            ctypes.POINTER(wintypes.DWORD)]
    security.GetTokenInformation.restype = wintypes.BOOL
    security.IsValidSid.argtypes = [ctypes.c_void_p]
    security.IsValidSid.restype = wintypes.BOOL
    security.GetLengthSid.argtypes = [ctypes.c_void_p]
    security.GetLengthSid.restype = wintypes.DWORD
    security.GetSecurityInfo.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
                                       ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                       ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                                       ctypes.POINTER(ctypes.c_void_p)]
    security.GetSecurityInfo.restype = wintypes.DWORD
    security.IsValidAcl.argtypes = [ctypes.c_void_p]
    security.IsValidAcl.restype = wintypes.BOOL
    security.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    security.GetAce.restype = wintypes.BOOL
    return kernel, security


def _copy_sid(pointer, security):
    if not pointer or not security.IsValidSid(pointer):
        raise WindowsPrivacyRejected("windows_invalid_sid")
    length = security.GetLengthSid(pointer)
    if not 8 <= length <= 68:
        raise WindowsPrivacyRejected("windows_sid_budget")
    return ctypes.string_at(pointer, length)


def _current_user_sid(kernel, security):
    """Use an effective impersonation token when present; otherwise process token."""
    token = wintypes.HANDLE()
    if not security.OpenThreadToken(kernel.GetCurrentThread(), 0x0008, True, ctypes.byref(token)):
        if ctypes.get_last_error() != 1008:  # ERROR_NO_TOKEN is the only fallback.
            raise WindowsPrivacyRejected("windows_effective_token_unavailable")
        if not security.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            raise WindowsPrivacyRejected("windows_process_token_unavailable")
    try:
        needed = wintypes.DWORD()
        security.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if ctypes.get_last_error() != 122 or not ctypes.sizeof(ctypes.c_void_p) <= needed.value <= MAX_TOKEN_BYTES:
            raise WindowsPrivacyRejected("windows_token_user_size_invalid")
        buffer = ctypes.create_string_buffer(needed.value)
        if not security.GetTokenInformation(token, 1, buffer, len(buffer), ctypes.byref(needed)):
            raise WindowsPrivacyRejected("windows_token_user_unavailable")
        pointer = ctypes.c_void_p.from_buffer(buffer).value
        # TOKEN_USER stores a SID_AND_ATTRIBUTES; its SID must point inside buffer.
        start = ctypes.addressof(buffer)
        if pointer is None or not start <= pointer <= start + len(buffer) - 8:
            raise WindowsPrivacyRejected("windows_token_sid_pointer_invalid")
        sid_header = ctypes.string_at(pointer, 8)
        if sid_header[1] > 15 or pointer + 8 + 4 * sid_header[1] > start + len(buffer):
            raise WindowsPrivacyRejected("windows_token_sid_bounds_invalid")
        sid = _copy_sid(pointer, security)
        if pointer + len(sid) > start + len(buffer):
            raise WindowsPrivacyRejected("windows_token_sid_outside_buffer")
        return sid
    finally:
        kernel.CloseHandle(token)


def _evaluate_acl(dacl, current_sid, security, protect_children=False):
    if not dacl:
        raise WindowsPrivacyRejected("windows_null_dacl_refused")
    if not security.IsValidAcl(dacl):
        raise WindowsPrivacyRejected("windows_invalid_dacl")
    header = _Acl.from_address(dacl)
    if not 8 <= header.size <= 65535 or header.ace_count > MAX_ACES:
        raise WindowsPrivacyRejected("windows_dacl_budget")
    # OWNER RIGHTS represents this object's owner, already verified as the
    # current effective token user before this evaluator is called.
    trusted = {current_sid, SYSTEM_SID, ADMINISTRATORS_SID, OWNER_RIGHTS_SID}
    effective_grants = 0
    for index in range(header.ace_count):
        pointer = ctypes.c_void_p()
        if not security.GetAce(dacl, index, ctypes.byref(pointer)):
            raise WindowsPrivacyRejected("windows_ace_unavailable")
        address = pointer.value
        if address is None or not dacl + 8 <= address <= dacl + header.size - 4:
            raise WindowsPrivacyRejected("windows_ace_pointer_invalid")
        ace_type, flags, size = struct.unpack("<BBH", ctypes.string_at(address, 4))
        if size < 16 or address + size > dacl + header.size or flags & ~0x1F:
            raise WindowsPrivacyRejected("windows_ace_layout_unsupported")
        # Fail closed on callback/object/compound/unknown ACE semantics.
        if ace_type not in (0, 1):
            raise WindowsPrivacyRejected("windows_ace_type_unsupported")
        mask = struct.unpack("<I", ctypes.string_at(address + 4, 4))[0]
        sid_header = ctypes.string_at(address + 8, 8)
        sid_length = 8 + 4 * sid_header[1]
        if sid_header[1] > 15 or sid_length > size - 8:
            raise WindowsPrivacyRejected("windows_ace_sid_bounds_invalid")
        sid = _copy_sid(address + 8, security)
        if len(sid) != sid_length:
            raise WindowsPrivacyRejected("windows_ace_sid_length_invalid")
        if ace_type == 1 or mask == 0:  # A deny or zero mask grants no access.
            continue
        if flags & 0x08:
            # A public inherit-only grant could expose children created later.
            if protect_children and sid not in trusted:
                raise WindowsPrivacyRejected("windows_untrusted_inheritable_allow_ace")
            continue
        if sid not in trusted:
            # Even a read-only public grant violates private-path confidentiality.
            raise WindowsPrivacyRejected("windows_untrusted_effective_allow_ace")
        effective_grants += 1
    return effective_grants


def _local_absolute_path(path):
    value = os.fspath(path)
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > 32767:
        raise WindowsPrivacyRejected("windows_privacy_path_invalid")
    drive, tail = os.path.splitdrive(value)
    normal_drive = len(drive) == 2 and drive[0].isalpha() and drive[1] == ":"
    extended_drive = (len(drive) == 6 and drive.startswith("\\\\?\\") and
                      drive[4].isalpha() and drive[5] == ":")
    if not (normal_drive or extended_drive) or not tail.startswith(("\\", "/")):
        raise WindowsPrivacyRejected("windows_local_absolute_leaf_required")
    return value


def _assert_private(path, expect_directory):
    kernel, security = _libraries()
    value = _local_absolute_path(path)
    # READ_CONTROL | FILE_READ_ATTRIBUTES; no contents requested or written.
    handle = kernel.CreateFileW(value, 0x00020080, 0x00000001, None, 3,
                                0x00200000 | 0x02000000, None)
    if not handle or handle == ctypes.c_void_p(-1).value:
        raise WindowsPrivacyRejected("windows_privacy_leaf_open_refused")
    try:
        return _inspect_private_handle(handle, expect_directory, kernel, security)
    finally:
        kernel.CloseHandle(handle)


def _inspect_private_handle(handle, expect_directory, kernel, security):
    """Inspect borrowed HANDLE; caller owns its lifetime and data operations."""
    descriptor = ctypes.c_void_p()
    try:
        info = _FileInformation()
        if kernel.GetFileType(handle) != 1 or not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
            raise WindowsPrivacyRejected("windows_privacy_disk_leaf_required")
        if info.attributes & 0x400:
            raise WindowsPrivacyRejected("windows_privacy_reparse_leaf_refused")
        if bool(info.attributes & 0x10) != expect_directory:
            raise WindowsPrivacyRejected("windows_privacy_leaf_type_mismatch")
        if not expect_directory and info.links != 1:
            raise WindowsPrivacyRejected("windows_privacy_single_link_required")
        owner, dacl = ctypes.c_void_p(), ctypes.c_void_p()
        status = security.GetSecurityInfo(handle, 1, 0x00000005, ctypes.byref(owner),
                                          None, ctypes.byref(dacl), None,
                                          ctypes.byref(descriptor))
        if status:
            raise WindowsPrivacyRejected("windows_privacy_security_info_unavailable")
        current = _current_user_sid(kernel, security)
        if _copy_sid(owner.value, security) != current:
            raise WindowsPrivacyRejected("windows_privacy_owner_mismatch")
        grants = _evaluate_acl(dacl.value, current, security, expect_directory)
        return {"status": "PRIVATE_WINDOWS_LEAF_CONFIRMED",
                "object_type": "directory" if expect_directory else "file",
                "owner_is_current_effective_user": True,
                "trusted_effective_allow_aces": grants,
                "identity": [info.volume, info.index_high, info.index_low],
                "scope": "held leaf privacy snapshot only; later reopens and ancestors unverified",
                "acl_mutated": False, "sandbox_proven": False}
    finally:
        if descriptor.value:
            kernel.LocalFree(descriptor)


def assert_private_directory(path):
    """Confirm a current-user-owned directory leaf with a conservative DACL."""
    return _assert_private(path, True)


def assert_private_file(path):
    """Confirm a current-user-owned, single-link regular disk file leaf."""
    return _assert_private(path, False)


def assert_private_file_descriptor(descriptor):
    """Check the caller's actual open CRT descriptor, without reopening a path."""
    if type(descriptor) is not int or descriptor < 0:
        raise WindowsPrivacyRejected("windows_file_descriptor_invalid")
    kernel, security = _libraries()
    import msvcrt
    handle = msvcrt.get_osfhandle(descriptor)
    if handle == -1:
        raise WindowsPrivacyRejected("windows_file_descriptor_invalid")
    return _inspect_private_handle(handle, False, kernel, security)


def open_private_readonly(path):
    """Return an owned binary CRT fd for a checked no-follow private leaf.

    The caller MUST close the returned descriptor. The same HANDLE is kept
    for metadata, ACL checks and subsequent reads. Leaf write/delete sharing
    is denied until close. Traversed ancestors are not a sandbox guarantee.
    """
    kernel, security = _libraries()
    value = _local_absolute_path(path)
    # GENERIC_READ includes file data, attributes and READ_CONTROL.
    handle = kernel.CreateFileW(value, 0x80000000, 0x00000001, None, 3,
                                0x00200000 | 0x02000000, None)
    if not handle or handle == ctypes.c_void_p(-1).value:
        raise WindowsPrivacyRejected("windows_private_read_open_refused")
    owned_handle = True
    try:
        _inspect_private_handle(handle, False, kernel, security)
        import msvcrt
        flags = os.O_RDONLY | os.O_BINARY | getattr(os, "O_NOINHERIT", 0)
        descriptor = msvcrt.open_osfhandle(handle, flags)
        if descriptor < 0:
            raise WindowsPrivacyRejected("windows_private_descriptor_transfer_failed")
        owned_handle = False  # CRT now owns and closes this exact HANDLE.
        return descriptor
    finally:
        if owned_handle:
            kernel.CloseHandle(handle)
