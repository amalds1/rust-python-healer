"""Scoped platform adapters; no ACL repair or production durability claim."""
import ctypes
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
