"""Bounded native Windows model evidence reads using retained no-follow handles."""
import importlib.util
import os
from pathlib import Path

def dependency(name, filename):
    module = globals().get(name)
    if module is None:
        spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        globals()[name] = module
    return module

def privacy():
    return dependency("_RPH_WINDOWS_PRIVACY", "windows_private_paths.py")

def read_regular(path, maximum, private=False):
    """Preserve ordinary/relative Unicode filenames; hold the validated leaf."""
    import ctypes
    from ctypes import wintypes
    if type(maximum) is not int or not 1 <= maximum <= 1048576:
        raise ValueError("evidence_size_limit")
    path = Path(os.path.abspath(path))  # No resolve(): aliases must be refused.
    value = privacy()._local_absolute_path(path)
    blob = dependency("_RPH_WINDOWS_BLOB", "windows_blob_reader_v029.py")
    _, kernel, _ = blob._libraries()
    handle = kernel.CreateFileW(value, 0x80000000, 1, None, 3, 0x00200000 | 0x02000000, None)
    if not handle or handle == ctypes.c_void_p(-1).value:
        raise ValueError("evidence_no_follow_open_refused")
    try:
        before = blob._information(handle, False, maximum)
        if private:
            privacy()._inspect_private_handle(handle, False, *privacy()._libraries())
        final = ctypes.create_unicode_buffer(32768)
        length = kernel.GetFinalPathNameByHandleW(handle, final, len(final), 0)
        if not 0 < length < len(final):
            raise ValueError("evidence_final_path_unavailable")
        def normal(value):
            if value.startswith("\\\\?\\"):
                value = value[4:]
            return os.path.normcase(os.path.normpath(value))
        if normal(final.value) != normal(value):
            raise ValueError("evidence_ancestor_alias_refused")
        raw = ctypes.create_string_buffer(maximum + 1)
        read = wintypes.DWORD()
        if not kernel.ReadFile(handle, raw, len(raw), ctypes.byref(read), None):
            raise ValueError("evidence_native_read_failed")
        after = blob._information(handle, False, maximum)
        if private:
            privacy()._inspect_private_handle(handle, False, *privacy()._libraries())
        if before != after or not 1 <= read.value <= maximum or read.value != before[3]:
            raise ValueError("evidence_changed_during_read")
        return raw.raw[:read.value]
    finally:
        kernel.CloseHandle(handle)
