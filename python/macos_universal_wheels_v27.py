"""Read-only, hash-pinned macOS wheel / Mach-O architecture inspection.

This is a *structural* inspector. It cannot validate dyld loading, code
signatures, macOS deployment targets, or CPython imports without macOS hosts.
No wheel is installed, extracted, loaded, or executed.
"""

import hashlib
import io
import os
import re
import stat
import struct
import zipfile

CPU_X86_64 = 0x01000007
CPU_ARM64 = 0x0100000C
ARCH_NAMES = {CPU_X86_64: "x86_64", CPU_ARM64: "arm64"}
FAT_HEADERS = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbf\xba\xfe\xca": ("<", True),
}
THIN_HEADERS = {b"\xcf\xfa\xed\xfe": "<", b"\xfe\xed\xfa\xcf": ">"}
MAX_WHEEL_BYTES = 48 * 1024 * 1024
MAX_NATIVE_BYTES = 32 * 1024 * 1024
MAX_ZIP_MEMBERS = 4096
MAX_UNCOMPRESSED_BYTES = 160 * 1024 * 1024
MAX_LOAD_COMMANDS = 4096
PLATFORM_RE = re.compile(r"^macosx_([0-9]{1,2})_([0-9]{1,2})_(universal2|x86_64|arm64)$")


def _thin_arch(payload):
    if len(payload) < 32 or payload[:4] not in THIN_HEADERS:
        raise ValueError("invalid_macho_64_header")
    endian = THIN_HEADERS[payload[:4]]
    _, cpu, _, filetype, ncmds, commands_size, _, _ = struct.unpack_from(
        endian + "IIIIIIII", payload, 0)
    if cpu not in ARCH_NAMES:
        raise ValueError("unsupported_macho_cpu")
    if filetype not in (1, 2, 6, 8, 11):
        raise ValueError("invalid_macho_filetype")
    if (ncmds == 0 or ncmds > MAX_LOAD_COMMANDS or commands_size < 8 or
            commands_size > len(payload) - 32):
        raise ValueError("invalid_macho_load_commands")
    cursor = 32
    boundary = cursor + commands_size
    for _ in range(ncmds):
        if cursor + 8 > boundary:
            raise ValueError("invalid_macho_load_commands")
        _, command_size = struct.unpack_from(endian + "II", payload, cursor)
        if command_size < 8 or command_size % 8 or command_size > boundary - cursor:
            raise ValueError("invalid_macho_load_commands")
        cursor += command_size
    if cursor != boundary:
        raise ValueError("invalid_macho_load_commands")
    return ARCH_NAMES[cpu], cpu


def inspect_macho_bytes(payload):
    """Return verified architecture slices; reject malformed/overlapping fat bins."""
    if not isinstance(payload, bytes) or not 32 <= len(payload) <= MAX_NATIVE_BYTES:
        raise ValueError("invalid_native_binary_size")
    if payload[:4] in THIN_HEADERS:
        arch, _ = _thin_arch(payload)
        return {"format": "thin_macho_64", "architectures": [arch],
                "slices": [{"arch": arch, "offset": 0, "size": len(payload),
                            "sha256": hashlib.sha256(payload).hexdigest()}]}
    if payload[:4] not in FAT_HEADERS:
        raise ValueError("not_macho_binary")
    endian, fat64 = FAT_HEADERS[payload[:4]]
    count = struct.unpack_from(endian + "I", payload, 4)[0]
    if count < 1 or count > len(ARCH_NAMES):
        raise ValueError("invalid_fat_arch_count")
    entry_size = 32 if fat64 else 20
    table_end = 8 + count * entry_size
    if table_end > len(payload):
        raise ValueError("truncated_fat_arch_table")
    slices = []
    seen = set()
    for index in range(count):
        offset = 8 + index * entry_size
        if fat64:
            cpu, _, start, length, align, reserved = struct.unpack_from(
                endian + "IIQQII", payload, offset)
            if reserved:
                raise ValueError("invalid_fat_reserved_field")
        else:
            cpu, _, start, length, align = struct.unpack_from(
                endian + "IIIII", payload, offset)
        if cpu not in ARCH_NAMES or cpu in seen:
            raise ValueError("unknown_or_duplicate_fat_arch")
        seen.add(cpu)
        if align > 30 or start % (1 << align) != 0:
            raise ValueError("invalid_fat_alignment")
        if start < table_end or length < 32 or start > len(payload) or length > len(payload) - start:
            raise ValueError("invalid_fat_slice_boundary")
        last = start + length
        for previous in slices:
            if start < previous["offset"] + previous["size"] and previous["offset"] < last:
                raise ValueError("overlapping_fat_slices")
        sub = payload[start:last]
        arch, thin_cpu = _thin_arch(sub)
        if thin_cpu != cpu:
            raise ValueError("macho_arch_table_mismatch")
        slices.append({"arch": arch, "offset": start, "size": length,
                       "sha256": hashlib.sha256(sub).hexdigest()})
    return {"format": "fat_macho_64" if fat64 else "fat_macho_32",
            "architectures": sorted(ARCH_NAMES[c] for c in seen), "slices": slices}


def _wheel_platform(filename):
    if not isinstance(filename, str) or not filename.endswith(".whl"):
        raise ValueError("invalid_wheel_filename")
    parts = filename[:-4].split("-")
    if len(parts) not in (5, 6) or not all(parts):
        raise ValueError("invalid_wheel_filename")
    if not re.fullmatch(r"[A-Za-z0-9_.]+", parts[0]):
        raise ValueError("invalid_wheel_filename")
    if not re.fullmatch(r"[A-Za-z0-9_.]+", parts[1]):
        raise ValueError("invalid_wheel_filename")
    platforms = parts[-1].split(".")
    if len(platforms) != 1 or not PLATFORM_RE.fullmatch(platforms[0]):
        raise ValueError("unsupported_macos_wheel_platform")
    return PLATFORM_RE.fullmatch(platforms[0]).group(3)


def inspect_wheel_bytes(wheel, filename, sha256_pin):
    """Inspect a pinned ZIP wheel without executing any embedded content."""
    if not isinstance(wheel, bytes) or not 32 <= len(wheel) <= MAX_WHEEL_BYTES:
        raise ValueError("invalid_wheel_size")
    if not isinstance(sha256_pin, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256_pin):
        raise ValueError("trusted_sha256_pin_required")
    actual_hash = hashlib.sha256(wheel).hexdigest()
    if actual_hash != sha256_pin:
        raise ValueError("wheel_sha256_pin_mismatch")
    platform = _wheel_platform(filename)
    filename_tag = "-".join(filename[:-4].split("-")[-3:])
    binaries = []
    with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
        infos = archive.infolist()
        if not infos or len(infos) > MAX_ZIP_MEMBERS:
            raise ValueError("wheel_member_count_limit")
        total = 0
        seen = set()
        wheel_metadata = []
        for entry in infos:
            name = entry.filename
            segments = name.rstrip("/").split("/")
            if (not name or name.startswith("/") or "\\" in name or
                    any(segment in ("", ".", "..") for segment in segments) or
                    name in seen or "\x00" in name):
                raise ValueError("unsafe_wheel_member_path")
            seen.add(name)
            mode = (entry.external_attr >> 16) & 0o170000
            if mode not in (0, stat.S_IFDIR, stat.S_IFREG) or entry.flag_bits & 1:
                raise ValueError("unsafe_wheel_member_type")
            if entry.file_size > MAX_NATIVE_BYTES or entry.file_size > MAX_UNCOMPRESSED_BYTES - total:
                raise ValueError("wheel_uncompressed_size_limit")
            total += entry.file_size
            if entry.is_dir():
                continue
            if name.endswith(".dist-info/WHEEL"):
                if entry.file_size > 65536:
                    raise ValueError("wheel_metadata_size_limit")
                wheel_metadata.append(archive.read(entry))
            if name.lower().endswith((".so", ".dylib", ".bundle")):
                binary = archive.read(entry)
                macho = inspect_macho_bytes(binary)
                binaries.append({"path": name, "sha256": hashlib.sha256(binary).hexdigest(),
                                 "mach_o": macho})
        if not binaries:
            raise ValueError("macos_wheel_has_no_native_binaries")
        if len(wheel_metadata) != 1:
            raise ValueError("missing_or_multiple_wheel_metadata")
        try:
            metadata_lines = wheel_metadata[0].decode("utf-8", "strict").splitlines()
        except UnicodeDecodeError as error:
            raise ValueError("invalid_wheel_metadata_encoding") from error
        metadata_tags = [line[5:].strip() for line in metadata_lines if line.startswith("Tag:")]
        if filename_tag not in metadata_tags or "Root-Is-Purelib: false" not in metadata_lines:
            raise ValueError("wheel_metadata_tag_or_purelib_mismatch")
        expected = {"universal2": {"arm64", "x86_64"},
                    "arm64": {"arm64"}, "x86_64": {"x86_64"}}[platform]
        for binary in binaries:
            if set(binary["mach_o"]["architectures"]) != expected:
                raise ValueError("wheel_platform_macho_arch_mismatch")
    return {"status": "PINNED_MACOS_WHEEL_STRUCTURE_VERIFIED_NOT_EXECUTED",
            "platform": platform, "wheel_filename": filename, "wheel_sha256": actual_hash,
            "native_binary_count": len(binaries), "native_binaries": binaries,
            "macos_host_execution": "NOT_RUN", "macos_dyld_loading": "NOT_RUN",
            "macos_abi_compatibility": "NOT_PROVEN", "release_authorized": False}


def inspect_wheel_path(path, sha256_pin):
    """Read a bounded, non-link local wheel and inspect by filename and pin."""
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("invalid_wheel_path")
    prior = os.lstat(path)
    if not stat.S_ISREG(prior.st_mode) or prior.st_nlink != 1 or prior.st_size > MAX_WHEEL_BYTES:
        raise ValueError("unsafe_wheel_file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        check = os.fstat(descriptor)
        if (not stat.S_ISREG(check.st_mode) or check.st_nlink != 1 or
                check.st_size > MAX_WHEEL_BYTES or check.st_dev != prior.st_dev or
                check.st_ino != prior.st_ino):
            raise ValueError("unsafe_wheel_file_changed")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            wheel = stream.read(MAX_WHEEL_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return inspect_wheel_bytes(wheel, os.path.basename(path), sha256_pin)
