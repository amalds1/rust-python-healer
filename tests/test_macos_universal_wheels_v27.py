"""Adversarial, execution-free Mach-O and pinned macOS wheel tests."""

import base64
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import struct
import tempfile
import unittest
import zipfile
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
REAL_OFFICIAL_WHEEL = (
    ROOT.parent / "cryptography-46.0.3-cp38-abi3-macosx_10_9_universal2.whl")
REAL_OFFICIAL_SHA256 = "cb3d760a6117f621261d662bccc8ef5bc32ca673e037c83fbe565324f5c46936"
REAL_HEADER_FIXTURE = (ROOT / "tests" / "fixtures" / "macos_universal_v27" /
                       "cryptography_46_0_3_real_macho_prefixes.json")
SPEC = importlib.util.spec_from_file_location(
    "macos_universal_wheels_v27", ROOT / "python" / "macos_universal_wheels_v27.py")
inspector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inspector)


def thin(cpu, endian="<", commands=True):
    header = struct.pack(endian + "IIIIIIII", 0xFEEDFACF, cpu, 0, 6,
                         1 if commands else 0, 8 if commands else 0, 0, 0)
    return header + (struct.pack(endian + "II", 0x1B, 8) if commands else b"") + b"test"


def fat(cpus=(inspector.CPU_ARM64, inspector.CPU_X86_64),
        endian=">", fat64=False, starts=None):
    starts = starts or [256 + index * 256 for index in range(len(cpus))]
    magic = 0xCAFEBABF if fat64 else 0xCAFEBABE
    entries = []
    content = bytearray(struct.pack(endian + "II", magic, len(cpus)))
    for cpu, start in zip(cpus, starts):
        blob = thin(cpu)
        if fat64:
            entries.append(struct.pack(endian + "IIQQII", cpu, 0, start, len(blob), 8, 0))
        else:
            entries.append(struct.pack(endian + "IIIII", cpu, 0, start, len(blob), 8))
    content += b"".join(entries)
    for cpu, start in zip(cpus, starts):
        if start >= len(content):
            content += b"\x00" * (start - len(content))
        content += thin(cpu)
    return bytes(content)


def wheel(binary=None, name="pkg-1.0-cp39-abi3-macosx_11_0_universal2.whl",
          extra=None):
    if binary is None:
        binary = fat()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("pkg/_native.so", binary)
        archive.writestr("pkg/module.py", "pass\n")
        tag = "-".join(name[:-4].split("-")[-3:])
        archive.writestr("pkg-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\n"
                         f"Root-Is-Purelib: false\nTag: {tag}\n")
        for item, data in extra or []:
            archive.writestr(item, data)
    payload = output.getvalue()
    return payload, name, hashlib.sha256(payload).hexdigest()


class MachOParsing(unittest.TestCase):
    def test_two_architectures_and_independent_hash_pins(self):
        result = inspector.inspect_macho_bytes(fat())
        self.assertEqual(result["architectures"], ["arm64", "x86_64"])
        self.assertEqual(len(result["slices"]), 2)
        for item in result["slices"]:
            start = item["offset"]
            end = start + item["size"]
            self.assertEqual(item["sha256"], hashlib.sha256(fat()[start:end]).hexdigest())

    def test_reverse_architecture_order(self):
        result = inspector.inspect_macho_bytes(fat((inspector.CPU_X86_64, inspector.CPU_ARM64)))
        self.assertEqual(result["architectures"], ["arm64", "x86_64"])
        self.assertEqual([s["arch"] for s in result["slices"]], ["x86_64", "arm64"])

    def test_fat64_supported(self):
        self.assertEqual(inspector.inspect_macho_bytes(fat(fat64=True))["format"], "fat_macho_64")

    def test_little_endian_fat32_supported(self):
        self.assertEqual(inspector.inspect_macho_bytes(fat(endian="<"))["format"], "fat_macho_32")

    def test_little_endian_fat64_supported(self):
        self.assertEqual(inspector.inspect_macho_bytes(fat(endian="<", fat64=True))["format"], "fat_macho_64")

    def test_little_endian_thin_x86(self):
        self.assertEqual(inspector.inspect_macho_bytes(thin(inspector.CPU_X86_64))["architectures"],
                         ["x86_64"])

    def test_big_endian_thin_arm(self):
        self.assertEqual(inspector.inspect_macho_bytes(thin(inspector.CPU_ARM64, ">"))["architectures"],
                         ["arm64"])

    def test_truncated_macho(self):
        with self.assertRaises(ValueError):
            inspector.inspect_macho_bytes(b"\xcf\xfa\xed\xfe")

    def test_reject_elf_disguised_as_macho(self):
        with self.assertRaisesRegex(ValueError, "not_macho_binary"):
            inspector.inspect_macho_bytes(b"\x7fELF" + b"\x00" * 32)

    def test_reject_duplicate_fat_cpu(self):
        with self.assertRaisesRegex(ValueError, "unknown_or_duplicate_fat_arch"):
            inspector.inspect_macho_bytes(fat((inspector.CPU_ARM64, inspector.CPU_ARM64)))

    def test_reject_unknown_fat_cpu(self):
        with self.assertRaisesRegex(ValueError, "unknown_or_duplicate_fat_arch"):
            inspector.inspect_macho_bytes(fat((inspector.CPU_ARM64, 0xBAD)))

    def test_reject_too_many_slices(self):
        data = bytearray(fat())
        struct.pack_into(">I", data, 4, 3)
        with self.assertRaisesRegex(ValueError, "invalid_fat_arch_count"):
            inspector.inspect_macho_bytes(bytes(data))

    def test_reject_empty_fat_table(self):
        data = bytearray(fat())
        struct.pack_into(">I", data, 4, 0)
        with self.assertRaisesRegex(ValueError, "invalid_fat_arch_count"):
            inspector.inspect_macho_bytes(bytes(data))

    def test_reject_truncated_fat_table(self):
        with self.assertRaisesRegex(ValueError, "truncated_fat_arch_table"):
            inspector.inspect_macho_bytes(struct.pack(">II", 0xCAFEBABE, 2) + b"!" * 24)

    def test_reject_overlapping_sections(self):
        data = bytearray(fat())
        # Second architecture points into first; byte overlap is invalid even
        # when a forged table claims different architecture.
        struct.pack_into(">I", data, 8 + 20 + 8, 256)
        with self.assertRaisesRegex(ValueError, "overlapping_fat_slices"):
            inspector.inspect_macho_bytes(bytes(data))

    def test_reject_slice_cpu_mismatch(self):
        data = bytearray(fat())
        struct.pack_into(">I", data, 8, inspector.CPU_X86_64)
        with self.assertRaises(ValueError):
            inspector.inspect_macho_bytes(bytes(data))

    def test_reject_fat_slice_out_of_bounds(self):
        data = bytearray(fat())
        struct.pack_into(">I", data, 8 + 12, 0xFFFFFF00)
        with self.assertRaisesRegex(ValueError, "invalid_fat_slice_boundary"):
            inspector.inspect_macho_bytes(bytes(data))

    def test_reject_slice_crossing_table(self):
        data = bytearray(fat())
        struct.pack_into(">I", data, 8 + 8, 0)
        with self.assertRaises(ValueError):
            inspector.inspect_macho_bytes(bytes(data))

    def test_reject_invalid_fat_alignment(self):
        data = bytearray(fat())
        struct.pack_into(">I", data, 8 + 16, 31)
        with self.assertRaisesRegex(ValueError, "invalid_fat_alignment"):
            inspector.inspect_macho_bytes(bytes(data))

    def test_reject_nonzero_fat64_reserved(self):
        data = bytearray(fat(fat64=True))
        struct.pack_into(">I", data, 8 + 28, 1)
        with self.assertRaisesRegex(ValueError, "invalid_fat_reserved_field"):
            inspector.inspect_macho_bytes(bytes(data))

    def test_reject_macho_load_command_overrun(self):
        data = bytearray(thin(inspector.CPU_ARM64))
        struct.pack_into("<I", data, 32 + 4, 0x200)
        with self.assertRaisesRegex(ValueError, "invalid_macho_load_commands"):
            inspector.inspect_macho_bytes(bytes(data))

    def test_reject_empty_macho_command_table(self):
        with self.assertRaisesRegex(ValueError, "invalid_macho_load_commands"):
            inspector.inspect_macho_bytes(thin(inspector.CPU_ARM64, commands=False))

    def test_reject_macho_excessive_load_command_count(self):
        data = bytearray(thin(inspector.CPU_ARM64))
        struct.pack_into("<I", data, 16, inspector.MAX_LOAD_COMMANDS + 1)
        with self.assertRaisesRegex(ValueError, "invalid_macho_load_commands"):
            inspector.inspect_macho_bytes(bytes(data))

    def test_reject_native_size_limit(self):
        with self.assertRaisesRegex(ValueError, "invalid_native_binary_size"):
            inspector.inspect_macho_bytes(b"\x00" * (inspector.MAX_NATIVE_BYTES + 1))


class WheelInspection(unittest.TestCase):
    def test_real_pypi_mac_universal2_wheel_pinned_and_inspected(self):
        """Bundled REAL Mach-O bytes are mandatory; full wheel is supplementary.

        The 8-KiB real header snapshot proves only header structure; it cannot
        authenticate missing bytes from the original 21-MiB native binary.
        """
        fixture = json.loads(REAL_HEADER_FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(fixture["source_wheel_sha256"], REAL_OFFICIAL_SHA256)
        compressed = base64.b64decode(fixture["compressed_base64"], validate=True)
        self.assertLess(len(compressed), 4096)
        snapshot = zlib.decompress(compressed)
        self.assertEqual(len(snapshot), 48 + 2 * 4096)
        self.assertEqual(hashlib.sha256(snapshot).hexdigest(),
                         fixture["concatenated_uncompressed_sha256"])
        fat_table, x86_header, arm_header = snapshot[:48], snapshot[48:4144], snapshot[4144:]
        self.assertEqual(hashlib.sha256(fat_table).hexdigest(),
                         fixture["parts_sha256"]["fat_table"])
        self.assertEqual(hashlib.sha256(x86_header).hexdigest(),
                         fixture["parts_sha256"]["x86_64_prefix"])
        self.assertEqual(hashlib.sha256(arm_header).hexdigest(),
                         fixture["parts_sha256"]["arm64_prefix"])
        self.assertEqual(struct.unpack_from(">II", fat_table), (0xCAFEBABE, 2))
        table_x86 = struct.unpack_from(">IIIII", fat_table, 8)
        table_arm = struct.unpack_from(">IIIII", fat_table, 28)
        self.assertEqual(table_x86, (inspector.CPU_X86_64, 3, 16384, 11204508, 14))
        self.assertEqual(table_arm, (inspector.CPU_ARM64, 0, 11223040, 10166928, 14))
        self.assertEqual(inspector._thin_arch(x86_header)[0], "x86_64")
        self.assertEqual(inspector._thin_arch(arm_header)[0], "arm64")
        if REAL_OFFICIAL_WHEEL.is_file():
            # Optional stronger full-wheel test. Bundled fingerprint above
            # still runs on offline checkouts without a skip or false PASS.
            result = inspector.inspect_wheel_path(REAL_OFFICIAL_WHEEL, REAL_OFFICIAL_SHA256)
            self.assertEqual(result["native_binary_count"], 1)
            native = result["native_binaries"][0]
            self.assertEqual(native["path"], "cryptography/hazmat/bindings/_rust.abi3.so")
            self.assertEqual(native["mach_o"]["architectures"], ["arm64", "x86_64"])
            self.assertEqual(len(native["mach_o"]["slices"]), 2)
            self.assertEqual(result["macos_host_execution"], "NOT_RUN")
            self.assertFalse(result["release_authorized"])

    def test_universal2_pinned_native_structures(self):
        data, name, pin = wheel()
        result = inspector.inspect_wheel_bytes(data, name, pin)
        self.assertEqual(result["status"], "PINNED_MACOS_WHEEL_STRUCTURE_VERIFIED_NOT_EXECUTED")
        self.assertEqual(result["platform"], "universal2")
        self.assertEqual(result["native_binary_count"], 1)
        self.assertFalse(result["release_authorized"])
        self.assertEqual(result["macos_host_execution"], "NOT_RUN")

    def test_arm64_wheel_with_arm64_thin(self):
        data, name, pin = wheel(thin(inspector.CPU_ARM64), "pkg-1.0-cp39-abi3-macosx_11_0_arm64.whl")
        self.assertEqual(inspector.inspect_wheel_bytes(data, name, pin)["platform"], "arm64")

    def test_x86_wheel_with_x86_thin(self):
        data, name, pin = wheel(thin(inspector.CPU_X86_64), "pkg-1.0-cp39-abi3-macosx_10_9_x86_64.whl")
        self.assertEqual(inspector.inspect_wheel_bytes(data, name, pin)["platform"], "x86_64")

    def test_reject_universal_tag_with_single_arch(self):
        data, name, pin = wheel(thin(inspector.CPU_X86_64))
        with self.assertRaisesRegex(ValueError, "wheel_platform_macho_arch_mismatch"):
            inspector.inspect_wheel_bytes(data, name, pin)

    def test_reject_arm_tag_with_universal_binary(self):
        data, name, pin = wheel(fat(), "pkg-1.0-cp39-abi3-macosx_11_0_arm64.whl")
        with self.assertRaisesRegex(ValueError, "wheel_platform_macho_arch_mismatch"):
            inspector.inspect_wheel_bytes(data, name, pin)

    def test_reject_wrong_hash_pin(self):
        data, name, _ = wheel()
        with self.assertRaisesRegex(ValueError, "wheel_sha256_pin_mismatch"):
            inspector.inspect_wheel_bytes(data, name, "0" * 64)

    def test_reject_missing_hash_pin(self):
        data, name, _ = wheel()
        with self.assertRaisesRegex(ValueError, "trusted_sha256_pin_required"):
            inspector.inspect_wheel_bytes(data, name, "")

    def test_reject_non_macos_platform_tag(self):
        data, _, pin = wheel()
        with self.assertRaisesRegex(ValueError, "unsupported_macos_wheel_platform"):
            inspector.inspect_wheel_bytes(data, "pkg-1-cp39-abi3-manylinux2014_x86_64.whl", pin)

    def test_reject_traversal_zip_member(self):
        data, name, pin = wheel(extra=[("../outside.py", "test")])
        with self.assertRaisesRegex(ValueError, "unsafe_wheel_member_path"):
            inspector.inspect_wheel_bytes(data, name, pin)

    def test_reject_duplicate_zip_member(self):
        data, name, pin = wheel(extra=[("pkg/module.py", "different")])
        with self.assertRaisesRegex(ValueError, "unsafe_wheel_member_path"):
            inspector.inspect_wheel_bytes(data, name, pin)

    def test_reject_mixed_architectures(self):
        data, name, pin = wheel(extra=[("pkg/_other.so", thin(inspector.CPU_X86_64))])
        with self.assertRaisesRegex(ValueError, "wheel_platform_macho_arch_mismatch"):
            inspector.inspect_wheel_bytes(data, name, pin)

    def test_reject_native_binary_not_macho(self):
        data, name, pin = wheel(b"\x7fELF" + b"\x00" * 64)
        with self.assertRaisesRegex(ValueError, "not_macho_binary"):
            inspector.inspect_wheel_bytes(data, name, pin)

    def test_reject_metadata_tag_disagreement(self):
        data, name, pin = wheel(extra=[("other.dist-info/WHEEL", "Tag: fake-fake-fake\n")])
        with self.assertRaisesRegex(ValueError, "missing_or_multiple_wheel_metadata"):
            inspector.inspect_wheel_bytes(data, name, pin)

    def test_reject_false_wheel_metadata_platform(self):
        data, name, _ = wheel()
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            items = [(i.filename, archive.read(i)) for i in archive.infolist()]
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            for path, item in items:
                if path.endswith(".dist-info/WHEEL"):
                    item = item.replace(b"universal2", b"x86_64")
                archive.writestr(path, item)
        changed = output.getvalue()
        with self.assertRaisesRegex(ValueError, "wheel_metadata_tag_or_purelib_mismatch"):
            inspector.inspect_wheel_bytes(changed, name, hashlib.sha256(changed).hexdigest())

    def test_reject_invalid_zip(self):
        data = b"x" * 50
        with self.assertRaises(zipfile.BadZipFile):
            inspector.inspect_wheel_bytes(data, "pkg-1-cp39-abi3-macosx_11_0_universal2.whl",
                                          hashlib.sha256(data).hexdigest())

    def test_reject_empty_native(self):
        data, name, pin = wheel(b"\x00" * 32)
        with self.assertRaisesRegex(ValueError, "not_macho_binary"):
            inspector.inspect_wheel_bytes(data, name, pin)

    def test_reject_symlink_wheel_path(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            target = pathlib.Path(directory) / "pkg-1.0-cp39-abi3-macosx_11_0_universal2.whl"
            data, _, pin = wheel()
            target.write_bytes(data)
            link = pathlib.Path(directory) / "link.whl"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "unsafe_wheel_file"):
                inspector.inspect_wheel_path(link, pin)

    def test_pinned_real_local_file(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            target = pathlib.Path(directory) / "pkg-1.0-cp39-abi3-macosx_11_0_universal2.whl"
            data, _, pin = wheel()
            target.write_bytes(data)
            self.assertEqual(inspector.inspect_wheel_path(target, pin)["wheel_sha256"], pin)

    def test_reject_hardlinked_wheel_path(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            target = pathlib.Path(directory) / "pkg-1.0-cp39-abi3-macosx_11_0_universal2.whl"
            data, _, pin = wheel()
            target.write_bytes(data)
            os.link(target, pathlib.Path(directory) / "other.whl")
            with self.assertRaisesRegex(ValueError, "unsafe_wheel_file"):
                inspector.inspect_wheel_path(target, pin)


if __name__ == "__main__":
    unittest.main()
