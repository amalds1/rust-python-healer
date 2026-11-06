"""Build and inspect a deterministic *offline candidate* OCI image layout.

The archive follows the OCI image-layout, image-manifest and image-config
formats, but does not prove that a host can run its dynamically linked ELF.
The sidecar sandbox policy is explicitly NOT ENFORCED.  No image is pushed,
executed, or approved for release by this module.
"""

import argparse
import hashlib
import io
import json
import os
import re
import stat
import tarfile
import tempfile
from pathlib import Path

MAX_BINARY = 50 * 1024 * 1024
MAX_ARCHIVE = 90 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
EPOCH = "1970-01-01T00:00:00Z"
INDEX_TYPE = "application/vnd.oci.image.index.v1+json"
MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"
CONFIG_TYPE = "application/vnd.oci.image.config.v1+json"
LAYER_TYPE = "application/vnd.oci.image.layer.v1.tar"
BINARY_NAME = "usr/local/bin/rust-python-healer"


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _json(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _tar(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, payload, mode in sorted(entries):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.uid = info.gid = info.mtime = 0
            info.mode = mode
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def _binary(path, expected):
    if not SHA256.fullmatch(expected):
        raise ValueError("explicit_sha256_pin_required")
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 64 <= info.st_size <= MAX_BINARY:
        raise ValueError("untrusted_binary_file_type_or_size")
    descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(descriptor)
        content = stream.read(MAX_BINARY + 1)
        after = os.fstat(stream.fileno())
    if (len(content) > MAX_BINARY or len(content) != before.st_size or
            before.st_dev != after.st_dev or before.st_ino != after.st_ino or
            before.st_mtime_ns != after.st_mtime_ns or before.st_size != after.st_size):
        raise ValueError("binary_changed_during_read")
    if _sha(content) != expected:
        raise ValueError("binary_sha256_mismatch")
    if (content[:4] != b"\x7fELF" or content[4] != 2 or content[5] != 1 or
            int.from_bytes(content[16:18], "little") not in (2, 3) or
            int.from_bytes(content[18:20], "little") != 62):
        raise ValueError("not_linux_amd64_elf")
    return content


def _descriptor(media_type, data):
    return {"mediaType": media_type, "digest": "sha256:" + _sha(data),
            "size": len(data)}


def candidate_bytes(binary):
    """Return reproducible OCI-layout tar bytes, with no execution authority."""
    layer = _tar([(BINARY_NAME, binary, 0o755)])
    configuration = _json({
        "architecture": "amd64", "os": "linux", "created": EPOCH,
        "config": {"User": "65532:65532", "WorkingDir": "/",
                   "Entrypoint": ["/usr/local/bin/rust-python-healer"]},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + _sha(layer)]},
        "history": [{"created": EPOCH, "created_by": "verified offline ELF packaging",
                     "comment": "Execution and dynamic dependencies NOT_VERIFIED"}],
    })
    manifest = _json({"schemaVersion": 2, "mediaType": MANIFEST_TYPE,
                      "config": _descriptor(CONFIG_TYPE, configuration),
                      "layers": [_descriptor(LAYER_TYPE, layer)],
                      "annotations": {"org.opencontainers.image.title": "rust-python-healer",
                                      "org.opencontainers.image.version": "0.27.0"}})
    index = _json({"schemaVersion": 2, "mediaType": INDEX_TYPE,
                   "manifests": [dict(_descriptor(MANIFEST_TYPE, manifest),
                                      platform={"architecture": "amd64", "os": "linux"},
                                      annotations={"org.opencontainers.image.ref.name": "offline-candidate"})]})
    sidecar = _json({"status": "SANDBOX_PROFILE_NOT_ENFORCED",
                     "require_external_runtime": True,
                     "required_controls": ["read_only_rootfs", "deny_network_and_dns",
                                           "drop_all_capabilities", "no_new_privileges",
                                           "non_root_user", "host_resource_limits"],
                     "independent_audit": False, "release_authorized": False})
    entries = [("oci-layout", _json({"imageLayoutVersion": "1.0.0"}), 0o644),
               ("index.json", index, 0o644),
               ("sandbox-requirements.json", sidecar, 0o644)]
    for payload in (configuration, manifest, layer):
        entries.append(("blobs/sha256/" + _sha(payload), payload, 0o644))
    return _tar(entries)


def _load_json(blob):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_field")
            result[key] = value
        return result
    return json.loads(blob.decode("utf-8"), object_pairs_hook=unique)


def inspect_bytes(archive):
    """Verify all digests, descriptors, shape and policy; never extract/run."""
    if not isinstance(archive, bytes) or len(archive) > MAX_ARCHIVE:
        raise ValueError("oci_archive_size_limit")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        names = tar.getnames()
        if len(names) != 6 or len(names) != len(set(names)):
            raise ValueError("oci_layout_members_not_unique")
        objects = {}
        for member in tar.getmembers():
            if not member.isfile() or member.size > MAX_BINARY + 10240:
                raise ValueError("untrusted_oci_layout_member")
            objects[member.name] = tar.extractfile(member).read()
    if set(objects) - {"oci-layout", "index.json", "sandbox-requirements.json"} != {
            name for name in objects if name.startswith("blobs/sha256/")}:
        raise ValueError("unexpected_oci_layout_paths")
    if _load_json(objects["oci-layout"]) != {"imageLayoutVersion": "1.0.0"}:
        raise ValueError("invalid_oci_layout_version")
    sidecar = _load_json(objects["sandbox-requirements.json"])
    if sidecar.get("status") != "SANDBOX_PROFILE_NOT_ENFORCED" or sidecar.get("release_authorized") is not False:
        raise ValueError("misleading_sandbox_claim")
    for name, payload in objects.items():
        if name.startswith("blobs/sha256/") and name != "blobs/sha256/" + _sha(payload):
            raise ValueError("oci_blob_digest_mismatch")

    def load_ref(descriptor, media_type):
        if not isinstance(descriptor, dict) or descriptor.get("mediaType") != media_type:
            raise ValueError("oci_wrong_media_type")
        digest = descriptor.get("digest", "")
        if not isinstance(digest, str) or not digest.startswith("sha256:") or not SHA256.fullmatch(digest[7:]):
            raise ValueError("invalid_oci_descriptor")
        data = objects.get("blobs/sha256/" + digest[7:])
        if data is None or descriptor.get("size") != len(data):
            raise ValueError("oci_descriptor_missing_or_size_mismatch")
        return data

    index = _load_json(objects["index.json"])
    if index.get("schemaVersion") != 2 or index.get("mediaType") != INDEX_TYPE or len(index.get("manifests", [])) != 1:
        raise ValueError("invalid_oci_index")
    manifest = _load_json(load_ref(index["manifests"][0], MANIFEST_TYPE))
    if manifest.get("schemaVersion") != 2 or len(manifest.get("layers", [])) != 1:
        raise ValueError("invalid_oci_manifest")
    configuration = _load_json(load_ref(manifest["config"], CONFIG_TYPE))
    layer = load_ref(manifest["layers"][0], LAYER_TYPE)
    if (configuration.get("architecture") != "amd64" or configuration.get("os") != "linux" or
            configuration.get("rootfs") != {"type": "layers", "diff_ids": ["sha256:" + _sha(layer)]} or
            configuration.get("config", {}).get("User") != "65532:65532"):
        raise ValueError("oci_platform_or_rootfs_mismatch")
    with tarfile.open(fileobj=io.BytesIO(layer), mode="r:") as tar:
        members = tar.getmembers()
        if len(members) != 1 or members[0].name != BINARY_NAME or not members[0].isfile():
            raise ValueError("unexpected_binary_layer_contents")
        actual = tar.extractfile(members[0]).read()
        if actual[:4] != b"\x7fELF":
            raise ValueError("invalid_binary_layer")
    return {"status": "OCI_LAYOUT_INTEGRITY_VERIFIED_RUNTIME_NOT_RUN",
            "binary_sha256": _sha(actual), "image_digest": "sha256:" + _sha(_json(manifest)),
            "sandbox_isolation_verified": False, "external_client_run": False,
            "release_authorized": False, "independent_audit": False}


def build(path, output, expected_sha256):
    binary = _binary(path, expected_sha256)
    archive = candidate_bytes(binary)
    report = inspect_bytes(archive)
    output = Path(output)
    if not output.parent.is_dir() or output.is_symlink() or output.exists():
        raise ValueError("output_must_be_new_regular_path")
    with tempfile.NamedTemporaryFile(dir=str(output.parent), prefix=".oci-v25-", delete=False) as temp:
        temp_path = Path(temp.name)
        temp.write(archive)
        temp.flush()
        os.fsync(temp.fileno())
    try:
        os.link(str(temp_path), str(output))  # atomic, never overwrite a user's file
    finally:
        temp_path.unlink(missing_ok=True)
    return dict(report, archive_sha256=_sha(archive), archive_bytes=len(archive))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "build"), default="build")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.mode == "capabilities":
        if args.binary or args.expected_sha256 or args.output:
            parser.error("capability_probe_rejects_mutation_arguments")
        print(json.dumps({"status": "OCI_LAYOUT_CANDIDATE_ADAPTER_AVAILABLE",
                          "image_built": False, "container_executed": False,
                          "sandbox_isolation_verified": False,
                          "release_authorized": False}))
        return 0
    if not args.binary or not args.expected_sha256 or not args.output:
        parser.error("build_requires_binary_sha256_and_output")
    try:
        result = build(args.binary, args.output, args.expected_sha256)
    except (OSError, ValueError, tarfile.TarError, UnicodeError) as exc:
        print(json.dumps({"status": "NOT_RUN", "reason": type(exc).__name__}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
