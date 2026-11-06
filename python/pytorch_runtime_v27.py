"""Non-executing PyTorch checkpoint triage and optional *real* local CPU probe.

Security boundary: an arbitrary checkpoint is never passed to pickle.loads,
torch.load, or any arbitrary Python function. A ZIP checkpoint is untrusted
metadata; the only executable fixture is a fixed in-memory model constructed
by this module, and it runs only when local PyTorch is really installed.

Static checks are *not* claims of checkpoint compatibility, safety, or GPU
qualification. The inspected checkpoint may have deliberately false metadata.
"""

import importlib.metadata
import json
import os
import pickletools
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

MAX_CHECKPOINT_BYTES = 64 * 1024 * 1024
MAX_PICKLE_BYTES = 1024 * 1024
MAX_MEMBERS = 4096
MAX_UNCOMPRESSED_BYTES = 128 * 1024 * 1024
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
MAX_PICKLE_OPS = 100_000
DEVICE_PATTERN = re.compile(r"^(?:cpu|cuda(?::[0-9]{1,3})?|mps|xpu(?::[0-9]{1,3})?)$")
ALLOWED_GLOBAL_PREFIXES = ("torch", "collections", "builtins", "numpy")


CPU_FIXTURE = r'''
import io
import json
import torch

left = torch.tensor([1, 2, 3], dtype=torch.float32, device="cpu")
right = torch.tensor([4, 5, 6], dtype=torch.float32, device="cpu")
actual = (left + right).tolist()
assert actual == [5.0, 7.0, 9.0]
assert (left + right).device.type == "cpu"
errors = []
try:
    torch.empty((1,), device="rph_invalid_device_999")
except (RuntimeError, ValueError, NotImplementedError):
    errors.append("INVALID_DEVICE_REJECTED")

safe_buffer = io.BytesIO()
torch.save({"fixed": left}, safe_buffer)
safe_buffer.seek(0)
try:
    recovered = torch.load(safe_buffer, map_location="cpu", weights_only=True)
    assert recovered["fixed"].tolist() == [1.0, 2.0, 3.0]
    errors.append("OWN_WEIGHTS_ONLY_CHECKPOINT_ROUNDTRIP")
except TypeError:
    pass  # Old torch versions may not have weights_only.

assert "INVALID_DEVICE_REJECTED" in errors
print(json.dumps({
    "status": "REAL_INSTALLED_TORCH_CPU_FIXED_FIXTURE_PASS",
    "torch_version": torch.__version__,
    "cpu_sum": actual,
    "fixed_negative_oracles": errors,
    "actual_framework_imported": True,
    "checkpoint_from_user_loaded": False,
    "cpu_verified": True,
    "gpu_verified": False,
    "cuda_driver_queried": False,
}))
'''


def _redacted_failure(status, error=None):
    report = {"status": status, "checkpoint_executed": False,
              "pickle_unpickled": False, "checkpoint_compatibility_verified": False,
              "gpu_verified": False}
    if error is not None:
        report["error_type"] = type(error).__name__
    return report


def _valid_member(name, archive_root):
    if (not name or "\\" in name or "\x00" in name or name.startswith("/")
            or len(name) > 255 or ":" in name or "//" in name):
        return False
    parts = name.split("/")
    return (all(part not in ("", ".", "..") for part in parts if part)
            and len(parts) >= 2 and parts[0] == archive_root)


def _inspect_pickle(payload):
    """Only parse opcodes. Even an apparently benign pickle is never trusted."""
    globals_seen = set()
    devices = set()
    dynamic_globals = False
    constructor_opcodes = 0
    persistent_ids = 0
    opcode_count = 0
    try:
        for opcode, argument, _position in pickletools.genops(payload):
            opcode_count += 1
            if opcode_count > MAX_PICKLE_OPS:
                return None
            if opcode.name == "GLOBAL":
                module = argument.split(" ", 1)[0]
                globals_seen.add(module[:96])
            elif opcode.name == "STACK_GLOBAL":
                dynamic_globals = True
            elif opcode.name in ("REDUCE", "BUILD", "NEWOBJ", "NEWOBJ_EX", "OBJ", "INST",
                                 "EXT1", "EXT2", "EXT4"):
                constructor_opcodes += 1
            elif opcode.name in ("PERSID", "BINPERSID"):
                persistent_ids += 1
            elif opcode.name in ("BINUNICODE", "SHORT_BINUNICODE", "UNICODE",
                                 "BINUNICODE8", "SHORT_BINSTRING", "BINSTRING"):
                if isinstance(argument, (str, bytes)):
                    candidate = argument.decode("ascii", "ignore") if isinstance(argument, bytes) else argument
                    if DEVICE_PATTERN.fullmatch(candidate):
                        devices.add(candidate)
    except (ValueError, IndexError, EOFError, UnicodeError):
        return None
    unknown_globals = sorted(module for module in globals_seen if not any(
        module == prefix or module.startswith(prefix + ".")
        for prefix in ALLOWED_GLOBAL_PREFIXES))
    return {"opcode_count": opcode_count,
            "constructor_opcode_count": constructor_opcodes,
            "persistent_id_opcode_count": persistent_ids,
            "dynamic_global_references": dynamic_globals,
            "nonframework_global_modules": unknown_globals[:16],
            "nonframework_global_module_count": len(unknown_globals),
            "device_hints_unverified": sorted(devices),
            "weights_only_unpickler_verified": False}


def inspect_checkpoint(path, max_checkpoint_bytes=MAX_CHECKPOINT_BYTES):
    """Inspect a regular, non-symlink checkpoint ZIP without unpickling it.

    A positive result proves only bounded *structural* inspection. PyTorch
    1.6+ ZIP layout is recognized; older legacy torch pickle format is NOT_RUN.
    """
    if (type(max_checkpoint_bytes) is not int or max_checkpoint_bytes < 1024
            or max_checkpoint_bytes > MAX_CHECKPOINT_BYTES):
        raise ValueError("invalid_checkpoint_limit")
    if not isinstance(path, (str, os.PathLike)):
        raise TypeError("checkpoint_path_required")
    try:
        source = Path(path)
        metadata = source.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            return _redacted_failure("REJECTED_NOT_REGULAR_FILE_OR_SYMLINK")
        if not 0 < metadata.st_size <= max_checkpoint_bytes:
            return _redacted_failure("REJECTED_ARCHIVE_SIZE")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
        try:
            opened = os.fstat(descriptor)
            if (not stat.S_ISREG(opened.st_mode) or
                    (opened.st_dev, opened.st_ino, opened.st_size) !=
                    (metadata.st_dev, metadata.st_ino, metadata.st_size)):
                return _redacted_failure("REJECTED_CHANGED_FILE")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                try:
                    with zipfile.ZipFile(handle, "r") as archive:
                        entries = archive.infolist()
                        if not entries or len(entries) > MAX_MEMBERS:
                            return _redacted_failure("REJECTED_ARCHIVE_ENTRY_COUNT")
                        roots = {entry.filename.split("/", 1)[0] for entry in entries}
                        if len(roots) != 1:
                            return _redacted_failure("REJECTED_ARCHIVE_ROOTS")
                        archive_root = next(iter(roots))
                        declared_size = 0
                        candidates = []
                        file_count = 0
                        for entry in entries:
                            if entry.is_dir():
                                # Directories end in '/', which _valid_member
                                # otherwise rejects as an empty final component.
                                name = entry.filename[:-1]
                            else:
                                name = entry.filename
                            if not _valid_member(name, archive_root):
                                return _redacted_failure("REJECTED_ARCHIVE_PATH")
                            if ((entry.external_attr >> 16) & 0o170000) == stat.S_IFLNK:
                                return _redacted_failure("REJECTED_ARCHIVE_SYMLINK")
                            if entry.file_size < 0 or entry.file_size > MAX_MEMBER_BYTES:
                                return _redacted_failure("REJECTED_MEMBER_SIZE")
                            declared_size += entry.file_size
                            if declared_size > MAX_UNCOMPRESSED_BYTES:
                                return _redacted_failure("REJECTED_TOTAL_DECOMPRESSED_SIZE")
                            if entry.file_size and entry.file_size > max(entry.compress_size, 1) * MAX_COMPRESSION_RATIO:
                                return _redacted_failure("REJECTED_COMPRESSION_RATIO")
                            if not entry.is_dir():
                                file_count += 1
                            if entry.filename == archive_root + "/data.pkl":
                                candidates.append(entry)
                        if len(candidates) != 1:
                            return _redacted_failure("NOT_RECOGNIZED_TORCH_ZIP_LAYOUT")
                        data_entry = candidates[0]
                        if data_entry.file_size > MAX_PICKLE_BYTES:
                            return _redacted_failure("REJECTED_PICKLE_SIZE")
                        payload = archive.read(data_entry)
                        parsed = _inspect_pickle(payload)
                        if parsed is None:
                            return _redacted_failure("REJECTED_INVALID_PICKLE_OPCODES")
                        return {"status": "PASS_BOUNDED_STATIC_TORCH_ZIP_INSPECTION_ONLY",
                                "format_heuristic": "PYTORCH_ZIP_STYLE_UNVERIFIED",
                                "archive_file_count": file_count,
                                "declared_uncompressed_bytes": declared_size,
                                "pickle_bytes": len(payload),
                                "pickle_opcode_analysis": parsed,
                                "archive_all_member_crcs_verified": False,
                                "checkpoint_executed": False,
                                "pickle_unpickled": False,
                                "checkpoint_compatibility_verified": False,
                                "gpu_verified": False}
                except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError) as error:
                    return _redacted_failure("NOT_RUN_CORRUPT_OR_UNSUPPORTED_ZIP", error)
        finally:
            os.close(descriptor)
    except (OSError, ValueError) as error:
        return _redacted_failure("NOT_RUN_CHECKPOINT_IO_FAILURE", error)


CUDA_FIXTURE = r'''
import io,json,sys,zipfile
import torch
if not torch.cuda.is_available():
    print(json.dumps({"status":"NOT_RUN_NO_CUDA_DEVICE"}))
    sys.exit(0)
left=torch.tensor([1.,2.,3.],device="cuda:0",requires_grad=True)
loss=(left*left).sum()
loss.backward()
assert left.grad.cpu().tolist()==[2.,4.,6.]
negative=[]
try:
    left + torch.ones((3,),device="cpu")
except RuntimeError:
    negative.append("CPU_CUDA_DEVICE_MISMATCH_REJECTED")
try:
    torch.ones((2,3),device="cuda:0") @ torch.ones((2,3),device="cuda:0")
except RuntimeError:
    negative.append("SHAPE_MISMATCH_REJECTED")
formats=[]
for modern in (True,False):
    own=io.BytesIO()
    torch.save({"fixed":left.detach()},own,_use_new_zipfile_serialization=modern)
    prefix=own.getvalue()[:2]
    assert (prefix==b"PK") is modern
    version=None
    if modern:
        with zipfile.ZipFile(own) as archive:
            members=[n for n in archive.namelist() if n.endswith("/version")]
            assert len(members)==1
            version=archive.read(members[0]).decode("ascii").strip()
    own.seek(0)
    restored=torch.load(own,map_location="cpu",weights_only=True)
    assert restored["fixed"].device.type=="cpu"
    assert restored["fixed"].tolist()==[1.,2.,3.]
    formats.append({"format":"zip" if modern else "legacy_pickle","archive_version":version,"map_location":"cpu","weights_only":True})
torch.cuda.synchronize()
assert set(negative)=={"CPU_CUDA_DEVICE_MISMATCH_REJECTED","SHAPE_MISMATCH_REJECTED"}
print(json.dumps({"status":"REAL_TORCH_CUDA_FIXED_FIXTURE_PASS","torch_version":torch.__version__,"cuda_version":torch.version.cuda,"device":str(left.device),"gpu_name":torch.cuda.get_device_name(0),"values":left.detach().cpu().tolist(),"gradient":left.grad.cpu().tolist(),"negative_oracles":negative,"checkpoint_formats":formats,"unknown_checkpoint_loaded":False}))
'''


def installed_torch_metadata():
    """A locally installed distribution is not evidence of usable PyTorch."""
    try:
        distribution = importlib.metadata.distribution("torch")
    except importlib.metadata.PackageNotFoundError:
        return {"status": "NOT_RUN_TORCH_NOT_INSTALLED", "torch_imported": False}
    try:
        root = Path(str(distribution.locate_file(""))).resolve()
        root.relative_to(Path(sys.prefix).resolve())
    except (ValueError, OSError):
        return {"status": "NOT_RUN_UNTRUSTED_TORCH_INSTALL_ROOT", "torch_imported": False}
    return {"status": "LOCAL_TORCH_METADATA_ONLY", "distribution_version": distribution.version,
            "torch_imported": False, "official_publisher_provenance_verified": False}


def _trusted_fixture_environment():
    environment = {"PATH": os.defpath, "OMP_NUM_THREADS": "1",
                   "MKL_NUM_THREADS": "1", "PYTHONIOENCODING": "utf-8"}
    if sys.platform == "win32":
        system_root = os.environ.get("SystemRoot")
        if system_root:
            environment["SystemRoot"] = system_root
    return environment


def probe_installed_torch_cpu(timeout_seconds=20):
    """Only a literal in-memory tensor/torch.save/weights_only CPU fixture."""
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 30:
        raise ValueError("invalid_timeout")
    metadata = installed_torch_metadata()
    if metadata["status"] != "LOCAL_TORCH_METADATA_ONLY":
        return dict(metadata, cpu_runtime_verified=False, gpu_runtime_verified=False)
    environment = _trusted_fixture_environment()
    try:
        child = subprocess.run([sys.executable, "-I", "-B", "-c", CPU_FIXTURE],
                               capture_output=True, check=False, timeout=timeout_seconds,
                               env=environment)
    except (OSError, subprocess.TimeoutExpired) as error:
        return dict(_redacted_failure("NOT_RUN_TORCH_CPU_FIXTURE_FAILED", error),
                    cpu_runtime_verified=False)
    if child.returncode != 0 or len(child.stdout) > 8192 or len(child.stderr) > 8192:
        return dict(_redacted_failure("NOT_RUN_TORCH_CPU_FIXTURE_FAILED"),
                    cpu_runtime_verified=False)
    try:
        observed = json.loads(child.stdout)
    except (UnicodeError, ValueError):
        return dict(_redacted_failure("NOT_RUN_TORCH_CPU_FIXTURE_FAILED"),
                    cpu_runtime_verified=False)
    if (type(observed) is not dict or
            observed.get("status") != "REAL_INSTALLED_TORCH_CPU_FIXED_FIXTURE_PASS" or
            observed.get("cpu_sum") != [5., 7., 9.] or
            observed.get("checkpoint_from_user_loaded") is not False or
            observed.get("gpu_verified") is not False or
            type(observed.get("torch_version")) is not str or
            observed["torch_version"].split("+", 1)[0] != metadata["distribution_version"].split("+", 1)[0] or
            type(observed.get("fixed_negative_oracles")) is not list or
            any(type(code) is not str or code not in {
                "INVALID_DEVICE_REJECTED", "OWN_WEIGHTS_ONLY_CHECKPOINT_ROUNDTRIP"}
                for code in observed["fixed_negative_oracles"]) or
            "INVALID_DEVICE_REJECTED" not in observed.get("fixed_negative_oracles", [])):
        return dict(_redacted_failure("NOT_RUN_TORCH_CPU_FIXTURE_ORACLE_MISMATCH"),
                    cpu_runtime_verified=False)
    return {"status": "PASS_REAL_INSTALLED_TORCH_CPU_FIXED_FIXTURE_ONLY",
            "installed_version": metadata["distribution_version"],
            "fixed_negative_oracles": observed["fixed_negative_oracles"],
            "cpu_runtime_verified": True, "gpu_runtime_verified": False,
            "untrusted_checkpoint_executed": False,
            "external_provenance_verified": False}


def probe_installed_torch_cuda(timeout_seconds=30):
    """Opt-in real CUDA + own legacy/ZIP roundtrips; never load supplied data."""
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60:
        raise ValueError("invalid_timeout")
    metadata = installed_torch_metadata()
    if metadata["status"] != "LOCAL_TORCH_METADATA_ONLY":
        return dict(metadata, gpu_runtime_verified=False)
    try:
        child = subprocess.run([sys.executable, "-I", "-B", "-c", CUDA_FIXTURE],
                               capture_output=True, check=False, timeout=timeout_seconds,
                               env=_trusted_fixture_environment())
    except (OSError, subprocess.TimeoutExpired) as error:
        return dict(_redacted_failure("NOT_RUN_TORCH_CUDA_FIXTURE_FAILED", error),
                    gpu_runtime_verified=False)
    if child.returncode or len(child.stdout) > 8192 or len(child.stderr) > 8192:
        return dict(_redacted_failure("NOT_RUN_TORCH_CUDA_FIXTURE_FAILED"),
                    gpu_runtime_verified=False)
    try:
        observed = json.loads(child.stdout)
    except (UnicodeError, ValueError):
        observed = None
    if observed == {"status": "NOT_RUN_NO_CUDA_DEVICE"}:
        return dict(observed, gpu_runtime_verified=False)
    fields = {"status", "torch_version", "cuda_version", "device", "gpu_name",
              "values", "gradient", "negative_oracles", "checkpoint_formats",
              "unknown_checkpoint_loaded"}
    valid = (type(observed) is dict and set(observed) == fields and
             observed.get("status") == "REAL_TORCH_CUDA_FIXED_FIXTURE_PASS" and
             observed.get("torch_version") == metadata["distribution_version"] and
             type(observed.get("cuda_version")) is str and 0 < len(observed["cuda_version"]) <= 64 and
             observed.get("device") == "cuda:0" and
             type(observed.get("gpu_name")) is str and 0 < len(observed["gpu_name"]) <= 256 and
             type(observed.get("values")) is list and
             all(type(v) in (int, float) for v in observed["values"]) and
             observed.get("values") == [1., 2., 3.] and
             type(observed.get("gradient")) is list and
             all(type(v) in (int, float) for v in observed["gradient"]) and
             observed.get("gradient") == [2., 4., 6.] and
             observed.get("unknown_checkpoint_loaded") is False and
             type(observed.get("negative_oracles")) is list and
             observed["negative_oracles"] == ["CPU_CUDA_DEVICE_MISMATCH_REJECTED", "SHAPE_MISMATCH_REJECTED"])
    formats = observed.get("checkpoint_formats") if type(observed) is dict else None
    if not (valid and type(formats) is list and len(formats) == 2 and
            all(type(row) is dict and set(row) == {"format", "archive_version", "map_location", "weights_only"}
                and row["map_location"] == "cpu" and row["weights_only"] is True for row in formats) and
            formats[0]["format"] == "zip" and type(formats[0]["archive_version"]) is str and
            formats[0]["archive_version"].isdigit() and len(formats[0]["archive_version"]) <= 8 and
            formats[1]["format"] == "legacy_pickle" and formats[1]["archive_version"] is None):
        return dict(_redacted_failure("NOT_RUN_TORCH_CUDA_ORACLE_MISMATCH"),
                    gpu_runtime_verified=False)
    return {"status": "PASS_REAL_INSTALLED_TORCH_CUDA_FIXED_FIXTURE_ONLY",
            "installed_version": metadata["distribution_version"],
            "cuda_version": observed["cuda_version"], "device": observed["device"],
            "gpu_name": observed["gpu_name"], "negative_oracles": observed["negative_oracles"],
            "own_checkpoint_formats_verified": formats, "gpu_runtime_verified": True,
            "untrusted_checkpoint_executed": False,
            "external_provenance_verified": False}


def report(checkpoint=None, probe_cuda=False):
    if type(probe_cuda) is not bool:
        raise ValueError("explicit_boolean_probe_cuda_required")
    gpu = probe_installed_torch_cuda() if probe_cuda else {
        "status": "NOT_RUN_CUDA_REQUIRES_EXPLICIT_REQUEST", "gpu_runtime_verified": False}
    return {"schema_version": 1,
            "python_version": "{}.{}.{}".format(*sys.version_info[:3]),
            "checkpoint": inspect_checkpoint(checkpoint) if checkpoint else None,
            "real_cpu_runtime": probe_installed_torch_cpu(),
            "real_cuda_runtime": gpu,
            "complete_F253_qualification": False,
            "untrusted_python_executed": False,
            "gpu_tested": gpu["gpu_runtime_verified"]}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkpoint")
    parser.add_argument("--probe-cuda", action="store_true",
                        help="Run only the fixed own-model CUDA/serialization fixture")
    arguments = parser.parse_args()
    print(json.dumps(report(arguments.checkpoint, probe_cuda=arguments.probe_cuda), sort_keys=True))
