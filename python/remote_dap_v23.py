"""Loopback mutual-TLS DAP channel and bounded cross-environment source paths.

No Internet listener, remote production process, IDE client, arbitrary program,
or source evaluation is enabled.  A real TLS socket with certificate-chain
validation AND out-of-band exact peer leaf pins protects a fixed trusted DAP
fixture.  The path mapper is lexical for non-local filesystems; it never opens
remote files and rejects traversal, ambiguous roots and local symlink escapes.
"""

import argparse
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import socket
import ssl
import stat
import threading


if "dap" not in globals():
    _DEP_PATH = Path(__file__).with_name("dap_runtime_v22.py")
    _DEP_SPEC = importlib.util.spec_from_file_location("rph_private_dap_v22", _DEP_PATH)
    dap = importlib.util.module_from_spec(_DEP_SPEC)
    _DEP_SPEC.loader.exec_module(dap)

VALID_PIN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
ENVIRONMENTS = frozenset(("host", "container", "wsl", "remote"))
MAX_PATH = 4096
MAX_SEGMENTS = 128


def _private_file(path):
    candidate = Path(path)
    meta = candidate.lstat()
    if (not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1
            or (os.name != "nt" and meta.st_mode & 0o077)):
        raise ValueError("private_key_file_required")
    if os.name == "nt":
        try:
            descriptor = dap._windows_key_privacy().open_private_readonly(candidate)
            os.close(descriptor)
        except (OSError, ValueError) as problem:
            raise ValueError("private_key_file_required") from problem
    return candidate


def _assert_pin(pin):
    if not isinstance(pin, str) or VALID_PIN.fullmatch(pin) is None:
        raise ValueError("out_of_band_leaf_pin_required")
    return pin


def leaf_pin_from_pem(path):
    """Fingerprint a certificate, never its public-only PEM metadata name."""
    content = Path(path).read_text(encoding="ascii")
    if content.count("-----BEGIN CERTIFICATE-----") != 1:
        raise ValueError("single_leaf_pem_required")
    der = ssl.PEM_cert_to_DER_cert(content)
    return hashlib.sha256(der).hexdigest()


def _tls_context(ca_file, cert_file, key_file, server):
    _private_file(key_file)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= getattr(ssl, "OP_NO_COMPRESSION", 0)
    context.verify_mode = ssl.CERT_REQUIRED
    if not server:
        context.check_hostname = True
    context.load_verify_locations(cafile=str(ca_file))
    # Keep the actual no-follow private leaf open while OpenSSL reads the same
    # key path. SHARE_READ excludes leaf replacement or writes on Windows.
    descriptor = dap._windows_key_privacy().open_private_readonly(key_file) if os.name == "nt" else None
    try:
        context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
        if descriptor is not None:
            dap._windows_key_privacy().assert_private_file_descriptor(descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return context


class PinnedRemoteDAPServer:
    """One bounded real loopback connection, with mutual TLS and peer pin."""

    def __init__(self, ca_file, cert_file, private_key_file, client_leaf_pin,
                 dap_approval_key):
        self.context = _tls_context(ca_file, cert_file, private_key_file, True)
        self.expected_client_pin = _assert_pin(client_leaf_pin)
        if not isinstance(dap_approval_key, bytes) or len(dap_approval_key) < 16:
            raise ValueError("dap_approval_key_missing")
        self.dap_approval_key = dap_approval_key
        self.socket = None
        self.thread = None
        self.actual_tls_version = None
        self.peer_leaf_verified = False
        self.peer_chain_verified = False
        self.peer_leaf_pin_mismatch = False
        self.error_class = None
        self.completed = threading.Event()

    def start(self):
        if self.socket is not None:
            raise ValueError("listener_already_started")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(1)
        self.socket.settimeout(3)
        self.thread = threading.Thread(target=self._accept_one,
                                       name="rph-remote-mtls-fixture", daemon=True)
        self.thread.start()
        return self.socket.getsockname()

    def _accept_one(self):
        try:
            raw, address = self.socket.accept()
            if address[0] != "127.0.0.1":
                raw.close()
                raise ValueError("non_loopback_client_refused")
            with raw:
                raw.settimeout(3)
                with self.context.wrap_socket(raw, server_side=True) as encrypted:
                    self.peer_chain_verified = True
                    leaf_der = encrypted.getpeercert(binary_form=True)
                    if not leaf_der:
                        raise ValueError("missing_client_certificate")
                    actual = hashlib.sha256(leaf_der).hexdigest()
                    if not hmac.compare_digest(actual, self.expected_client_pin):
                        self.peer_leaf_pin_mismatch = True
                        raise ValueError("wrong_operator_pinned_client_leaf")
                    self.peer_leaf_verified = True
                    self.actual_tls_version = encrypted.version()
                    encrypted.settimeout(3)
                    with encrypted.makefile("rwb") as framed_stream:
                        dap.serve(framed_stream, framed_stream, self.dap_approval_key)
        except (OSError, ssl.SSLError, ValueError, dap.ProtocolError) as error:
            self.error_class = type(error).__name__
        finally:
            self.completed.set()

    def close(self):
        if self.socket is not None:
            self.socket.close()
            self.socket = None
        if self.thread is not None:
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                raise RuntimeError("listener_did_not_stop")
            self.thread = None


class PinnedRemoteDAPClient:
    """Operator-pinned real TLS client: only literal 127.0.0.1 is allowed."""

    def __init__(self, ca_file, cert_file, private_key_file, server_leaf_pin):
        self.context = _tls_context(ca_file, cert_file, private_key_file, False)
        self.expected_server_pin = _assert_pin(server_leaf_pin)
        self.connection = None
        self.stream = None
        self.actual_tls_version = None
        self.peer_leaf_verified = False

    def connect(self, host, port):
        if host != "127.0.0.1" or type(port) is not int or not 0 < port <= 65535:
            raise ValueError("only_loopback_fixture_enabled")
        with socket.create_connection((host, port), timeout=3) as raw:
            self.connection = self.context.wrap_socket(raw, server_hostname="localhost")
        actual = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
        if not hmac.compare_digest(actual, self.expected_server_pin):
            self.connection.close()
            self.connection = None
            raise ValueError("wrong_operator_pinned_server_leaf")
        self.peer_leaf_verified = True
        self.actual_tls_version = self.connection.version()
        self.connection.settimeout(3)
        self.stream = self.connection.makefile("rwb")

    def request(self, packet, response_count=1):
        if self.stream is None or not 1 <= response_count <= 4:
            raise ValueError("not_connected_or_response_limit")
        dap.write_frame(self.stream, packet)
        return [dap.read_frame(self.stream) for _ in range(response_count)]

    def close(self):
        if self.stream is not None:
            self.stream.close()
            self.stream = None
        if self.connection is not None:
            self.connection.close()
            self.connection = None


def _validate_path(value, flavor):
    if (not isinstance(value, str) or not 0 < len(value) <= MAX_PATH or "\x00" in value
            or flavor not in ("posix", "windows")):
        raise ValueError("unsafe_or_unbounded_source_path")
    if flavor == "posix":
        if (not value.startswith("/") or "\\" in value or "//" in value
                or re.search(r"%(?:2e|2f|5c)", value, flags=re.IGNORECASE)
                or any(part in ("", ".", "..") for part in value[1:].split("/"))):
            raise ValueError("unsafe_posix_source_path")
        path = PurePosixPath(value)
    else:
        if (not PureWindowsPath(value).is_absolute() or "/" in value
                or "\\\\\\" in value or value.endswith("\\")
                or value.startswith(("\\\\?\\", "\\\\.\\"))
                or re.search(r"%(?:2e|2f|5c)", value, flags=re.IGNORECASE)):
            raise ValueError("unsafe_windows_root_or_component")
        path = PureWindowsPath(value)
        if (any(part in ("", ".", "..") for part in path.parts[1:])
                or any(":" in part for part in path.parts[1:])
                or any(part.endswith((" ", ".")) for part in path.parts[1:])
                or any(any(c in part for c in '<>"|?*') for part in path.parts[1:])
                or any(part.split(".", 1)[0].upper() in
                       {"CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5",
                        "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5",
                        "LPT6", "LPT7", "LPT8", "LPT9"} for part in path.parts[1:])
                or any(part in (".", "..") for part in value.split("\\"))):
            raise ValueError("unsafe_windows_source_path")
    if len(path.parts) > MAX_SEGMENTS:
        raise ValueError("path_component_limit")
    return path


def _parts_equal(first, second, flavor):
    if flavor == "windows":
        return first.casefold() == second.casefold()
    return first == second


class SourcePathMapper:
    """One-to-one environment roots; no remote file access is attempted."""

    def __init__(self, roots, verify_host=False):
        if not isinstance(roots, dict) or set(roots) != ENVIRONMENTS:
            raise ValueError("all_four_environments_required")
        self.roots = {}
        self.verify_host = verify_host
        known = set()
        for environment in sorted(ENVIRONMENTS):
            value = roots[environment]
            if not isinstance(value, dict) or set(value) != {"root", "flavor"}:
                raise ValueError("invalid_path_environment_entry")
            path = _validate_path(value["root"], value["flavor"])
            normalized = str(path).casefold()
            if normalized in known:
                raise ValueError("cross_environment_root_collision")
            known.add(normalized)
            self.roots[environment] = (path, value["flavor"])
        if verify_host:
            root, flavor = self.roots["host"]
            actual_flavor = "windows" if os.name == "nt" else "posix"
            if flavor != actual_flavor:
                raise ValueError("host_root_flavor_must_match_actual_platform")
            # UNC is supported for lexical remote mapping, never for a local
            # verification that could otherwise initiate network file access.
            if flavor == "windows" and (len(root.drive) != 2 or root.drive[1:] != ":"):
                raise ValueError("host_root_must_be_real_local_windows_directory")
            self._check_host_symlinks(str(root), root)
            if not Path(str(root)).is_dir():
                raise ValueError("host_root_must_be_real_directory")

    def _check_host_symlinks(self, value, root):
        """Existing host ancestors under the allowed root must never be links."""
        path = Path(value)
        base = Path(str(root))
        if os.path.normcase(os.path.commonpath((str(path), str(base)))) != os.path.normcase(str(base)):
            raise ValueError("host_path_outside_root")
        current = base
        for ancestor in base.parents:
            if _host_link_or_reparse(ancestor):
                raise ValueError("linked_host_root_ancestor")
        if _host_link_or_reparse(current):
            raise ValueError("linked_host_root")
        for segment in path.relative_to(base).parts:
            current = current / segment
            if _host_link_or_reparse(current):
                raise ValueError("linked_host_path_component")

    def translate(self, value, source, target):
        if source not in self.roots or target not in self.roots or source == target:
            raise ValueError("unknown_or_duplicate_environment")
        root, source_flavor = self.roots[source]
        parsed = _validate_path(value, source_flavor)
        full_parts = parsed.parts
        prefix = root.parts
        if len(full_parts) < len(prefix) or any(not _parts_equal(left, right, source_flavor)
                for left, right in zip(full_parts, prefix)):
            raise ValueError("source_path_outside_allowlisted_root")
        if self.verify_host and source == "host":
            self._check_host_symlinks(value, root)
        tail = full_parts[len(prefix):]
        dest_root, target_flavor = self.roots[target]
        if target_flavor == "windows":
            dest = PureWindowsPath(str(dest_root), *tail)
        else:
            dest = PurePosixPath(str(dest_root), *tail)
        if self.verify_host and target == "host":
            self._check_host_symlinks(str(dest), dest_root)
        if len(str(dest)) > MAX_PATH:
            raise ValueError("translated_path_limit")
        return {"status": "SAFE_BOUNDED_LEXICAL_PATH_MAPPING",
                "source_environment": source, "target_environment": target,
                "translated_path": str(dest),
                "existing_host_symlinks_checked": self.verify_host and (
                    source == "host" or target == "host"),
                "remote_filesystem_verified": False,
                "arbitrary_files_opened": False}


def _host_link_or_reparse(path):
    """Metadata only; do not follow junctions, symlinks or linked file leaves.

    This is a lexical mapping preflight, not a race-free open primitive.
    Source contents and remote filesystems are never opened by the mapper.
    """
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return (stat.S_ISLNK(info.st_mode) or
            (os.name == "nt" and getattr(info, "st_file_attributes", 0) & 0x400 != 0) or
            (stat.S_ISREG(info.st_mode) and info.st_nlink != 1))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-pathmap-selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.fixture_pathmap_selftest:
        mapper = SourcePathMapper({
            "host": {"root": "/trusted/project", "flavor": "posix"},
            "container": {"root": "/app/project", "flavor": "posix"},
            "wsl": {"root": "/mnt/c/project", "flavor": "posix"},
            "remote": {"root": "C:\\remote\\project", "flavor": "windows"}})
        print(json.dumps(mapper.translate("/trusted/project/app/main.py", "host", "remote"),
                         sort_keys=True))
        return 0
    parser.error("only explicit trusted selftest supported via CLI; tests own TLS fixture")


if __name__ == "__main__":
    raise SystemExit(main())
