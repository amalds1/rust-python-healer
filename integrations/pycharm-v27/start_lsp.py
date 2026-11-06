"""Auditable stdio launcher for an LSP4IJ user-defined language-server template.

Only use with the trusted installed project, never copy a launcher into an
untrusted workspace or point the key path at workspace-controlled material.
"""

import os
import stat
import subprocess
import sys
from pathlib import Path


def checked_launch():
    """Return fixed argument list; never execute a shell or ingest source."""
    backend = (Path(__file__).resolve().parents[2] /
               "python" / "developer_protocols_v21.py").resolve(strict=True)
    if backend.name != "developer_protocols_v21.py" or backend.parent.name != "python":
        raise ValueError("untrusted_lsp_backend")
    key_name = os.environ.get("RPH_LSP_KEY_FILE", "")
    if not key_name or not os.path.isabs(key_name):
        raise ValueError("absolute_private_key_path_required")
    key = Path(key_name)
    info = key.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 16 <= info.st_size <= 128:
        raise ValueError("invalid_private_key")
    if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("review_key_must_be_private")
    if os.name == "nt":
        import importlib.util
        spec = importlib.util.spec_from_file_location("rph_pycharm_windows_privacy", backend.with_name("windows_private_paths.py"))
        privacy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(privacy)
        try:
            privacy.assert_private_file(key)
        except (OSError, ValueError) as problem:
            raise ValueError("review_key_must_be_private") from problem
    return [sys.executable, str(backend), "--mode", "lsp", "--key-file", str(key)]


def main():
    try:
        command = checked_launch()
    except (OSError, ValueError):
        print("Rust Python Healer: local LSP key/configuration rejected", file=sys.stderr)
        return 2
    if os.name != "nt":
        os.execv(command[0], command)
    # execv on Windows may use incompatible handle semantics; inherit stdio.
    return subprocess.call(command, shell=False)


if __name__ == "__main__":
    sys.exit(main())
