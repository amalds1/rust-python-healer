"""Real Redis 7.2.11 + Celery 5.5.3 cross-process local fixture (F257).

Only the immutable task below is allowed.  An operator-pinned build from the
official, SHA256-verified Redis tarball runs on loopback with a fresh password
and owner-private configuration.  No unknown project code, no public broker.
"""

import argparse
import hashlib
import gc
import json
import os
import platform
import re
from typing import NamedTuple
from contextlib import contextmanager
from pathlib import Path
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import time


REDIS_VERSION = "7.2.11"
REDIS_SOURCE_SHA256 = "2f9886eca68d30114ad6a01da65631f8007d802fd3e6c9fac711251e6390323d"
LOCAL_BUILT_REDIS_SHA256 = "213b4b0be30768e156092d6bd2bc1bd53133463d202b60b42ff955f4e5a38800"
CELERY_VERSION = "5.5.3"
REDIS_PY_VERSION = "6.4.0"
MAX_BINARY_BYTES = 32_000_000
FIXTURE_QUEUE = "rph_v23_trusted"
EVENT_KEY = "rph:v23:events"
FIXTURE_MAX_TASKS = 48
SRC = Path(__file__).resolve() if "__file__" in globals() else None
ROOT = SRC.parents[2] if SRC is not None else None
REDIS_BUILD = (ROOT / "redis-server-v23" / "redis-7.2.11" / "src" /
               "redis-server") if ROOT is not None else None
REDIS_TARBALL = (ROOT / "redis-server-v23" /
                 "redis-7.2.11.tar.gz") if ROOT is not None else None
TARGET = ROOT / ".ecosystem-v23" if ROOT is not None else None


class QueueEvidenceRejected(ValueError):
    """Return a bounded blocker; never forge cross-process PASS."""


LEGACY_BACKEND_PROFILE = "legacy-linux-v23"
WSL_R6_BACKEND_PROFILE = "wsl-r6-kali"
# Separate reviewed local build: never replace LOCAL_BUILT_REDIS_SHA256.
WSL_R6_BUILT_REDIS_SHA256 = "f1f7f48496a324e20ff4bb4e1d3b00bed78e8b24ed5fbca6fe77d5f94b990723"
WSL_R6_HOST_UID = 1000
WSL_R6_HOST_KERNEL = '6.18.54.1-microsoft-standard-WSL2+'
WSL_R6_OS_RELEASE_SHA256 = 'df9a3ff26c7e1310f1d0b3127710e6654e1f869c6b791058e39a0688dc586f96'
WSL_R6_COMPILER_SHA256 = "f835734c0e7a17d87dec3ee306730195e3775c28a5f8da75c82ea72a780456d3"
WSL_R6_BUILD_RECEIPT_SHA256 = "ed10188fabb482f4f8d524e0f16b7ced2bb8671457df54092cb2b176f9c9b497"
WSL_R6_PROFILE_ID = "wsl-r6-kali-redis-7.2.11-gcc16-libc-O2"
WSL_R6_CLIENTS_PEER_REVIEW_SHA256 = "8fac302e49d5b99b6ff755e8aab572adcece8194f9dc4923dbf2435d3971f796"
WSL_R6_CLIENTS_MANIFEST_SHA256 = "92eb6abbe7df019be0ee7cc542fb072a5c7f5dd33e57a44c75ec287a5544f423"
WSL_R6_PEER_REVIEW_SHA256 = "0cd205bf113fe4c831d2ed08a4026946b33122c09ed4f97a892a0f7cf630f3ae"
_DEFAULT = object()


class RedisBackendProfile(NamedTuple):
    identifier: str
    binary: object
    tarball: object
    binary_sha256: str
    clients: object
    python_minors: tuple
    wsl_only: bool


def backend_profile(name=LEGACY_BACKEND_PROFILE):
    if name == LEGACY_BACKEND_PROFILE:
        return RedisBackendProfile(name,REDIS_BUILD,REDIS_TARBALL,LOCAL_BUILT_REDIS_SHA256,
                                   TARGET,("3.9","3.10","3.11","3.12","3.13","3.14","3.15"),False)
    if name == WSL_R6_BACKEND_PROFILE:
        base = ROOT / "redis-server-r6" if ROOT is not None else None
        return RedisBackendProfile(name,base / "redis-7.2.11/src/redis-server" if base else None,
                                   base / "redis-7.2.11.tar.gz" if base else None,
                                   WSL_R6_BUILT_REDIS_SHA256,base / "clients" if base else None,("3.12",),True)
    raise QueueEvidenceRejected("BACKEND_PROFILE_NOT_ALLOWLISTED")


def _windows_privacy():
    module = globals().get("_RPH_WINDOWS_PRIVACY")
    if module is None:
        import importlib.util
        spec = importlib.util.spec_from_file_location("rph_queue_privacy",Path(__file__).resolve().with_name("windows_private_paths.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        globals()["_RPH_WINDOWS_PRIVACY"] = module
    return module


def _windows_sha(path,limit,allow_empty=False):
    import ctypes
    from ctypes import wintypes
    privacy = _windows_privacy()
    kernel,_ = privacy._libraries()
    handle = kernel.CreateFileW(privacy._local_absolute_path(os.path.abspath(path)),0x80000000,1,None,3,0x00200000|0x02000000,None)
    if not handle or handle == ctypes.c_void_p(-1).value:
        raise QueueEvidenceRejected("UNSAFE_REGULAR_FILE_REQUIRED")
    try:
        def identity():
            info = privacy._FileInformation()
            if not kernel.GetFileInformationByHandle(handle,ctypes.byref(info)) or kernel.GetFileType(handle)!=1:
                raise QueueEvidenceRejected("UNSAFE_REGULAR_FILE_REQUIRED")
            size = (info.size_high<<32)|info.size_low
            if info.attributes & (0x400|0x10) or info.links != 1 or not (0 if allow_empty else 1)<=size<=limit:
                raise QueueEvidenceRejected("UNSAFE_REGULAR_FILE_REQUIRED")
            return (info.volume,info.index_high,info.index_low,size,info.write.dwHighDateTime,info.write.dwLowDateTime)
        before=identity();digest=hashlib.sha256();total=0
        kernel.ReadFile.argtypes=[wintypes.HANDLE,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD),ctypes.c_void_p]
        kernel.ReadFile.restype=wintypes.BOOL
        while total<=limit:
            buffer=ctypes.create_string_buffer(131072);read=wintypes.DWORD()
            if not kernel.ReadFile(handle,buffer,len(buffer),ctypes.byref(read),None):
                raise QueueEvidenceRejected("SOURCE_READ_FAILED")
            if not read.value:break
            total+=read.value;digest.update(buffer.raw[:read.value])
        if identity()!=before or total!=before[3] or total>limit:
            raise QueueEvidenceRejected("SOURCE_CHANGED_DURING_READ")
        return digest.hexdigest()
    finally:
        kernel.CloseHandle(handle)


def _sha(path, limit, *, allow_empty=False):
    if type(limit) is not int or not 1 <= limit <= MAX_BINARY_BYTES:
        raise QueueEvidenceRejected("INVALID_HASH_READ_BUDGET")
    if os.name == "nt":
        return _windows_sha(path,limit,allow_empty)
    info = Path(path).lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit or info.st_size < (0 if allow_empty else 1):
        raise QueueEvidenceRejected("UNSAFE_REGULAR_FILE_REQUIRED")
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_ino, opened.st_dev, opened.st_size) != (
                info.st_ino, info.st_dev, info.st_size):
            raise QueueEvidenceRejected("SOURCE_CHANGED_BEFORE_READ")
        for block in iter(lambda: stream.read(131_072), b""):
            digest.update(block)
        final = os.fstat(stream.fileno())
        if (final.st_mtime_ns, final.st_size, final.st_ino) != (
                info.st_mtime_ns, info.st_size, info.st_ino):
            raise QueueEvidenceRejected("SOURCE_CHANGED_DURING_READ")
    return digest.hexdigest()


def wsl_r6_host_scope_qualified(observed):
    return (type(observed.get('uid')) is int and observed=={
        'system':'Linux','release':WSL_R6_HOST_KERNEL,'machine':'x86_64',
        'uid':WSL_R6_HOST_UID,'os_release_sha256':WSL_R6_OS_RELEASE_SHA256})


def verified_redis_binary(binary=_DEFAULT, source_tarball=_DEFAULT, *, profile=LEGACY_BACKEND_PROFILE):
    """Authenticate the exact selected source/local build, with explicit host scope."""
    selected=backend_profile(profile)
    binary=selected.binary if binary is _DEFAULT else binary
    source_tarball=selected.tarball if source_tarball is _DEFAULT else source_tarball
    base={"backend_profile":profile,"native_windows_execution_proven":False,
          "redis_server_available":False,"crossprocess_tested":False,
          "production_binary_publisher_attested":False}
    if binary is None or source_tarball is None:
        return {**base,"status":"NOT_RUN_EMBEDDED_CAPABILITY_ONLY"}
    if not Path(binary).is_file() or not Path(source_tarball).is_file():
        return {**base,"status":"NOT_RUN_NATIVE_WINDOWS_REDIS_UNSUPPORTED" if os.name=="nt" else "NOT_RUN_NO_LOCAL_REDIS_SERVER"}
    if (_sha(source_tarball,5_000_000)!=REDIS_SOURCE_SHA256 or _sha(binary,MAX_BINARY_BYTES)!=selected.binary_sha256):
        raise QueueEvidenceRejected("REDIS_SOURCE_OR_BINARY_SHA_MISMATCH")
    base.update(source_sha256=REDIS_SOURCE_SHA256,local_binary_sha256=selected.binary_sha256,redis_version=REDIS_VERSION)
    if os.name=="nt":
        return {**base,"status":"NOT_RUN_NATIVE_WINDOWS_REDIS_UNSUPPORTED","artifact_identity_verified":True}
    if selected.wsl_only:
        os_release=Path('/etc/os-release').read_text(encoding='utf-8')
        observed={'system':platform.system(),'release':platform.release(),'machine':platform.machine(),
                  'uid':os.getuid(),'os_release_sha256':hashlib.sha256(os_release.encode('utf-8')).hexdigest()}
        if not wsl_r6_host_scope_qualified(observed):
            return {**base,"status":"NOT_RUN_WSL_R6_PROFILE_HOST_MISMATCH"}
        if _sha(Path('/usr/bin/cc').resolve(strict=True),MAX_BINARY_BYTES)!=WSL_R6_COMPILER_SHA256:
            raise QueueEvidenceRejected("WSL_R6_REVIEWED_COMPILER_IDENTITY_MISMATCH")
        base.update(profile_registration_id=WSL_R6_PROFILE_ID,build_receipt_sha256=WSL_R6_BUILD_RECEIPT_SHA256,peer_review_sha256=WSL_R6_PEER_REVIEW_SHA256,
                    backend_host_system=platform.system(),backend_host_release=platform.release(),
                    backend_host_machine=platform.machine(),backend_host_distribution='kali',
                    backend_host_uid=os.getuid(),backend_os_release_sha256=observed['os_release_sha256'],
                    native_windows_execution_proven=False,local_fixed_fixture_profile_reviewed=True)
    result=subprocess.run([str(binary),'--version'],check=False,capture_output=True,timeout=4)
    if result.returncode!=0 or b'Redis server v=7.2.11' not in result.stdout:
        raise QueueEvidenceRejected('REDIS_REAL_BINARY_VERSION_UNVERIFIED')
    return {**base,"status":"OFFICIAL_SOURCE_SHA_AND_LOCAL_BUILD_VERIFIED","redis_server_available":True}


def _clients_manifest():
    if ROOT is None:
        raise QueueEvidenceRejected("REQUIRES_STANDALONE_TRUSTED_SOURCE")
    path=ROOT/'redis-server-r6/clients-manifest.json'
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>1_000_000:
            raise QueueEvidenceRejected("WSL_R6_CLIENT_MANIFEST_UNSAFE")
        raw=stream.read(1_000_001)
        after=os.fstat(stream.fileno())
    if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns) or hashlib.sha256(raw).hexdigest()!=WSL_R6_CLIENTS_MANIFEST_SHA256:
        raise QueueEvidenceRejected("WSL_R6_CLIENT_MANIFEST_PIN_MISMATCH")
    data=json.loads(raw)
    if data.get('schema_version')!=1 or not isinstance(data.get('all_installed_file_sha256'),dict):
        raise QueueEvidenceRejected('WSL_R6_CLIENT_MANIFEST_INVALID')
    return data['all_installed_file_sha256']


def _private_linux_site(site):
    info=site.lstat()
    if os.name!='posix' or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)&0o077:
        raise QueueEvidenceRejected('WSL_R6_CLIENT_SNAPSHOT_NOT_OWNER_PRIVATE')
    expected=_clients_manifest();actual=set()
    for path in site.rglob('*'):
        details=path.lstat()
        if stat.S_ISLNK(details.st_mode):
            raise QueueEvidenceRejected('WSL_R6_CLIENT_SNAPSHOT_ALIAS_REFUSED')
        if stat.S_ISREG(details.st_mode):
            relative=path.relative_to(site).as_posix();actual.add(relative)
            if relative not in expected or _sha(path,MAX_BINARY_BYTES,allow_empty=True)!=expected[relative]:
                raise QueueEvidenceRejected('WSL_R6_CLIENT_MODULE_HASH_MISMATCH')
        elif not stat.S_ISDIR(details.st_mode):
            raise QueueEvidenceRejected('WSL_R6_CLIENT_SNAPSHOT_SPECIAL_FILE')
    if actual!=set(expected):
        raise QueueEvidenceRejected('WSL_R6_CLIENT_SNAPSHOT_INCOMPLETE')
    return site


@contextmanager
def _prepared_clients(minor,profile):
    source=_site_for_minor(minor,profile)
    if profile!=WSL_R6_BACKEND_PROFILE:
        yield source
        return
    if os.name!='posix' or platform.system()!='Linux':
        raise QueueEvidenceRejected('WSL_R6_CLIENT_EXECUTION_REQUIRES_LINUX')
    # Imported bytes live in a real Linux owner-private snapshot. /mnt/c DACLs
    # are separately proved; they are not claimed as Linux POSIX privacy.
    with tempfile.TemporaryDirectory(prefix='rph-v23-client-snapshot-',dir='/tmp') as folder:
        target=Path(folder);os.chmod(target,0o700)
        expected=_clients_manifest()
        for relative,digest in expected.items():
            parts=Path(relative).parts
            if not parts or Path(relative).is_absolute() or any(p in ('..','.') for p in parts):
                raise QueueEvidenceRejected('WSL_R6_CLIENT_MEMBER_UNSAFE')
            original=source/relative
            info=original.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or not 0<=info.st_size<=MAX_BINARY_BYTES:
                raise QueueEvidenceRejected('WSL_R6_CLIENT_MEMBER_NOT_BOUNDED')
            fd=os.open(original,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
            with os.fdopen(fd,'rb') as stream:raw=stream.read(MAX_BINARY_BYTES+1)
            if hashlib.sha256(raw).hexdigest()!=digest or len(raw)>MAX_BINARY_BYTES:
                raise QueueEvidenceRejected('WSL_R6_CLIENT_MODULE_HASH_MISMATCH')
            destination=target/relative
            destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with destination.open('xb') as out:out.write(raw)
            destination.chmod(0o600)
        yield _private_linux_site(target)


def _site_for_minor(minor, profile=LEGACY_BACKEND_PROFILE):
    selected=backend_profile(profile)
    if selected.clients is None:
        raise QueueEvidenceRejected("REQUIRES_STANDALONE_TRUSTED_SOURCE")
    if minor not in ("3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15"):
        raise QueueEvidenceRejected("PYTHON_MINOR_NOT_SUPPORTED")
    if minor not in selected.python_minors:
        raise QueueEvidenceRejected("BACKEND_PYTHON_MINOR_NOT_QUALIFIED")
    if selected.wsl_only and (sys.implementation.name!='cpython' or sys.version_info[:2]!=(3,12)):
        raise QueueEvidenceRejected("WSL_R6_ACTUAL_PYTHON_MINOR_NOT_QUALIFIED")
    supplied=os.environ.get("RPH_TRUSTED_CLIENT_SITE") if selected.wsl_only else None
    site=Path(supplied) if supplied else (selected.clients if selected.wsl_only else selected.clients/minor)
    if supplied:
        _private_linux_site(site)
    if not site.is_dir() or site.is_symlink():
        raise QueueEvidenceRejected("OFFLINE_CELERY_SITE_MISSING")
    return site


CLIENT_PROBE = (
    "import json,sys\n"
    "sys.path.insert(0,sys.argv[1])\n"
    "import celery,redis\n"
    "print(json.dumps({'celery':celery.__version__,'redis':redis.__version__,'python_minor':str(sys.version_info[0])+'.'+str(sys.version_info[1]),'python_version':sys.version,'implementation':sys.implementation.name}))\n"
)


def verify_private_clients(minor, python=sys.executable, *, profile=LEGACY_BACKEND_PROFILE):
    with _prepared_clients(minor,profile) as site:
        return _probe_private_clients(minor,python,site,profile)


def _probe_private_clients(minor,python,site,profile):
    result = subprocess.run([python, "-I", "-S", "-B", "-c", CLIENT_PROBE,
                             str(site)], check=False, capture_output=True,
                            timeout=6)
    try:
        report = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise QueueEvidenceRejected("CLIENT_VERSION_PROBE_FAILED") from None
    if report.get("python_minor")!=minor:
        raise QueueEvidenceRejected("ACTUAL_CLIENT_PROBE_PYTHON_MINOR_MISMATCH")
    if (result.returncode != 0 or report.get("celery") != CELERY_VERSION or
            report.get("redis") != REDIS_PY_VERSION):
        raise QueueEvidenceRejected("CLIENT_PINS_NOT_MET")
    return {"status": "ACTUAL_OFFLINE_CELERY_REDIS_IMPORTS_VERIFIED",
            "python_minor": report["python_minor"],"python_runtime_version":report["python_version"],
            "python_implementation":report["implementation"], "celery": CELERY_VERSION,
            "redis_client": REDIS_PY_VERSION,
            "actual_redis_server_tested": False,"backend_profile":profile,
            "private_linux_snapshot_used":profile==WSL_R6_BACKEND_PROFILE,
            "client_manifest_sha256":WSL_R6_CLIENTS_MANIFEST_SHA256 if profile==WSL_R6_BACKEND_PROFILE else None,
            "client_peer_review_sha256":WSL_R6_CLIENTS_PEER_REVIEW_SHA256 if profile==WSL_R6_BACKEND_PROFILE else None}


def fixed_worker_main(minor, profile=LEGACY_BACKEND_PROFILE):
    """Run only the reviewed static Celery worker function in this file."""
    broker = os.environ.get("RPH_TRUSTED_REDIS_URL", "")
    hostname = os.environ.get("RPH_TRUSTED_WORKER_NAME", "")
    if not re.fullmatch(r"redis://:[0-9a-f]{64}@127[.]0[.]0[.]1:[0-9]{1,5}/0",broker):
        raise QueueEvidenceRejected("WORKER_BROKER_NOT_LOOPBACK")
    if hostname not in ("rph_v23_a@localhost", "rph_v23_b@localhost"):
        raise QueueEvidenceRejected("WORKER_ID_NOT_ALLOWLISTED")
    site = _site_for_minor(minor,profile)
    sys.path.insert(0,str(site))
    from celery import Celery
    import redis

    app = Celery("rph_v23_fixed", broker=broker, backend=broker)
    app.conf.update(task_default_queue=FIXTURE_QUEUE, task_serializer="json",
                    accept_content=["json"], result_serializer="json",
                    task_track_started=True, worker_prefetch_multiplier=1,
                    broker_connection_retry_on_startup=True)

    @app.task(bind=True, name="rph_v23_fixed_task")
    def fixed_task(self, value):
        if type(value) is not int or not 0 <= value <= 100:
            raise ValueError("FIXTURE_VALUE_INVALID")
        # Deterministic actual DB-backed, cross-process correlation.
        client = redis.Redis.from_url(broker, decode_responses=True)
        event = "EXPECTED_FAILURE" if value == 13 else "COMPLETED"
        client.xadd(EVENT_KEY, {"task_id": self.request.id,
                                "worker_pid": os.getpid(), "event": event}, maxlen=1000)
        time.sleep(0.025)
        if value == 13:
            raise ValueError("EXPECTED_TRUSTED_CELERY_FIXTURE_FAILURE")
        return {"value": value * 2, "worker_pid": os.getpid(),
                "task_id": self.request.id}

    app.worker_main(["worker", "--loglevel=ERROR", "--pool=solo", "--concurrency=1",
                     "--without-gossip", "--without-mingle", "--without-heartbeat",
                     "--hostname=" + hostname, "--queues=" + FIXTURE_QUEUE])


def _private_redis_config(folder, port, password):
    directory = Path(folder)
    mode = directory.lstat().st_mode
    if not stat.S_ISDIR(mode) or (os.name!="nt" and stat.S_IMODE(mode) & 0o077):
        raise QueueEvidenceRejected("REDIS_CONFIG_DIRECTORY_NOT_OWNER_PRIVATE")
    if os.name=="nt":
        try:_windows_privacy().assert_private_directory(directory)
        except (OSError,ValueError) as problem:
            raise QueueEvidenceRejected("REDIS_CONFIG_DIRECTORY_NOT_OWNER_PRIVATE") from problem
    if not (type(port) is int and 1 <= port <= 65535 and type(password) is str and re.fullmatch(r"[A-Za-z0-9_-]{40,128}",password)):
        raise QueueEvidenceRejected("REDIS_PRIVATE_CONFIG_INVALID")
    config = directory / "redis.conf"
    contents = ("bind 127.0.0.1\nprotected-mode yes\nport {}\n"
                "daemonize no\nsave \"\"\nappendonly no\n"
                "loglevel warning\nlogfile \"\"\n"
                "dir {}\nrequirepass {}\n").format(port, json.dumps(str(directory)), password)
    with config.open("x", encoding="ascii") as out:
        out.write(contents)
    config.chmod(0o600)
    if os.name=="nt":
        _windows_privacy().assert_private_file(config)
    return config


def _unused_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _process_identity(child):
    folder=Path('/proc')/str(child.pid)
    raw=(folder/'stat').read_text()
    start=raw[raw.rfind(')')+2:].split()[19]
    command=(folder/'cmdline').read_bytes().split(b'\0')
    return {'pid':child.pid,'start_ticks':start,'executable':os.readlink(folder/'exe'),
            'command_line':[p.decode('utf-8','replace') for p in command if p]}


def _owned_spawn(command,**options):
    # Kernel-enforced parent-death cleanup also covers an outer timeout that
    # kills this controller before Python can enter its normal finally block.
    import ctypes
    import signal
    if platform.system()!='Linux':
        raise QueueEvidenceRejected('OWNED_LINUX_PROCESS_REQUIRED')
    libc=ctypes.CDLL(None,use_errno=True)
    libc.prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong]
    libc.prctl.restype=ctypes.c_int
    require_pidfd=options.pop("require_pidfd",True)
    parent=os.getpid()
    def child_parent_death_guard():
        if libc.prctl(1,signal.SIGKILL,0,0,0)!=0 or os.getppid()!=parent:
            os._exit(125)
    options['preexec_fn']=child_parent_death_guard
    options['start_new_session']=True
    child=subprocess.Popen(command,**options)
    child._rph_pidfd=None
    try:
        try:child._rph_pidfd=os.pidfd_open(child.pid)
        except (AttributeError,OSError):
            if require_pidfd:raise
        child._rph_identity=_process_identity(child)
    except BaseException:
        # Popen still owns the unreaped child, so its PID cannot be reused.
        if child.poll() is None:
            if child._rph_pidfd is not None:
                signal.pidfd_send_signal(child._rph_pidfd,signal.SIGKILL)
            else:child.terminate()
        child.wait(timeout=5)
        if child._rph_pidfd is not None:os.close(child._rph_pidfd)
        raise
    return child


def _stop(child):
    if child is None:return None
    before=child._rph_identity
    proof={'before':before,'signalled':False,'kernel_pidfd_used':child._rph_pidfd is not None}
    if child.poll() is None:
        current=_process_identity(child)
        if (current['pid'],current['start_ticks'],current['executable'])!=(before['pid'],before['start_ticks'],before['executable']):
            raise QueueEvidenceRejected('OWNED_PROCESS_IDENTITY_CHANGED_NO_SIGNAL_SENT')
        args=current['command_line']
        expected=Path(before['executable']).name
        if not args or not (Path(args[0]).name==expected or (expected=='redis-server' and 'redis-server' in args[0])):
            raise QueueEvidenceRejected('OWNED_PROCESS_COMMAND_CHANGED_NO_SIGNAL_SENT')
        proof['before_signal']=current
        import signal
        if child._rph_pidfd is not None:signal.pidfd_send_signal(child._rph_pidfd,signal.SIGTERM)
        else:child.terminate()
        proof['signalled']=True
        try:child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            current=_process_identity(child)
            if (current['start_ticks'],current['executable'])!=(before['start_ticks'],before['executable']):
                raise QueueEvidenceRejected('OWNED_PROCESS_IDENTITY_CHANGED_NO_KILL_SENT')
            if child._rph_pidfd is not None:signal.pidfd_send_signal(child._rph_pidfd,signal.SIGKILL)
            else:child.kill()
            child.wait(timeout=5);proof['kill_after_timeout']=True
    proof.update(exit_code=child.returncode,reaped=child.poll() is not None)
    if child._rph_pidfd is not None:
        os.close(child._rph_pidfd);child._rph_pidfd=None
    return proof


def actual_redis_celery_correlation(minor, python=sys.executable,
                                    binary=_DEFAULT, tarball=_DEFAULT, *, profile=LEGACY_BACKEND_PROFILE):
    """Only a real broker and two separate Celery workers can produce PASS."""
    proof = verified_redis_binary(binary,tarball,profile=profile)
    if not proof["redis_server_available"]:
        return proof
    selected=backend_profile(profile)
    binary=selected.binary if binary is _DEFAULT else binary
    with _prepared_clients(minor,profile) as site:
        _probe_private_clients(minor,python,site,profile)
        sys.path.insert(0, str(site))
        from celery import Celery  # pylint: disable=import-outside-toplevel
        import redis  # pylint: disable=import-outside-toplevel

        with tempfile.TemporaryDirectory(prefix="rph-v23-real-redis-",dir="/tmp" if profile==WSL_R6_BACKEND_PROFILE else None) as folder:
            os.chmod(folder, 0o700)
            port = _unused_loopback_port()
            password = secrets.token_hex(32)
            config = _private_redis_config(folder, port, password)
            url = "redis://:{}@127.0.0.1:{}/0".format(password, port)
            env = os.environ.copy()
            env["RPH_TRUSTED_REDIS_URL"] = url
            if profile==WSL_R6_BACKEND_PROFILE:
                env["RPH_TRUSTED_CLIENT_SITE"]=str(site)
            child = None
            workers = []
            tasks = []
            app = None
            client = None
            report=None
            started = time.monotonic()
            try:
                child = _owned_spawn([str(binary), str(config)],require_pidfd=selected.wsl_only,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         cwd=folder, env=env)
                client = redis.Redis.from_url(url, decode_responses=True,
                                              socket_connect_timeout=1, socket_timeout=1)
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    if child.poll() is not None:
                        raise QueueEvidenceRejected("REDIS_SERVER_EXITED_EARLY")
                    try:
                        if client.ping():
                            break
                    except redis.exceptions.RedisError:
                        time.sleep(0.08)
                else:
                    raise QueueEvidenceRejected("REDIS_LOOPBACK_NOT_READY")
                for label in ("a", "b"):
                    name = "rph_v23_{}@localhost".format(label)
                    worker_env = dict(env)
                    worker_env["RPH_TRUSTED_WORKER_NAME"] = name
                    worker_env["RPH_TRUSTED_REDIS_URL"] = url
                    workers.append(_owned_spawn(
                        [python, "-I", "-S", "-B", str(SRC), "--mode", "worker",
                         "--minor", minor, "--backend-profile", profile], require_pidfd=selected.wsl_only,cwd=folder, env=worker_env,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
                app = Celery("rph_v23_producer", broker=url, backend=url)
                app.conf.update(task_default_queue=FIXTURE_QUEUE,
                                task_serializer="json", result_serializer="json",
                                accept_content=["json"], broker_connection_retry_on_startup=True)
                deadline = time.monotonic() + 16
                while time.monotonic() < deadline:
                    if any(worker.poll() is not None for worker in workers):
                        raise QueueEvidenceRejected("CELERY_WORKER_EXITED_EARLY")
                    answered = app.control.ping(timeout=1, destination=[
                        "rph_v23_a@localhost", "rph_v23_b@localhost"])
                    if len(answered) >= 2:
                        break
                    time.sleep(0.15)
                else:
                    raise QueueEvidenceRejected("CELERY_TWO_WORKERS_NOT_READY")
                for value in list(range(1, 13)) + [13] + list(range(14, 26)):
                    task = app.send_task("rph_v23_fixed_task", args=[value],
                                         queue=FIXTURE_QUEUE)
                    tasks.append((value, task))
                completed = 0
                expected_failures = 0
                workers_observed = set()
                submitted = {task.id for _, task in tasks}
                task_evidence=[]
                for value, task in tasks:
                    result = task.get(timeout=15, propagate=False)
                    if value == 13:
                        if type(result).__name__ != "ValueError":
                            raise QueueEvidenceRejected("TRUSTED_TASK_ERROR_NOT_CORRELATED")
                        expected_failures += 1
                        task_evidence.append({"task_id":task.id,"input_value":value,"actual_error_type":type(result).__name__})
                    else:
                        if (type(result) is not dict or result.get("value") != value * 2
                                or result.get("task_id") != task.id):
                            raise QueueEvidenceRejected("TRUSTED_TASK_RESULT_MISMATCH")
                        workers_observed.add(result["worker_pid"])
                        completed += 1
                        task_evidence.append({"task_id":task.id,"input_value":value,"actual_return_value":result["value"],"actual_worker_pid":result["worker_pid"]})
                events = client.xrange(EVENT_KEY)
                matched = [event for _, event in events if event.get("task_id") in submitted]
                if (completed != 24 or expected_failures != 1 or len(matched) != 25
                        or workers_observed != {worker.pid for worker in workers}
                        or {event["task_id"] for event in matched} != submitted):
                    raise QueueEvidenceRejected("CROSS_PROCESS_CELERY_REDIS_EVIDENCE_INCOMPLETE")
                expected_events={task.id:("EXPECTED_FAILURE" if value==13 else "COMPLETED") for value,task in tasks}
                if any(event.get("event")!=expected_events[event["task_id"]] or int(event.get("worker_pid",-1)) not in {worker.pid for worker in workers} for event in matched):
                    raise QueueEvidenceRejected("STREAM_EVENT_PID_OR_TASK_BINDING_INVALID")
                if child.pid in workers_observed or any(worker.pid == child.pid for worker in workers):
                    raise QueueEvidenceRejected("WORKER_BROKER_PROCESS_NOT_DISTINCT")
                report = {"status": "REAL_REDIS_CELERY_CROSSPROCESS_ERROR_CORRELATION_PASS",
                        "python_minor": minor,"python_runtime_version":sys.version, "redis_version": REDIS_VERSION,
                        "backend_profile":profile,"backend_identity":proof,
                        "celery_version": CELERY_VERSION,
                        "redis_client_version": REDIS_PY_VERSION,
                        "broker_bind": "127.0.0.1", "ephemeral_port": True,
                        "private_config": True, "password_disclosed": False,
                        "real_broker_processes": 1, "real_worker_processes": len(workers),
                        "distinct_workers_observed": len(workers_observed),
                        "tasks_successful": completed,
                        "tasks_failed_expected": expected_failures,
                        "redis_stream_events_correlated": len(matched),
                        "correlated_events":matched,"task_evidence":task_evidence,
                        "owned_worker_pids":sorted(worker.pid for worker in workers),
                        "owned_broker_pid":child.pid,"kernel_parent_death_signal":"SIGKILL",
                        "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
                        "unknown_project_code_executed": False,
                        "external_redis_network_used": False,
                        "windows_macos_real_worker_proven": False,
                        "loopback_port":port,"client_manifest_sha256":WSL_R6_CLIENTS_MANIFEST_SHA256 if profile==WSL_R6_BACKEND_PROFILE else None,
                        "private_linux_client_snapshot":profile==WSL_R6_BACKEND_PROFILE}
                return report
            finally:
                # Celery AsyncResult.__del__ may contact its Redis backend. Ensure
                # every result is forgotten and GC'd WHILE Redis still responds.
                for _value, waiting in tasks:
                    try:
                        waiting.forget()
                    except Exception:
                        pass
                tasks.clear()
                waiting = None
                task = None
                result = None
                gc.collect()
                if app is not None:
                    app.close()
                if client is not None:
                    client.close()
                cleanup=[];cleanup_errors=[]
                for owned in workers+[child]:
                    try:cleanup.append(_stop(owned))
                    except Exception as problem:cleanup_errors.append(type(problem).__name__)
                if cleanup_errors:
                    raise QueueEvidenceRejected('OWNED_PROCESS_CLEANUP_FAILED')
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:
                    probe.settimeout(.5)
                    port_closed=probe.connect_ex(('127.0.0.1',port))!=0
                if not port_closed:
                    raise QueueEvidenceRejected('OWNED_LOOPBACK_PORT_REMAINED_OPEN')
                if report is not None:
                    report['cleanup']={'owned_processes':cleanup,'loopback_port_closed':port_closed}



def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("capabilities", "availability", "clients",
                                           "run", "worker"),
                        default="availability")
    parser.add_argument("--minor", default="3.12")
    parser.add_argument("--backend-profile",choices=(LEGACY_BACKEND_PROFILE,WSL_R6_BACKEND_PROFILE),default=LEGACY_BACKEND_PROFILE)
    args = parser.parse_args(argv)
    try:
        if args.mode == "capabilities":
            print(json.dumps({
                "status": "REAL_REDIS_CELERY_PRIVATE_ADAPTER_AVAILABLE",
                "redis_version_pinned": REDIS_VERSION,
                "redis_source_sha256": REDIS_SOURCE_SHA256,
                "celery_version_pinned": CELERY_VERSION,
                "redis_client_version_pinned": REDIS_PY_VERSION,
                "redis_server_executed": False,
                "crossprocess_tested": False,
                "unknown_project_source_executed": False,
                "standalone_binary_provenance_required_for_run": True,
                "backend_profiles":[LEGACY_BACKEND_PROFILE,WSL_R6_BACKEND_PROFILE],
                "native_windows_execution_supported":False,
            }, sort_keys=True))
            return 0
        if SRC is None:
            raise QueueEvidenceRejected("REQUIRES_STANDALONE_TRUSTED_SOURCE")
        if args.mode == "worker":
            fixed_worker_main(args.minor,args.backend_profile)
            return 0
        if args.mode == "clients":
            response = verify_private_clients(args.minor,profile=args.backend_profile)
        elif args.mode == "run":
            response = actual_redis_celery_correlation(args.minor,profile=args.backend_profile)
        else:
            response = verified_redis_binary(profile=args.backend_profile)
    except QueueEvidenceRejected as problem:
        print(json.dumps({"status": "NOT_VERIFIED", "reason": str(problem),
                          "unknown_project_code_executed": False}, sort_keys=True))
        return 2
    print(json.dumps(response, sort_keys=True))
    return 2 if args.mode in ("run","clients") and response["status"].startswith("NOT_RUN") else 0


if __name__ == "__main__":
    raise SystemExit(main())
