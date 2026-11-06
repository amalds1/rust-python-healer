"""Measured FTS5 on pinned million-part data, no source execution or source auth.

Only the producer/independent review can establish that the pinned input
represents real source pages. This read-only adapter measures that exact data;
it does not authenticate arbitrary manifest declarations or prove relevance.
"""
from contextlib import contextmanager
from functools import lru_cache
import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import time

MIN_PARTS = 1_000_000
MAX_PARTS = 1_500_000
MAX_DB_BYTES = 4 * 1024 ** 3
MAX_MANIFEST_BYTES = 65536
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
QUERIES = ("education", "science", "history", "research", "information",
           "python", "database", "computer", "engineering", "mathematics",
           "biology", "language", "machine learning", "climate change",
           "public health", "photosynthesis", "neutrino", "compiler",
           "learning", "library")
QUERY_SQL = """WITH ranked AS MATERIALIZED (
    SELECT rowid,bm25(chunks_fts) AS score FROM chunks_fts
    WHERE chunks_fts MATCH ? ORDER BY score,rowid LIMIT 10)
    SELECT c.rowid,c.content,c.content_sha256,
    c.char_start,c.char_end,d.source_uri,d.document_id
    FROM ranked JOIN chunks c ON c.rowid=ranked.rowid
    JOIN documents d ON d.rowid=c.document_rowid
    ORDER BY ranked.score,ranked.rowid"""


@lru_cache(maxsize=2)
def _dependency(name):
    injected, filename = {
        "privacy": ("_RPH_WINDOWS_PRIVACY", "windows_private_paths.py"),
        "memory": ("_RPH_PROCESS_MEMORY", "process_memory.py"),
    }[name]
    module = globals().get(injected)
    if module is not None:
        return module
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location("rph_corpus_" + name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def windows_process_observation():
    """Actual current-process HANDLE APIs; unavailable is an error, never zero."""
    if os.name != "nt":
        raise RuntimeError("actual_windows_process_metrics_required")
    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
            (name, ctypes.c_size_t) for name in ("peak", "current", "qpp", "qpc",
                "qnpp", "qnpc", "pagefile", "peakpagefile")]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.GetProcessHandleCount.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetProcessHandleCount.restype = wintypes.BOOL
    kernel.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    kernel.K32GetProcessMemoryInfo.restype = wintypes.BOOL
    handle = kernel.GetCurrentProcess()  # Borrowed pseudo-HANDLE, never close it.
    creation, exit_time, system, user = (wintypes.FILETIME() for _ in range(4))
    count = wintypes.DWORD()
    counters = Counters(); counters.cb = ctypes.sizeof(counters)
    if not (kernel.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_time),
            ctypes.byref(system), ctypes.byref(user)) and
            kernel.GetProcessHandleCount(handle, ctypes.byref(count)) and
            kernel.K32GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb)):
        raise ctypes.WinError(ctypes.get_last_error())
    if counters.peak <= 0 or counters.current <= 0 or count.value <= 0:
        raise RuntimeError("windows_process_metrics_unavailable")
    ticks = lambda value: (value.dwHighDateTime << 32) | value.dwLowDateTime
    return {"pid": os.getpid(), "process_creation_filetime": ticks(creation),
            "user_cpu_100ns": ticks(user), "kernel_cpu_100ns": ticks(system),
            "working_set_bytes": counters.current, "peak_working_set_bytes": counters.peak,
            "handle_count": count.value,
            "peak_rss_kib": _dependency("memory").peak_rss_kib(),
            "rss_basis": _dependency("memory").rss_basis()}


def percentile(values, percent):
    if not values:
        raise ValueError("missing_actual_latency_samples")
    return sorted(values)[math.ceil(percent * len(values) / 100) - 1]


def _normalized_final_path(value):
    if value.startswith("\\\\?\\"):
        value = value[4:]
    return os.path.normcase(os.path.normpath(value))


@contextmanager
def _directory_chain_lease(path):
    """Pin every traversed directory name; deny DELETE through SQLite reopen."""
    privacy = _dependency("privacy")
    kernel, security = privacy._libraries()
    kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR,
                                               wintypes.DWORD, wintypes.DWORD]
    kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    directories = list(reversed(path.parent.parents)) + [path.parent]
    held = []
    def inspect(handle, directory):
        info = privacy._FileInformation()
        if (not kernel.GetFileInformationByHandle(handle, ctypes.byref(info))
                or not info.attributes & 0x10 or info.attributes & 0x400):
            raise ValueError("corpus_ancestor_reparse_or_type_refused")
        final = ctypes.create_unicode_buffer(32768)
        length = kernel.GetFinalPathNameByHandleW(handle, final, len(final), 0)
        if not 0 < length < len(final) or _normalized_final_path(final.value) != _normalized_final_path(str(directory)):
            raise ValueError("corpus_ancestor_path_alias_refused")
        return info.volume, info.index_high, info.index_low
    try:
        for directory in directories:
            # GENERIC_READ|SYNCHRONIZE requests FILE_LIST_DIRECTORY, so Windows
            # enforces no-DELETE sharing; metadata-only opens do not suffice.
            handle = kernel.CreateFileW(str(directory), 0x80100000, 3, None, 3,
                                        0x02200000, None)
            if not handle or handle == ctypes.c_void_p(-1).value:
                raise ValueError("corpus_ancestor_lease_unavailable")
            held.append((handle, directory, None))
            identity = inspect(handle, directory)
            held[-1] = (handle, directory, identity)
        yield
        for handle, directory, identity in held:
            if inspect(handle, directory) != identity:
                raise ValueError("corpus_ancestor_identity_changed")
    finally:
        for handle, _, _ in reversed(held):
            kernel.CloseHandle(handle)


@contextmanager
def private_data_lease(path, maximum):
    """Hold a no-follow leaf plus directory chain through SQLite path reopen."""
    path = Path(path)
    if os.name != "nt" or not path.is_absolute():
        raise ValueError("absolute_private_windows_data_required")
    privacy = _dependency("privacy")
    path = Path(privacy._local_absolute_path(path))  # Refuse UNC before any traversal I/O.
    drive, tail = os.path.splitdrive(str(path))
    if ":" in tail or ".." in path.parts:
        raise ValueError("corpus_alternate_stream_or_parent_traversal_refused")
    with _directory_chain_lease(path):
        descriptor = privacy.open_private_readonly(path)
        try:
            info = os.fstat(descriptor)
            if not 0 < info.st_size <= maximum:
                raise ValueError("corpus_data_size_budget")
            privacy.assert_private_file_descriptor(descriptor)
            yield descriptor, info
            after = os.fstat(descriptor)
            if (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError("corpus_data_changed_during_lease")
        finally:
            os.close(descriptor)


def descriptor_digest(descriptor):
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        raw = os.read(descriptor, 4 * 1024 * 1024)
        if not raw:
            break
        digest.update(raw)
    return digest.hexdigest()


def checked_manifest(path, expected_sha256):
    if type(expected_sha256) is not str or not HEX64.fullmatch(expected_sha256):
        raise ValueError("corpus_manifest_digest_required")
    with private_data_lease(path, MAX_MANIFEST_BYTES) as (fd, info):
        raw = os.read(fd, MAX_MANIFEST_BYTES + 1)
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("corpus_manifest_digest_mismatch")
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_corpus_manifest_key")
            result[key] = value
        return result
    data = json.loads(raw, object_pairs_hook=unique_pairs)
    if (type(data) is not dict or data.get("schema_version") != 1
            or type(data.get("unique_chunks")) is not int
            or not MIN_PARTS <= data["unique_chunks"] <= MAX_PARTS
            or data.get("content_minimum") != 15 or data.get("content_maximum") != 512
            or data.get("preflight_status") != "REAL_MILLION_SCALE_INPUT_READY"
            or data.get("fts_build_integrity") != "PASS"
            or any(type(data.get(key)) is not str or not HEX64.fullmatch(data[key])
                   for key in ("database_sha256", "corpus_digest", "source_archive_sha256"))):
        raise ValueError("insufficient_or_invalid_real_corpus_manifest")
    return data


def _validate_database(conn, manifest):
    conn.execute("PRAGMA query_only=ON")
    conn.execute("PRAGMA trusted_schema=OFF")
    conn.execute("PRAGMA cache_size=-32768")
    conn.execute("PRAGMA mmap_size=0")
    conn.execute("PRAGMA temp_store=MEMORY")
    schema = {name: (kind, sql) for name, kind, sql in conn.execute(
        "SELECT name,type,sql FROM sqlite_schema WHERE name IN ('chunks','documents','corpus_meta')")}
    if set(schema) != {"chunks", "documents", "corpus_meta"} or any(
            kind != "table" or not sql.lstrip().upper().startswith("CREATE TABLE")
            for kind, sql in schema.values()):
        raise ValueError("plain_bounded_corpus_tables_required")
    count, unique = conn.execute("SELECT count(*),count(DISTINCT normalized_sha256) FROM chunks").fetchone()
    if count != manifest["unique_chunks"] or unique != count or count < MIN_PARTS:
        raise ValueError("million_distinct_corpus_required")
    meta = dict(conn.execute("SELECT key,value FROM corpus_meta"))
    if (meta.get("corpus_digest") != manifest["corpus_digest"]
            or meta.get("source_archive_sha256") != manifest["source_archive_sha256"]):
        raise ValueError("corpus_provenance_digest_mismatch")
    return {"chunks": count, "distinct_normalized_sha256": unique,
            "source_documents": conn.execute("SELECT count(*) FROM documents").fetchone()[0]}


def benchmark_existing(database, manifest_path, manifest_sha256, iterations=100):
    """One fresh process run, read-only FTS and real process metrics only."""
    if type(iterations) is not int or not 5 <= iterations <= 1000:
        raise ValueError("invalid_corpus_benchmark_iterations")
    manifest = checked_manifest(manifest_path, manifest_sha256)
    baseline = windows_process_observation()
    latencies, query_rows = [], []
    verification_started = time.perf_counter_ns()
    with private_data_lease(database, MAX_DB_BYTES) as (fd, info):
        if descriptor_digest(fd) != manifest["database_sha256"]:
            raise ValueError("corpus_database_digest_mismatch")
        target = Path(database)
        if any(Path(str(target) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
            raise ValueError("corpus_database_sidecar_refused")
        conn = sqlite3.connect(target.as_uri() + "?mode=ro&immutable=1", uri=True,
                               timeout=10, isolation_level=None)
        try:
            current = target.stat()
            if (current.st_dev, current.st_ino, current.st_size) != (info.st_dev, info.st_ino, info.st_size):
                raise ValueError("sqlite_reopen_identity_mismatch")
            validation_deadline = time.monotonic() + 60
            conn.set_progress_handler(lambda: 1 if time.monotonic() > validation_deadline else 0, 10000)
            readiness = _validate_database(conn, manifest)
            verification_seconds = (time.perf_counter_ns() - verification_started) / 1e9
            before_queries = windows_process_observation()
            deadline = time.monotonic() + 30
            conn.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10000)
            for index in range(iterations):
                text = QUERIES[index % len(QUERIES)]
                expression = '"' + text + '"'
                deadline = time.monotonic() + 30
                started = time.perf_counter_ns()
                rows = conn.execute(QUERY_SQL, (expression,)).fetchall()
                for _, content, digest, start, end, uri, docid in rows:
                    if (hashlib.sha256(content.encode()).digest() != digest
                            or end - start != len(content) or not 15 <= len(content) <= 512
                            or not uri or not docid):
                        raise ValueError("returned_corpus_content_or_provenance_invalid")
                elapsed = (time.perf_counter_ns() - started) / 1e6
                latencies.append(elapsed)
                query_rows.append({"query": text, "latency_ms": elapsed,
                                   "matches": len(rows), "top_rowids": [r[0] for r in rows]})
            after_queries = windows_process_observation()
            conn.set_progress_handler(None, 0)
            current = target.stat()
            if (current.st_dev, current.st_ino, current.st_size) != (info.st_dev, info.st_ino, info.st_size):
                raise ValueError("sqlite_reopen_identity_changed")
        finally:
            conn.close()
        if descriptor_digest(fd) != manifest["database_sha256"]:
            raise ValueError("corpus_database_changed_after_benchmark")
    final = windows_process_observation()
    cpu_ticks = lambda s: s["user_cpu_100ns"] + s["kernel_cpu_100ns"]
    return {"status": "MILLION_PINNED_CORPUS_FTS_WINDOWS_MEASURED",
            "readiness": readiness, "source_archive_sha256": manifest["source_archive_sha256"],
            "corpus_digest": manifest["corpus_digest"], "database_sha256": manifest["database_sha256"],
            "manifest_sha256": manifest_sha256, "database_bytes": info.st_size,
            "queries_measured": iterations, "latency_p50_ms": percentile(latencies, 50),
            "latency_p95_ms": percentile(latencies, 95), "latency_max_ms": max(latencies),
            "samples": query_rows, "verification_seconds": verification_seconds,
            "process_baseline": baseline, "process_before_queries": before_queries,
            "process_after_queries": after_queries, "process_after_cleanup": final,
            "query_cpu_seconds": (cpu_ticks(after_queries) - cpu_ticks(before_queries)) / 1e7,
            "raw_query_cpu_100ns": cpu_ticks(after_queries) - cpu_ticks(before_queries),
            "readonly_database_sha_before_after_equal": True,
            "sqlite_path_reopen_binding": "NO_DELETE_ANCESTOR_CHAIN_AND_LEAF_IDENTITY_BEFORE_AFTER",
            "validation_sql_cooperative_deadline_seconds": 60,
            "source_provenance": "PINNED_PREPARATION_MANIFEST_NOT_AUTOMATIC_PUBLISHER_AUTHENTICATION",
            "corpus_representativeness_independently_verified_by_adapter": False,
            "retrieved_content_hashes_and_declared_spans_verified": True,
            "original_source_spans_replayed_by_adapter": False,
            "cache_scope": "fresh process, OS cache not cleared or claimed cold",
            "source_executed": False, "network_used": False,
            "semantic_vector_or_ANN_qualification": False, "full_product_release": False}
