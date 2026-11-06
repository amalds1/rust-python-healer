"""Conservative knowledge self-updater: official CPython docs and PyPI metadata.

No downloaded code is executed or installed. Binary self-updates deliberately
remain disabled pending a signed, independently audited release channel.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html.parser import HTMLParser
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


TRUSTED_HOSTS = frozenset(("www.python.org", "docs.python.org", "pypi.org"))
PACKAGE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
RELEASE_RE = re.compile(r"Download Python (3\.\d+\.\d+)(?![0-9a-zA-Z])")
# The PyPI project endpoint also contains release file metadata. Widely used
# projects can exceed 6 MB even though we retain only selected info fields.
MAX_BYTES = 12_000_000


class PlainText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.depth = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript"):
            self.depth += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript") and self.depth:
            self.depth -= 1

    def handle_data(self, data):
        if not self.depth:
            self.parts.append(data)

    def result(self):
        return re.sub(r"\s+", " ", " ".join(self.parts)).strip()


def checked_url(url):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in TRUSTED_HOSTS or parsed.username or parsed.password:
        raise ValueError("niet-goedgekeurde of niet-HTTPS bron")
    return url


def download(url, etag=None, timeout=30):
    checked_url(url)
    headers = {"User-Agent": "RustPythonHealer-KnowledgeUpdater/0.2"}
    if etag:
        headers["If-None-Match"] = etag
    try:
        with urlopen(Request(url, headers=headers), timeout=timeout) as response:
            checked_url(response.geturl())
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise ValueError("antwoord te groot voor veilige indexering: " + url)
            return body, response.headers.get("ETag"), False
    except HTTPError as exc:
        if exc.code == 304:
            if not etag:
                raise ValueError("304 zonder eerder gevalideerde ETag is onbetrouwbaar") from exc
            return None, etag, True
        raise


def latest_stable(downloads_html):
    text = downloads_html.decode("utf-8", "replace")
    # First primary Download Python button points at the stable release;
    # do not select alpha/beta versions from the release archive.
    found = RELEASE_RE.search(text)
    if not found:
        raise ValueError("officiële Python-release niet herkenbaar; niets bijgewerkt")
    version = found.group(1)
    numbers = tuple(int(item) for item in version.split("."))
    if numbers[0] != 3 or not 9 <= numbers[1] <= 99:
        raise ValueError("onverwachte Python-versie")
    return version


def version_tuple(version):
    parts = version.split(".")
    if len(parts) != 3 or not all(x.isdecimal() for x in parts):
        raise ValueError("ongeldig releaseformaat")
    return tuple(map(int, parts))


def safe_packages(packages):
    names = []
    for item in packages:
        if not PACKAGE_RE.fullmatch(item):
            raise ValueError("ongeldige pakketnaam: " + item)
        name = re.sub(r"[-_.]+", "-", item).lower()
        if name not in names:
            names.append(name)
    if len(names) > 50:
        raise ValueError("maximaal 50 packages per update; batch grotere collecties")
    return names


def database(connection, schema_text):
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA busy_timeout=5000")
    connection.executescript(schema_text)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS update_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    )


def read_state(connection, key):
    row = connection.execute("SELECT value FROM update_state WHERE key=?", (key,)).fetchone()
    return row[0] if row else None


def record_state(connection, key, value):
    connection.execute(
        "INSERT INTO update_state(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value)
    )


def managed_source(url):
    """Bind updater-owned URLs to their own document namespace only."""
    if re.fullmatch(r"https://docs\.python\.org/3\.\d+/whatsnew/3\.\d+\.html", url):
        return "python-official-whatsnew"
    if re.fullmatch(r"https://pypi\.org/pypi/[a-z0-9][a-z0-9-]*/json", url):
        return "pypi-metadata"
    raise ValueError("onbekende updater-bron in lokale status")


def verified_copy(connection, url):
    """Accept a conditional GET only when every cached version is intact."""
    rows = connection.execute(
        "SELECT content,sha256 FROM documents WHERE uri=? AND source=? "
        "ORDER BY indexed_at DESC,id DESC", (url, managed_source(url))
    ).fetchall()
    return bool(rows) and all(
        hashlib.sha256(content.encode("utf-8")).hexdigest() == digest
        for content, digest in rows
    )


def purge_corrupt_documents(connection, active_urls):
    """Remove only hash-invalid updater-owned rows after all fetches succeed."""
    removed = 0
    for url in sorted(set(active_urls)):
        rows = connection.execute(
            "SELECT id,content,sha256 FROM documents WHERE uri=? AND source=?",
            (url, managed_source(url)),
        )
        for row_id, content, digest in rows.fetchall():
            if hashlib.sha256(content.encode("utf-8")).hexdigest() != digest:
                removed += connection.execute(
                    "DELETE FROM documents WHERE id=?", (row_id,)
                ).rowcount
    return removed


def reconcile_sources(connection, active_urls, timestamp):
    """Tombstone removed watch sources, retaining audit history in update_state."""
    tracked = {row[0][len("source_active:"):] for row in connection.execute(
        "SELECT key FROM update_state WHERE key GLOB 'source_active:*' AND value='1'"
    )}
    # On upgrading a pre-v0.12 database, previous updater-owned ETags are
    # strong evidence of an active source; do not guess from arbitrary docs.
    for (key,) in connection.execute("SELECT key FROM update_state WHERE key GLOB 'etag:https://*'"):
        url = key[len("etag:"):]
        if read_state(connection, "source_active:" + url) is None:
            managed_source(url)  # Refuse tampered state instead of deleting unrelated documents.
            tracked.add(url)
    active = set(active_urls)
    removed = tracked - active
    deleted = 0
    for url in sorted(removed):
        deleted += connection.execute("DELETE FROM documents WHERE uri=? AND source=?",
                                      (url, managed_source(url))).rowcount
        connection.execute("DELETE FROM update_state WHERE key=?", ("etag:" + url,))
        record_state(connection, "source_active:" + url, "0")
        record_state(connection, "tombstone:" + url, timestamp)
    for url in sorted(active):
        record_state(connection, "source_active:" + url, "1")
        connection.execute("DELETE FROM update_state WHERE key=?", ("tombstone:" + url,))
    return deleted, len(removed)


def index_document(connection, doc):
    body = doc["content"]
    if len(body.encode("utf-8")) > 2_000_000:
        raise ValueError("geïndexeerd document te groot")
    sha = hashlib.sha256(body.encode("utf-8")).hexdigest()
    connection.execute(
        "INSERT INTO documents(source,uri,title,package,version,python_constraint,content,sha256) "
        "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(source,uri,version) DO UPDATE SET "
        "title=excluded.title,package=excluded.package,"
        "python_constraint=excluded.python_constraint,content=excluded.content,"
        "sha256=excluded.sha256,indexed_at=CURRENT_TIMESTAMP",
        (doc["source"], doc["uri"], doc["title"], doc["package"],
         doc["version"], doc["python_constraint"], body, sha),
    )


def fetch_doc(minor, etag=None):
    version = "3." + str(minor)
    url = f"https://docs.python.org/{version}/whatsnew/{version}.html"
    body, new_etag, unchanged = download(url, etag)
    if unchanged:
        return {"unchanged": True, "uri": url, "etag": new_etag, "document": None}
    parsed = PlainText()
    parsed.feed(body.decode("utf-8", "replace"))
    content = parsed.result()
    if len(content) < 100:
        raise ValueError("documentatie lijkt onvolledig: " + version)
    return {"unchanged": False, "uri": url, "etag": new_etag,
            "document": {"source": "python-official-whatsnew", "uri": url,
                         "title": "What's New in Python " + version,
                         "package": "cpython", "version": version,
                         "python_constraint": "==" + version + ".*",
                         "content": content}}


def fetch_package(package, etag=None):
    url = f"https://pypi.org/pypi/{package}/json"
    body, new_etag, unchanged = download(url, etag)
    if unchanged:
        return {"unchanged": True, "uri": url, "etag": new_etag, "document": None}
    data = json.loads(body)
    info = data.get("info", {})
    version = str(info.get("version") or "")
    if not version or not isinstance(info.get("requires_dist"), (list, type(None))):
        raise ValueError("PyPI-metadata ontbreekt: " + package)
    content = "\n".join([str(info.get("summary") or ""),
                         "Requires-Python: " + str(info.get("requires_python") or ""),
                         "Requires-Dist: " + "; ".join(info.get("requires_dist") or []),
                         "Project: " + str(info.get("project_url") or url)])
    return {"unchanged": False, "uri": url, "etag": new_etag,
            "document": {"source": "pypi-metadata", "uri": url,
                         "title": package + " " + version,
                         "package": package, "version": version,
                         "python_constraint": str(info.get("requires_python") or "unknown"),
                         "content": content}}


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".versions-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def update(manifest_path, schema_path, db_path, mode="check", packages=None, auto=False):
    """Close SQLite handles even when fetch, commit or manifest write fails."""
    connections = []
    try:
        return _update(manifest_path, schema_path, db_path, mode, packages, auto, connections)
    finally:
        for conn in connections:
            conn.close()


def _update(manifest_path, schema_path, db_path, mode, packages, auto, connections):
    manifest_path = Path(manifest_path)
    config = json.loads(manifest_path.read_text(encoding="utf-8"))
    existing = config["latest_stable"]
    names = safe_packages(packages if packages is not None else config.get("watch_packages", []))
    if mode not in ("check", "apply"):
        raise ValueError("mode moet check of apply zijn")

    if mode == "apply":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path), timeout=15)
        connections.append(conn)
        database(conn, Path(schema_path).read_text(encoding="utf-8"))
        if auto:
            previous = read_state(conn, "last_success")
            if previous:
                elapsed = datetime.now(timezone.utc).timestamp() - float(previous)
                committed = read_state(conn, "committed_latest_stable")
                if (committed in (None, existing)
                        and elapsed < int(config.get("auto_check_hours", 24)) * 3600):
                    conn.close()
                    return {"status": "SKIPPED_FRESH", "latest_stable": existing,
                            "documents_updated": 0, "packages_checked": 0}
    else:
        conn = None

    # No database or manifest mutation until the trusted release is parsed.
    html, _, _ = download("https://www.python.org/downloads/")
    discovered = latest_stable(html)
    if version_tuple(discovered) < version_tuple(existing):
        raise ValueError("releasebron lijkt ouder dan de huidige metadata")
    if mode == "check":
        return {"status": "UPDATE_AVAILABLE" if discovered != existing else "UP_TO_DATE",
                "current": existing, "discovered": discovered,
                "binary_update": "DISABLED_UNTIL_SIGNED_RELEASE_CHANNEL"}

    latest_minor = version_tuple(discovered)[1]
    jobs = []
    for minor in range(9, latest_minor + 1):
        version = f"3.{minor}"
        url = f"https://docs.python.org/{version}/whatsnew/{version}.html"
        jobs.append(("doc", minor, url))
    for name in names:
        jobs.append(("package", name, f"https://pypi.org/pypi/{name}/json"))
    if len(jobs) > 100:
        raise ValueError("teveel bronnen voor één update")
    docs = []
    etags = []
    unchanged_count = 0
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {}
        for kind, item, url in jobs:
            old_tag = read_state(conn, "etag:" + url)
            # A 304 is usable only when its local body matches the known hash.
            if not verified_copy(conn, url):
                old_tag = None
            future = executor.submit(fetch_doc if kind == "doc" else fetch_package, item, old_tag)
            futures[future] = url
        for future in as_completed(futures):
            row = future.result()  # Any invalid or unavailable source fails closed.
            if row["unchanged"]:
                unchanged_count += 1
            else:
                docs.append(row["document"])
            if row["etag"]:
                etags.append(("etag:" + row["uri"], row["etag"]))

    # SQLite changes are one transaction; manifest only advances afterward.
    now = str(datetime.now(timezone.utc).timestamp())
    active_urls = [url for _, _, url in jobs]
    with conn:
        deleted, tombstones = reconcile_sources(conn, active_urls, now)
        corrupt_removed = purge_corrupt_documents(conn, active_urls)
        for doc in docs:
            index_document(conn, doc)
        for key, value in etags:
            record_state(conn, key, value)
        record_state(conn, "last_success", now)
        # Enables a retry after DB commit but before atomic manifest replace.
        record_state(conn, "committed_latest_stable", discovered)
    conn.close()

    updated = dict(config)
    updated["latest_stable"] = discovered
    updated["verified_as_of"] = datetime.now(timezone.utc).date().isoformat()
    atomic_json(manifest_path, updated)
    return {"status": "UPDATED", "previous": existing,
            "latest_stable": discovered, "documents_updated": len(docs),
            "documents_deleted": deleted, "tombstoned_sources": tombstones,
            "corrupt_documents_removed": corrupt_removed,
            "sources_unchanged": unchanged_count, "packages_checked": len(names),
            "binary_update": "DISABLED_UNTIL_SIGNED_RELEASE_CHANNEL"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--schema", required=True)
    parser.add_argument("--db", required=True)
    parser.add_argument("--mode", choices=["check", "apply"], default="check")
    parser.add_argument("--package", action="append")
    parser.add_argument("--auto", action="store_true", help="TTL voorkomt overbodige updates")
    parser.add_argument("--watch", action="store_true", help="Blijft controleren volgens TTL")
    args = parser.parse_args()
    if args.watch and args.mode != "apply":
        parser.error("--watch vereist --mode apply")
    while True:
        try:
            print(json.dumps(update(args.manifest, args.schema, args.db,
                                    args.mode, args.package, args.auto or args.watch)))
        except Exception as exc:
            print(json.dumps({"status": "FAILED", "error": str(exc)}))
            if not args.watch:
                raise SystemExit(2)
        if not args.watch:
            break
        time.sleep(3600)


if __name__ == "__main__":
    main()
