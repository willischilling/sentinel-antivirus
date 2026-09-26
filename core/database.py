"""SQLite storage for known-bad signatures, scan history, and quarantine records."""
import sqlite3
from contextlib import contextmanager

from . import paths

DB_PATH = paths.DATA_DIR / "signatures.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS signatures (
    hash TEXT PRIMARY KEY,
    algo TEXT NOT NULL DEFAULT 'sha256',
    name TEXT NOT NULL,
    added_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    verdict TEXT NOT NULL,
    detail TEXT,
    scanned_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS quarantine (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    reason TEXT NOT NULL,
    quarantined_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Downloaded threat feed (MalwareBazaar): ~1M+ rows, so hashes are stored as
-- raw 32-byte blobs in a WITHOUT ROWID table to keep the file small.
CREATE TABLE IF NOT EXISTS malware_hashes (
    sha256 BLOB PRIMARY KEY,
    family TEXT
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


_wal = False


def _use_wal(conn):
    """Write-ahead logging, so reads never wait for a write. Without it, the first threat
    database download (over a million rows in one transaction) locked the window out of the
    database long enough to freeze it and, on slower PCs, crash it with "database is locked".
    The mode is stored in the file; switching needs a moment with no other writer, so a busy
    database just tries again on the next connection."""
    global _wal
    if _wal:
        return
    try:
        _wal = conn.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal"
    except sqlite3.OperationalError:
        pass


@contextmanager
def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    # The agent and the window share this file; wait rather than fail on a lock.
    conn = sqlite3.connect(DB_PATH, timeout=30)
    _use_wal(conn)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with connect() as conn:
        conn.executescript(SCHEMA)


def add_signature(file_hash: str, name: str, algo: str = "sha256"):
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO signatures (hash, algo, name) VALUES (?, ?, ?)",
            (file_hash.lower(), algo, name),
        )


def lookup_signature(file_hash: str) -> str | None:
    file_hash = file_hash.lower()
    with connect() as conn:
        row = conn.execute("SELECT name FROM signatures WHERE hash = ?", (file_hash,)).fetchone()
        if row:
            return row[0]
        try:
            blob = bytes.fromhex(file_hash)
        except ValueError:
            return None
        row = conn.execute("SELECT family FROM malware_hashes WHERE sha256 = ?", (blob,)).fetchone()
        if row:
            if row[0] and row[0].endswith("(ThreatFox)"):
                return row[0]
            return f"{row[0]} (MalwareBazaar)" if row[0] else "Known malware (MalwareBazaar)"
        return None


def lookup_signatures(file_hashes) -> dict[str, str]:
    """lookup_signature() for many hashes at once, over one connection (e.g. every file in an
    archive). Returns {hash: threat name} for the ones that are known."""
    hashes = list({h.lower() for h in file_hashes})
    found = {}
    with connect() as conn:
        for i in range(0, len(hashes), 500):
            chunk = hashes[i:i + 500]
            marks = ",".join("?" * len(chunk))
            for h, name in conn.execute(f"SELECT hash, name FROM signatures WHERE hash IN ({marks})", chunk):
                found[h] = name
            blobs = [bytes.fromhex(h) for h in chunk if h not in found]
            if not blobs:
                continue
            marks = ",".join("?" * len(blobs))
            for blob, family in conn.execute(
                    f"SELECT sha256, family FROM malware_hashes WHERE sha256 IN ({marks})", blobs):
                if family and family.endswith("(ThreatFox)"):
                    found[blob.hex()] = family
                else:
                    found[blob.hex()] = f"{family} (MalwareBazaar)" if family else "Known malware (MalwareBazaar)"
    return found


def add_feed_hashes(rows, replace_family: bool = False) -> int:
    """rows: iterable of (sha256_hex, family_or_None). Returns rows written."""
    if replace_family:
        sql = ("INSERT INTO malware_hashes (sha256, family) VALUES (?, ?) "
               "ON CONFLICT(sha256) DO UPDATE SET family = excluded.family "
               "WHERE excluded.family IS NOT NULL")
    else:
        sql = "INSERT OR IGNORE INTO malware_hashes (sha256, family) VALUES (?, ?)"

    def blobs():
        for sha, family in rows:
            try:
                blob = bytes.fromhex(sha.strip())
            except ValueError:
                continue
            if len(blob) == 32:
                yield blob, family

    with connect() as conn:
        before = conn.total_changes
        conn.executemany(sql, blobs())
        return conn.total_changes - before


def feed_hash_count() -> int:
    with connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM malware_hashes").fetchone()[0]


def get_meta(key: str, default: str | None = None) -> str | None:
    with connect() as conn:
        row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else default


def set_meta(**values):
    with connect() as conn:
        conn.executemany(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [(k, None if v is None else str(v)) for k, v in values.items()],
        )


def log_scan(path: str, verdict: str, detail: str = ""):
    with connect() as conn:
        # One new file fires several filesystem events (created, modified...),
        # each rescanning it; record the same finding only once per minute.
        duplicate = conn.execute(
            "SELECT 1 FROM scan_log WHERE path = ? AND verdict = ? AND detail = ? "
            "AND scanned_at >= datetime('now', '-60 seconds') LIMIT 1",
            (path, verdict, detail),
        ).fetchone()
        if duplicate:
            return
        conn.execute(
            "INSERT INTO scan_log (path, verdict, detail) VALUES (?, ?, ?)",
            (path, verdict, detail),
        )


def log_quarantine(original_path: str, quarantine_path: str, reason: str):
    with connect() as conn:
        conn.execute(
            "INSERT INTO quarantine (original_path, quarantine_path, reason) VALUES (?, ?, ?)",
            (original_path, quarantine_path, reason),
        )


def signature_count() -> int:
    with connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]


def quarantine_count() -> int:
    with connect() as conn:
        return conn.execute("SELECT COUNT(*) FROM quarantine").fetchone()[0]


def get_recent_scans(limit: int = 200):
    with connect() as conn:
        return conn.execute(
            "SELECT path, verdict, detail, scanned_at FROM scan_log "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()


