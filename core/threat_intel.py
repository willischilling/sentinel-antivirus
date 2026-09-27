"""Downloads and installs threat data:

- MalwareBazaar (abuse.ch) SHA-256 fingerprints of real malware: the full
  history once, then the rolling last-48-hours list (with family names).
- ThreatFox (abuse.ch) SHA-256 hashes of malware payloads seen in active
  campaigns, with family names (confidence 75% or higher only).
- YARA Forge "extended" rule set, compiled for core/yara_engine.py.
- Phishing/malware link lists (core/link_intel.py) and known-bad browser
  extension IDs (core/extensions.py).

Only hash lists and rule text are downloaded, never malware samples.
"""
import csv
import io
import os
import tempfile
import time
import urllib.request
import zipfile
from datetime import datetime, timezone

from . import database, extensions, link_intel, paths, yara_engine

MB_FULL_URL = "https://bazaar.abuse.ch/export/txt/sha256/full/"
MB_RECENT_URL = "https://bazaar.abuse.ch/export/csv/recent/"
TF_FULL_URL = "https://threatfox.abuse.ch/export/csv/sha256/full/"  # small (~1 MB), so fetched whole each time
TF_MIN_CONFIDENCE = 75
# "extended" (~10,700 rules) over "core" (~5,000): no extra false alarms on 2,196 test files, ~1.5x scan time
YARA_RULES_URL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip"
UPDATE_EVERY_SECONDS = 6 * 3600  # the recent feed covers 48h, so this never misses entries
USER_AGENT = "Sentinel-Antivirus/1.0"
LOCK_PATH = paths.DATA_DIR / "update.lock"


def _download(url: str, timeout: int = 120) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def last_update() -> datetime | None:
    value = database.get_meta("intel_updated")
    return datetime.fromisoformat(value) if value else None


def needs_update() -> bool:
    updated = last_update()
    return updated is None or (datetime.now(timezone.utc) - updated).total_seconds() > UPDATE_EVERY_SECONDS


def stats() -> dict:
    return {
        "hashes": int(database.get_meta("intel_hashes", "0")),
        "rules": int(database.get_meta("intel_rules", "0")),
        "updated": last_update(),
    }


class _UpdateLock:
    """Cross-process lock so the agent and the window never update at once."""

    def __enter__(self):
        import msvcrt

        self.file = open(LOCK_PATH, "a+")
        self.file.seek(0)  # both processes must lock the same byte
        try:
            msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            self.file.close()
            raise RuntimeError("An update is already running.")
        return self

    def __exit__(self, *exc):
        import msvcrt

        try:
            self.file.seek(0)
            msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            self.file.close()


def _install_full_hashes(progress):
    progress("intel_downloading_full")
    archive = zipfile.ZipFile(io.BytesIO(_download(MB_FULL_URL, timeout=600)))
    name = next(n for n in archive.namelist() if n.endswith(".txt"))
    progress("intel_installing_full")
    with archive.open(name) as raw:
        lines = io.TextIOWrapper(raw, encoding="utf-8", errors="replace")
        database.add_feed_hashes(
            (line, None) for line in lines if line.strip() and not line.startswith("#")
        )
    database.set_meta(intel_full_installed=_now_iso())


def _install_recent_hashes(progress):
    progress("intel_downloading_recent")
    text = _download(MB_RECENT_URL).decode("utf-8", errors="replace")
    rows = csv.reader((line for line in text.splitlines() if line and not line.startswith("#")),
                      skipinitialspace=True)
    entries = []
    for row in rows:
        if len(row) > 8:
            family = row[8].strip()
            entries.append((row[1], None if family in ("", "n/a") else family))
    database.add_feed_hashes(entries, replace_family=True)


def _install_threatfox_hashes(progress):
    progress("intel_downloading_threatfox")
    archive = zipfile.ZipFile(io.BytesIO(_download(TF_FULL_URL)))
    name = next(n for n in archive.namelist() if n.endswith(".csv"))
    text = archive.read(name).decode("utf-8", errors="replace")
    rows = csv.reader((line for line in text.splitlines() if line and not line.startswith("#")),
                      skipinitialspace=True)
    entries = []
    for row in rows:
        # first_seen, id, ioc_value, ioc_type, threat_type, malware, alias, malware_printable, last_seen, confidence
        if len(row) > 9 and row[3] == "sha256_hash" and row[9].isdigit() and int(row[9]) >= TF_MIN_CONFIDENCE:
            family = row[7].strip() or "Known malware"
            entries.append((row[2], f"{family} (ThreatFox)"))
    database.add_feed_hashes(entries)  # never overrides MalwareBazaar's names


def _install_yara_rules(progress):
    if yara_engine.yara is None:
        return
    progress("intel_downloading_yara")
    archive = zipfile.ZipFile(io.BytesIO(_download(YARA_RULES_URL)))
    name = next(n for n in archive.namelist() if n.endswith(".yar"))
    source = archive.read(name).decode("utf-8", errors="replace")
    progress("intel_compiling_yara")
    compiled = yara_engine.yara.compile(source=source)
    yara_engine.RULES_DIR.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=yara_engine.RULES_DIR, suffix=".tmp")
    os.close(fd)
    compiled.save(tmp)
    os.replace(tmp, yara_engine.COMPILED_PATH)  # atomic: scanners never see a half-written file


def update(progress=lambda key: None) -> dict:
    """Runs a full update. Raises on network failure; partial progress is kept.
    progress() receives translation keys (see core/translations.py)."""
    with _UpdateLock():
        started = time.monotonic()
        if not database.get_meta("intel_full_installed"):
            _install_full_hashes(progress)
        _install_recent_hashes(progress)
        _install_threatfox_hashes(progress)
        _install_yara_rules(progress)
        link_intel.install(progress)
        extensions.install(progress)
        database.set_meta(
            intel_updated=_now_iso(),
            intel_hashes=database.feed_hash_count(),
            intel_rules=yara_engine.rule_count(),
        )
        result = stats()
        result["seconds"] = round(time.monotonic() - started, 1)
        return result
