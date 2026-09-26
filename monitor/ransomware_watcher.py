"""Detects ransomware-like behavior: many files in personal folders suddenly
becoming unreadable (encrypted) or renamed to strange extensions.

A file "looks encrypted" when its content no longer matches its type, e.g. a
.pdf that doesn't start with %PDF. Normal saving never does that, so a burst
of such files in a short window is a strong ransomware signal. When it fires,
Sentinel identifies the likely program and alerts; the user decides what to do.
"""
import math
import os
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass
from pathlib import Path

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from core import paths

WINDOW_SECONDS = 20
THRESHOLD = 10           # damaged files within the window before alerting
COOLDOWN_SECONDS = 120   # don't repeat the alert for the same burst

MAGIC = {
    ".pdf": [b"%PDF"],
    ".png": [b"\x89PNG"],
    ".jpg": [b"\xff\xd8\xff"], ".jpeg": [b"\xff\xd8\xff"],
    ".gif": [b"GIF87a", b"GIF89a"],
    ".docx": [b"PK"], ".xlsx": [b"PK"], ".pptx": [b"PK"], ".odt": [b"PK"], ".zip": [b"PK"],
    ".doc": [b"\xd0\xcf\x11\xe0"], ".xls": [b"\xd0\xcf\x11\xe0"], ".ppt": [b"\xd0\xcf\x11\xe0"],
    ".rtf": [b"{\\rtf"],
    ".7z": [b"7z\xbc\xaf"], ".rar": [b"Rar!"],
}
TEXT_SUFFIXES = {".txt", ".csv", ".md", ".html", ".htm", ".json", ".xml", ".py", ".js", ".css", ".log"}
KNOWN_SUFFIXES = set(MAGIC) | TEXT_SUFFIXES | {
    ".mp4", ".mov", ".mp3", ".wav", ".heic", ".webp", ".bmp", ".tif", ".tiff", ".psd", ".ai",
    ".exe", ".msi", ".lnk", ".ini", ".tmp", ".bak", ".crdownload", ".part", ".partial",
    ".url", ".ico", ".svg", ".epub", ".key", ".pages", ".numbers", ".one", ".accdb",
}
# Cloud-only (OneDrive "online-only") files would be downloaded just by reading them.
SKIP_ATTRIBUTES = 0x00001000 | 0x00400000 | 0x00040000  # OFFLINE | RECALL_ON_DATA_ACCESS | RECALL_ON_OPEN


def default_folders() -> list[str]:
    folders = []
    for name in ("documents", "desktop", "pictures", "music", "videos", "downloads"):
        p = paths.known_folder(name)
        if not p.exists():
            continue
        # Skip folders already covered by another (recursive) watch.
        if any(Path(f) == p or Path(f) in p.parents for f in folders):
            continue
        folders.append(str(p))
    return folders


def _entropy(data: bytes) -> float:
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values()) if n else 0.0


def looks_encrypted(path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix not in MAGIC and suffix not in TEXT_SUFFIXES:
        return False
    try:
        st = path.stat()
        if st.st_size < 16 or getattr(st, "st_file_attributes", 0) & SKIP_ATTRIBUTES:
            return False
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError:
        return False
    if suffix in MAGIC:
        return not any(head.startswith(m) for m in MAGIC[suffix])
    # Text files have no header, but readable text never looks like random bytes.
    return len(head) >= 512 and _entropy(head) > 7.2


@dataclass
class RansomwareAlert:
    folder: str
    damaged: int
    examples: list[str]
    suspect_pid: int | None
    suspect_name: str | None
    suspect_exe: str | None
    written_mb: float
    confirmed: bool = False  # the suspect had files open inside the affected folder


class _Handler(FileSystemEventHandler):
    def __init__(self, detector):
        self.detector = detector

    def on_modified(self, event):
        if not event.is_directory:
            self.detector.check(Path(event.src_path))

    def on_created(self, event):
        if not event.is_directory:
            self.detector.check(Path(event.src_path))

    def on_moved(self, event):
        if not event.is_directory:
            self.detector.check_rename(Path(event.src_path), Path(event.dest_path))


class RansomwareDetector:
    def __init__(self, on_alert, threshold=THRESHOLD, window=WINDOW_SECONDS):
        self.on_alert, self.threshold, self.window = on_alert, threshold, window
        self._events: deque[tuple[float, str]] = deque()
        self._lock = threading.Lock()
        self._last_alert = -COOLDOWN_SECONDS

    def check(self, path: Path):
        if looks_encrypted(path):
            self._record(path)

    def check_rename(self, src: Path, dest: Path):
        # e.g. report.docx -> report.docx.locked / report.docx.x7g2k
        renamed_away = (src.suffix.lower() in KNOWN_SUFFIXES
                        and dest.suffix.lower() not in KNOWN_SUFFIXES
                        and dest.name.lower().startswith(src.stem.lower()))
        if renamed_away or looks_encrypted(dest):
            self._record(dest)

    def _record(self, path: Path):
        now = time.monotonic()
        with self._lock:
            self._events.append((now, str(path)))
            while self._events and now - self._events[0][0] > self.window:
                self._events.popleft()
            distinct = list(dict.fromkeys(p for _, p in self._events))
            if len(distinct) < self.threshold or now - self._last_alert < COOLDOWN_SECONDS:
                return
            self._last_alert = now
        # Identify outside the lock: it samples disk writes for a moment.
        threading.Thread(target=self._raise, args=(distinct,), daemon=True).start()

    def _raise(self, damaged: list[str]):
        folder = os.path.commonpath(damaged) if len(damaged) > 1 else str(Path(damaged[0]).parent)
        pid, name, exe, mb, confirmed = identify_culprit(folder)
        self.on_alert(RansomwareAlert(folder, len(damaged), [Path(p).name for p in damaged[:3]],
                                      pid, name, exe, mb, confirmed))


def identify_culprit(folder: str, sample_seconds: float = 2.0):
    """Returns (pid, name, exe, MB written, confirmed). Prefers a top writer
    that has files open inside the affected folder over the raw top writer."""
    me = os.getpid()

    def writes():
        totals = {}
        for p in psutil.process_iter(["pid", "name"]):
            try:
                if p.pid in (0, 4, me):  # idle, System, ourselves
                    continue
                totals[p.pid] = (p.io_counters().write_bytes, p.info["name"])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return totals

    before = writes()
    time.sleep(sample_seconds)
    after = writes()
    ranked = sorted(((after[pid][0] - before[pid][0], pid) for pid in after if pid in before), reverse=True)
    ranked = [(w, pid) for w, pid in ranked if w > 0][:5]
    if not ranked:
        return None, None, None, 0.0, False

    folder_key = os.path.normcase(folder)
    for written, pid in ranked:
        try:
            proc = psutil.Process(pid)
            if any(os.path.normcase(f.path).startswith(folder_key) for f in proc.open_files()):
                return pid, after[pid][1], _exe(proc), written / 1e6, True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    written, pid = ranked[0]
    try:
        exe = _exe(psutil.Process(pid))
    except psutil.NoSuchProcess:
        exe = None
    return pid, after[pid][1], exe, written / 1e6, False


def _exe(proc) -> str | None:
    try:
        return proc.exe()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def watch(folders: list[str], on_alert, **detector_options) -> Observer:
    detector = RansomwareDetector(on_alert, **detector_options)
    observer = Observer()
    for folder in folders:
        observer.schedule(_Handler(detector), folder, recursive=True)
    observer.start()
    return observer
