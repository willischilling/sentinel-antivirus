"""Hands paths from the right-click menu to the main window.

Selecting several files and choosing "Scan with Sentinel" (or "Shred with
Sentinel") starts one Sentinel.exe per file. Each drops its path here as a
small file and the open window collects them, so they all end up in one scan
or one shred confirmation (no lost paths, no racing writers).
"""
import uuid
from pathlib import Path

from . import paths

FOLDER = paths.DATA_DIR / "scan_requests"
KINDS = ("scan", "shred", "page")  # page: "open the window on this page"


def add(path: str, kind: str = "scan"):
    FOLDER.mkdir(parents=True, exist_ok=True)
    target = FOLDER / f"{kind}-{uuid.uuid4().hex}.txt"
    tmp = target.with_suffix(".tmp")
    tmp.write_text(str(Path(path)), encoding="utf-8")
    tmp.replace(target)  # the window never sees a half-written request


def pending(kind: str = "scan") -> bool:
    try:
        return any(FOLDER.glob(f"{kind}-*.txt"))
    except OSError:
        return False


def take(kind: str = "scan", must_exist: bool = True) -> list[str]:
    """Every waiting path of this kind (existing ones only, no repeats), removing the requests."""
    found = []
    try:
        requests = sorted(FOLDER.glob(f"{kind}-*.txt"), key=lambda p: p.stat().st_mtime)
    except OSError:
        return []
    for request in requests:
        try:
            value = request.read_text(encoding="utf-8").strip()
            request.unlink()
        except OSError:
            continue
        if value and (not must_exist or Path(value).exists()) and value not in found:
            found.append(value)
    return found
