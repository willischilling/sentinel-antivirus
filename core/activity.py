"""Shared activity feed: the background agent appends, the main window tails it."""
import time

from . import paths

LOG_PATH = paths.DATA_DIR / "activity.log"
MAX_BYTES = 512 * 1024


def log(text: str, level: str = "info"):
    """level: info, muted, warn or threat."""
    line = f"{time.strftime('%H:%M:%S')}\t{level}\t{text}\n"
    try:
        if LOG_PATH.exists() and LOG_PATH.stat().st_size > MAX_BYTES:
            keep = LOG_PATH.read_bytes()[-(MAX_BYTES // 2):]
            LOG_PATH.write_bytes(keep[keep.find(b"\n") + 1:])
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass


class Tail:
    """Reads lines appended since the last call, starting with a little backlog."""

    def __init__(self, backlog_bytes: int = 16 * 1024):
        size = LOG_PATH.stat().st_size if LOG_PATH.exists() else 0
        self.offset = max(0, size - backlog_bytes)
        self._skip_partial = self.offset > 0

    def read_new(self) -> list[tuple[str, str, str]]:
        try:
            size = LOG_PATH.stat().st_size
        except FileNotFoundError:
            return []
        if size < self.offset:  # log was trimmed; start over
            self.offset = 0
            self._skip_partial = False
        if size == self.offset:
            return []
        with open(LOG_PATH, "rb") as f:
            f.seek(self.offset)
            data = f.read(size - self.offset)
        end = data.rfind(b"\n")
        if end == -1:
            return []
        self.offset += end + 1
        lines = data[: end + 1].decode("utf-8", errors="replace").splitlines()
        if self._skip_partial:
            lines = lines[1:]
            self._skip_partial = False
        entries = []
        for line in lines:
            parts = line.split("\t", 2)
            if len(parts) == 3:
                entries.append((parts[0], parts[1], parts[2]))
        return entries
