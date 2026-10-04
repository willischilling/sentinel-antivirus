"""Stealer guard's watching (the checks themselves are in core/stealer_guard.py).

Two parts, both in the background agent:

- Programs. Every second, programs started in the last 15 minutes that aren't
  signed by a publisher (or are script runners) have their open files checked
  against the places saved logins live. A program found with one open is
  paused straight away, before it can finish, and the user decides.
- Stolen data. New and changed files in Temp and AppData (where stealers
  gather what they took before sending it) are checked for copies of browser
  password and cookie databases, Discord tokens, Roblox sign-in cookies and
  password lists. The program behind them is the one holding the file, or
  else the newest unsigned program.
"""
import os
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from core import authenticode, paths, stealer_guard

WATCH_FOR = 15 * 60       # seconds after a program starts that its open files are checked
TICK = 1.0
PER_TICK = 8              # programs checked each second (the rest wait for the next round)
SETTINGS_EVERY = 5.0
DUMP_POPUP_GAP = 60       # stolen-data files with no program behind them: one popup a minute
SKIP_SUFFIXES = {
    ".exe", ".dll", ".sys", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".mp3", ".mp4", ".wav",
    ".zip", ".7z", ".rar", ".msi", ".cab", ".pak", ".node", ".pyd", ".pyc", ".jar", ".etl", ".evtx",
}
SKIP_PARTS = ("\\cache\\", "\\code cache\\", "\\gpucache\\", "\\service worker\\", "\\crashpad\\",
              "\\shadercache\\", "\\dawncache\\", "\\grshadercache\\")


@dataclass
class StealerAlert:
    kind: str                       # "reading": has the files open; "copied": left stolen data behind
    categories: set
    pid: int | None = None
    name: str | None = None
    exe: str | None = None
    file: str | None = None         # the stolen-data file ("copied")
    paused: bool = False
    script_host: bool = False
    likely: bool = False            # "copied", but the program no longer had the file open


@dataclass
class _Candidate:
    proc: psutil.Process
    name: str
    exe: str
    started: float
    script_host: bool = False


def _key(path) -> str:
    return str(path).replace("/", "\\").lower()


def _is_sentinel(proc: psutil.Process, exe: str) -> bool:
    if proc.pid == os.getpid():
        return True
    base = _key(paths.BASE_DIR)
    if getattr(sys, "frozen", False):
        return _key(exe).startswith(base + "\\")
    try:  # from source: python.exe gui.py, from the project folder
        return base in _key(" ".join(proc.cmdline()))
    except (psutil.Error, OSError):
        return False


class StealerWatcher:
    def __init__(self, on_alert, stop_flag: list[bool]):
        self.on_alert = on_alert
        self.stop_flag = stop_flag
        self._lock = threading.Lock()
        self._candidates: dict[int, _Candidate] = {}
        self._judged: dict[int, float] = {}   # pid -> start time (a reused pid gets judged again)
        self._alerted: set[int] = set()
        self._pending: dict[str, float] = {}  # file -> when it last changed
        self._inspected: dict[str, tuple] = {}
        self._last_dump_popup = 0.0
        self._enabled = True
        self._allowed: set[str] = set()
        self._next_settings = 0.0
        self.observer = None

    # ------------------------------------------------------------ start/stop --
    def start(self):
        threading.Thread(target=self._process_loop, daemon=True).start()
        threading.Thread(target=self._inspect_loop, daemon=True).start()
        folders = []
        for folder in (tempfile.gettempdir(), os.environ.get("APPDATA")):
            if folder and Path(folder).is_dir() and not any(_key(folder).startswith(_key(f) + "\\") for f in folders):
                folders.append(folder)
        if folders:
            handler = _Handler(self)
            self.observer = Observer()
            for folder in folders:
                self.observer.schedule(handler, folder, recursive=True)
            self.observer.start()
        return self

    def stop(self):
        self.stop_flag[0] = True
        if self.observer:
            self.observer.stop()
            self.observer.join()

    def _refresh_settings(self):
        if time.monotonic() >= self._next_settings:
            self._next_settings = time.monotonic() + SETTINGS_EVERY
            self._enabled = stealer_guard.enabled()
            self._allowed = stealer_guard.allowed()

    # -------------------------------------------------------------- programs --
    def _judge(self, pid: int) -> _Candidate | None:
        """A program worth watching: new, not Sentinel, not allowed, and not signed (or a script runner)."""
        proc = psutil.Process(pid)
        started = proc.create_time()
        if self._judged.get(pid) == started:
            return None
        self._judged[pid] = started
        if time.time() - started > WATCH_FOR:
            return None
        exe = proc.exe()
        if not exe or _is_sentinel(proc, exe) or _key(exe) in self._allowed:
            return None
        name = proc.name()
        script_host = name.lower() in stealer_guard.SCRIPT_HOSTS
        if not script_host and authenticode.check(Path(exe)).signed:
            return None
        return _Candidate(proc, name, exe, started, script_host)

    def _process_loop(self):
        rotation = 0
        while not self.stop_flag[0]:
            time.sleep(TICK)
            self._refresh_settings()
            if not self._enabled:
                continue
            try:
                current = set(psutil.pids())
            except OSError:
                continue
            for pid in current - set(self._judged):
                try:
                    candidate = self._judge(pid)
                except (psutil.Error, OSError):
                    self._judged.setdefault(pid, -1.0)  # can't look inside it (system or admin): don't retry
                    continue
                if candidate:
                    with self._lock:
                        self._candidates[pid] = candidate
            now = time.time()
            with self._lock:
                for pid in list(self._candidates):
                    c = self._candidates[pid]
                    if pid not in current or now - c.started > WATCH_FOR or pid in self._alerted:
                        del self._candidates[pid]
                watched = sorted(self._candidates)
                self._alerted &= current
            for pid in list(self._judged):
                if pid not in current:
                    del self._judged[pid]
            if not watched:
                continue
            rotation %= len(watched)
            batch = (watched[rotation:] + watched[:rotation])[:PER_TICK]
            rotation += PER_TICK
            for pid in batch:
                with self._lock:
                    candidate = self._candidates.get(pid)
                if candidate:
                    self._check_open_files(candidate)

    def _check_open_files(self, c: _Candidate):
        try:
            files = c.proc.open_files()
        except (psutil.Error, OSError):
            with self._lock:
                self._candidates.pop(c.proc.pid, None)
            return
        found = set()
        for f in files:
            category = stealer_guard.classify(f.path)
            if category and not stealer_guard.is_owner(c.name, category):
                found.add(category)
        if found:
            self._raise(c, "reading", found)

    def _raise(self, c: _Candidate, kind: str, categories: set, file: str | None = None, likely: bool = False):
        with self._lock:
            if c.proc.pid in self._alerted:
                return
            self._alerted.add(c.proc.pid)
            self._candidates.pop(c.proc.pid, None)
        paused = False
        if not likely:  # only a program caught in the act is paused
            try:
                c.proc.suspend()  # stop it before it finishes; the popup decides what happens next
                paused = True
            except (psutil.Error, OSError):
                pass
        self.on_alert(StealerAlert(kind, categories, c.proc.pid, c.name, c.exe, file, paused, c.script_host, likely))

    # ---------------------------------------------------------- stolen data --
    def note_file(self, path: str):
        p = _key(path)
        if Path(p).suffix in SKIP_SUFFIXES or any(part in p for part in SKIP_PARTS):
            return
        if p.startswith(_key(paths.BASE_DIR) + "\\") or "\\sentinel-" in p:  # Sentinel's own (recovery check)
            return
        with self._lock:
            self._pending[path] = time.monotonic()

    def _inspect_loop(self):
        while not self.stop_flag[0]:
            time.sleep(0.3)
            if not self._enabled:
                with self._lock:
                    self._pending.clear()
                continue
            with self._lock:
                pending, self._pending = self._pending, {}
            for path in pending:
                try:
                    stat = os.stat(path)
                except OSError:
                    continue
                ident = (stat.st_size, stat.st_mtime_ns)
                if self._inspected.get(path) == ident:
                    continue
                self._inspected[path] = ident
                category = stealer_guard.inspect(Path(path))
                if category:
                    self._on_stolen_file(path, category)
            if len(self._inspected) > 5000:
                self._inspected.clear()

    def _on_stolen_file(self, path: str, category: str):
        suspect, holding = self._suspect(path)
        if suspect:
            self._raise(suspect, "copied", {category}, path, likely=not holding)
            return
        if time.monotonic() - self._last_dump_popup < DUMP_POPUP_GAP:
            return
        self._last_dump_popup = time.monotonic()
        self.on_alert(StealerAlert("copied", {category}, file=path))

    def _suspect(self, path: str) -> tuple[_Candidate | None, bool]:
        """The program holding the file (True), or else the newest program being watched (False)."""
        with self._lock:
            candidates = sorted(self._candidates.values(), key=lambda c: c.started, reverse=True)
        target = _key(path)
        for c in candidates:
            try:
                if any(_key(f.path) == target for f in c.proc.open_files()):
                    return c, True
            except (psutil.Error, OSError):
                continue
        return (candidates[0] if candidates else None), False


class _Handler(FileSystemEventHandler):
    def __init__(self, watcher: StealerWatcher):
        super().__init__()
        self.watcher = watcher

    def on_created(self, event):
        if not event.is_directory:
            self.watcher.note_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.watcher.note_file(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.watcher.note_file(event.dest_path)
