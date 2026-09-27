"""Junk cleaner: finds and removes files Windows and apps keep around but don't
need: temporary files, browser and app caches, crash reports, the Recycle Bin
and the recent-files list.

Only these fixed folders are touched. Browser caches never include passwords,
cookies, history or bookmarks. Folder links (junctions) are never followed,
files in use are skipped, and apps that are running are left alone (their
cache is in use; closing them lets it be cleaned).
"""
import ctypes
import os
import stat
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

LOCAL = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
ROAMING = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
DAY = 24 * 3600

CHROMIUM_DATA = [  # (name, exe, user data folder, single profile)
    ("Google Chrome", "chrome.exe", LOCAL / "Google" / "Chrome" / "User Data", False),
    ("Microsoft Edge", "msedge.exe", LOCAL / "Microsoft" / "Edge" / "User Data", False),
    ("Brave", "brave.exe", LOCAL / "BraveSoftware" / "Brave-Browser" / "User Data", False),
    ("Vivaldi", "vivaldi.exe", LOCAL / "Vivaldi" / "User Data", False),
    ("Opera", "opera.exe", ROAMING / "Opera Software" / "Opera Stable", True),
    ("Opera GX", "opera.exe", ROAMING / "Opera Software" / "Opera GX Stable", True),
]
PROFILE_CACHES = ("Cache", "Code Cache", "GPUCache", "DawnGraphiteCache", "DawnWebGPUCache")
SHARED_CACHES = ("ShaderCache", "GrShaderCache", "GraphiteDawnCache")
APPS = [  # (name, exes that mean it's running, cache folders)
    ("Discord", ("discord.exe", "discordptb.exe", "discordcanary.exe"),
     [ROAMING / d / c for d in ("discord", "discordptb", "discordcanary") for c in ("Cache", "Code Cache", "GPUCache")]),
    ("Spotify", ("spotify.exe",), [LOCAL / "Spotify" / "Data", LOCAL / "Spotify" / "Browser" / "Cache"]),
    ("Steam", ("steam.exe", "steamwebhelper.exe"), [LOCAL / "Steam" / "htmlcache"]),
    ("Epic Games", ("epicgameslauncher.exe",), [LOCAL / "EpicGamesLauncher" / "Saved" / "webcache",
                                                 LOCAL / "EpicGamesLauncher" / "Saved" / "webcache_4430",
                                                 LOCAL / "EpicGamesLauncher" / "Saved" / "webcache_4147"]),
    ("Roblox", ("robloxplayerbeta.exe", "robloxstudiobeta.exe"), [LOCAL / "Roblox" / "logs"]),
    ("Microsoft Teams", ("ms-teams.exe", "teams.exe"), [ROAMING / "Microsoft" / "Teams" / c
                                                        for c in ("Cache", "Code Cache", "GPUCache")]),
]
CATEGORIES = ("temp", "browser", "apps", "crash", "recycle", "recent")
DEFAULT_SELECTED = {"temp", "browser", "apps", "crash"}  # emptying the bin and recent list is opt-in


@dataclass
class Found:
    key: str
    size: int = 0
    files: int = 0
    skipped_apps: list = field(default_factory=list)  # running apps whose cache was left alone


@dataclass
class _Target:
    root: Path
    min_age: float = 0  # seconds: only files older than this
    top_only: bool = False


def _running() -> set:
    import psutil

    names = set()
    for proc in psutil.process_iter(["name"]):
        if proc.info.get("name"):
            names.add(proc.info["name"].lower())
    return names


def _targets(key: str, running: set) -> tuple[list[_Target], list[str]]:
    skipped = []
    if key == "temp":
        return [_Target(Path(tempfile.gettempdir()), min_age=DAY)], skipped
    if key == "browser":
        found = []
        for name, exe, data, single in CHROMIUM_DATA:
            if not data.is_dir():
                continue
            if exe in running:
                skipped.append(name)
                continue
            profiles = [data] if single else [p for p in data.iterdir() if p.is_dir() and (
                p.name == "Default" or p.name.startswith("Profile ") or p.name in ("Guest Profile", "System Profile"))]
            for profile in profiles:
                found += [_Target(profile / c) for c in PROFILE_CACHES]
            found += [_Target(data / c) for c in SHARED_CACHES]
            if single:  # Opera also keeps its disk cache under Local
                found.append(_Target(LOCAL / "Opera Software" / data.name / "Cache"))
        firefox = LOCAL / "Mozilla" / "Firefox" / "Profiles"
        if firefox.is_dir():
            if "firefox.exe" in running:
                skipped.append("Firefox")
            else:
                found += [_Target(p / "cache2") for p in firefox.iterdir() if p.is_dir()]
        return found, skipped
    if key == "apps":
        found = []
        for name, exes, folders in APPS:
            present = [f for f in folders if f.is_dir()]
            if not present:
                continue
            if any(e in running for e in exes):
                skipped.append(name)
                continue
            found += [_Target(f, min_age=DAY if f.name == "logs" else 0) for f in present]
        return found, skipped
    if key == "crash":
        wer = LOCAL / "Microsoft" / "Windows" / "WER"
        return [_Target(LOCAL / "CrashDumps"), _Target(wer / "ReportArchive"), _Target(wer / "ReportQueue")], skipped
    if key == "recent":
        # Only the shortcuts in Recent itself; the files they point to are untouched.
        return [_Target(ROAMING / "Microsoft" / "Windows" / "Recent", top_only=True)], skipped
    return [], skipped


def _is_link(entry: os.DirEntry) -> bool:
    try:
        return entry.is_symlink() or entry.is_junction() or bool(
            entry.stat(follow_symlinks=False).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)
    except OSError:
        return True


def _walk(target: _Target):
    """(path, size) of every file to clean under the target, links never followed."""
    if not target.root.is_dir():
        return
    now = time.time()
    stack = [target.root]
    while stack:
        folder = stack.pop()
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for entry in entries:
            if _is_link(entry):
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    if not target.top_only:
                        stack.append(Path(entry.path))
                    continue
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if target.top_only and not entry.name.lower().endswith(".lnk"):
                continue
            if target.min_age and now - max(info.st_mtime, info.st_ctime) < target.min_age:
                continue
            yield Path(entry.path), info.st_size


# ----------------------------------------------------------- recycle bin --
class _SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [("cbSize", ctypes.c_ulong), ("i64Size", ctypes.c_longlong), ("i64NumItems", ctypes.c_longlong)]


def _recycle_bin() -> tuple[int, int]:
    info = _SHQUERYRBINFO(cbSize=ctypes.sizeof(_SHQUERYRBINFO))
    if ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info)) != 0:
        return 0, 0
    return int(info.i64Size), int(info.i64NumItems)


# ---------------------------------------------------------------- public --
def analyze(keys=CATEGORIES) -> dict[str, Found]:
    """How much each category would free right now."""
    running = _running()
    results = {}
    for key in keys:
        found = Found(key)
        if key == "recycle":
            found.size, found.files = _recycle_bin()
        else:
            targets, found.skipped_apps = _targets(key, running)
            for target in targets:
                for _path, size in _walk(target):
                    found.size += size
                    found.files += 1
        results[key] = found
    return results


def clean(keys, progress=lambda key: None) -> tuple[int, int]:
    """Removes the chosen categories. Returns (bytes freed, files that were in use and skipped)."""
    running = _running()
    freed = skipped = 0
    for key in keys:
        progress(key)
        if key == "recycle":
            size, _count = _recycle_bin()
            # SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND
            if size and ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, 0x7) == 0:
                freed += size
            continue
        targets, _apps = _targets(key, running)
        for target in targets:
            for path, size in list(_walk(target)):
                try:
                    path.unlink()
                    freed += size
                except OSError:  # in use, or read-only
                    skipped += 1
            if not target.top_only:
                _remove_empty_folders(target.root)
    return freed, skipped


def _remove_empty_folders(root: Path):
    """Deletes folders left empty under root (never root itself, never through links)."""
    def prune(folder: Path):
        try:
            entries = list(os.scandir(folder))
        except OSError:
            return
        for entry in entries:
            try:
                if not _is_link(entry) and entry.is_dir(follow_symlinks=False):
                    prune(Path(entry.path))
                    os.rmdir(entry.path)  # only succeeds when empty
            except OSError:
                pass

    if root.is_dir():
        prune(root)


def open_disk_cleanup():
    """Windows' own Disk Cleanup, for Windows Update leftovers and other system files."""
    import subprocess

    subprocess.Popen(["cleanmgr.exe", "/d", os.environ.get("SystemDrive", "C:")])
