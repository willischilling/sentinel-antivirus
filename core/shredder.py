"""File shredder: deletes files so recovery tools can't bring them back.

Each file's contents are overwritten with random data (flushed to disk), then
it's renamed to random characters (so the name is gone too), cut to zero
length, and deleted. Folders are shredded file by file, then removed.

One pass of random data is what current guidance (NIST SP 800-88) calls enough
for hard drives. On SSDs and USB sticks the drive itself may keep old copies
of blocks out of reach of any program, so the note in the app says so;
Windows' built-in encryption (BitLocker) is the real answer there.

Refuses Windows' own folders, program folders, drive roots and the user
profile folder itself, and never follows folder links.
"""
import os
import secrets
import stat
from pathlib import Path

CHUNK = 1024 * 1024


def _protected() -> list[Path]:
    env = os.environ
    places = [env.get("SystemRoot", r"C:\Windows"), env.get("ProgramFiles", r"C:\Program Files"),
              env.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), env.get("ProgramData", r"C:\ProgramData")]
    return [Path(p).resolve() for p in places if p]


def check(path: Path) -> str | None:
    """None if the path may be shredded, else a translation key saying why not."""
    try:
        resolved = path.resolve()
    except OSError:
        return "shred_err_missing"
    if not path.exists():
        return "shred_err_missing"
    if resolved.parent == resolved or resolved == Path.home().resolve():
        return "shred_err_protected"
    if any(resolved == p or resolved.is_relative_to(p) for p in _protected()):
        return "shred_err_protected"
    try:
        from . import paths

        if resolved.is_relative_to(paths.BASE_DIR.resolve()):
            return "shred_err_protected"
    except (OSError, ValueError):
        pass
    return None


def files_in(path: Path) -> list[Path]:
    """The files a shred would remove (links never followed)."""
    if path.is_file() or path.is_symlink():
        return [path]
    found, stack = [], [path]
    while stack:
        folder = stack.pop()
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for e in entries:
            try:
                if e.is_symlink() or e.is_junction():
                    found.append(Path(e.path))  # the link itself is removed, not what it points to
                elif e.is_dir(follow_symlinks=False):
                    stack.append(Path(e.path))
                else:
                    found.append(Path(e.path))
            except OSError:
                continue
    return found


def shred_file(path: Path):
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
        path.unlink() if not path.is_dir() else os.rmdir(path)
        return
    try:
        os.chmod(path, stat.S_IWRITE)  # read-only files too
    except OSError:
        pass
    size = path.stat().st_size
    with open(path, "r+b", buffering=0) as f:
        written = 0
        while written < size:
            n = min(CHUNK, size - written)
            f.write(secrets.token_bytes(n))
            written += n
        f.flush()
        os.fsync(f.fileno())
        f.truncate(0)
        os.fsync(f.fileno())
    renamed = path.with_name(secrets.token_hex(8))
    os.replace(path, renamed)
    renamed.unlink()


def shred(paths_to_shred, progress=lambda done, total: None) -> tuple[int, list[str]]:
    """Shreds files and folders. Returns (files shredded, names that couldn't be)."""
    targets = []
    for p in map(Path, paths_to_shred):
        if check(p) is None:
            targets.append(p)
    files = [f for t in targets for f in files_in(t)]
    done, failed = 0, []
    for f in files:
        try:
            shred_file(f)
            done += 1
        except OSError:
            failed.append(f.name)
        progress(done + len(failed), len(files))
    for t in targets:  # now-empty folders, deepest first
        if t.is_dir() and not t.is_symlink():
            for folder in sorted((Path(r) for r, _d, _f in os.walk(t)), key=lambda p: len(p.parts), reverse=True):
                try:
                    os.rmdir(folder)
                except OSError:
                    pass
    return done, failed
