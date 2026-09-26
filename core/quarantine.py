"""Safely isolate detected files: move + rename so they can't be executed."""
import shutil
import time
from pathlib import Path

from . import database, paths

QUARANTINE_DIR = paths.QUARANTINE_DIR


def quarantine_file(path: Path, reason: str) -> Path:
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = int(time.time())
    # Append .quarantined so the OS/shell won't treat it as executable by extension.
    dest = QUARANTINE_DIR / f"{timestamp}_{path.name}.quarantined"
    shutil.move(str(path), str(dest))
    database.log_quarantine(str(path), str(dest), reason)
    return dest


def list_quarantine():
    with database.connect() as conn:
        return conn.execute(
            "SELECT id, original_path, quarantine_path, reason, quarantined_at "
            "FROM quarantine ORDER BY id DESC"
        ).fetchall()


def restore_file(quarantine_id: int) -> Path | None:
    with database.connect() as conn:
        row = conn.execute(
            "SELECT original_path, quarantine_path FROM quarantine WHERE id = ?",
            (quarantine_id,),
        ).fetchone()
    if not row:
        return None
    original_path, quarantine_path = row
    shutil.move(quarantine_path, original_path)
    return Path(original_path)


def delete_permanently(quarantine_id: int) -> bool:
    with database.connect() as conn:
        row = conn.execute(
            "SELECT quarantine_path FROM quarantine WHERE id = ?", (quarantine_id,)
        ).fetchone()
        if not row:
            return False
        Path(row[0]).unlink(missing_ok=True)
        conn.execute("DELETE FROM quarantine WHERE id = ?", (quarantine_id,))
    return True
