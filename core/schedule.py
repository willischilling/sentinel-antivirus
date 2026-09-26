"""Scheduled quick scans: when they're due, and what they cover.

The schedule lives in settings ("scan_schedule"); the background agent checks
it every minute and runs the scan itself. A scan missed because the PC was off
runs the next time the agent starts (catch-up), once.
"""
from datetime import datetime, timedelta

from . import paths, settings

FREQUENCIES = ("off", "daily", "weekly")
HOURS = (6, 9, 12, 15, 18, 21)
DEFAULT = {"frequency": "weekly", "hour": 12, "weekday": 6}  # Sundays at noon
LAST_RUN_KEY = "scheduled_last_run"


def get() -> dict:
    return {**DEFAULT, **(settings.load().get("scan_schedule") or {})}


def save(**changes):
    schedule = {**get(), **changes}
    settings.save(scan_schedule=schedule)


def quick_scan_folders():
    folders = []
    for key in ("downloads", "desktop", "documents"):
        folder = paths.known_folder(key)
        if folder and folder.exists() and folder not in folders:
            folders.append(folder)
    return folders


def last_slot(schedule: dict, now: datetime) -> datetime | None:
    """The most recent time a scan should have started, at or before now."""
    if schedule["frequency"] == "off":
        return None
    slot = now.replace(hour=schedule["hour"], minute=0, second=0, microsecond=0)
    if schedule["frequency"] == "daily":
        return slot if slot <= now else slot - timedelta(days=1)
    slot -= timedelta(days=(slot.weekday() - schedule["weekday"]) % 7)
    return slot if slot <= now else slot - timedelta(days=7)


def next_slot(schedule: dict, now: datetime) -> datetime | None:
    last = last_slot(schedule, now)
    if last is None:
        return None
    return last + timedelta(days=1 if schedule["frequency"] == "daily" else 7)


def is_due(now: datetime | None = None) -> bool:
    """True if a scheduled slot has passed since the last scheduled scan."""
    now = now or datetime.now()
    schedule = get()
    slot = last_slot(schedule, now)
    if slot is None:
        return False
    raw = settings.load().get(LAST_RUN_KEY)
    if raw is None:
        # First run of this feature: start counting from now, don't scan straight away.
        mark_ran(now)
        return False
    return datetime.fromisoformat(raw) < slot


def mark_ran(when: datetime | None = None):
    settings.save(**{LAST_RUN_KEY: (when or datetime.now()).isoformat(timespec="seconds")})
