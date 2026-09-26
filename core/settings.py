"""Persistent user settings, so protection survives restarts and shutdowns."""
import json

from . import paths

SETTINGS_PATH = paths.DATA_DIR / "settings.json"

# Protection defaults to on for a fresh install; it only stays off once the
# user explicitly turns it off.
DEFAULTS = {"protection_on": True, "watch_path": None}


def load() -> dict:
    try:
        data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError):
        data = {}
    return {**DEFAULTS, **data}


def save(**changes):
    data = load()
    data.update(changes)
    # Write-then-rename so a shutdown mid-write can't leave a corrupt file.
    tmp = SETTINGS_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(SETTINGS_PATH)
