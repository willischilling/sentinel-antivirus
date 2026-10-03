"""Persistent settings, stored as one JSON file in the user's app-data folder.

Write-then-rename so a crash or shutdown mid-write can't leave a corrupt file.
"""
import json
import os
from pathlib import Path


def data_dir() -> Path:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser(r"~\AppData\Local")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    path = Path(base) / "HomeNetManager"
    path.mkdir(parents=True, exist_ok=True)
    return path


SETTINGS_PATH = data_dir() / "settings.json"
DEFAULTS: dict = {}


def load() -> dict:
    try:
        data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        data = {}
    return {**DEFAULTS, **data}


def save(**changes):
    data = load()
    data.update(changes)
    tmp = SETTINGS_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(SETTINGS_PATH)
