"""Remembers the devices seen on each network, so the app can show when a
device was first and last seen and flag ones that are new."""
from datetime import datetime, timezone

from . import settings

NEW_WINDOW = 24 * 3600  # a device first seen within this many seconds is "new"


def _all() -> dict:
    data = settings.load().get("history")
    return data if isinstance(data, dict) else {}


def record(network_id: str, devices) -> dict:
    """Update first/last-seen for every device on this network, and return a
    map mac -> {"first": iso, "last": iso, "new": bool}."""
    data = settings.load()
    hist = data.get("history") if isinstance(data.get("history"), dict) else {}
    net = hist.setdefault(network_id, {})
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat(timespec="seconds")
    seen_before = bool(net)  # was this network ever recorded?
    out = {}
    for dev in devices:
        entry = net.get(dev.mac)
        if entry is None:
            entry = {"first": now_iso, "last": now_iso}
            net[dev.mac] = entry
        else:
            entry["last"] = now_iso
        try:
            first = datetime.fromisoformat(entry["first"])
            is_new = seen_before and (now - first).total_seconds() < NEW_WINDOW
        except (KeyError, ValueError):
            is_new = False
        out[dev.mac] = {"first": entry["first"], "last": entry["last"], "new": is_new}
    hist[network_id] = net
    data["history"] = hist
    settings.save(history=hist)
    return out


def seen_count(network_id: str) -> int:
    return len(_all().get(network_id, {}))
