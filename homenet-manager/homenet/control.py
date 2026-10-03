"""The control layer: device policy, admin PIN, website blocking, and the
"active" blocklist the background check keeps in place.

What is really enforced, and where:
- THIS PC — pausing cuts all outbound traffic (firewall.py); website/category
  blocking writes the hosts file (hostsblock.py); the "adult" category also
  switches on a family DNS filter (dns.py).
- OTHER devices on your network — the policy you set (paused, profile, blocks)
  is stored and shown as managed, ready to push to a router that supports it.
  A desktop app can't flip another device's internet without the router, so
  these are recorded, not pretended to be live.

The admin PIN protects your own access: once set, pausing or resuming the admin
device needs the PIN, so no one else can keep you offline.
"""
import hashlib
import json
import os
from datetime import datetime, time as dtime, timezone

from . import dns, firewall, hostsblock, settings

PROFILES = ("me", "family", "kids", "guest", "other")

CATEGORIES = {
    "adult": ["pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com", "redtube.com",
              "youporn.com", "onlyfans.com"],
    "social": ["facebook.com", "instagram.com", "twitter.com", "x.com", "tiktok.com",
               "snapchat.com", "reddit.com", "tumblr.com"],
    "gaming": ["roblox.com", "epicgames.com", "steampowered.com", "store.steampowered.com",
               "ea.com", "battle.net", "xbox.com", "playstation.com"],
    "streaming": ["youtube.com", "netflix.com", "hulu.com", "disneyplus.com", "twitch.tv",
                  "primevideo.com", "max.com"],
    "ads": ["doubleclick.net", "googlesyndication.com", "googleadservices.com",
            "ads.yahoo.com", "adnxs.com", "taboola.com", "outbrain.com"],
}

clean_domain = hostsblock.clean_domain


# --------------------------------------------------------------- config --
def _all() -> dict:
    data = settings.load().get("homenet")
    return data if isinstance(data, dict) else {}


def _save(data: dict):
    settings.save(homenet=data)


def net_config(network_id: str):
    data = _all()
    conf = data.setdefault("networks", {}).setdefault(network_id, {})
    conf.setdefault("admin_mac", None)
    conf.setdefault("devices", {})
    conf.setdefault("categories", [])
    conf.setdefault("sites", [])
    return data, conf


# ------------------------------------------------------------- admin PIN --
def has_pin() -> bool:
    return bool(_all().get("pin"))


def set_pin(pin: str):
    salt = os.urandom(16).hex()
    data = _all()
    data["pin_salt"] = salt
    data["pin"] = _hash(pin, salt)
    _save(data)


def clear_pin():
    data = _all()
    data.pop("pin", None)
    data.pop("pin_salt", None)
    _save(data)


def check_pin(pin: str) -> bool:
    data = _all()
    stored, salt = data.get("pin"), data.get("pin_salt")
    if not stored or not salt:
        return True
    return _hash(pin, salt) == stored


def _hash(pin: str, salt: str) -> str:
    return hashlib.sha256((salt + ":" + pin).encode("utf-8")).hexdigest()


# ----------------------------------------------------------- the devices --
def set_admin_device(network_id: str, mac: str):
    data, conf = net_config(network_id)
    conf["admin_mac"] = mac
    _save(data)


def is_admin_device(network_id: str, mac: str) -> bool:
    return net_config(network_id)[1].get("admin_mac") == mac


def device(network_id: str, mac: str) -> dict:
    entry = net_config(network_id)[1]["devices"].get(mac) or {}
    return {"label": entry.get("label"), "profile": entry.get("profile", "other"),
            "paused": bool(entry.get("paused")), "paused_at": entry.get("paused_at")}


def _entry(conf: dict, mac: str) -> dict:
    return conf["devices"].setdefault(mac, {"profile": "other"})


def set_label(network_id: str, mac: str, label: str):
    data, conf = net_config(network_id)
    _entry(conf, mac)["label"] = label.strip() or None
    _save(data)


def set_profile(network_id: str, mac: str, profile: str):
    if profile not in PROFILES:
        raise ValueError(profile)
    data, conf = net_config(network_id)
    _entry(conf, mac)["profile"] = profile
    _save(data)


def set_paused(network_id: str, mac: str, paused: bool):
    data, conf = net_config(network_id)
    entry = _entry(conf, mac)
    entry["paused"] = paused
    entry["paused_at"] = datetime.now(timezone.utc).isoformat() if paused else None
    _save(data)


def paused_count(network_id: str) -> int:
    return sum(1 for d in net_config(network_id)[1]["devices"].values() if d.get("paused"))


def enforce_this_pc(paused: bool):
    firewall.pause_internet() if paused else firewall.resume_internet()


# ----------------------------------------------------- website blocking --
def blocked_domains(network_id: str) -> list[str]:
    conf = net_config(network_id)[1]
    domains = []
    for key in conf.get("categories", []):
        domains += CATEGORIES.get(key, [])
    domains += conf.get("sites", [])
    seen, unique = set(), []
    for d in domains:
        d = clean_domain(d)
        if d and d not in seen:
            seen.add(d)
            unique.append(d)
    return unique


def toggle_category(network_id: str, key: str, on: bool):
    if key not in CATEGORIES:
        raise ValueError(key)
    data, conf = net_config(network_id)
    cats = set(conf.get("categories", []))
    cats.add(key) if on else cats.discard(key)
    conf["categories"] = sorted(cats)
    _save(data)


def add_site(network_id: str, domain: str):
    domain = clean_domain(domain)
    if not domain:
        return
    data, conf = net_config(network_id)
    if domain not in conf["sites"]:
        conf["sites"].append(domain)
        _save(data)


def remove_site(network_id: str, domain: str):
    data, conf = net_config(network_id)
    if domain in conf["sites"]:
        conf["sites"].remove(domain)
        _save(data)


def apply_site_blocks(network_id: str):
    """Write the blocklist to the hosts file and (for 'adult') switch on the
    family DNS filter. Records the applied list so the background check keeps
    it in place. One admin prompt."""
    domains = blocked_domains(network_id)
    from . import elevate
    elevate.run("hosts", "set", json.dumps(domains))
    _set_active(domains, enforce=True)
    conf = net_config(network_id)[1]
    want_family = "adult" in conf.get("categories", [])
    if want_family and not dns.is_on():
        dns.enable()


# ------------------------------------------- staying applied (the check) --
def _active() -> dict:
    data = _all().get("active")
    if not isinstance(data, dict):
        return {"domains": [], "enforce": False}
    return {"domains": list(data.get("domains") or []), "enforce": bool(data.get("enforce"))}


def _set_active(domains: list[str], enforce: bool):
    data = _all()
    data["active"] = {"domains": sorted(set(domains)), "enforce": enforce}
    _save(data)


def active_blocklist() -> list[str]:
    return _active()["domains"]


def enforce_setting() -> bool:
    """The switch position, whether or not anything has been applied yet."""
    return _active()["enforce"]


def enforce_on() -> bool:
    return _active()["enforce"] and bool(_active()["domains"])


def set_enforce(on: bool):
    data = _all()
    active = data.get("active")
    if not isinstance(active, dict):
        active = {"domains": [], "enforce": False}
    active["enforce"] = bool(on)
    data["active"] = active
    _save(data)


def needs_reapply() -> bool:
    if not enforce_on():
        return False
    return set(active_blocklist()) != hostsblock.current_domains()


def reapply():
    from . import elevate
    elevate.run("hosts", "set", json.dumps(active_blocklist()))


# ===================================================== this-PC pause state ==
# The internet pause for THIS PC is driven by three things: a manual pause, a
# focus timer, and the off-hours schedule. desired_pc_paused() combines them;
# the background watcher keeps the firewall matching it.
def pc_paused_manual() -> bool:
    return bool(_all().get("pc_paused"))


def set_pc_paused_manual(on: bool):
    data = _all()
    data["pc_paused"] = bool(on)
    _save(data)


def desired_pc_paused(now: datetime | None = None) -> bool:
    return pc_paused_manual() or focus_active() or schedule_active(now)


def pause_reason(now: datetime | None = None) -> str | None:
    if focus_active():
        return "focus"
    if schedule_active(now):
        return "schedule"
    if pc_paused_manual():
        return "manual"
    return None


# ============================================================ focus timer ==
def focus_start(minutes: int):
    from datetime import timedelta
    until = datetime.now(timezone.utc) + timedelta(minutes=max(1, int(minutes)))
    data = _all()
    data["focus"] = {"until": until.isoformat()}
    _save(data)
    log("focus", f"Focus started for {int(minutes)} min")


def focus_cancel():
    data = _all()
    if data.pop("focus", None):
        _save(data)
        log("focus", "Focus ended early")


def focus_remaining() -> int:
    """Seconds left, or 0 if no focus session is running."""
    info = _all().get("focus")
    if not info:
        return 0
    try:
        until = datetime.fromisoformat(info["until"])
    except (KeyError, ValueError):
        return 0
    left = (until - datetime.now(timezone.utc)).total_seconds()
    if left <= 0:
        data = _all()
        if data.pop("focus", None):
            _save(data)
            log("focus", "Focus finished")
        return 0
    return int(left)


def focus_active() -> bool:
    return focus_remaining() > 0


# =============================================================== schedule ==
DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def schedule() -> dict:
    data = _all().get("schedule")
    if not isinstance(data, dict):
        return {"enabled": False, "windows": []}
    data.setdefault("enabled", False)
    data.setdefault("windows", [])
    return data


def set_schedule_enabled(on: bool):
    data = _all()
    sch = schedule()
    sch["enabled"] = bool(on)
    data["schedule"] = sch
    _save(data)
    log("schedule", "Schedule turned " + ("on" if on else "off"))


def add_window(days: list[int], start: str, end: str, label: str = ""):
    data = _all()
    sch = schedule()
    sch["windows"].append({"days": sorted(set(days)), "start": start, "end": end, "label": label})
    data["schedule"] = sch
    _save(data)


def remove_window(index: int):
    data = _all()
    sch = schedule()
    if 0 <= index < len(sch["windows"]):
        sch["windows"].pop(index)
        data["schedule"] = sch
        _save(data)


def _parse_hhmm(text: str) -> dtime | None:
    try:
        h, m = text.split(":")
        return dtime(int(h) % 24, int(m) % 60)
    except (ValueError, AttributeError):
        return None


def _window_active(win: dict, now: datetime) -> bool:
    start, end = _parse_hhmm(win.get("start", "")), _parse_hhmm(win.get("end", ""))
    if not start or not end:
        return False
    today = now.weekday()
    cur = now.time()
    if start <= end:  # same-day window, e.g. 09:00–17:00
        return today in win.get("days", []) and start <= cur < end
    # overnight window, e.g. 23:00–07:00: belongs to the day it starts
    if today in win.get("days", []) and cur >= start:
        return True
    yesterday = (today - 1) % 7
    return yesterday in win.get("days", []) and cur < end


def schedule_active(now: datetime | None = None) -> bool:
    sch = schedule()
    if not sch["enabled"]:
        return False
    now = now or datetime.now()
    return any(_window_active(w, now) for w in sch["windows"])


# ============================================================ activity log ==
def log(kind: str, text: str):
    data = _all()
    events = data.get("events")
    if not isinstance(events, list):
        events = []
    events.append({"t": datetime.now(timezone.utc).isoformat(timespec="seconds"), "kind": kind, "text": text})
    data["events"] = events[-200:]
    _save(data)


def events() -> list:
    evs = _all().get("events")
    return list(reversed(evs)) if isinstance(evs, list) else []


# ============================================================= app settings ==
UI_DEFAULTS = {"theme": "dark", "scan_on_launch": True, "minimize_to_tray": False}


def ui_settings() -> dict:
    data = _all().get("ui")
    return {**UI_DEFAULTS, **(data if isinstance(data, dict) else {})}


def set_ui(**changes):
    data = _all()
    ui = {**UI_DEFAULTS, **(data.get("ui") or {}), **changes}
    data["ui"] = ui
    _save(data)
