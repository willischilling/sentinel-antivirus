"""Home Network control: a simple, GVTC-style front-end for managing the
devices on *your own* home network. You can give each device a name and a
profile (who it belongs to), pause or resume its internet, and block whole
categories of websites (or your own list of sites) across the network.

Scope and safety
----------------
This only ever manages your own home network and the devices on it. It never
touches, scans or disrupts a network or device you don't own.

What is really enforced, and where:

- *This PC* — pausing and site/category blocking are enforced for real. The
  pause cuts all outbound traffic through the built-in Windows Firewall
  (core/firewall.py); site/category blocking writes the chosen domains into
  Windows' hosts file so every browser and app is covered; the "adult" blur
  switches DNS to a family filter (core/webprotect.py). All of these go
  through the one Windows admin prompt (core/elevate.py).
- *Other devices on your network* — Sentinel keeps the policy you set (paused,
  profile, blocklist) and shows it as managed, ready to push to a router that
  supports it. A desktop app can't flip another device's internet without the
  router, so these are recorded, not silently pretended to be live. This is
  exactly how the ISP's own app works: it is a front-end to the router.

Your own access is protected by an admin PIN. Once set, pausing *or* resuming
the admin device (this PC) needs the PIN, so no one else using this app can
keep you offline — you can always turn your own internet back on.
"""
import hashlib
import json
import os
from datetime import datetime, timezone

from . import settings

# Profiles a device can belong to. "me" is the admin's own device(s).
PROFILES = ("me", "family", "kids", "guest", "other")

# Website categories you can block network-wide. Each carries a small list of
# the main domains it covers, so blocking is real on this PC (via the hosts
# file). "adult" additionally flips on the family DNS filter, which catches far
# more than any fixed list can.
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


# --------------------------------------------------------------- config --
def _all() -> dict:
    data = settings.load().get("homenet")
    return data if isinstance(data, dict) else {}


def _save(data: dict):
    settings.save(homenet=data)


def net_config(network_id: str) -> dict:
    """The stored policy for one network, with every field present."""
    data = _all()
    nets = data.setdefault("networks", {})
    conf = nets.setdefault(network_id, {})
    conf.setdefault("admin_mac", None)
    conf.setdefault("devices", {})       # mac -> {label, profile, paused, paused_at}
    conf.setdefault("categories", [])    # blocked category keys
    conf.setdefault("sites", [])         # extra blocked domains
    return data, conf


def _commit(data: dict):
    _save(data)


# ------------------------------------------------------------- admin PIN --
def has_pin() -> bool:
    return bool(_all().get("pin"))


def set_pin(pin: str):
    """Sets or replaces the admin PIN (stored only as a salted hash)."""
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
        return True  # no PIN set: nothing to check against
    return _hash(pin, salt) == stored


def _hash(pin: str, salt: str) -> str:
    return hashlib.sha256((salt + ":" + pin).encode("utf-8")).hexdigest()


# ----------------------------------------------------------- the devices --
def set_admin_device(network_id: str, mac: str):
    data, conf = net_config(network_id)
    conf["admin_mac"] = mac
    _commit(data)


def is_admin_device(network_id: str, mac: str) -> bool:
    _data, conf = net_config(network_id)
    return conf.get("admin_mac") == mac


def device(network_id: str, mac: str) -> dict:
    _data, conf = net_config(network_id)
    entry = conf["devices"].get(mac) or {}
    return {"label": entry.get("label"), "profile": entry.get("profile", "other"),
            "paused": bool(entry.get("paused")), "paused_at": entry.get("paused_at")}


def _device_entry(conf: dict, mac: str) -> dict:
    return conf["devices"].setdefault(mac, {"profile": "other"})


def set_label(network_id: str, mac: str, label: str):
    data, conf = net_config(network_id)
    _device_entry(conf, mac)["label"] = label.strip() or None
    _commit(data)


def set_profile(network_id: str, mac: str, profile: str):
    if profile not in PROFILES:
        raise ValueError(profile)
    data, conf = net_config(network_id)
    _device_entry(conf, mac)["profile"] = profile
    _commit(data)


def set_paused(network_id: str, mac: str, paused: bool):
    """Records the paused state. Real enforcement for this PC is done by the
    caller via enforce_this_pc(); other devices stay managed-only."""
    data, conf = net_config(network_id)
    entry = _device_entry(conf, mac)
    entry["paused"] = paused
    entry["paused_at"] = datetime.now(timezone.utc).isoformat() if paused else None
    _commit(data)


def paused_count(network_id: str) -> int:
    _data, conf = net_config(network_id)
    return sum(1 for d in conf["devices"].values() if d.get("paused"))


# ----------------------------------------------- enforcement (this PC) --
def enforce_this_pc(paused: bool):
    """Really cut or restore this PC's internet, through the Windows Firewall.
    Raises if the admin prompt is declined."""
    from . import firewall

    firewall.pause_internet() if paused else firewall.resume_internet()


def blocked_domains(network_id: str) -> list[str]:
    """Every domain to block on this PC: the chosen categories' domains plus
    your own sites. The 'adult' category is handled by the DNS filter as well,
    but its headline sites go in the hosts list too."""
    _data, conf = net_config(network_id)
    domains: list[str] = []
    for key in conf.get("categories", []):
        domains += CATEGORIES.get(key, [])
    domains += conf.get("sites", [])
    seen, unique = set(), []
    for d in domains:
        d = _clean_domain(d)
        if d and d not in seen:
            seen.add(d)
            unique.append(d)
    return unique


def apply_site_blocks(network_id: str):
    """Write the current blocklist into Windows' hosts file (one admin prompt),
    and turn the family DNS filter on/off depending on the 'adult' category."""
    from . import elevate, webprotect

    domains = blocked_domains(network_id)
    elevate.run("homenet", "hosts", json.dumps(domains))
    _data, conf = net_config(network_id)
    if "adult" in conf.get("categories", []):
        if webprotect.status().level != "family":
            webprotect.enable("family")


def toggle_category(network_id: str, key: str, on: bool):
    if key not in CATEGORIES:
        raise ValueError(key)
    data, conf = net_config(network_id)
    cats = set(conf.get("categories", []))
    cats.add(key) if on else cats.discard(key)
    conf["categories"] = sorted(cats)
    _commit(data)


def add_site(network_id: str, domain: str):
    domain = _clean_domain(domain)
    if not domain:
        return
    data, conf = net_config(network_id)
    if domain not in conf["sites"]:
        conf["sites"].append(domain)
        _commit(data)


def remove_site(network_id: str, domain: str):
    data, conf = net_config(network_id)
    if domain in conf["sites"]:
        conf["sites"].remove(domain)
        _commit(data)


def _clean_domain(raw: str) -> str:
    """'https://www.Example.com/path' -> 'example.com'."""
    d = (raw or "").strip().lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    d = d.split("/")[0].split("?")[0]
    if d.startswith("www."):
        d = d[4:]
    return d if "." in d and " " not in d else ""


# ------------------------------------------------- hosts file (admin side) --
HOSTS = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                     "System32", "drivers", "etc", "hosts")
BEGIN = "# >>> Sentinel Home Network >>>"
END = "# <<< Sentinel Home Network <<<"


def elevated(action: str, args: list[str]):
    """Admin side (called from core/elevate.py). Only rewrites Sentinel's own
    clearly-marked block in the hosts file; it never touches other lines."""
    if action != "hosts":
        raise RuntimeError(f"unknown home-network action {action!r}")
    domains = [d for d in json.loads(args[0] or "[]") if _clean_domain(d)]
    try:
        with open(HOSTS, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        text = ""
    kept = _strip_block(text)
    if domains:
        lines = [BEGIN, "# Added by Sentinel Antivirus. Edit these from the Home Network page."]
        for d in domains:
            lines.append(f"0.0.0.0 {d}")
            lines.append(f"0.0.0.0 www.{d}")
        lines.append(END)
        block = "\n".join(lines)
        new = (kept.rstrip() + "\n\n" + block + "\n") if kept.strip() else (block + "\n")
    else:
        new = kept if kept.endswith("\n") or not kept else kept + "\n"
    import subprocess

    with open(HOSTS, "w", encoding="utf-8") as fh:
        fh.write(new)
    subprocess.run(["ipconfig", "/flushdns"], capture_output=True,
                   creationflags=0x08000000)


def _strip_block(text: str) -> str:
    """Remove Sentinel's marked block (and nothing else) from the hosts text."""
    while BEGIN in text and END in text:
        before, _, rest = text.partition(BEGIN)
        _, _, after = rest.partition(END)
        text = before.rstrip("\n") + ("\n" + after.lstrip("\n") if after.strip() else "\n")
    return text
