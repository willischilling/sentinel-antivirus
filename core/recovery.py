"""After password-stealing or remote-control malware: a recovery checklist.

Stealers (RedLine, Lumma, Vidar...) copy saved browser passwords, sign-in
cookies, Discord tokens and crypto wallets within seconds of running, so
removing the file isn't the end of it. When Sentinel finds one, it opens an
"incident" and the app walks through what to secure, in the order that matters
(email first: it can reset everything else). Progress is saved in the settings.
"""
import re
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import database, extensions, settings

# Families (and generic rule words) that steal data or give remote control.
_PATTERN = re.compile(
    r"steal|grabber|infostealer|keylog|redline|lumma|vidar|raccoon|rhadamanthys|risepro|meduza|mystic|"
    r"agent\s?tesla|formbook|xloader|snake\s?keylogger|lokibot|loki\s?bot|azorult|arkei|mars\s?stealer|"
    r"phemedrone|atlantida|amos\b|asyncrat|dcrat|njrat|quasar|venomrat|xworm|remcos|nanocore|warzone|"
    r"avemaria|darkcomet|netwire|orcus|purelogs|stealc|lumar|metastealer",
    re.IGNORECASE)
STEPS = ("remove", "defender", "email", "passwords", "sessions", "twofa", "money", "leaks")
SIGN_OUT_LINKS = (  # (name, where to sign out of every other device)
    ("Google", "https://myaccount.google.com/device-activity"),
    ("Microsoft", "https://account.microsoft.com/security"),
    ("Steam", "https://store.steampowered.com/twofactor/manage"),
    ("Roblox", "https://www.roblox.com/my/account#!/security"),
    ("Epic Games", "https://www.epicgames.com/account/password"),
)


def is_stealer(threat_name: str | None) -> bool:
    return bool(threat_name and _PATTERN.search(threat_name))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def incident() -> dict | None:
    """The current recovery checklist ({"found", "threat", "done", ...}), or None."""
    data = settings.load().get("recovery")
    return data if isinstance(data, dict) and data.get("found") else None


def is_open() -> bool:
    data = incident()
    return bool(data) and not data.get("resolved")


def needs_attention() -> bool:
    """A stealer was found and the checklist isn't finished (shown on the dashboard)."""
    data = incident()
    return bool(data) and not data.get("resolved") and bool(data.get("threat"))


def record(threat_name: str, when: str | None = None):
    """Opens a checklist for a newly found stealer (or updates the open one)."""
    when = when or _now()
    current = incident()
    if current and not current.get("resolved"):
        if current.get("threat") != threat_name:
            current["others"] = sorted(set(current.get("others", [])) | {threat_name})[:10]
            settings.save(recovery=current)
        return
    if current and current.get("resolved") and when <= current["resolved"]:
        return  # already dealt with
    settings.save(recovery={"found": when, "threat": threat_name, "done": [], "resolved": None})


def set_done(step: str, done: bool):
    if not is_open():
        start_manual()  # ticking a step without a detection: "I think I was hacked"
    data = incident()
    steps = set(data.get("done", []))
    steps.add(step) if done else steps.discard(step)
    data["done"] = [s for s in STEPS if s in steps]
    settings.save(recovery=data)


def resolve():
    data = incident()
    if data:
        data["resolved"] = _now()
        settings.save(recovery=data)


def start_manual():
    """Opens a checklist without a detection ("I think I was hacked")."""
    if not is_open():
        settings.save(recovery={"found": _now(), "threat": None, "done": [], "resolved": None})


def check_history():
    """Opens a checklist for stealers found before this feature existed (or by the
    background agent while the window was closed)."""
    try:
        with database.connect() as conn:
            rows = conn.execute(
                "SELECT quarantined_at, reason FROM quarantine UNION ALL "
                "SELECT scanned_at, detail FROM scan_log WHERE verdict = 'signature_match' "
                "ORDER BY 1 DESC LIMIT 400").fetchall()
    except sqlite3.Error:
        return
    for when, name in rows:
        if is_stealer(name):
            stamp = when.replace(" ", "T") + "+00:00" if "T" not in when else when
            record(name, stamp)
            return


def browsers_with_passwords() -> list[str]:
    """Browsers on this PC that have saved passwords (only a count is read; the
    passwords themselves are encrypted and never touched)."""
    found = []
    for _key, name, data_dir, _exe, _page, single in extensions.CHROMIUM:
        if not data_dir.is_dir():
            continue
        profiles = [data_dir] if single else [p for p in data_dir.iterdir() if p.is_dir()]
        if any(_login_count(p / "Login Data") for p in profiles):
            found.append(name)
    for profile in extensions.FIREFOX_PROFILES.glob("*"):
        try:
            import json

            if json.loads((profile / "logins.json").read_text(encoding="utf-8")).get("logins"):
                found.append("Firefox")
                break
        except (OSError, ValueError):
            continue
    return found


def _login_count(db: Path) -> int:
    if not db.is_file():
        return 0
    tmp = Path(tempfile.mkdtemp(prefix="sentinel-"))
    try:
        copy = tmp / "logins.db"
        shutil.copy2(db, copy)  # the browser keeps the original locked while it runs
        with sqlite3.connect(copy) as conn:
            return conn.execute("SELECT COUNT(*) FROM logins").fetchone()[0]
    except (OSError, sqlite3.Error):
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
