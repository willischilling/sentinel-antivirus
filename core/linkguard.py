"""Link guard: warns when you copy a dangerous link, before you paste it anywhere.

The background agent notices when the clipboard changes (Windows keeps a counter,
so nothing is read until it does), and checks any links in newly copied text with
Ask Sentinel's link checks: the phishing and malware lists (Phishing.Database,
URLhaus, OpenPhish) and brand look-alikes like paypa1-secure.com. Only clear red
flags alert; nothing about the clipboard is stored or sent anywhere.
"""
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone

from . import scam_check, settings

MAX_TEXT = 20_000
RECENT_KEEP = 20


@dataclass
class LinkWarning:
    link: str
    host: str
    finding: scam_check.Finding


def enabled() -> bool:
    return settings.load().get("link_guard", True)


def clipboard_counter() -> int:
    """Changes whenever anything is copied (cheap; doesn't read the clipboard)."""
    try:
        return ctypes.windll.user32.GetClipboardSequenceNumber()
    except (AttributeError, OSError):
        return 0


def check_text(text: str) -> list[LinkWarning]:
    """Dangerous links in the text (at most one warning per link, the worst reason)."""
    if not text or len(text) > MAX_TEXT:
        return []
    found = []
    for link in scam_check.extract_links(text)[:5]:
        bad = [f for f in scam_check.check_link(link) if f.level == "bad"]
        if bad:
            found.append(LinkWarning(link, bad[0].values.get("host", link), bad[0]))
    return found


def remember(warning: LinkWarning):
    """Keeps the last few warnings for the Link guard page."""
    recent = settings.load().get("link_alerts") or []
    recent.insert(0, {"link": warning.link[:300], "host": warning.host, "key": warning.finding.key,
                      "values": warning.finding.values, "time": datetime.now(timezone.utc).isoformat()})
    settings.save(link_alerts=recent[:RECENT_KEEP])


def recent() -> list[dict]:
    return settings.load().get("link_alerts") or []


def clear_clipboard() -> bool:
    user32 = ctypes.windll.user32
    if not user32.OpenClipboard(None):
        return False
    try:
        return bool(user32.EmptyClipboard())
    finally:
        user32.CloseClipboard()
