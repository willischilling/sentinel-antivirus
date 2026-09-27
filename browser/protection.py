"""What Sentinel Browser checks, separate from the window code so it can be tested alone.

- Sites: every page and frame address goes through Ask Sentinel's link checks
  (the Phishing.Database / URLhaus / OpenPhish lists Sentinel keeps updated, and
  brand look-alikes like paypa1-secure.com). A red flag blocks the page.
- Ads and trackers: requests to servers on Peter Lowe's ad/tracking server list
  (pgl.yoyo.org, ~3,500 servers, refreshed weekly) plus a few big trackers are
  blocked, except the site's own servers (so logins and checkouts keep working).
- HTTPS-only: plain http:// addresses are upgraded to https://.
"""
import json
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from core import paths, scam_check, settings
from core.version import VERSION

TRACKER_URL = "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&mimetype=plaintext"
TRACKER_PATH = paths.DATA_DIR / "browser_trackers.txt"
TRACKER_MAX_AGE = 7 * 24 * 3600
BUILT_IN_TRACKERS = {
    "google-analytics.com", "googletagmanager.com", "doubleclick.net", "googlesyndication.com", "adservice.google.com",
    "scorecardresearch.com", "hotjar.com", "quantserve.com", "criteo.com", "criteo.net", "taboola.com",
    "outbrain.com", "adnxs.com", "rubiconproject.com", "pubmatic.com", "moatads.com", "amazon-adsystem.com",
    "adsrvr.org", "bat.bing.com", "clarity.ms", "mixpanel.com", "segment.io", "newrelic.com", "branch.io",
}
LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]")
DEFAULTS = {"block_trackers": True, "https_only": True}


def options() -> dict:
    return {**DEFAULTS, **(settings.load().get("browser") or {})}


def set_option(name: str, value: bool):
    current = settings.load().get("browser") or {}
    current[name] = value
    settings.save(browser=current)


# --------------------------------------------------------------- sites --
class Verdict:
    def __init__(self, level: str, key: str | None = None, values: dict | None = None):
        self.level = level      # "safe", "caution" or "blocked"
        self.key = key          # translation key of the reason
        self.values = values or {}


def check_site(url: str) -> Verdict:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return Verdict("safe")
    findings = scam_check.check_link(url)
    bad = [f for f in findings if f.level == "bad"]
    if bad:
        return Verdict("blocked", bad[0].key, bad[0].values)
    warn = [f for f in findings if f.level == "warn"]
    if warn:
        return Verdict("caution", warn[0].key, warn[0].values)
    return Verdict("safe")


def upgrade_to_https(url: str) -> str | None:
    """The https:// version of a plain http:// address (None if it shouldn't be upgraded)."""
    parts = urlsplit(url)
    if parts.scheme != "http" or not parts.hostname or parts.hostname in LOCAL_HOSTS:
        return None
    host = parts.hostname
    if host.endswith(".local") or host.startswith(("192.168.", "10.")) or host.startswith("172."):
        return None  # your router's and devices' own pages usually have no https
    return "https://" + url[len("http://"):]


# ------------------------------------------------------------ trackers --
class TrackerList:
    def __init__(self):
        self.hosts = set(BUILT_IN_TRACKERS)
        self._load()

    def _load(self):
        try:
            text = TRACKER_PATH.read_text(encoding="utf-8")
            self.hosts |= {line.strip().lower() for line in text.splitlines() if line.strip() and "." in line}
        except OSError:
            pass

    def refresh_if_old(self):
        """Downloads the list again when it's a week old (called off the UI thread)."""
        try:
            if TRACKER_PATH.exists() and time.time() - TRACKER_PATH.stat().st_mtime < TRACKER_MAX_AGE:
                return
            request = urllib.request.Request(TRACKER_URL, headers={"User-Agent": f"Sentinel-Browser/{VERSION}"})
            with urllib.request.urlopen(request, timeout=30) as response:
                text = response.read().decode("utf-8", errors="replace")
            if text.count("\n") > 1000:
                TRACKER_PATH.write_text(text, encoding="utf-8")
                self._load()
        except OSError:
            pass

    def blocks(self, request_host: str, page_host: str) -> bool:
        """True if the request goes to a known ad/tracking server that isn't the page's own site."""
        request_host = (request_host or "").lower()
        if not request_host or _same_site(request_host, page_host):
            return False
        labels = request_host.split(".")
        return any(".".join(labels[i:]) in self.hosts for i in range(len(labels) - 1))


def _same_site(a: str, b: str) -> bool:
    return bool(b) and scam_check.registrable(a) == scam_check.registrable(b.lower())


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def display_url(url: str) -> str:
    """What the address bar shows: no https://, and friendly names for Sentinel's own pages."""
    if url.startswith("https://sentinel.local/"):
        return ""
    return url.split("://", 1)[1] if url.startswith(("https://", "http://")) else url


def to_url(text: str) -> str:
    """Address bar input -> address: a site, or a private DuckDuckGo search."""
    text = text.strip()
    if not text:
        return "https://sentinel.local/start.html"
    if "://" in text or text.startswith("about:"):
        return text
    if " " not in text and "." in text and not text.endswith("."):
        return "https://" + text
    from urllib.parse import quote_plus

    return "https://duckduckgo.com/?q=" + quote_plus(text)


def page_payload(**values) -> str:
    return json.dumps(values)
