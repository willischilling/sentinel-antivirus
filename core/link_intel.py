"""Known phishing and malware links, for Ask Sentinel's link checks.

- Phishing.Database: ~390,000 active phishing domains (whole-host matches).
- URLhaus (abuse.ch): hosts that exist only to spread malware, plus the exact
  URLs of live malware downloads. Many of those sit on legitimate sites
  (GitHub, Discord's CDN...), so for them only the exact URL counts.
- OpenPhish: the current community feed of phishing URLs (exact URLs).

Only hostnames and URL text are downloaded. Updated with the threat database.
"""
import urllib.request
from urllib.parse import urlsplit

from . import database

PHISHING_DB_URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt"
URLHAUS_HOSTS_URL = "https://urlhaus.abuse.ch/downloads/hostfile/"
URLHAUS_URLS_URL = "https://urlhaus.abuse.ch/downloads/text_online/"
OPENPHISH_URL = "https://openphish.com/feed.txt"
USER_AGENT = "Sentinel-Antivirus/1.0"

# Big shared platforms where anyone can publish a page. Scammers use them, so they
# show up on phishing lists, but the platform itself must never be flagged as a
# whole; only a specific bad URL on it can be.
SHARED_HOSTS = {
    "sites.google.com", "docs.google.com", "drive.google.com", "forms.gle", "github.com",
    "raw.githubusercontent.com", "cdn.discordapp.com", "dropbox.com", "www.dropbox.com",
    "onedrive.live.com", "1drv.ms", "bit.ly", "tinyurl.com", "t.co",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS bad_hosts (host TEXT PRIMARY KEY, source TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bad_urls (url TEXT PRIMARY KEY, source TEXT NOT NULL) WITHOUT ROWID;
"""


def _download(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=180) as response:
        return response.read().decode("utf-8", errors="replace")


def normalize_url(url: str) -> str:
    """Lowercase scheme and host, no fragment, no trailing slash: how both sides are compared."""
    parts = urlsplit(url.strip())
    host = (parts.hostname or "").lower()
    port = f":{parts.port}" if parts.port else ""
    path = parts.path.rstrip("/")
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme.lower()}://{host}{port}{path}{query}"


def install(progress=lambda key: None):
    progress("intel_downloading_links")
    hosts = [(h, "Phishing.Database") for h in _lines(_download(PHISHING_DB_URL))]
    hosts += [(line.split()[1], "URLhaus") for line in _download(URLHAUS_HOSTS_URL).splitlines()
              if line.startswith("127.0.0.1") and len(line.split()) > 1]
    urls = [(u, "URLhaus") for u in _lines(_download(URLHAUS_URLS_URL))]
    urls += [(u, "OpenPhish") for u in _lines(_download(OPENPHISH_URL))]
    with database.connect() as conn:
        conn.executescript(SCHEMA)
        # Replace the lists: they only contain what's active now.
        conn.execute("DELETE FROM bad_hosts")
        conn.execute("DELETE FROM bad_urls")
        conn.executemany("INSERT OR IGNORE INTO bad_hosts VALUES (?, ?)",
                         ((h.lower(), s) for h, s in hosts if h.lower() not in SHARED_HOSTS))
        conn.executemany("INSERT OR IGNORE INTO bad_urls VALUES (?, ?)",
                         ((normalize_url(u), s) for u, s in urls if "://" in u))
    database.set_meta(links_hosts=len(hosts), links_urls=len(urls))


def _lines(text: str):
    return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]


def lookup(url: str) -> str | None:
    """The list that has this URL (or its host) as phishing/malware, else None."""
    host = (urlsplit(url).hostname or "").lower()
    with database.connect() as conn:
        conn.executescript(SCHEMA)
        row = conn.execute("SELECT source FROM bad_urls WHERE url = ?", (normalize_url(url),)).fetchone()
        if row:
            return row[0]
        if host and host not in SHARED_HOSTS:
            for candidate in (host, host.removeprefix("www.")):
                row = conn.execute("SELECT source FROM bad_hosts WHERE host = ?", (candidate,)).fetchone()
                if row:
                    return row[0]
    return None


def available() -> bool:
    return bool(database.get_meta("links_hosts"))
