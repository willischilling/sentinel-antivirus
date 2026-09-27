"""Email breach check: which known data breaches an email address appears in.

Uses XposedOrNot (xposedornot.com), a free, community-run breach index that
needs no account or API key. The email address is sent to it (that's how the
lookup works); nothing else is, and Sentinel doesn't store the address.
"""
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from .version import VERSION

API = "https://api.xposedornot.com/v1/breach-analytics?email={}"
USER_AGENT = f"Sentinel-Antivirus/{VERSION}"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@dataclass
class Breach:
    name: str
    domain: str
    year: str
    records: int
    data: list = field(default_factory=list)      # what leaked, as the service names it
    details: str = ""
    passwords: bool = False                         # passwords (or hints) were in it


class BreachCheckError(RuntimeError):
    pass


def valid(email: str) -> bool:
    return bool(EMAIL_RE.match(email.strip()))


def check(email: str) -> list[Breach]:
    """Breaches the address is in, most recent first ([] when it's in none)."""
    email = email.strip().lower()
    if not valid(email):
        raise BreachCheckError("invalid")
    request = urllib.request.Request(API.format(urllib.parse.quote(email)), headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []
        raise BreachCheckError("busy" if e.code == 429 else f"HTTP {e.code}")
    except (OSError, ValueError) as e:
        raise BreachCheckError(str(getattr(e, "reason", e)))
    details = ((data or {}).get("ExposedBreaches") or {}).get("breaches_details") or []
    breaches = []
    for d in details:
        leaked = [x.strip() for x in (d.get("xposed_data") or "").split(";") if x.strip()]
        breaches.append(Breach(
            name=d.get("breach") or "?", domain=d.get("domain") or "", year=str(d.get("xposed_date") or ""),
            records=int(d.get("xposed_records") or 0), data=leaked, details=d.get("details") or "",
            passwords=any(x.lower() in ("passwords", "password hints") for x in leaked)))
    return sorted(breaches, key=lambda b: (b.year, b.records), reverse=True)
