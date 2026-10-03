"""Checks whether a newer version of the app has been published, using the
project's GitHub Releases. The check only reads a public page; it never sends
anything about you. Downloading an update opens it in your browser so you stay
in control.
"""
import json
import re
import urllib.request

from . import __version__

# Where published builds live. If releases are published here, the app finds
# them; if none exist yet, the app simply reports it's up to date.
RELEASES_API = "https://api.github.com/repos/willischilling/sentinel-antivirus/releases/latest"
RELEASES_PAGE = "https://github.com/willischilling/sentinel-antivirus/releases"
USER_AGENT = "HomeNetManager/" + __version__


def _nums(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:3]) or (0,)


def check() -> dict:
    """Returns one of:
      {"status": "current", "version": "2.0.0"}
      {"status": "update", "version": "2.1.0", "current": "2.0.0", "url": ..., "notes": ...}
      {"status": "none"}          # no releases published yet
      {"status": "error", "message": ...}
    """
    req = urllib.request.Request(RELEASES_API, headers={"User-Agent": USER_AGENT,
                                                        "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "none"}
        return {"status": "error", "message": f"GitHub returned {e.code}."}
    except Exception as e:
        return {"status": "error", "message": f"Couldn't reach the update server ({e})."}

    latest = (data.get("tag_name") or data.get("name") or "").lstrip("vV")
    if not latest:
        return {"status": "none"}
    url = data.get("html_url") or RELEASES_PAGE
    # prefer a direct .zip/.exe asset link if present
    for asset in data.get("assets") or []:
        name = (asset.get("name") or "").lower()
        if name.endswith((".zip", ".exe")) and asset.get("browser_download_url"):
            url = asset["browser_download_url"]
            break
    if _nums(latest) > _nums(__version__):
        return {"status": "update", "version": latest, "current": __version__, "url": url,
                "notes": (data.get("body") or "").strip()}
    return {"status": "current", "version": __version__}
