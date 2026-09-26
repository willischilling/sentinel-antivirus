"""Checks GitHub for a newer Sentinel release and installs it.

The installer is downloaded from this repository's latest GitHub release and
its SHA-256 is compared with the digest GitHub publishes for that file before
it is ever run. It then runs in --update mode: no questions, keeps the user's
choices, and reopens Sentinel when done.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .version import VERSION

REPO = "willischilling/sentinel-antivirus"
# Overridable for testing against a local server.
LATEST_URL = os.environ.get("SENTINEL_UPDATE_URL",
                            f"https://api.github.com/repos/{REPO}/releases/latest")
ASSET_NAME = "SentinelSetup.exe"
USER_AGENT = f"Sentinel-Antivirus/{VERSION}"
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200


@dataclass
class Release:
    version: str
    notes: str
    url: str
    size: int
    sha256: str | None
    page: str


def parse_version(text: str) -> tuple[int, ...]:
    parts = []
    for piece in text.strip().lstrip("vV").split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts + [0] * (3 - len(parts)))


def is_newer(candidate: str, current: str = VERSION) -> bool:
    return parse_version(candidate) > parse_version(current)


def can_self_update() -> bool:
    """Only the installed app can replace itself; a run from source can't."""
    return getattr(sys, "frozen", False)


def latest_release(timeout: int = 20) -> Release:
    request = urllib.request.Request(LATEST_URL, headers={
        "User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.loads(response.read().decode("utf-8"))
    asset = next((a for a in data.get("assets", []) if a.get("name") == ASSET_NAME), None)
    if asset is None:
        raise RuntimeError(f"The latest release has no {ASSET_NAME}")
    digest = asset.get("digest") or ""
    return Release(
        version=data.get("tag_name", "").lstrip("vV"),
        notes=data.get("body") or "",
        url=asset["browser_download_url"],
        size=int(asset.get("size") or 0),
        sha256=digest.split(":", 1)[1].lower() if digest.startswith("sha256:") else None,
        page=data.get("html_url", ""),
    )


def download(release: Release, progress=lambda done, total: None, cancelled=lambda: False) -> Path:
    """Downloads the installer to a temp file and verifies it. Returns its path."""
    if not release.sha256:
        raise RuntimeError("GitHub didn't provide a checksum for this download, so it won't be run.")
    target = Path(tempfile.gettempdir()) / f"SentinelSetup-{release.version}.exe"
    partial = target.with_suffix(".part")
    digest = hashlib.sha256()
    done = 0
    request = urllib.request.Request(release.url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response, open(partial, "wb") as out:
        total = int(response.headers.get("Content-Length") or release.size or 0)
        while True:
            if cancelled():
                raise RuntimeError("Cancelled")
            chunk = response.read(256 * 1024)
            if not chunk:
                break
            out.write(chunk)
            digest.update(chunk)
            done += len(chunk)
            progress(done, total)
    if digest.hexdigest() != release.sha256:
        partial.unlink(missing_ok=True)
        raise RuntimeError("The download didn't match GitHub's checksum, so it was deleted and not run.")
    os.replace(partial, target)
    return target


def launch_installer(installer: Path):
    """Starts the installer in automatic update mode, detached, so it can close
    and replace this app while it runs."""
    subprocess.Popen([str(installer), "--update"], cwd=str(installer.parent),
                     creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP, close_fds=True)
