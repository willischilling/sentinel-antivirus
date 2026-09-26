"""Out-of-date apps, found and updated with Windows' own package manager
(winget, the "App Installer" that ships with Windows 10 and 11).

Old versions of apps are one of the most common ways into a PC, so the
Updates tab lists every app winget knows a newer version of, with one-click
updates. Only the "winget" source is used (Microsoft's community repository,
where installers are checked by hash); Microsoft Store apps update themselves.
"""
import re
import shutil
import subprocess
from dataclasses import dataclass

CREATE_NO_WINDOW = 0x08000000
COMMON = ["--source", "winget", "--accept-source-agreements", "--disable-interactivity"]


@dataclass
class AppUpdate:
    name: str
    id: str
    version: str
    available: str


def available() -> bool:
    return shutil.which("winget") is not None


def _run(args, timeout):
    return subprocess.run(["winget", *args], capture_output=True, encoding="utf-8", errors="replace",
                          timeout=timeout, creationflags=CREATE_NO_WINDOW)


def list_updates() -> list[AppUpdate]:
    out = _run(["upgrade", "--include-unknown", *COMMON], timeout=180).stdout
    return parse_table(out)


def parse_table(text: str) -> list[AppUpdate]:
    """Reads winget's table. Column positions come from the header row (the line above the
    dashes), so names with spaces are read correctly whatever language winget prints in."""
    lines = [line.rstrip("\r") for line in text.splitlines()]
    try:
        dash = next(i for i, line in enumerate(lines) if re.fullmatch(r"-{20,}", line.strip()))
    except StopIteration:
        return []
    header = lines[dash - 1]
    # The progress spinner can leave junk before the header; the header is the last run of words.
    starts = [m.start() for m in re.finditer(r"(?:(?<=\s)|^)\S", header)]
    if len(starts) < 4:
        return []
    cols = starts[:5] + [None] * (5 - len(starts[:5]))
    updates = []
    for line in lines[dash + 1:]:
        if not line.strip() or len(line) < cols[3]:
            break  # the summary lines after the table
        def cell(i):
            end = cols[i + 1] if i + 1 < len(cols) and cols[i + 1] is not None else None
            return line[cols[i]:end].strip()
        name, pkg_id, version, new = cell(0), cell(1), cell(2), cell(3)
        if pkg_id and new and " " not in pkg_id:
            updates.append(AppUpdate(name.rstrip("…").strip(), pkg_id, version, new))
    return updates


def upgrade(pkg_id: str) -> tuple[bool, str]:
    """Installs the newest version of one app. Its installer may show the Windows admin prompt."""
    if not re.fullmatch(r"[\w.+\-]+", pkg_id):
        return False, "invalid package id"
    result = _run(["upgrade", "--id", pkg_id, "--exact", "--silent", "--accept-package-agreements", *COMMON],
                  timeout=1800)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip() and not re.fullmatch(r"[-\\|/ ]+", line.strip())]
    message = lines[-1] if lines else ""
    return result.returncode == 0, message
