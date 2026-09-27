"""Ransomware shield: Windows' Controlled folder access, managed from Sentinel.

When it's on, only apps Microsoft trusts (and ones you allow) can change files
in protected folders: Documents, Pictures, Videos, Music, Desktop and Favorites
always, plus any folders added here. Anything else, like ransomware, is blocked
by Windows itself, before a single file is changed. It's part of Microsoft
Defender, so it only works while Defender is the active antivirus.

Reading the state works as a normal user. Changing it needs administrator
rights (one Windows prompt each time). What Sentinel changed is recorded in an
admin-only folder, so the uninstaller can undo exactly that and nothing else.
"""
import base64
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from . import paths

STATE_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Sentinel Antivirus" / "shield"
STATE_FILE = STATE_DIR / "state.json"
CREATE_NO_WINDOW = 0x08000000
ALWAYS_PROTECTED = ("documents", "pictures", "videos", "music", "desktop")

_STATUS = r"""
$ErrorActionPreference = 'Stop'
try {
  $p = Get-MpPreference; $s = Get-MpComputerStatus
  [pscustomobject]@{ mode = [int]$p.EnableControlledFolderAccess; folders = @($p.ControlledFolderAccessProtectedFolders);
    am = "$($s.AMRunningMode)"; rtp = [bool]$s.RealTimeProtectionEnabled } | ConvertTo-Json -Compress
} catch { Write-Output ('ERROR: ' + $_.Exception.Message) }
"""
_BLOCKED = r"""
$ErrorActionPreference = 'SilentlyContinue'
$start = (Get-Date).AddDays(-DAYS)
$out = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1123; StartTime=$start} -MaxEvents 300 | ForEach-Object {
  $d = @{}; ([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
  [pscustomobject]@{ time = $_.TimeCreated.ToString('o'); process = $d['Process Name']; path = $d['Path'] }
}
ConvertTo-Json -InputObject @($out) -Compress
"""


@dataclass
class ShieldStatus:
    available: bool          # Defender is the active antivirus
    on: bool
    audit: bool              # "audit mode": only logs, doesn't block
    folders: list            # extra protected folders (beyond Windows' defaults)
    error: str | None = None


@dataclass
class BlockedApp:
    exe: str
    count: int
    last: datetime
    files: list = field(default_factory=list)  # a few examples


def _ps(script: str, timeout=60) -> subprocess.CompletedProcess:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                          capture_output=True, text=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)


def status() -> ShieldStatus:
    out = _ps(_STATUS).stdout.strip()
    if not out or out.startswith("ERROR: "):
        return ShieldStatus(False, False, False, [], error=out[7:] or None)
    data = json.loads(out)
    folders = [f for f in (data.get("folders") or []) if f and not str(f).startswith("N/A")]
    available = data.get("am") == "Normal"
    mode = int(data.get("mode") or 0)
    return ShieldStatus(available, available and mode == 1, available and mode == 2, folders)


def default_folders() -> list[Path]:
    """Folders Windows protects automatically when the shield is on."""
    return [paths.known_folder(name) for name in ALWAYS_PROTECTED]


def blocked(days: int = 30) -> list[BlockedApp]:
    """Apps Windows stopped from changing protected files recently, most recent first."""
    out = _ps(_BLOCKED.replace("DAYS", str(int(days)))).stdout.strip()
    try:
        events = json.loads(out or "[]")
    except ValueError:
        return []
    apps: dict[str, BlockedApp] = {}
    for e in events:
        exe = (e or {}).get("process")
        if not exe:
            continue
        when = datetime.fromisoformat(e["time"])
        app = apps.setdefault(exe.lower(), BlockedApp(exe, 0, when))
        app.count += 1
        app.last = max(app.last, when)
        if e.get("path") and len(app.files) < 3 and e["path"] not in app.files:
            app.files.append(e["path"])
    return sorted(apps.values(), key=lambda a: a.last, reverse=True)


def recorded() -> dict:
    """What Sentinel itself changed: {"enabled_by_sentinel", "folders", "apps"}."""
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    return {"enabled_by_sentinel": bool(data.get("enabled_by_sentinel")), "folders": list(data.get("folders") or []),
            "apps": list(data.get("apps") or [])}


def allowed_apps() -> list[str]:
    """Apps allowed through Sentinel (Windows only shows the full list to administrators)."""
    own = os.path.normcase(sys.executable) if getattr(sys, "frozen", False) else None
    return [a for a in recorded()["apps"] if os.path.normcase(a) != own]


# ------------------------------------------------ changes (admin prompt) --
def _run(*args):
    from . import elevate

    elevate.run("shield", *args)


def turn_on():
    _run("on")


def turn_off():
    _run("off")


def add_folder(folder: str):
    _run("addfolder", folder)


def remove_folder(folder: str):
    _run("removefolder", folder)


def allow_app(exe: str):
    _run("allow", exe)


def disallow_app(exe: str):
    _run("disallow", exe)


def _q(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def elevated(action: str, args: list[str]):
    """Admin side: only these changes, with checked arguments."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(["icacls", str(STATE_DIR), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F",
                    "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/grant:r", "*S-1-5-32-545:(OI)(CI)R"],
                   capture_output=True, creationflags=CREATE_NO_WINDOW)
    state = recorded()
    own = sys.executable if getattr(sys, "frozen", False) else None  # never allow python.exe in a dev run
    if action == "on":
        if status().on is False and not state["enabled_by_sentinel"]:
            state["enabled_by_sentinel"] = True
        lines = ["Set-MpPreference -EnableControlledFolderAccess Enabled"]
        if own:  # so Sentinel can still move threats out of protected folders into quarantine
            lines.append(f"Add-MpPreference -ControlledFolderAccessAllowedApplications {_q(own)}")
            if own not in state["apps"]:
                state["apps"].append(own)
    elif action == "off":
        lines = ["Set-MpPreference -EnableControlledFolderAccess Disabled"]
        state["enabled_by_sentinel"] = False
    elif action in ("addfolder", "removefolder") and args:
        folder = str(Path(args[0]))
        if action == "addfolder" and not Path(folder).is_dir():
            raise RuntimeError(f"not a folder: {folder}")
        verb = "Add" if action == "addfolder" else "Remove"
        lines = [f"{verb}-MpPreference -ControlledFolderAccessProtectedFolders {_q(folder)}"]
        state["folders"] = [f for f in state["folders"] if f.lower() != folder.lower()]
        if action == "addfolder":
            state["folders"].append(folder)
    elif action in ("allow", "disallow") and args:
        exe = str(Path(args[0]))
        if not exe.lower().endswith(".exe") or (action == "allow" and not Path(exe).is_file()):
            raise RuntimeError(f"not a program: {exe}")
        verb = "Add" if action == "allow" else "Remove"
        lines = [f"{verb}-MpPreference -ControlledFolderAccessAllowedApplications {_q(exe)}"]
        state["apps"] = [a for a in state["apps"] if a.lower() != exe.lower()]
        if action == "allow":
            state["apps"].append(exe)
    else:
        raise RuntimeError(f"unknown shield action {action!r}")
    body = "\n".join(lines)
    result = _ps("$ProgressPreference = 'SilentlyContinue'; $ErrorActionPreference = 'Stop'\n"
                 f"try {{\n{body}\n}} catch {{ Write-Output ('ERROR: ' + $_.Exception.Message); exit 1 }}")
    if result.returncode != 0:
        errors = [line[7:] for line in result.stdout.splitlines() if line.startswith("ERROR: ")]
        raise RuntimeError(errors[-1].strip() if errors else "Windows couldn't change Controlled folder access")
    if action in ("on", "off"):  # Tamper Protection can silently undo it; check it really changed
        now = status()
        if now.on != (action == "on"):
            raise RuntimeError("Windows didn't apply the change. Tamper Protection or an organization policy may be "
                               "managing this setting.")
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def undo_script() -> list[str]:
    """PowerShell lines that undo exactly what Sentinel changed (for the uninstaller)."""
    state = recorded()
    lines = [f"Remove-MpPreference -ControlledFolderAccessAllowedApplications {_q(a)} -ErrorAction SilentlyContinue"
             for a in state["apps"]]
    lines += [f"Remove-MpPreference -ControlledFolderAccessProtectedFolders {_q(f)} -ErrorAction SilentlyContinue"
              for f in state["folders"]]
    if state["enabled_by_sentinel"]:
        lines.append("Set-MpPreference -EnableControlledFolderAccess Disabled -ErrorAction SilentlyContinue")
    return lines
