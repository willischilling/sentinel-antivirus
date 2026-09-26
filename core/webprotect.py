"""Web protection: blocks scam and malware websites in every browser and app,
by pointing Windows' website lookups (DNS) at a free filtering service.

  standard: Quad9 (Swiss non-profit; blocks malware and phishing domains,
            doesn't log IP addresses)
  family:   Cloudflare for Families (also blocks adult sites)

Turning it on changes the DNS servers of the PC's network adapters, which
needs administrator rights (one Windows prompt). What each adapter used
before is saved in an admin-only folder and put back when it's turned off,
whether that was automatic (from the router) or a fixed address.
"""
import base64
import json
import os
import socket
import subprocess
from dataclasses import dataclass
from pathlib import Path

LEVELS = {
    "standard": {"v4": ["9.9.9.9", "149.112.112.112"], "v6": ["2620:fe::fe", "2620:fe::9"],
                 "test": "isitblocked.org"},
    "family": {"v4": ["1.1.1.3", "1.0.0.3"], "v6": ["2606:4700:4700::1113", "2606:4700:4700::1003"],
               "test": "malware.testcategory.com"},
}
STATE_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Sentinel Antivirus" / "webprotect"
SAVED = STATE_DIR / "previous_dns.json"
CREATE_NO_WINDOW = 0x08000000

_STATUS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$out = foreach ($a in Get-NetAdapter -Physical) {
  $v4 = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4).ServerAddresses)
  [pscustomobject]@{ name = $a.Name; up = ($a.Status -eq 'Up'); v4 = $v4 }
}
ConvertTo-Json -InputObject @($out) -Compress
"""


@dataclass
class Adapter:
    name: str
    up: bool
    servers: list


@dataclass
class WebStatus:
    level: str | None       # "standard", "family", or None when off
    adapters: list          # every physical network adapter
    missing: list           # connected adapters that aren't using the filter

    @property
    def on(self) -> bool:
        return self.level is not None


def _ps(script: str, timeout=90) -> subprocess.CompletedProcess:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                          capture_output=True, text=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)


def status() -> WebStatus:
    data = json.loads(_ps(_STATUS).stdout or "[]")
    adapters = [Adapter(a["name"], bool(a["up"]), [s for s in (a.get("v4") or []) if s]) for a in data]
    connected = [a for a in adapters if a.up] or adapters
    level = None
    for key, info in LEVELS.items():
        if any(set(a.servers) & set(info["v4"]) for a in connected):
            level = key
    missing = [a.name for a in connected if level and not set(a.servers) & set(LEVELS[level]["v4"])]
    return WebStatus(level, adapters, missing)


def check_blocking(level: str) -> bool:
    """True if the level's test site is blocked right now (i.e. the filter is really in use)."""
    try:
        results = socket.getaddrinfo(LEVELS[level]["test"], 443)
    except socket.gaierror:
        return True  # doesn't resolve: blocked
    return all(r[4][0] in ("0.0.0.0", "::") for r in results)


# ------------------------------------------------ changes (admin prompt) --
def enable(level: str):
    from . import elevate

    elevate.run("webprotect", "on", level)


def disable():
    from . import elevate

    elevate.run("webprotect", "off")


def _q(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def elevated(action: str, args: list[str]):
    """Admin side: only turning the filter on (with a known level) or off."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    subprocess.run(["icacls", str(STATE_DIR), "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F",
                    "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/grant:r", "*S-1-5-32-545:(OI)(CI)R"],
                   capture_output=True, creationflags=CREATE_NO_WINDOW)
    saved = json.loads(SAVED.read_text(encoding="utf-8")) if SAVED.exists() else {}
    if action == "on" and args and args[0] in LEVELS:
        info = LEVELS[args[0]]
        ours = {ip for lvl in LEVELS.values() for ip in lvl["v4"] + lvl["v6"]}
        # Remember each adapter's own DNS the first time (not our filter's, when switching levels).
        script = r"""
$ErrorActionPreference = 'Stop'
$out = foreach ($a in Get-NetAdapter -Physical) {
  $key = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($a.InterfaceGuid)"
  $key6 = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$($a.InterfaceGuid)"
  [pscustomobject]@{ guid = "$($a.InterfaceGuid)"; name = $a.Name; index = $a.ifIndex;
    v4 = "$((Get-ItemProperty $key -ErrorAction SilentlyContinue).NameServer)";
    v6 = "$((Get-ItemProperty $key6 -ErrorAction SilentlyContinue).NameServer)" }
}
ConvertTo-Json -InputObject @($out) -Compress
"""
        result = _ps(script)
        adapters = json.loads(result.stdout or "[]")
        for a in adapters:
            fixed = [s for s in (a["v4"] + "," + a["v6"]).replace(" ", ",").split(",") if s]
            if a["guid"] not in saved and not set(fixed) & ours:
                saved[a["guid"]] = {"name": a["name"], "servers": fixed}  # [] means "automatic"
        SAVED.write_text(json.dumps(saved, indent=2), encoding="utf-8")
        servers = ",".join(_q(s) for s in info["v4"] + info["v6"])
        lines = [f"Set-DnsClientServerAddress -InterfaceIndex {int(a['index'])} -ServerAddresses @({servers})"
                 for a in adapters]
    elif action == "off":
        lines = off_script(saved)
    else:
        raise RuntimeError(f"unknown web protection action {action!r}")
    lines.append("Clear-DnsClientCache")
    body = "\n".join(lines)
    result = _ps("$ProgressPreference = 'SilentlyContinue'; $ErrorActionPreference = 'Stop'\n"
                 f"try {{\n{body}\n}} catch {{ Write-Output ('ERROR: ' + $_.Exception.Message); exit 1 }}")
    if result.returncode != 0:
        errors = [line[7:] for line in result.stdout.splitlines() if line.startswith("ERROR: ")]
        raise RuntimeError(errors[-1].strip() if errors else "couldn't change the DNS settings")
    if action == "off":
        SAVED.unlink(missing_ok=True)


def saved_settings() -> dict:
    try:
        return json.loads(SAVED.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def off_script(saved: dict) -> list[str]:
    """PowerShell lines that put every adapter's DNS back the way it was."""
    lines = []
    for guid, prev in saved.items():
        find = f"$a = Get-NetAdapter -Physical | Where-Object {{ \"$($_.InterfaceGuid)\" -eq {_q(guid)} }}"
        if prev["servers"]:
            servers = ",".join(_q(s) for s in prev["servers"])
            lines.append(f"{find}; if ($a) {{ Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex "
                         f"-ServerAddresses @({servers}) }}")
        else:
            lines.append(f"{find}; if ($a) {{ Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex "
                         "-ResetServerAddresses }")
    # Adapters we never saw (added later) but that use our filter: back to automatic.
    ours = ",".join(_q(ip) for lvl in LEVELS.values() for ip in lvl["v4"])
    lines.append("foreach ($a in Get-NetAdapter -Physical) { $s = @((Get-DnsClientServerAddress -InterfaceIndex "
                 "$a.ifIndex -AddressFamily IPv4).ServerAddresses); if (@($s | Where-Object { @(" + ours +
                 ") -contains $_ }).Count) { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex "
                 "-ResetServerAddresses } }")
    return lines
