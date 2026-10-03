"""Optional family DNS filter for adult content, using Cloudflare for Families
(1.1.1.3 / 1.0.0.3), which blocks adult sites far beyond any fixed list.

Turning it on changes the DNS servers of the PC's network adapters (one admin
prompt). What each adapter used before is saved in an admin-only file and put
back when it's turned off.
"""
import base64
import json
import os
import subprocess
from pathlib import Path

FAMILY_V4 = ["1.1.1.3", "1.0.0.3"]
FAMILY_V6 = ["2606:4700:4700::1113", "2606:4700:4700::1003"]
STATE_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "HomeNetManager"
SAVED = STATE_DIR / "previous_dns.json"
CREATE_NO_WINDOW = 0x08000000

_STATUS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$out = foreach ($a in Get-NetAdapter -Physical) {
  $v4 = @((Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4).ServerAddresses)
  [pscustomobject]@{ up = ($a.Status -eq 'Up'); v4 = $v4 }
}
ConvertTo-Json -InputObject @($out) -Compress
"""


def _ps(script: str, timeout=90) -> subprocess.CompletedProcess:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                          capture_output=True, text=True, timeout=timeout, creationflags=CREATE_NO_WINDOW)


def _q(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def is_on() -> bool:
    """True if any connected adapter is using the family filter (reads state)."""
    try:
        data = json.loads(_ps(_STATUS).stdout or "[]")
    except ValueError:
        return False
    adapters = [a for a in data if a.get("up")] or data
    return any(set(a.get("v4") or []) & set(FAMILY_V4) for a in adapters)


def enable():
    from . import elevate
    elevate.run("dns", "on")


def disable():
    from . import elevate
    elevate.run("dns", "off")


# ------------------------------------------------------- admin side --------
def elevated(action: str, args: list[str]):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    saved = json.loads(SAVED.read_text(encoding="utf-8")) if SAVED.exists() else {}
    if action == "on":
        ours = set(FAMILY_V4 + FAMILY_V6)
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
        adapters = json.loads(_ps(script).stdout or "[]")
        for a in adapters:
            fixed = [s for s in (a["v4"] + "," + a["v6"]).replace(" ", ",").split(",") if s]
            if a["guid"] not in saved and not set(fixed) & ours:
                saved[a["guid"]] = {"name": a["name"], "servers": fixed}  # [] means "automatic"
        SAVED.write_text(json.dumps(saved, indent=2), encoding="utf-8")
        servers = ",".join(_q(s) for s in FAMILY_V4 + FAMILY_V6)
        lines = [f"Set-DnsClientServerAddress -InterfaceIndex {int(a['index'])} -ServerAddresses @({servers})"
                 for a in adapters]
    elif action == "off":
        lines = _off_lines(saved)
    else:
        raise RuntimeError(f"unknown dns action {action!r}")
    lines.append("Clear-DnsClientCache")
    body = "\n".join(lines)
    result = _ps("$ProgressPreference = 'SilentlyContinue'; $ErrorActionPreference = 'Stop'\n"
                 f"try {{\n{body}\n}} catch {{ Write-Output ('ERROR: ' + $_.Exception.Message); exit 1 }}")
    if result.returncode != 0:
        errors = [line[7:] for line in result.stdout.splitlines() if line.startswith("ERROR: ")]
        raise RuntimeError(errors[-1].strip() if errors else "couldn't change the DNS settings")
    if action == "off":
        SAVED.unlink(missing_ok=True)


def _off_lines(saved: dict) -> list[str]:
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
    ours = ",".join(_q(ip) for ip in FAMILY_V4)
    lines.append("foreach ($a in Get-NetAdapter -Physical) { $s = @((Get-DnsClientServerAddress -InterfaceIndex "
                 "$a.ifIndex -AddressFamily IPv4).ServerAddresses); if (@($s | Where-Object { @(" + ours +
                 ") -contains $_ }).Count) { Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex "
                 "-ResetServerAddresses } }")
    return lines
