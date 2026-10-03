"""Turns THIS PC's internet off and back on by disabling / enabling the network
adapter(s) it uses.

Why the adapter and not a firewall rule: a firewall rule does nothing if the
Windows Firewall is off or has been taken over by another security product.
Disabling the network adapter cuts the connection at the device level, so it
works no matter what else is installed. Resuming re-enables the same adapters,
and Windows reconnects to your saved Wi-Fi automatically.

After pausing it verifies the internet is really cut, and after resuming it
waits for the connection to come back, so it never silently does nothing.
Both go through the one Windows admin prompt (elevate.py).
"""
import json
import os
import socket
import subprocess
import time
from pathlib import Path

STATE_DIR = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "HomeNetManager"
STATE = STATE_DIR / "paused_adapters.json"
CREATE_NO_WINDOW = 0x08000000
PROBES = [("1.1.1.1", 443), ("8.8.8.8", 443), ("1.1.1.1", 53)]


def _ps(script: str, timeout=60) -> subprocess.CompletedProcess:
    import base64
    enc = base64.b64encode(script.encode("utf-16-le")).decode()
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                           "-EncodedCommand", enc], capture_output=True, text=True, stdin=subprocess.DEVNULL,
                          timeout=timeout, creationflags=CREATE_NO_WINDOW, errors="replace")


def _can_reach(timeout=1.5) -> bool:
    for host, port in PROBES:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def pause_internet():
    from . import elevate
    elevate.run("firewall", "pause")


def resume_internet():
    from . import elevate
    elevate.run("firewall", "resume")


def internet_paused() -> bool:
    """True if adapters we disabled are currently disabled (reads state, no admin)."""
    try:
        names = json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not names:
        return False
    script = ("$n = @(" + ",".join(_q(x) for x in names) + "); "
              "@(Get-NetAdapter -Name $n -ErrorAction SilentlyContinue | "
              "Where-Object { $_.Status -eq 'Disabled' }).Count")
    out = _ps(script, timeout=25).stdout.strip()
    return out.isdigit() and int(out) > 0


def _q(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


# ------------------------------------------------ admin side (one prompt) --
def _set_adapters(names, enable: bool) -> subprocess.CompletedProcess:
    verb = "Enable-NetAdapter" if enable else "Disable-NetAdapter"
    body = "; ".join(f"{verb} -Name {_q(n)} -Confirm:$false" for n in names)
    return _ps("$ErrorActionPreference='Stop'\n"
               f"try {{ {body} }} catch {{ Write-Output ('ERROR: ' + $_.Exception.Message); exit 1 }}")


def elevated(action: str, args: list[str]):
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    if action == "pause":
        could_reach = _can_reach()
        # the physical adapters that are currently up (the ones carrying the internet)
        found = _ps("ConvertTo-Json -Compress -InputObject @(Get-NetAdapter -Physical | "
                    "Where-Object { $_.Status -eq 'Up' } | ForEach-Object { $_.Name })")
        try:
            names = json.loads(found.stdout or "[]")
        except ValueError:
            names = []
        if isinstance(names, str):
            names = [names]
        if not names:
            raise RuntimeError("No active network adapter was found to turn off.")
        res = _set_adapters(names, enable=False)
        if res.returncode != 0:
            err = next((l[7:] for l in res.stdout.splitlines() if l.startswith("ERROR: ")), "")
            raise RuntimeError("Couldn't turn off the network adapter. " + err[:200])
        STATE.write_text(json.dumps(names), encoding="utf-8")
        if could_reach:  # make sure it really went down
            time.sleep(2.0)
            if _can_reach():
                raise RuntimeError("Disabled the adapter but the internet is still reachable — another connection "
                                   "(like a second adapter or a USB tether) may still be up.")

    elif action == "resume":
        try:
            names = json.loads(STATE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            names = []
        if names:
            _set_adapters(names, enable=True)
        # also re-enable any physical adapter left disabled, so we never strand the PC offline
        _ps("Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Disabled' } | "
            "Enable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue")
        STATE.unlink(missing_ok=True)

    else:
        raise RuntimeError(f"unknown firewall action {action!r}")
