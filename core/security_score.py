"""The security score: a checklist of what protects this PC, each item
weighted, adding up to a score out of 100.

gather() runs the slow checks (PowerShell, the registry) and is called from a
worker thread; the window passes in what it already knows (whether the
background protection runs, Sentinel's own update state, the app update list).
"""
import subprocess
import winreg
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from . import autostart, firewall, schedule, settings, threat_intel, webprotect

CREATE_NO_WINDOW = 0x08000000


@dataclass
class Check:
    key: str            # translation keys: score_<key> (title), score_<key>_ok / _bad (detail)
    ok: bool | None     # None = couldn't tell (doesn't count against the score)
    weight: int
    fix: str | None = None   # what the Fix button does (handled by the window)
    detail: dict | None = None

    @property
    def points(self) -> int:
        return self.weight if self.ok else 0


def _defender_on() -> bool | None:
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                              "$m = Get-MpComputerStatus; \"$($m.AntivirusEnabled) $($m.RealTimeProtectionEnabled)\""],
                             capture_output=True, text=True, timeout=30, creationflags=CREATE_NO_WINDOW).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    words = out.split()
    return (words == ["True", "True"]) if len(words) == 2 else None


def _uac_on() -> bool | None:
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            return winreg.QueryValueEx(key, "EnableLUA")[0] == 1
    except OSError:
        return None


def gather(protection_on: bool, sentinel_current: bool | None, outdated_apps: int | None) -> list[Check]:
    checks = [Check("protection", protection_on, 20, "protection")]

    updated = threat_intel.last_update()
    fresh = bool(updated and datetime.now(timezone.utc) - updated < timedelta(days=2))
    checks.append(Check("intel", fresh, 10, "intel"))

    try:
        fw = firewall.status()
        checks.append(Check("firewall", fw.all_enabled and not fw.lockdown, 15, "firewall"))
    except Exception:
        checks.append(Check("firewall", None, 15))

    checks.append(Check("defender", _defender_on(), 10, "defender"))

    try:
        checks.append(Check("web", webprotect.status().on, 10, "web"))
    except Exception:
        checks.append(Check("web", None, 10))

    checks.append(Check("apps", None if outdated_apps is None else outdated_apps == 0, 10, "apps",
                        {"n": outdated_apps or 0}))
    checks.append(Check("sentinel", sentinel_current, 5, "updates"))
    checks.append(Check("schedule", schedule.get()["frequency"] != "off", 5, "schedule"))

    last = settings.load().get("last_scan")
    recent = False
    if last:
        try:
            recent = datetime.now().astimezone() - datetime.fromisoformat(last["time"]) < timedelta(days=8)
        except (KeyError, ValueError):
            pass
    checks.append(Check("scanned", recent, 5, "scan"))
    checks.append(Check("autostart", autostart.is_enabled() if autostart.supported() else None, 5, "autostart"))
    checks.append(Check("uac", _uac_on(), 5, "uac"))
    return checks


def score(checks: list[Check]) -> int:
    counted = [c for c in checks if c.ok is not None]
    total = sum(c.weight for c in counted)
    return round(100 * sum(c.points for c in counted) / total) if total else 0
