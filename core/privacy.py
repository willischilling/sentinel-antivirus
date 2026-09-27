"""Camera and microphone monitor.

Windows records, per app, when it last started and stopped using the webcam
and the microphone (the same data behind the camera/mic icon in the taskbar),
under CapabilityAccessManager\\ConsentStore in the registry. "Stopped" is zero
while the app is still using it. This module reads that: which apps are using
them right now, and which used them recently. Nothing is recorded or sent.
"""
import winreg
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import settings

BASE = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
DEVICES = ("webcam", "microphone")
_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


@dataclass
class Use:
    device: str            # "webcam" or "microphone"
    key: str               # exe path, or Store app package name
    name: str              # what to show: "Discord.exe", "Microsoft.WindowsCamera"
    path: str | None       # exe path for desktop programs, None for Store apps
    start: datetime | None
    stop: datetime | None

    @property
    def in_use(self) -> bool:
        return self.start is not None and self.stop is None


def _time(value) -> datetime | None:
    if not value:
        return None
    return _EPOCH + timedelta(microseconds=value // 10)


def _entries(device: str):
    try:
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"{BASE}\{device}")
    except OSError:
        return
    with root:
        for i in range(10_000):
            try:
                name = winreg.EnumKey(root, i)
            except OSError:
                break
            if name == "NonPackaged":
                try:
                    sub_root = winreg.OpenKey(root, name)
                except OSError:
                    continue
                with sub_root:
                    for j in range(10_000):
                        try:
                            sub = winreg.EnumKey(sub_root, j)
                        except OSError:
                            break
                        yield sub_root, sub, sub.replace("#", "\\"), True
            else:
                yield root, name, name, False


def usage() -> list[Use]:
    """Every app that has used the camera or microphone, most recent first. Different
    versions of the same program (Discord's app-1.0.x folders) count as one."""
    found: dict[tuple, Use] = {}
    for device in DEVICES:
        for parent, sub, key, desktop in _entries(device):
            try:
                with winreg.OpenKey(parent, sub) as k:
                    start = _value(k, "LastUsedTimeStart")
                    stop = _value(k, "LastUsedTimeStop")
            except OSError:
                continue
            if not start:
                continue
            name = Path(key).name if desktop else key.split("_")[0]
            use = Use(device, key, name, key if desktop else None, _time(start), _time(stop))
            ident = (device, name.lower())
            old = found.get(ident)
            if old is None or (use.in_use and not old.in_use) or (use.start > old.start and not old.in_use):
                found[ident] = use
    return sorted(found.values(), key=lambda u: (not u.in_use, -(u.start.timestamp() if u.start else 0)))


def _value(key, name):
    try:
        return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return 0


def in_use() -> list[Use]:
    return [u for u in usage() if u.in_use]


def allowed() -> set[str]:
    return {a.lower() for a in settings.load().get("privacy_allowed") or []}


def allow(name: str):
    names = list(dict.fromkeys((settings.load().get("privacy_allowed") or []) + [name]))
    settings.save(privacy_allowed=names)


def disallow(name: str):
    settings.save(privacy_allowed=[a for a in settings.load().get("privacy_allowed") or []
                                   if a.lower() != name.lower()])


def alerts_on() -> bool:
    return settings.load().get("privacy_alerts", True)
