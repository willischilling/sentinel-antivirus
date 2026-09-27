"""Startup apps: everything that starts with Windows, with an on/off switch.

Turning an app off works exactly like Task Manager's Startup tab: Windows keeps
an on/off flag per entry under Explorer\\StartupApproved, so nothing is deleted
and turning it back on restores it. Entries for all users are flagged in
HKLM, which needs the admin prompt; your own need nothing.
"""
import struct
import time
import winreg
from dataclasses import dataclass
from pathlib import Path

from . import authenticode

APPROVED = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved"
HKCU, HKLM = winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE
RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_32 = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"

# Words in the name or program -> advice (translation key). Chat, games and music start
# themselves "to be ready"; turning them off only means they open when you open them.
SAFE_TO_DISABLE = ("discord", "steam", "epicgames", "spotify", "teams", "skype", "zoom", "battle.net", "riot",
                   "ubisoft", "eadesktop", "origin", "opera", "cortana", "msedge", "edge startup", "itunes",
                   "adobe creative cloud", "ccxprocess", "adobegcclient", "dropbox", "googledrivesync", "whatsapp",
                   "telegram", "slack", "obs", "medal", "overwolf", "razer", "logitech g hub", "lghub", "icue",
                   "wallpaper", "utorrent", "bittorrent", "qbittorrent", "ccleaner", "grammarly")
KEEP_ON = ("securityhealth", "windows defender", "windowsdefender", "realtek", "rtkaud", "nvidia", "amd", "radeon",
           "intel", "synaptics", "elan", "bluetooth", "onedrive", "sentinel", "igfx", "wacom", "dolby", "waves")


@dataclass
class StartupApp:
    name: str
    command: str
    program: Path | None
    publisher: str | None
    enabled: bool
    scope: str            # "user" or "all" (all users: changing needs admin)
    approved_key: str     # StartupApproved subkey: Run, Run32 or StartupFolder
    advice: str | None    # translation key, or None


def _approved(hive, sub: str, name: str) -> bool:
    try:
        with winreg.OpenKey(hive, rf"{APPROVED}\{sub}") as key:
            data = winreg.QueryValueEx(key, name)[0]
    except OSError:
        return True  # no flag: on
    return not (isinstance(data, bytes) and data and data[0] & 1)  # odd first byte: turned off


def _advice(name: str, program: Path | None, publisher: str | None) -> str | None:
    text = f"{name} {program.name if program else ''}".lower()
    if any(w in text for w in KEEP_ON):
        return "startup_keep"
    if any(w in text for w in SAFE_TO_DISABLE):
        return "startup_safe"
    if not publisher:
        return "startup_unknown"
    return None


def list_apps() -> list[StartupApp]:
    from monitor import startup_watcher

    user_folder, all_folder = (str(f) for f, _label in startup_watcher.default_folder_locations())
    locations = [(HKCU, RUN, "Startup registry (your account)"), (HKLM, RUN, "Startup registry (all users)"),
                 (HKLM, RUN_32, "Startup registry (all users, 32-bit)")]
    entries = startup_watcher.snapshot(locations)
    apps = []
    for entry in entries.values():
        if entry.kind == "registry":
            hive = entry.hive
            sub = "Run32" if entry.key == RUN_32 else "Run"
        else:
            hive = HKLM if str(entry.file.parent) == all_folder else HKCU
            sub = "StartupFolder"
        program = startup_watcher.target_program(entry)
        signature = authenticode.check(program) if program else None
        publisher = signature.publisher if signature and signature.signed else None
        display = entry.name[:-4] if entry.kind == "folder" and entry.name.lower().endswith(".lnk") else entry.name
        apps.append(StartupApp(display, entry.command, program, publisher, _approved(hive, sub, entry.name),
                               "user" if hive == HKCU else "all", sub, _advice(entry.name, program, publisher)))
        apps[-1]._value_name = entry.name  # the name Windows' flag is stored under
    return sorted(apps, key=lambda a: (not a.enabled, a.name.lower()))


def _flag(on: bool) -> bytes:
    if on:
        return bytes([2]) + bytes(11)
    filetime = int((time.time() + 11644473600) * 10_000_000)  # when it was turned off, as Task Manager records
    return bytes([3, 0, 0, 0]) + struct.pack("<Q", filetime)


def set_enabled(app: StartupApp, on: bool):
    name = getattr(app, "_value_name", app.name)
    if app.scope == "user":
        _write(HKCU, app.approved_key, name, on)
    else:
        from . import elevate

        elevate.run("startupapps", app.approved_key, name, "on" if on else "off")


def _write(hive, sub: str, name: str, on: bool):
    if sub not in ("Run", "Run32", "StartupFolder"):
        raise RuntimeError(f"not a startup list: {sub}")
    with winreg.CreateKeyEx(hive, rf"{APPROVED}\{sub}", 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_BINARY, _flag(on))


def elevated(args: list[str]):
    """Admin side: turn one all-users startup entry on or off (nothing else)."""
    if len(args) != 3 or args[2] not in ("on", "off"):
        raise RuntimeError("bad startup apps arguments")
    _write(HKLM, args[0], args[1], args[2] == "on")
