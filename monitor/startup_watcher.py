"""Alerts when a program adds itself to Windows startup, a common way for
malware to survive reboots.

Watches the registry Run/RunOnce keys and Startup folders (every few seconds)
and Task Scheduler tasks (every few minutes, since listing them is slow).
Entries that exist when a location is first watched become its baseline;
anything added later is reported once. Baselines are saved, so entries added
while Sentinel wasn't running are still caught at next start.
"""
import json
import os
import shutil
import subprocess
import time
import winreg
from dataclasses import dataclass
from pathlib import Path

from core import database, paths

HKCU, HKLM = winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE
RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_ONCE = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
RUN_32 = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"

# (hive, key, label) for registry locations; folders are listed separately.
DEFAULT_REG_LOCATIONS = [
    (HKCU, RUN, "Startup registry (your account)"),
    (HKCU, RUN_ONCE, "Run-once registry (your account)"),
    (HKLM, RUN, "Startup registry (all users)"),
    (HKLM, RUN_ONCE, "Run-once registry (all users)"),
    (HKLM, RUN_32, "Startup registry (all users, 32-bit)"),
]
IGNORED_NAMES = {"SentinelAntivirus"}  # our own start-with-Windows entry
META_KEY = "startup_known"
# v2: component (COM) tasks are now recorded as "com:{CLSID}" instead of
# "(no program)", so they get a fresh baseline rather than all looking changed.
TASKS_META_KEY = "startup_known_tasks_v2"
TASK_POLL_SECONDS = 300
TASK_LOCATION = "Scheduled task"
_TASK_SCRIPT = (
    "Get-ScheduledTask | ForEach-Object { [pscustomobject]@{ n = $_.TaskPath + $_.TaskName; "
    "a = (($_.Actions | ForEach-Object { if ($_.Execute) { ($_.Execute + ' ' + $_.Arguments).Trim() } "
    "elseif ($_.ClassId) { 'com:' + $_.ClassId } }) -join ' ; ') } } | ConvertTo-Json -Compress"
)
COM_PREFIX = "com:"

# Publishers whose signed programs may add themselves to startup without a popup.
TRUSTED_PUBLISHERS = {"Microsoft Corporation", "Microsoft Windows", "Microsoft Windows Publisher"}
# Microsoft-signed programs that run whatever they're told to. Malware often
# hides behind these, so entries launching them always alert.
LAUNCHERS = {
    "powershell.exe", "pwsh.exe", "powershell_ise.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "msiexec.exe", "explorer.exe", "conhost.exe", "schtasks.exe", "forfiles.exe",
    "certutil.exe", "bitsadmin.exe", "curl.exe", "wmic.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
    "regsvcs.exe", "cmstp.exe", "odbcconf.exe", "pcalua.exe", "hh.exe", "bash.exe", "wsl.exe", "msdt.exe",
    "control.exe", "mmc.exe", "wmiprvse.exe", "scriptrunner.exe", "syncappvpublishingserver.exe",
}
CREATE_NO_WINDOW = 0x08000000


def default_folder_locations():
    return [(paths.known_folder("startup"), "Startup folder (your account)"),
            (paths.known_folder("common_startup"), "Startup folder (all users)")]


@dataclass
class StartupEntry:
    location: str        # human-readable place
    name: str
    command: str
    kind: str            # "registry", "folder" or "task"
    hive: int | None = None
    key: str | None = None
    file: Path | None = None

    @property
    def id(self) -> str:
        return f"{self.location}|{self.name}"


def snapshot(reg_locations=None, folder_locations=None) -> dict[str, StartupEntry]:
    reg_locations = DEFAULT_REG_LOCATIONS if reg_locations is None else reg_locations
    folder_locations = default_folder_locations() if folder_locations is None else folder_locations
    entries = {}
    for hive, key, label in reg_locations:
        try:
            with winreg.OpenKey(hive, key, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    if name and name not in IGNORED_NAMES:
                        e = StartupEntry(label, name, str(value), "registry", hive=hive, key=key)
                        entries[e.id] = e
        except OSError:
            continue
    for folder, label in folder_locations:
        try:
            for f in Path(folder).iterdir():
                if f.is_file() and f.name.lower() != "desktop.ini":
                    e = StartupEntry(label, f.name, str(f), "folder", file=f)
                    entries[e.id] = e
        except OSError:
            continue
    return entries


def com_server(clsid: str) -> str | None:
    """The file registered for a COM class (what a component task really runs), or None if it
    isn't registered the classic way (Store/packaged app components, which are signed packages)."""
    for sub_key in ("InprocServer32", "LocalServer32"):
        try:
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, rf"CLSID\{clsid}\{sub_key}", 0,
                                winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as k:
                value = winreg.QueryValueEx(k, "")[0]
        except OSError:
            continue
        if value:
            return str(value)
    return None


def target_program(entry: StartupEntry) -> Path | None:
    """Best guess at the program a startup entry launches."""
    command = entry.command
    if command.startswith(COM_PREFIX):
        command = com_server(command[len(COM_PREFIX):].split(" ; ")[0].strip()) or ""
        if not command:
            return None
    if entry.kind == "folder" and entry.file and entry.file.suffix.lower() == ".lnk":
        command = _shortcut_target(entry.file) or command
    command = os.path.expandvars(command.split(" ; ")[0].strip())  # tasks: first action
    if command.startswith('"'):
        candidate = command[1:].split('"', 1)[0]
    else:
        lower = command.lower()
        cut = next((lower.find(ext) + len(ext) for ext in (".exe", ".bat", ".cmd", ".vbs", ".ps1", ".js")
                    if ext in lower), -1)
        candidate = command[:cut] if cut > 0 else command.split(" ", 1)[0]
    path = Path(candidate)
    if not path.is_absolute():  # e.g. plain "powershell.exe"
        found = shutil.which(candidate)
        system32 = Path(os.environ.get("SystemRoot", r"C:\Windows"), "System32", candidate)
        path = Path(found) if found else system32 if system32.is_file() else path  # DLLs aren't on PATH
    return path if path.is_file() else None


def trusted_reason(entry: StartupEntry, program: Path | None, signature) -> str | None:
    """Why an entry needs no popup (a publisher name, or "component"), or None if it should alert.
    Only for entries that didn't match any malware."""
    if program is None:
        # A component task whose class isn't registered as a file: it's served by an installed
        # (signed) app package, so there's no dropped file it could be running.
        if entry.command.startswith(COM_PREFIX) and " ; " not in entry.command:
            clsid = entry.command[len(COM_PREFIX):].strip()
            if com_server(clsid) is None:
                return "component"
        return None
    if program.name.lower() in LAUNCHERS:
        return None
    if signature.signed and signature.publisher in TRUSTED_PUBLISHERS:
        return signature.publisher
    return None


def snapshot_tasks() -> dict[str, StartupEntry] | None:
    """All scheduled tasks, or None if they couldn't be listed this time."""
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", _TASK_SCRIPT], capture_output=True,
                             timeout=120, creationflags=CREATE_NO_WINDOW)
        tasks = json.loads(out.stdout.decode("utf-8", "replace") or "null")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    if not tasks:
        return None
    if isinstance(tasks, dict):  # PowerShell emits a bare object when there's only one
        tasks = [tasks]
    entries = {}
    for t in tasks:
        e = StartupEntry(TASK_LOCATION, t.get("n", ""), t.get("a") or "(no program)", "task")
        entries[e.id] = e
    return entries


def _shortcut_target(lnk: Path) -> str | None:
    # Resolving .lnk needs the Shell COM API; this runs only when an alert fires.
    script = f"(New-Object -ComObject WScript.Shell).CreateShortcut('{str(lnk).replace(chr(39), chr(39) * 2)}').TargetPath"
    try:
        out = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True,
                             text=True, timeout=15, creationflags=0x08000000)
        return out.stdout.strip() or None
    except (OSError, subprocess.TimeoutExpired):
        return None


def remove(entry: StartupEntry):
    """Takes the entry out of startup. Folder entries go to quarantine (restorable)."""
    if entry.kind == "registry":
        try:
            with winreg.OpenKey(entry.hive, entry.key, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
                winreg.DeleteValue(k, entry.name)
        except PermissionError:  # an all-users entry: ask for admin approval
            from core import elevate

            elevate.run("regdel", entry.key, entry.name)
    elif entry.kind == "task":
        result = subprocess.run(["schtasks", "/delete", "/tn", entry.name, "/f"], capture_output=True,
                                creationflags=CREATE_NO_WINDOW)
        if result.returncode != 0:
            message = (result.stderr or result.stdout).decode("mbcs", "replace").strip()
            if "denied" not in message.lower():
                raise RuntimeError(message or "schtasks couldn't delete the task")
            from core import elevate

            elevate.run("taskdel", entry.name)
    else:
        from core import quarantine
        quarantine.quarantine_file(entry.file, f"Startup entry: {entry.name}")


def _load_known(meta_key):
    raw = database.get_meta(meta_key)
    return None if raw is None else json.loads(raw)


def _save_known(entries: dict[str, StartupEntry], meta_key):
    database.set_meta(**{meta_key: json.dumps({k: e.command for k, e in entries.items()})})


class _Group:
    """One set of startup locations with its own saved baseline and poll rate."""

    def __init__(self, take_snapshot, meta_key, every_seconds):
        self.take_snapshot, self.meta_key, self.every = take_snapshot, meta_key, every_seconds
        self.known = _load_known(meta_key)
        self.next_poll = 0.0

    def poll(self, on_new):
        now = time.monotonic()
        if now < self.next_poll:
            return
        self.next_poll = now + self.every
        current = self.take_snapshot()
        if current is None:  # listing failed: keep the old baseline rather than report everything
            return
        if self.known is None:  # first time this group is watched: silent baseline
            self.known = {k: e.command for k, e in current.items()}
            _save_known(current, self.meta_key)
            return
        changed = [e for k, e in current.items() if self.known.get(k) != e.command]
        if changed or current.keys() != self.known.keys():
            for entry in changed:
                on_new(entry)
            self.known = {k: e.command for k, e in current.items()}
            _save_known(current, self.meta_key)


def watch_loop(on_new, stop_flag: list[bool], interval: float = 5.0,
               reg_locations=None, folder_locations=None, meta_key: str = META_KEY,
               task_snapshot=snapshot_tasks, task_meta_key: str = TASKS_META_KEY,
               task_interval: float = TASK_POLL_SECONDS):
    """Calls on_new(StartupEntry) once for each entry added (or changed) after the baseline."""
    groups = [_Group(lambda: snapshot(reg_locations, folder_locations), meta_key, interval)]
    if task_snapshot is not None:
        groups.append(_Group(task_snapshot, task_meta_key, task_interval))
    while not stop_flag[0]:
        for group in groups:
            group.poll(on_new)
        time.sleep(min(1.0, interval))
