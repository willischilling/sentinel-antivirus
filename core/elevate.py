"""Runs one privileged action with administrator rights, after the Windows
admin (UAC) prompt.

Sentinel itself never runs as administrator: it lives in a user-writable
folder, so an always-elevated Sentinel would let any program that replaced
its files gain admin rights. Instead, when an action fails with "access
denied" (ending a program running as administrator, removing an all-users
startup entry...), the caller asks for approval through run() here. That
starts `Sentinel.exe --elevated <action> <args>`, which does exactly that one
thing and exits. Windows asks the person every time, so nothing is gained by
anything else launching it.
"""
import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
import winreg
from ctypes import wintypes
from pathlib import Path

from .i18n import t

FLAG = "--elevated"
ERROR_CANCELLED = 1223
SEE_MASK_NOCLOSEPROCESS = 0x40
SEE_MASK_NO_CONSOLE = 0x8000
SW_HIDE = 0
TIMEOUT_MS = 120_000
CREATE_NO_WINDOW = 0x08000000
waiting = 0  # how many actions are waiting on the admin prompt right now (read by popups)

# Only these registry keys can be edited, and only these processes are never ended
# (ending them crashes Windows, and they can't be malware in their real location).
ALLOWED_REG_KEYS = {
    r"Software\Microsoft\Windows\CurrentVersion\Run",
    r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
}
CRITICAL = {"csrss.exe", "wininit.exe", "winlogon.exe", "smss.exe", "services.exe", "lsass.exe",
            "svchost.exe", "system", "registry", "memcompression"}


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("fMask", wintypes.ULONG), ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR),
                ("lpParameters", wintypes.LPCWSTR), ("lpDirectory", wintypes.LPCWSTR),
                ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE), ("lpIDList", ctypes.c_void_p),
                ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY), ("dwHotKey", wintypes.DWORD),
                ("hIconOrMonitor", wintypes.HANDLE), ("hProcess", wintypes.HANDLE)]


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def _command() -> tuple[str, list[str]]:
    if getattr(sys, "frozen", False):
        return sys.executable, []
    # From source: python.exe gui.py
    return sys.executable, [str(Path(__file__).resolve().parent.parent / "gui.py")]


def run(action: str, *args) -> None:
    """Performs the action as administrator. Raises RuntimeError if the person declines
    the prompt or the action fails."""
    if is_admin():  # already elevated (e.g. Sentinel started from an admin prompt)
        _perform(action, [str(a) for a in args])
        return
    exe, prefix = _command()
    fd, result_path = tempfile.mkstemp(prefix="sentinel-elevated-", suffix=".txt")
    os.close(fd)
    params = subprocess.list2cmdline(prefix + [FLAG, result_path, action, *map(str, args)])
    global waiting
    info = SHELLEXECUTEINFOW(cbSize=ctypes.sizeof(SHELLEXECUTEINFOW),
                             fMask=SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE,
                             lpVerb="runas", lpFile=exe, lpParameters=params, nShow=SW_HIDE)
    waiting += 1
    try:
        if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)):
            error = ctypes.GetLastError()
            if error == ERROR_CANCELLED:
                raise RuntimeError(t("err_admin_declined"))
            raise RuntimeError(ctypes.FormatError(error))
        kernel32 = ctypes.windll.kernel32
        try:
            kernel32.WaitForSingleObject(info.hProcess, TIMEOUT_MS)
            code = wintypes.DWORD()
            kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
        finally:
            kernel32.CloseHandle(info.hProcess)
        if code.value != 0:
            message = Path(result_path).read_text(encoding="utf-8", errors="replace").strip()
            raise RuntimeError(message or t("err_admin_blocked"))
    finally:
        waiting -= 1
        Path(result_path).unlink(missing_ok=True)


# ------------------------------------------------------- elevated side --
def main(argv: list[str]) -> int:
    """Entry point for `Sentinel.exe --elevated <result file> <action> <args>`."""
    result_path, action, args = argv[0], argv[1], argv[2:]
    try:
        _perform(action, args)
        return 0
    except Exception as e:  # report anything back to the unelevated caller
        try:
            Path(result_path).write_text(str(e), encoding="utf-8")
        except OSError:
            pass
        return 1


def _perform(action: str, args: list[str]):
    if action == "kill":
        _kill(int(args[0]), args[1])
    elif action == "move":
        shutil.move(args[0], args[1])
    elif action == "delete":
        Path(args[0]).unlink(missing_ok=True)
    elif action == "regdel":
        _delete_run_value(args[0], args[1])
    elif action == "taskdel":
        _delete_task(args[0])
    elif action == "vpnsetup":
        from . import vpn

        vpn.elevated_setup(args[0], args[1], args[2])
    elif action == "webprotect":
        from . import webprotect

        webprotect.elevated(args[0], args[1:])
    elif action == "firewall":
        from . import firewall

        firewall.elevated(args[0], args[1:])
    elif action == "shield":
        from . import shield

        shield.elevated(args[0], args[1:])
    elif action == "browserguard":
        from . import hijack

        hijack.elevated(args[0], args[1:])
    elif action == "vpnremove":
        from . import vpn

        vpn.elevated_remove()
    elif action in ("vpnstart", "vpnstop"):
        from . import vpn

        result = vpn._sc("start" if action == "vpnstart" else "stop", vpn.SERVICE)
        if result.returncode != 0 and not any(code in result.stdout for code in ("1056", "1062")):
            raise RuntimeError(result.stdout.strip())
    else:
        raise RuntimeError(f"unknown action {action!r}")


def _kill(pid: int, expected_exe: str):
    import psutil

    try:
        _enable_debug_privilege()  # lets an administrator end programs running as SYSTEM
    except OSError:
        pass  # best effort: most programs can be ended without it
    try:
        proc = psutil.Process(pid)
        exe = proc.exe()
    except psutil.NoSuchProcess:
        return  # already gone
    # The PID could have been reused by another program since the alert.
    if os.path.normcase(exe) != os.path.normcase(expected_exe):
        raise RuntimeError(f"PID {pid} is now a different program ({Path(exe).name})")
    windows_dir = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
    if Path(exe).name.lower() in CRITICAL and os.path.normcase(exe).startswith(windows_dir):
        raise RuntimeError(f"{Path(exe).name} is a core part of Windows")
    proc.kill()
    proc.wait(timeout=10)


def _delete_run_value(key: str, name: str):
    if key not in ALLOWED_REG_KEYS:
        raise RuntimeError(f"not a startup key: {key}")
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as k:
        winreg.DeleteValue(k, name)


def _delete_task(name: str):
    result = subprocess.run(["schtasks", "/delete", "/tn", name, "/f"], capture_output=True,
                            creationflags=CREATE_NO_WINDOW)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout).decode("mbcs", "replace").strip()
                           or "schtasks couldn't delete the task")


def _enable_debug_privilege():
    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Luid", LUID), ("Attributes", wintypes.DWORD)]

    advapi32, kernel32 = ctypes.WinDLL("advapi32"), ctypes.WinDLL("kernel32")
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.c_void_p, wintypes.DWORD,
                                               ctypes.c_void_p, ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x20 | 0x8, ctypes.byref(token)):
        return
    try:
        luid = LUID()
        if advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            privileges = TOKEN_PRIVILEGES(1, luid, 0x2)  # SE_PRIVILEGE_ENABLED
            advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(privileges), 0, None, None)
    finally:
        kernel32.CloseHandle(token)
