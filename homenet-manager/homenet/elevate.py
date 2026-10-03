"""Runs one privileged action with administrator rights, after the Windows
admin (UAC) prompt.

The app itself runs as a normal user. The few changes that need administrator
rights — pausing/resuming this PC's internet through the Windows Firewall,
editing the hosts file, switching the DNS filter — each go through run() here,
which launches this same program again with `--elevated <action> <args>` and
Windows' "runas" verb. That shows the UAC prompt, does exactly that one thing,
and exits. The admin side (main / _perform) only allows a fixed set of actions
with checked arguments.
"""
import ctypes
import os
import subprocess
import sys
import tempfile
from ctypes import wintypes
from pathlib import Path

FLAG = "--elevated"
ERROR_CANCELLED = 1223
SEE_MASK_NOCLOSEPROCESS = 0x40
SEE_MASK_NO_CONSOLE = 0x8000
SW_HIDE = 0
TIMEOUT_MS = 120_000
CREATE_NO_WINDOW = 0x08000000


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
    except (AttributeError, OSError):
        return False


def _command() -> tuple[str, list[str]]:
    if getattr(sys, "frozen", False):          # a built .exe
        return sys.executable, []
    # Running from source: python.exe main.py
    main = str(Path(__file__).resolve().parent.parent / "main.py")
    return sys.executable, [main]


def run(action: str, *args) -> None:
    """Perform the action as administrator. Raises RuntimeError if the person
    declines the prompt or the action fails."""
    if os.name != "nt":
        raise RuntimeError("This action needs Windows.")
    if is_admin():
        _perform(action, [str(a) for a in args])
        return
    exe, prefix = _command()
    fd, result_path = tempfile.mkstemp(prefix="homenet-elevated-", suffix=".txt")
    os.close(fd)
    params = subprocess.list2cmdline(prefix + [FLAG, result_path, action, *map(str, args)])
    info = SHELLEXECUTEINFOW(cbSize=ctypes.sizeof(SHELLEXECUTEINFOW),
                             fMask=SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE,
                             lpVerb="runas", lpFile=exe, lpParameters=params, nShow=SW_HIDE)
    if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)):
        error = ctypes.GetLastError()
        if error == ERROR_CANCELLED:
            raise RuntimeError("Administrator permission was declined.")
        raise RuntimeError(ctypes.FormatError(error))
    kernel32 = ctypes.windll.kernel32
    try:
        kernel32.WaitForSingleObject(info.hProcess, TIMEOUT_MS)
        code = wintypes.DWORD()
        kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
    finally:
        kernel32.CloseHandle(info.hProcess)
    error_text = ""
    try:
        error_text = Path(result_path).read_text(encoding="utf-8").strip()
    except OSError:
        pass
    finally:
        try:
            os.unlink(result_path)
        except OSError:
            pass
    if code.value != 0:
        raise RuntimeError(error_text or "The change could not be made.")


# ------------------------------------------------------- elevated side --
def main(argv: list[str]) -> int:
    """Entry point for `<program> --elevated <result file> <action> <args>`."""
    result_path, action, args = argv[0], argv[1], argv[2:]
    try:
        _perform(action, args)
        return 0
    except Exception as e:
        try:
            Path(result_path).write_text(str(e), encoding="utf-8")
        except OSError:
            pass
        return 1


def _perform(action: str, args: list[str]):
    if action == "firewall":
        from . import firewall
        firewall.elevated(args[0], args[1:])
    elif action == "hosts":
        from . import hostsblock
        hostsblock.elevated(args[0], args[1:])
    elif action == "dns":
        from . import dns
        dns.elevated(args[0], args[1:])
    else:
        raise RuntimeError(f"unknown action {action!r}")
