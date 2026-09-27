"""The "Scan with Sentinel" entry in File Explorer's right-click menu, for files,
folders and drives. Per-user registry keys, so no admin rights are needed.

On Windows 11 it's under "Show more options" (or Shift+F10): the new compact
menu only takes entries from code-signed, packaged apps.
"""
import sys

KEYS = (
    r"Software\Classes\*\shell\SentinelScan",
    r"Software\Classes\Directory\shell\SentinelScan",
    r"Software\Classes\Drive\shell\SentinelScan",
)
FLAG = "--scan"


def supported() -> bool:
    # Only the installed exe gets registered; a dev run would point Explorer at python.exe.
    return sys.platform == "win32" and getattr(sys, "frozen", False)


def is_enabled() -> bool:
    import winreg

    try:
        winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEYS[0]).Close()
        return True
    except OSError:
        return False


def enable(label: str):
    """Adds (or re-points and relabels) the menu entry at this exe."""
    import winreg

    command = f'"{sys.executable}" {FLAG} "%1"'
    for path in KEYS:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
            winreg.SetValueEx(key, None, 0, winreg.REG_SZ, label)
            winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, f'"{sys.executable}",0')
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path + r"\command") as key:
            winreg.SetValueEx(key, None, 0, winreg.REG_SZ, command)


def disable():
    import winreg

    for path in KEYS:
        for sub in (path + r"\command", path):
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
            except FileNotFoundError:
                pass
