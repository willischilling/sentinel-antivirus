"""Sentinel's entries in File Explorer's right-click menu: "Scan with Sentinel"
(files, folders and drives) and "Shred with Sentinel" (files and folders).
Per-user registry keys, so no admin rights are needed.

On Windows 11 they're under "Show more options" (or Shift+F10): the new compact
menu only takes entries from code-signed, packaged apps.
"""
import sys

FLAG = "--scan"
SHRED_FLAG = "--shred"
# verb -> (registry key name, command-line flag, the kinds of item it appears on)
VERBS = {
    "scan": ("SentinelScan", FLAG, ("*", "Directory", "Drive")),
    "shred": ("SentinelShred", SHRED_FLAG, ("*", "Directory")),
}


def _keys(verb):
    name, _flag, targets = VERBS[verb]
    return [rf"Software\Classes\{target}\shell\{name}" for target in targets]


def supported() -> bool:
    # Only the installed exe gets registered; a dev run would point Explorer at python.exe.
    return sys.platform == "win32" and getattr(sys, "frozen", False)


def is_enabled(verb: str = "scan") -> bool:
    import winreg

    try:
        winreg.OpenKey(winreg.HKEY_CURRENT_USER, _keys(verb)[0]).Close()
        return True
    except OSError:
        return False


def enable(label: str, verb: str = "scan"):
    """Adds (or re-points and relabels) one menu entry at this exe."""
    import winreg

    command = f'"{sys.executable}" {VERBS[verb][1]} "%1"'
    for path in _keys(verb):
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
            winreg.SetValueEx(key, None, 0, winreg.REG_SZ, label)
            winreg.SetValueEx(key, "Icon", 0, winreg.REG_SZ, f'"{sys.executable}",0')
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path + r"\command") as key:
            winreg.SetValueEx(key, None, 0, winreg.REG_SZ, command)


def sync():
    """Adds or removes each entry to match the settings, in the current language (also re-points
    them at this exe after a reinstall). Called by the window and the background agent."""
    if not supported():
        return
    from . import settings
    from .i18n import t

    conf = settings.load()
    for verb, setting, label in (("scan", "context_menu", "ctx_scan_with"), ("shred", "shred_menu", "ctx_shred_with")):
        try:
            if conf.get(setting, True):
                enable(t(label), verb)
            else:
                disable(verb)
        except OSError:
            pass


def disable(verb: str | None = None):
    """Removes one menu entry, or all of Sentinel's (None)."""
    import winreg

    for v in ([verb] if verb else list(VERBS)):
        for path in _keys(v):
            for sub in (path + r"\command", path):
                try:
                    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, sub)
                except FileNotFoundError:
                    pass
