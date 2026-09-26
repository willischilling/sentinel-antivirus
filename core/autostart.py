"""Start-with-Windows via the per-user Run registry key (no admin needed)."""
import sys

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "SentinelAntivirus"


def supported() -> bool:
    # Only the installed exe gets registered; a dev run would register python.exe.
    return sys.platform == "win32" and getattr(sys, "frozen", False)


def _command() -> str:
    # Login starts just the background protection agent, not the window.
    return f'"{sys.executable}" --agent'


def is_enabled() -> bool:
    if sys.platform != "win32":
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            winreg.QueryValueEx(key, VALUE_NAME)
        return True
    except FileNotFoundError:
        return False


def set_enabled(enabled: bool):
    import winreg

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
        if enabled:
            winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, _command())
        else:
            try:
                winreg.DeleteValue(key, VALUE_NAME)
            except FileNotFoundError:
                pass
