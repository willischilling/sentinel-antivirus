"""Shared constants for the installer and uninstaller."""
import json
import os
import sys
from pathlib import Path

if not getattr(sys, "frozen", False):
    # Running from source: make the project root importable (core.i18n, theme).
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import version  # noqa: E402  (after the path setup above)

VERSION = version.VERSION
APP_NAME = "Sentinel Antivirus"
PUBLISHER = "Sentinel"

INSTALL_DIR = Path(os.environ["LOCALAPPDATA"]) / APP_NAME
APP_SUBDIR = "app"  # the --onedir build's folder, so its DLLs don't clutter INSTALL_DIR
APP_EXE_NAME = "Sentinel.exe"
UNINSTALL_EXE_NAME = "Uninstall.exe"
ICON_NAME = "icon.ico"
BROWSER_NAME = "Sentinel Browser"
BROWSER_SUBDIR = "browser"          # Sentinel Browser's own --onedir build
BROWSER_EXE_NAME = "SentinelBrowser.exe"

START_MENU_DIR = (
    Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
)
REG_UNINSTALL_KEY = (
    r"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelAntivirus"
)
def desktop_dir() -> Path:
    """The Desktop folder Windows actually shows. OneDrive and folder
    redirection move it, so ~/Desktop is often the wrong place."""
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                    ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]

    folderid_desktop = GUID(0xB4BFCC3A, 0xDB2C, 0x424C,
                            (ctypes.c_ubyte * 8)(0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41))
    path_ptr = ctypes.c_wchar_p()
    if ctypes.windll.shell32.SHGetKnownFolderPath(
        ctypes.byref(folderid_desktop), 0, None, ctypes.byref(path_ptr)
    ) == 0:
        try:
            return Path(path_ptr.value)
        finally:
            ctypes.windll.ole32.CoTaskMemFree(path_ptr)
    return Path.home() / "Desktop"


# Where older installer versions put the desktop shortcut, for cleanup.
LEGACY_DESKTOP_DIR = Path.home() / "Desktop"

# Must match core/autostart.py in the app.
REG_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
REG_RUN_VALUE = "SentinelAntivirus"

# The app's settings file (see core/paths.py and core/settings.py).
SETTINGS_PATH = INSTALL_DIR / "data" / "settings.json"


def saved_language() -> str | None:
    try:
        return json.loads(SETTINGS_PATH.read_text(encoding="utf-8")).get("language")
    except (OSError, ValueError):
        return None


def save_language(code: str):
    """Merges the chosen language into the app's settings, keeping everything else."""
    try:
        data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    data["language"] = code
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = SETTINGS_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(SETTINGS_PATH)
