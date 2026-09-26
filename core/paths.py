"""Resolves persistent storage locations for both dev runs and a frozen (PyInstaller) build.

A PyInstaller --onefile exe unpacks itself into a fresh temp directory on
every launch, so anything written next to the script would vanish when the
process exits. Installed builds must use a stable per-user data directory instead.
"""
import sys
from pathlib import Path

APP_NAME = "Sentinel Antivirus"


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        import os

        return Path(os.environ.get("LOCALAPPDATA", Path.home())) / APP_NAME
    return Path(__file__).resolve().parent.parent


BASE_DIR = _base_dir()
DATA_DIR = BASE_DIR / "data"
QUARANTINE_DIR = BASE_DIR / "quarantine"

DATA_DIR.mkdir(parents=True, exist_ok=True)
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)


_KNOWN_FOLDERS = {
    "desktop": "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}",
    "documents": "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}",
    "downloads": "{374DE290-123F-4565-9164-39C4925E467B}",
    "pictures": "{33E28130-4E1E-4676-835A-98395C3BC3BB}",
    "music": "{4BD8D571-6D19-48D3-BE97-422220080E43}",
    "videos": "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}",
    "startup": "{B97D20BB-F46A-4C97-BA10-5E3608430854}",
    "common_startup": "{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}",
}


def known_folder(name: str) -> Path:
    """Where Windows actually keeps Desktop/Documents/Downloads (OneDrive can
    redirect them), falling back to ~/<Name>."""
    fallback = Path.home() / name.capitalize()
    if sys.platform != "win32":
        return fallback
    import ctypes
    import uuid

    guid = (ctypes.c_byte * 16).from_buffer_copy(uuid.UUID(_KNOWN_FOLDERS[name]).bytes_le)
    path_ptr = ctypes.c_wchar_p()
    if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(guid), 0, None, ctypes.byref(path_ptr)) != 0:
        return fallback
    try:
        return Path(path_ptr.value)
    finally:
        ctypes.windll.ole32.CoTaskMemFree(path_ptr)


def resource(relative: str) -> Path:
    """Read-only files bundled with the app (icons), in dev or frozen builds."""
    base = getattr(sys, "_MEIPASS", None)
    return (Path(base) if base else Path(__file__).resolve().parent.parent) / relative
