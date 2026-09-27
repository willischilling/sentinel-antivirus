"""Game mode: notices when a game (or anything else) is running full screen, so
the background agent can hold its popups and put off scheduled scans until
it's over. Nothing to set up: it checks what Windows reports and whether the
window in front covers its whole monitor (for borderless games).
"""
import ctypes
import os
from ctypes import wintypes

from . import settings

# SHQueryUserNotificationState results that mean "don't interrupt"
QUNS_BUSY, QUNS_RUNNING_D3D_FULL_SCREEN, QUNS_PRESENTATION_MODE = 2, 3, 4
DESKTOP_CLASSES = {"Progman", "WorkerW", "Shell_TrayWnd", "Shell_SecondaryTrayWnd"}
OWN_EXE = "sentinel.exe"


class MONITORINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("rcMonitor", wintypes.RECT), ("rcWork", wintypes.RECT),
                ("dwFlags", wintypes.DWORD)]


def enabled() -> bool:
    return settings.load().get("game_mode", True)


def fullscreen_app() -> str | None:
    """The file name of the program running full screen right now, if any
    ("" when Windows says something is, but its program can't be read)."""
    try:
        state = ctypes.c_int()
        if ctypes.windll.shell32.SHQueryUserNotificationState(ctypes.byref(state)) == 0 and state.value in (
                QUNS_BUSY, QUNS_RUNNING_D3D_FULL_SCREEN, QUNS_PRESENTATION_MODE):
            return _foreground_exe() or ""
        return _borderless_fullscreen()
    except (AttributeError, OSError):
        return None


def _borderless_fullscreen() -> str | None:
    user32 = ctypes.windll.user32
    user32.GetForegroundWindow.restype = wintypes.HWND
    user32.MonitorFromWindow.restype = wintypes.HANDLE
    user32.MonitorFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD]
    user32.GetMonitorInfoW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MONITORINFO)]
    hwnd = user32.GetForegroundWindow()
    # A maximized window can also cover the screen when the taskbar auto-hides; that's not a game.
    if not hwnd or not user32.IsWindowVisible(hwnd) or user32.IsZoomed(hwnd):
        return None
    name = ctypes.create_unicode_buffer(64)
    user32.GetClassNameW(hwnd, name, 64)
    if name.value in DESKTOP_CLASSES:
        return None
    rect = wintypes.RECT()
    if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        return None
    info = MONITORINFO(cbSize=ctypes.sizeof(MONITORINFO))
    if not user32.GetMonitorInfoW(user32.MonitorFromWindow(hwnd, 2), ctypes.byref(info)):  # 2: nearest
        return None
    mon = info.rcMonitor
    if rect.left <= mon.left and rect.top <= mon.top and rect.right >= mon.right and rect.bottom >= mon.bottom:
        exe = _foreground_exe(hwnd)
        if exe and exe.lower() != OWN_EXE:
            return exe
    return None


def _foreground_exe(hwnd=None) -> str | None:
    user32 = ctypes.windll.user32
    user32.GetForegroundWindow.restype = wintypes.HWND
    hwnd = hwnd or user32.GetForegroundWindow()
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if not pid.value:
        return None
    try:
        import psutil

        return os.path.basename(psutil.Process(pid.value).exe())
    except Exception:
        return None
