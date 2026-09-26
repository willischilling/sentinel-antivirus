"""Colors and fonts. Two palettes (dark and light); apply() swaps the module's
color attributes in place, so code must read them as theme.BG etc. at draw
time rather than importing the values (which would freeze them).
"""
import sys

DARK = {
    "BG": "#0b1120",
    "PANEL": "#0f172a",
    "CARD": "#151f33",
    "CARD_HOVER": "#1b2842",
    "BORDER": "#24324d",
    "TEXT": "#e7ecf5",
    "TEXT_MUTED": "#8b97ad",
    "ACCENT": "#3b82f6",
    "ACCENT_DARK": "#2563eb",
    "ON_ACCENT": "#ffffff",
    "GOOD": "#22c55e",
    "WARN": "#f59e0b",
    "BAD": "#ef4444",
    "SWITCH_DISABLED": "#2a3142",
    "KNOB_DISABLED": "#6b7385",
}
LIGHT = {
    "BG": "#f5f7fb",
    "PANEL": "#e9edf5",  # gray, so the active (white) menu item stands out
    "CARD": "#ffffff",
    "CARD_HOVER": "#eef2f9",
    "BORDER": "#dfe4ee",
    "TEXT": "#0f172a",
    "TEXT_MUTED": "#5b6477",
    "ACCENT": "#2563eb",
    "ACCENT_DARK": "#1d4ed8",
    "ON_ACCENT": "#ffffff",
    "GOOD": "#16a34a",
    "WARN": "#d97706",
    "BAD": "#dc2626",
    "SWITCH_DISABLED": "#e3e7ef",
    "KNOB_DISABLED": "#b5bccb",
}
PALETTES = {"dark": DARK, "light": LIGHT}
CHOICES = ("dark", "light", "system")

current = "dark"
BG = PANEL = CARD = CARD_HOVER = BORDER = TEXT = TEXT_MUTED = ""
ACCENT = ACCENT_DARK = ON_ACCENT = GOOD = WARN = BAD = SWITCH_DISABLED = KNOB_DISABLED = ""


def windows_prefers_light() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as key:
            return winreg.QueryValueEx(key, "AppsUseLightTheme")[0] == 1
    except OSError:
        return False


def resolve(choice: str | None) -> str:
    """'dark' / 'light' / 'system' (follow Windows) -> the palette to use."""
    if choice == "system":
        return "light" if windows_prefers_light() else "dark"
    return choice if choice in PALETTES else "dark"


def apply(name: str):
    global current
    current = name if name in PALETTES else "dark"
    globals().update(PALETTES[current])


def style_title_bar(window):
    """Dark or light window title bar to match (Windows 10 20H1+ / 11)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        value = ctypes.c_int(1 if current == "dark" else 0)
        DWMWA_USE_IMMERSIVE_DARK_MODE = 20
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
                                                   ctypes.byref(value), ctypes.sizeof(value))
    except (AttributeError, OSError):
        pass


apply("dark")

FONT = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI Semibold", 10)
FONT_LARGE = ("Segoe UI Semibold", 12)
FONT_TITLE = ("Segoe UI Semibold", 18)
FONT_HERO = ("Segoe UI Semibold", 24)
FONT_SMALL = ("Segoe UI", 9)
FONT_MONO = ("Consolas", 9)
