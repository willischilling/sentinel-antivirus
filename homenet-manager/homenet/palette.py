"""The colour palette, swappable at runtime for dark / light mode.

Code reads colours as ``palette.ACCENT`` (etc.) at draw time, never by importing
the names, so ``use("light")`` followed by a re-render repaints everything.
"""

DARK = {
    "BG": "#0a0f1c", "SIDEBAR": "#0c1322", "CARD": "#121a2b", "CARD_HI": "#192439",
    "BORDER": "#1f2b43", "TEXT": "#e9eef8", "MUTED": "#8793aa", "FAINT": "#56627a",
    "ACCENT": "#4f8cff", "ACCENT_HI": "#6c9fff", "PURPLE": "#8b5cf6",
    "GOOD": "#22c55e", "WARN": "#f5a524", "BAD": "#f05252", "ENTRY": "#192439",
}
LIGHT = {
    "BG": "#eef1f7", "SIDEBAR": "#ffffff", "CARD": "#ffffff", "CARD_HI": "#eef2fa",
    "BORDER": "#dde3ee", "TEXT": "#0f1b31", "MUTED": "#5a6683", "FAINT": "#95a0b8",
    "ACCENT": "#2f6bff", "ACCENT_HI": "#5789ff", "PURPLE": "#7c4dff",
    "GOOD": "#15a34a", "WARN": "#c77700", "BAD": "#dc2626", "ENTRY": "#f2f5fb",
}
THEMES = {"dark": DARK, "light": LIGHT}

current = "dark"
# These are filled in by use(); declared here so linters/imports see them.
BG = SIDEBAR = CARD = CARD_HI = BORDER = TEXT = MUTED = FAINT = ""
ACCENT = ACCENT_HI = PURPLE = GOOD = WARN = BAD = ENTRY = ""


def use(name: str):
    global current
    current = name if name in THEMES else "dark"
    globals().update(THEMES[current])


def mix(c1: str, c2: str, t: float) -> str:
    """Blend two #rrggbb colours; t=0 → c1, t=1 → c2."""
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(a, b))


def on_card() -> str:
    """A subtle inner fill that works on either theme (for entries, rows)."""
    return ENTRY


use("dark")
