"""Stealer guard page: the on/off switch, which saved logins it protects on this PC,
the last warnings, and the programs you allowed. The watching itself is done by the
background agent (monitor/stealer_watcher.py)."""
import tkinter as tk
from datetime import datetime
from pathlib import Path

import theme as C
from core import settings, stealer_guard
from core.i18n import relative, t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from tools_page import subpage_header, wrap_to_width
from widgets import Ring, RoundedCard, ScrollArea, ToggleSwitch, icon_label, pill


def what_text(categories) -> str:
    return ", ".join(t(f"stealer_cat_{c}") for c in stealer_guard.CATEGORIES if c in categories)


class StealerPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        subpage_header(self, app, t("stealer_page_title"), t("stealer_sub"), "nav_tools", "tools")
        self.body = tk.Frame(self, bg=C.BG)
        self.body.pack(fill="both", expand=True)
        self._protected = []
        self._render()

    def refresh(self):
        try:
            self._protected = stealer_guard.protected_here()
        except OSError:
            self._protected = []
        self._render()

    def _render(self):
        for child in self.body.winfo_children():
            child.destroy()
        on = stealer_guard.enabled()

        top = RoundedCard(self.body, radius=16, padx=24, pady=16)
        top.pack(fill="x")
        row = tk.Frame(top.body, bg=C.CARD)
        row.pack(fill="x")
        ring = Ring(row, size=64)
        ring.pack(side="left", padx=(0, 18))
        ring.show(C.GOOD if on else C.BORDER, glyph="key", glyph_color=C.GOOD if on else C.TEXT_MUTED)
        ToggleSwitch(row, command=self._toggle, on=on).pack(side="right", anchor="n")
        col = tk.Frame(row, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, text=t("stealer_on") if on else t("stealer_off"), font=FONT_LARGE, fg=C.TEXT, bg=C.CARD,
                 anchor="w").pack(anchor="w", fill="x")
        sub = tk.Label(col, text=t("stealer_how"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left",
                       anchor="w")
        sub.pack(anchor="w", fill="x")
        wrap_to_width(sub, col)
        if self._protected:
            chips = tk.Frame(top.body, bg=C.CARD)
            chips.pack(fill="x", pady=(12, 0))
            tk.Label(chips, text=t("stealer_protects"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(
                side="left", padx=(0, 8))
            for category in self._protected:
                pill(chips, t(f"stealer_cat_{category}"), C.GOOD if on else C.TEXT_MUTED).pack(side="left", padx=(0, 6))

        card = RoundedCard(self.body, radius=16, padx=18, pady=12)
        card.pack(fill="both", expand=True, pady=(14, 0))
        tk.Label(card.body, text=t("stealer_recent"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        area = ScrollArea(card.body)
        area.pack(fill="both", expand=True, pady=(6, 0))
        recent = stealer_guard.recent()
        if not recent:
            tk.Label(area.inner, text=t("stealer_none"), font=FONT, fg=C.TEXT_MUTED, bg=C.CARD).pack(anchor="w", pady=8)
        for r in recent:
            item = tk.Frame(area.inner, bg=C.CARD)
            item.pack(fill="x", pady=4, padx=(0, 8))
            icon_label(item, "warning", 13, fg=C.BAD).pack(side="left", anchor="n", padx=(4, 12), pady=2)
            when = relative(datetime.fromisoformat(r["time"]).astimezone())
            tk.Label(item, text=when, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(side="right", anchor="n")
            text = tk.Frame(item, bg=C.CARD)
            text.pack(side="left", fill="x", expand=True)
            name = r.get("program") or (Path(r["file"]).name if r.get("file") else t("unknown"))
            tk.Label(text, text=name, font=FONT_BOLD, fg=C.TEXT, bg=C.CARD, anchor="w").pack(anchor="w")
            key = "stealer_kind_reading" if r.get("kind") == "reading" else "stealer_kind_copied"
            reason = tk.Label(text, text=t(key, what=what_text(r.get("categories") or [])), font=FONT_SMALL,
                              fg=C.TEXT_MUTED, bg=C.CARD, justify="left", anchor="w")
            reason.pack(anchor="w", fill="x")
            wrap_to_width(reason, text, 200)

        allowed = settings.load().get("stealer_allowed") or []
        if allowed:
            trusted = RoundedCard(self.body, radius=16, padx=18, pady=12)
            trusted.pack(fill="x", pady=(14, 0))
            tk.Label(trusted.body, text=t("stealer_allowed_title"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
            for exe in allowed:
                line = tk.Frame(trusted.body, bg=C.CARD)
                line.pack(fill="x", pady=(6, 0))
                link = tk.Label(line, text=t("privacy_disallow"), font=FONT_SMALL, fg=C.ACCENT, bg=C.CARD,
                                cursor="hand2")
                link.pack(side="right")
                link.bind("<Button-1>", lambda e, p=exe: self._disallow(p))
                tk.Label(line, text=Path(exe).name, font=FONT, fg=C.TEXT, bg=C.CARD).pack(side="left")
                tk.Label(line, text=str(Path(exe).parent), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(
                    side="left", padx=(8, 0))

    def _toggle(self):
        settings.save(stealer_guard=not stealer_guard.enabled())  # the background agent reads it
        self._render()

    def _disallow(self, exe):
        stealer_guard.disallow(exe)
        self._render()

    def handle(self, kind, payload):
        pass
