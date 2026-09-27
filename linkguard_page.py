"""Link guard page: the on/off switch, a box to check any link by hand, and the
last dangerous links it warned about. The warnings themselves come from the
background agent, which watches what you copy."""
import tkinter as tk
from datetime import datetime
from tkinter import ttk

import theme as C
from core import linkguard, settings
from core.i18n import relative, t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from tools_page import subpage_header, wrap_to_width
from widgets import Ring, RoundedCard, ScrollArea, ToggleSwitch, icon_label


class LinkGuardPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        self._checked = None  # (link, warnings) from the box
        subpage_header(self, app, t("link_title"), t("link_sub"), "nav_tools", "tools")
        self.body = tk.Frame(self, bg=C.BG)
        self.body.pack(fill="both", expand=True)
        self._render()

    def refresh(self):
        self._render()

    def _render(self):
        typed = self.entry.get() if getattr(self, "entry", None) and self.entry.winfo_exists() else ""
        for child in self.body.winfo_children():
            child.destroy()
        on = linkguard.enabled()

        top = RoundedCard(self.body, radius=16, padx=24, pady=16)
        top.pack(fill="x")
        row = tk.Frame(top.body, bg=C.CARD)
        row.pack(fill="x")
        ring = Ring(row, size=64)
        ring.pack(side="left", padx=(0, 18))
        ring.show(C.GOOD if on else C.BORDER, glyph="web", glyph_color=C.GOOD if on else C.TEXT_MUTED)
        switch = ToggleSwitch(row, command=self._toggle, on=on)
        switch.pack(side="right", anchor="n")
        col = tk.Frame(row, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, text=t("link_on") if on else t("link_off"), font=FONT_LARGE, fg=C.TEXT, bg=C.CARD,
                 anchor="w").pack(anchor="w", fill="x")
        sub = tk.Label(col, text=t("link_how"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left", anchor="w")
        sub.pack(anchor="w", fill="x")
        wrap_to_width(sub, col)

        checker = RoundedCard(self.body, radius=16, padx=24, pady=14)
        checker.pack(fill="x", pady=(14, 0))
        tk.Label(checker.body, text=t("link_check_title"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        line = tk.Frame(checker.body, bg=C.CARD)
        line.pack(fill="x", pady=(8, 0))
        box = RoundedCard(line, bg=C.BG, outer=C.CARD, radius=8, padx=10, pady=4)
        box.pack(side="left", fill="x", expand=True)
        self.entry = tk.Entry(box.body, font=FONT, bg=C.BG, fg=C.TEXT, insertbackground=C.TEXT, relief="flat", bd=0,
                              highlightthickness=0)
        self.entry.pack(fill="x", ipady=6)
        self.entry.insert(0, typed)
        self.entry.bind("<Return>", lambda e: self._check())
        ttk.Button(line, text=t("link_check"), style="Accent.TButton", command=self._check).pack(side="left",
                                                                                               padx=(10, 0))
        if self._checked:
            link, warnings = self._checked
            if warnings:
                w = warnings[0]
                text, color = t("link_check_bad", reason=t(w.finding.key, **w.finding.values)), C.BAD
            else:
                text, color = t("link_check_ok"), C.GOOD
            result = tk.Label(checker.body, text=text, font=FONT_BOLD, fg=color, bg=C.CARD, justify="left", anchor="w")
            result.pack(anchor="w", fill="x", pady=(8, 0))
            wrap_to_width(result, checker.body)

        card = RoundedCard(self.body, radius=16, padx=18, pady=12)
        card.pack(fill="both", expand=True, pady=(14, 0))
        tk.Label(card.body, text=t("link_recent"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        area = ScrollArea(card.body)
        area.pack(fill="both", expand=True, pady=(6, 0))
        recent = linkguard.recent()
        if not recent:
            tk.Label(area.inner, text=t("link_none"), font=FONT, fg=C.TEXT_MUTED, bg=C.CARD).pack(anchor="w", pady=8)
        for r in recent:
            item = tk.Frame(area.inner, bg=C.CARD)
            item.pack(fill="x", pady=4, padx=(0, 8))
            icon_label(item, "warning", 13, fg=C.BAD).pack(side="left", anchor="n", padx=(4, 12), pady=2)
            when = relative(datetime.fromisoformat(r["time"]).astimezone())
            tk.Label(item, text=when, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(side="right", anchor="n")
            text = tk.Frame(item, bg=C.CARD)
            text.pack(side="left", fill="x", expand=True)
            tk.Label(text, text=r["host"], font=FONT_BOLD, fg=C.TEXT, bg=C.CARD, anchor="w").pack(anchor="w")
            reason = tk.Label(text, text=t(r["key"], **r.get("values", {})), font=FONT_SMALL, fg=C.TEXT_MUTED,
                              bg=C.CARD, justify="left", anchor="w")
            reason.pack(anchor="w", fill="x")
            wrap_to_width(reason, text, 200)

    def _check(self):
        link = self.entry.get().strip()
        if not link:
            return
        from core import scam_check

        links = scam_check.extract_links(link) or [link]
        warnings = linkguard.check_text(" ".join(links))
        self._checked = (link, warnings)
        self._render()

    def _toggle(self):
        settings.save(link_guard=not linkguard.enabled())  # the background agent reads it
        self._render()
