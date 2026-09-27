"""Camera & microphone page: which apps are using them right now and which used
them recently, with "always allow" for apps you trust. The background agent
does the alerting; this page only reads what Windows records.
"""
import tkinter as tk

import theme as C
from core import privacy, settings
from core.i18n import relative, t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from tools_page import subpage_header, wrap_to_width
from widgets import Ring, RoundedCard, ScrollArea, ToggleSwitch, icon_label, pill


class PrivacyPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        subpage_header(self, app, t("privacy_title"), t("privacy_sub"), "nav_tools", "tools")
        self.body = tk.Frame(self, bg=C.BG)
        self.body.pack(fill="both", expand=True)
        self._uses = []
        self._shown = None
        self._render()
        self.after(3000, self._tick)

    def refresh(self):
        try:
            self._uses = privacy.usage()
        except OSError:
            self._uses = []
        shown = [(u.device, u.name, u.in_use, u.start) for u in self._uses] + [sorted(privacy.allowed())]
        if shown != self._shown:  # redraw only when something changed, so the list doesn't jump
            self._shown = shown
            self._render()

    def _tick(self):  # keeps "in use now" live while the page is open
        if not self.winfo_exists():
            return
        if self.app.current_page == "privacy":
            self.refresh()
        self.after(3000, self._tick)

    def _render(self):
        for child in self.body.winfo_children():
            child.destroy()
        live = [u for u in self._uses if u.in_use]
        allowed = privacy.allowed()

        top = RoundedCard(self.body, radius=16, padx=24, pady=16)
        top.pack(fill="x")
        row = tk.Frame(top.body, bg=C.CARD)
        row.pack(fill="x")
        ring = Ring(row, size=64)
        ring.pack(side="left", padx=(0, 18))
        col = tk.Frame(row, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        if live:
            ring.show(C.WARN, glyph="warning")
            names = ", ".join(f"{u.name} ({t('privacy_dev_' + u.device)})" for u in live)
            title, sub = t("privacy_live", apps=names), t("privacy_live_sub")
        else:
            ring.show(C.GOOD, glyph="check")
            title, sub = t("privacy_idle"), t("privacy_idle_sub")
        tk.Label(col, text=title, font=FONT_LARGE, fg=C.TEXT, bg=C.CARD, anchor="w", justify="left",
                 wraplength=460).pack(anchor="w", fill="x")
        sub_label = tk.Label(col, text=sub, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left", anchor="w")
        sub_label.pack(anchor="w", fill="x")
        wrap_to_width(sub_label, col)
        alerts = tk.Frame(top.body, bg=C.CARD)
        alerts.pack(fill="x", pady=(10, 0))
        ToggleSwitch(alerts, command=self._toggle_alerts, on=privacy.alerts_on()).pack(side="right")
        tk.Label(alerts, text=t("privacy_alerts"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(side="left")

        card = RoundedCard(self.body, radius=16, padx=18, pady=12)
        card.pack(fill="both", expand=True, pady=(14, 0))
        tk.Label(card.body, text=t("privacy_recent"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        area = ScrollArea(card.body)
        area.pack(fill="both", expand=True, pady=(6, 0))
        if not self._uses:
            tk.Label(area.inner, text=t("privacy_none"), font=FONT, fg=C.TEXT_MUTED, bg=C.CARD).pack(pady=20)
        for use in self._uses:
            line = tk.Frame(area.inner, bg=C.CARD)
            line.pack(fill="x", pady=4, padx=(0, 8))
            icon_label(line, "health" if use.device == "microphone" else "scan", 13,
                       fg=C.WARN if use.in_use else C.TEXT_MUTED).pack(side="left", padx=(4, 12))
            trusted = use.name.lower() in allowed
            link = tk.Label(line, text=t("privacy_disallow") if trusted else t("privacy_always_allow"), font=FONT_SMALL,
                            fg=C.ACCENT, bg=C.CARD, cursor="hand2")
            link.pack(side="right")
            link.bind("<Button-1>", lambda e, n=use.name, a=trusted: self._set_allowed(n, not a))
            text = tk.Frame(line, bg=C.CARD)
            text.pack(side="left", fill="x", expand=True)
            head = tk.Frame(text, bg=C.CARD)
            head.pack(anchor="w")
            tk.Label(head, text=use.name, font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left")
            if use.in_use:
                pill(head, t("privacy_in_use"), C.WARN).pack(side="left", padx=(8, 0))
            if trusted:
                pill(head, t("privacy_trusted"), C.GOOD).pack(side="left", padx=(8, 0))
            when = relative(use.start.astimezone()) if use.start else ""
            tk.Label(text, text=f"{t('privacy_dev_' + use.device)}  ·  {when}", font=FONT_SMALL, fg=C.TEXT_MUTED,
                     bg=C.CARD, anchor="w").pack(anchor="w")

    def _toggle_alerts(self):
        settings.save(privacy_alerts=not privacy.alerts_on())  # the background agent reads it
        self._render()

    def _set_allowed(self, name, allow):
        if allow:
            privacy.allow(name)
        else:
            privacy.disallow(name)
        self._shown = None
        self.refresh()

    def handle(self, kind, payload):
        pass
