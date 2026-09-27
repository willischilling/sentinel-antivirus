"""Startup apps page: everything that starts with Windows, who made it, advice,
and an on/off switch (the same flag Task Manager uses). Listing and switching
run on worker threads.
"""
import threading
import tkinter as tk
from tkinter import ttk

import theme as C
from core import startup_apps
from core.i18n import number, t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from tools_page import subpage_header, wrap_to_width
from widgets import Ring, RoundedCard, ScrollArea, ToggleSwitch, icon_label, pill

ADVICE_COLORS = {"startup_safe": "GOOD", "startup_keep": "ACCENT", "startup_unknown": "WARN"}


def new_state() -> dict:
    return {"apps": None, "busy": False, "error": None}


class StartupPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        self.state = app.startup_state
        subpage_header(self, app, t("startup_title"), t("startup_sub"), "nav_tools", "tools")
        self.body = tk.Frame(self, bg=C.BG)
        self.body.pack(fill="both", expand=True)
        self._render()

    def refresh(self):
        queue = self.app.event_queue

        def run():
            try:
                queue.put(("startup_list", startup_apps.list_apps()))
            except Exception as e:
                queue.put(("startup_done", str(e)))

        threading.Thread(target=run, daemon=True).start()

    def _toggle(self, item):
        if self.state["busy"]:
            return
        self.state.update(busy=True, error=None)
        self._render()
        queue = self.app.event_queue

        def run():
            error = None
            try:
                startup_apps.set_enabled(item, not item.enabled)
            except Exception as e:  # declined the admin prompt
                error = str(e)
            queue.put(("startup_done", error))
            queue.put(("startup_list", startup_apps.list_apps()))

        threading.Thread(target=run, daemon=True).start()

    def handle(self, kind, payload):
        s = self.state
        if kind == "startup_list":
            s["apps"] = payload
        else:
            s.update(busy=False, error=payload)
        if self.winfo_exists():
            self._render()
        self.app.tools_page.handle(kind, payload)

    def _render(self):
        for child in self.body.winfo_children():
            child.destroy()
        s = self.state
        apps = s["apps"]

        top = RoundedCard(self.body, radius=16, padx=24, pady=16)
        top.pack(fill="x")
        row = tk.Frame(top.body, bg=C.CARD)
        row.pack(fill="x")
        ring = Ring(row, size=64)
        ring.pack(side="left", padx=(0, 18))
        col = tk.Frame(row, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        if apps is None:
            ring.spin("")
            title, sub = t("startup_loading"), ""
        else:
            on = sum(1 for a in apps if a.enabled)
            safe = sum(1 for a in apps if a.enabled and a.advice == "startup_safe")
            ring.show(C.ACCENT, glyph="power", glyph_color=C.ACCENT)
            title = t("startup_count", on=number(on), total=number(len(apps)))
            sub = t("startup_safe_count", n=number(safe)) if safe else t("startup_tip")
        tk.Label(col, text=title, font=FONT_LARGE, fg=C.TEXT, bg=C.CARD, anchor="w").pack(anchor="w", fill="x")
        sub_label = tk.Label(col, text=sub, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left", anchor="w")
        sub_label.pack(anchor="w", fill="x")
        wrap_to_width(sub_label, col)
        if s["error"]:
            tk.Label(top.body, text=t("fw_failed", error=s["error"]), font=FONT_SMALL, fg=C.BAD, bg=C.CARD,
                     wraplength=640, justify="left").pack(anchor="w", pady=(8, 0))

        card = RoundedCard(self.body, radius=16, padx=18, pady=12)
        card.pack(fill="both", expand=True, pady=(14, 0))
        area = ScrollArea(card.body)
        area.pack(fill="both", expand=True)
        for item in apps or []:
            line = tk.Frame(area.inner, bg=C.CARD)
            line.pack(fill="x", pady=5, padx=(0, 8))
            icon_label(line, "power", 13, fg=C.ACCENT if item.enabled else C.TEXT_MUTED).pack(
                side="left", anchor="n", padx=(4, 12), pady=3)
            switch = ToggleSwitch(line, command=lambda i=item: self._toggle(i), on=item.enabled)
            switch.pack(side="right", anchor="n")
            switch.set_enabled(not s["busy"])
            text = tk.Frame(line, bg=C.CARD)
            text.pack(side="left", fill="x", expand=True)
            head = tk.Frame(text, bg=C.CARD)
            head.pack(anchor="w")
            tk.Label(head, text=item.name, font=FONT_BOLD, fg=C.TEXT if item.enabled else C.TEXT_MUTED,
                     bg=C.CARD).pack(side="left")
            if item.advice and (item.enabled or item.advice == "startup_unknown"):  # advice about turning it off
                color = getattr(C, ADVICE_COLORS[item.advice])
                pill(head, t(item.advice), color, fg="#0b1120" if item.advice != "startup_keep" else "#ffffff").pack(
                    side="left", padx=(8, 0))
            who = item.publisher or t("startup_no_publisher")
            detail = who + ("  ·  " + t("startup_all_users") if item.scope == "all" else "")
            tk.Label(text, text=detail, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, anchor="w").pack(anchor="w")
        note = tk.Frame(card.body, bg=C.CARD)
        note.pack(fill="x", pady=(8, 0))
        icon_label(note, "info", 11, fg=C.TEXT_MUTED).pack(side="left", anchor="n", padx=(0, 8), pady=1)
        text = tk.Label(note, text=t("startup_note"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left",
                        anchor="w")
        text.pack(side="left", fill="x", expand=True)
        wrap_to_width(text, note, 200, reserve=30)
