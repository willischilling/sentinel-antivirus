"""Browser guard page: what's currently set in the places browser hijackers use
(browser policies, the hosts file, proxy settings), each with a Remove button.
The background agent watches them and alerts on changes.
"""
import threading
import tkinter as tk
from tkinter import ttk

import theme as C
from core import hijack
from core.i18n import number, t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from tools_page import subpage_header, wrap_to_width
from widgets import Ring, RoundedCard, ScrollArea, icon_label

SECTION_ICONS = {"policy": "web", "hosts": "globe", "proxy": "firewall"}


def new_state() -> dict:
    return {"items": None, "busy": False, "error": None}


class GuardPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        self.state = app.guard_state
        subpage_header(self, app, t("guard_title"), t("guard_sub"), "nav_tools", "tools")
        self.body = tk.Frame(self, bg=C.BG)
        self.body.pack(fill="both", expand=True)
        self._render()

    def refresh(self):
        queue = self.app.event_queue
        threading.Thread(target=lambda: queue.put(("guard_items", hijack.current())), daemon=True).start()

    def _remove(self, item):
        if self.state["busy"]:
            return
        self.state.update(busy=True, error=None)
        self._render()
        queue = self.app.event_queue

        def run():
            error = None
            try:
                hijack.remove(item)
            except Exception as e:  # declined the admin prompt, or Windows refused
                error = str(e)
            queue.put(("guard_done", error))
            queue.put(("guard_items", hijack.current()))

        threading.Thread(target=run, daemon=True).start()

    def handle(self, kind, payload):
        s = self.state
        if kind == "guard_items":
            s["items"] = payload
        elif kind == "guard_done":
            s.update(busy=False, error=payload)
        if self.winfo_exists():
            self._render()
        self.app.tools_page.handle(kind, payload)

    def _render(self):
        for child in self.body.winfo_children():
            child.destroy()
        s = self.state
        items = s["items"]

        top = RoundedCard(self.body, radius=16, padx=24, pady=16)
        top.pack(fill="x")
        row = tk.Frame(top.body, bg=C.CARD)
        row.pack(fill="x")
        ring = Ring(row, size=64)
        ring.pack(side="left", padx=(0, 18))
        col = tk.Frame(row, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        if items is None:
            ring.spin("")
            title, sub = t("guard_checking"), ""
        elif items:
            ring.show(C.WARN, glyph="warning")
            title, sub = t("guard_found", n=number(len(items))), t("guard_found_sub")
        else:
            ring.show(C.GOOD, glyph="check")
            title, sub = t("guard_clean"), t("guard_clean_sub")
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
        if items is not None:  # what's watched, with a check for each kind that's clear
            kinds = {i.kind for i in items}
            for kind in ("policy", "hosts", "proxy"):
                if kind in kinds:
                    continue
                ok = tk.Frame(area.inner, bg=C.CARD)
                ok.pack(fill="x", pady=5, padx=(0, 8))
                icon_label(ok, "check", 13, fg=C.GOOD).pack(side="left", padx=(4, 12))
                tk.Label(ok, text=t(f"guard_ok_{kind}"), font=FONT, fg=C.TEXT, bg=C.CARD).pack(side="left")
        for item in items or []:
            line = tk.Frame(area.inner, bg=C.CARD)
            line.pack(fill="x", pady=5, padx=(0, 8))
            icon_label(line, SECTION_ICONS[item.kind], 13, fg=C.WARN).pack(side="left", anchor="n", padx=(4, 12), pady=2)
            btn = ttk.Button(line, text=t("shield_remove"), style="Danger.TButton", command=lambda i=item: self._remove(i))
            btn.pack(side="right", anchor="n")
            if s["busy"]:
                btn.state(["disabled"])
            text = tk.Frame(line, bg=C.CARD)
            text.pack(side="left", fill="x", expand=True)
            label = t("guard_hosts_label") if item.kind == "hosts" else item.label
            tk.Label(text, text=f"{label}: {t(item.what)}", font=FONT_BOLD, fg=C.TEXT, bg=C.CARD, anchor="w").pack(
                anchor="w")
            value = tk.Label(text, text=hijack.describe(item), font=("Consolas", 9), fg=C.TEXT_MUTED, bg=C.CARD,
                             justify="left", anchor="w")
            value.pack(anchor="w", fill="x")
            wrap_to_width(value, text, 200)
        watch = tk.Frame(card.body, bg=C.CARD)
        watch.pack(fill="x", pady=(8, 0))
        icon_label(watch, "info", 11, fg=C.TEXT_MUTED).pack(side="left", anchor="n", padx=(0, 8), pady=1)
        note = tk.Label(watch, text=t("guard_note"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left",
                        anchor="w")
        note.pack(side="left", fill="x", expand=True)
        wrap_to_width(note, watch, 200, reserve=30)
