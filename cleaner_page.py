"""Junk cleaner page: how much each category would free, switches to choose
them, and a Clean button. Analysing and cleaning run on worker threads.
"""
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import theme as C
from core import cleaner
from core.i18n import number, t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from tools_page import size_text, subpage_header, wrap_to_width
from widgets import Ring, RoundedCard, ScrollArea, ToggleSwitch, icon_label

ICONS = {"temp": "folder", "browser": "web", "apps": "apps", "crash": "warning", "recycle": "delete",
         "recent": "history"}


def new_state() -> dict:
    return {"found": None, "busy": None, "selected": set(cleaner.DEFAULT_SELECTED), "result": None, "error": None}


class CleanerPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        self.state = app.clean_state
        subpage_header(self, app, t("clean_title"), t("clean_sub"), "nav_tools", "tools")
        self.body = tk.Frame(self, bg=C.BG)
        self.body.pack(fill="both", expand=True)
        self._render()

    # ------------------------------------------------------------- work --
    def analyze(self):
        s = self.state
        if s["busy"]:
            return
        s.update(busy="analyze", error=None)
        queue = self.app.event_queue

        def run():
            try:
                queue.put(("clean_found", cleaner.analyze()))
            except Exception as e:
                queue.put(("clean_found", e))

        threading.Thread(target=run, daemon=True).start()
        if self.winfo_exists():
            self._render()

    def _clean(self):
        s = self.state
        keys = [k for k in cleaner.CATEGORIES if k in s["selected"]]
        if s["busy"] or not keys:
            return
        if "recycle" in keys and not messagebox.askyesno("Sentinel", t("clean_confirm_bin")):
            return
        s.update(busy="clean", result=None, error=None)
        queue = self.app.event_queue

        def run():
            try:
                freed, skipped = cleaner.clean(keys)
                queue.put(("clean_done", (freed, skipped)))
                queue.put(("clean_found", cleaner.analyze()))
            except Exception as e:
                queue.put(("clean_done", e))

        threading.Thread(target=run, daemon=True).start()
        self._render()

    def _toggle(self, key):
        selected = self.state["selected"]
        selected.symmetric_difference_update({key})
        self._render()
        self.app.tools_page.handle("clean_toggle", None)

    def handle(self, kind, payload):
        s = self.state
        if kind == "clean_found":
            if isinstance(payload, Exception):
                s.update(busy=None, error=str(payload))
            else:
                s.update(found=payload, busy=None if s["busy"] == "analyze" else s["busy"])
        elif kind == "clean_done":
            s["busy"] = None
            if isinstance(payload, Exception):
                s["error"] = str(payload)
            else:
                s["result"] = payload
        if self.winfo_exists():
            self._render()
        self.app.tools_page.handle(kind, payload)

    # ----------------------------------------------------------- render --
    def _render(self):
        for child in self.body.winfo_children():
            child.destroy()
        s = self.state
        found = s["found"]
        total = sum(f.size for k, f in (found or {}).items() if k in s["selected"])

        top = RoundedCard(self.body, radius=16, padx=24, pady=18)
        top.pack(fill="x")
        row = tk.Frame(top.body, bg=C.CARD)
        row.pack(fill="x")
        ring = Ring(row, size=72)
        ring.pack(side="left", padx=(0, 18))
        buttons = tk.Frame(row, bg=C.CARD)
        buttons.pack(side="right", anchor="n", padx=(12, 0))
        col = tk.Frame(row, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        if s["busy"] == "clean":
            ring.spin("")
            title, sub = t("clean_cleaning"), t("clean_cleaning_sub")
        elif found is None:
            ring.spin("")
            title, sub = t("clean_checking"), t("clean_checking_sub")
        else:
            ring.show(C.ACCENT if total else C.GOOD, glyph="broom" if total else "check")
            title = t("clean_total", size=size_text(total)) if total else t("clean_nothing")
            sub = t("clean_total_sub")
            if s["result"]:
                freed, skipped = s["result"]
                sub = t("clean_freed", size=size_text(freed)) + (" " + t("clean_skipped", n=number(skipped))
                                                                  if skipped else "")
        tk.Label(col, text=title, font=FONT_LARGE, fg=C.TEXT, bg=C.CARD, anchor="w").pack(anchor="w", fill="x")
        sub_label = tk.Label(col, text=sub, font=FONT, fg=C.GOOD if s["result"] and not s["busy"] else C.TEXT_MUTED,
                             bg=C.CARD, justify="left", anchor="w")
        sub_label.pack(anchor="w", fill="x")
        wrap_to_width(sub_label, col)
        clean = ttk.Button(buttons, text=t("clean_now"), style="Accent.TButton", command=self._clean)
        clean.pack(side="left")
        again = ttk.Button(buttons, text=t("check_again"), style="Ghost.TButton", command=self.analyze)
        again.pack(side="left", padx=(8, 0))
        if s["busy"] or not total:
            clean.state(["disabled"])
        if s["busy"]:
            again.state(["disabled"])
        if s["error"]:
            tk.Label(top.body, text=t("fw_failed", error=s["error"]), font=FONT_SMALL, fg=C.BAD, bg=C.CARD,
                     wraplength=640, justify="left").pack(anchor="w", pady=(10, 0))

        card = RoundedCard(self.body, radius=16, padx=22, pady=8)
        card.pack(fill="both", expand=True, pady=(14, 0))
        area = ScrollArea(card.body)
        area.pack(fill="both", expand=True)
        for key in cleaner.CATEGORIES:
            self._category_row(area.inner, key, (found or {}).get(key))
            tk.Frame(area.inner, bg=C.BORDER, height=1).pack(fill="x", padx=(0, 8))
        system = tk.Frame(area.inner, bg=C.CARD)
        system.pack(fill="x", pady=8, padx=(0, 8))
        icon_label(system, "settings", 15, fg=C.ACCENT).pack(side="left", padx=(0, 16))
        ttk.Button(system, text=t("clean_open_disk_cleanup"), style="Ghost.TButton",
                   command=cleaner.open_disk_cleanup).pack(side="right")
        col = tk.Frame(system, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, text=t("clean_cat_system"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        desc = tk.Label(col, text=t("clean_cat_system_desc"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD,
                        justify="left", anchor="w")
        desc.pack(anchor="w", fill="x")
        wrap_to_width(desc, col)

    def _category_row(self, parent, key, found):
        row = tk.Frame(parent, bg=C.CARD)
        row.pack(fill="x", pady=6, padx=(0, 8))
        icon_label(row, ICONS[key], 15, fg=C.ACCENT).pack(side="left", padx=(0, 16))
        switch = ToggleSwitch(row, command=lambda k=key: self._toggle(k), on=key in self.state["selected"])
        switch.pack(side="right", padx=(14, 0))
        switch.set_enabled(not self.state["busy"])
        size = tk.Label(row, text=size_text(found.size) if found else "…", font=FONT_BOLD,
                        fg=C.TEXT if found and found.size else C.TEXT_MUTED, bg=C.CARD)
        size.pack(side="right")
        col = tk.Frame(row, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, text=t(f"clean_cat_{key}"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        text = t(f"clean_cat_{key}_desc")
        if found and found.skipped_apps:
            text += " " + t("clean_close_apps", apps=", ".join(found.skipped_apps))
        desc = tk.Label(col, text=text, font=FONT_SMALL, bg=C.CARD, justify="left", anchor="w",
                        fg=C.WARN if found and found.skipped_apps else C.TEXT_MUTED)
        desc.pack(anchor="w", fill="x")
        wrap_to_width(desc, col)
