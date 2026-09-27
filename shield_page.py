"""Ransomware shield page (Windows' Controlled folder access): the on/off
switch, which folders are protected, and the apps Windows blocked, with a
button to allow each one. Every change goes through one admin prompt, on a
worker thread.
"""
import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

import theme as C
from core import shield
from core.i18n import number, relative, t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from tools_page import subpage_header, wrap_to_width
from widgets import Ring, RoundedCard, ScrollArea, ToggleSwitch, icon_label, pill


def new_state() -> dict:
    return {"status": None, "blocked": None, "busy": False, "error": None}


class ShieldPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        self.state = app.shield_state
        subpage_header(self, app, t("shield_title"), t("shield_sub"), "nav_protection", "protection")
        self.body = tk.Frame(self, bg=C.BG)
        self.body.pack(fill="both", expand=True)
        self._render()

    # ------------------------------------------------------------- work --
    def refresh(self):
        queue = self.app.event_queue

        def run():
            try:
                queue.put(("shield_status", (shield.status(), shield.blocked())))
            except Exception as e:
                queue.put(("shield_done", str(e)))

        threading.Thread(target=run, daemon=True).start()

    def _change(self, action):
        if self.state["busy"]:
            return
        self.state.update(busy=True, error=None)
        self._render()
        queue = self.app.event_queue

        def run():
            error = None
            try:
                action()
            except Exception as e:  # declined prompt, or Windows refused
                error = str(e)
            queue.put(("shield_done", error))
            try:
                queue.put(("shield_status", (shield.status(), shield.blocked())))
            except Exception:
                pass

        threading.Thread(target=run, daemon=True).start()

    def _toggle(self):
        st = self.state["status"]
        self._change(shield.turn_off if st and st.on else shield.turn_on)

    def _add_folder(self):
        folder = filedialog.askdirectory(title=t("shield_add_folder"))
        if folder:
            self._change(lambda: shield.add_folder(str(Path(folder))))

    def handle(self, kind, payload):
        s = self.state
        if kind == "shield_status":
            s["status"], s["blocked"] = payload
        elif kind == "shield_done":
            s.update(busy=False, error=payload)
        if self.winfo_exists():
            self._render()

    # ----------------------------------------------------------- render --
    def _render(self):
        for child in self.body.winfo_children():
            child.destroy()
        s = self.state
        st = s["status"]
        on = bool(st and st.on)
        busy = s["busy"] or st is None

        main = RoundedCard(self.body, radius=16, padx=24, pady=18)
        main.pack(fill="x")
        top = tk.Frame(main.body, bg=C.CARD)
        top.pack(fill="x")
        ring = Ring(top, size=72)
        ring.pack(side="left", padx=(0, 18))
        ring.show(C.GOOD if on else C.BORDER, glyph="lock", glyph_color=C.GOOD if on else C.TEXT_MUTED)
        col = tk.Frame(top, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        switch = ToggleSwitch(top, command=self._toggle, on=on)
        switch.pack(side="right", anchor="n")
        if st is None:
            title, sub = t("shield_off"), t("fw_reading")
        elif not st.available:
            title, sub = t("shield_unavailable"), t("shield_unavailable_desc")
        elif s["busy"]:
            title, sub = t("shield_on") if on else t("shield_off"), t("fw_working")
        elif on:
            title, sub = t("shield_on"), t("shield_on_desc")
        else:
            title, sub = t("shield_off"), t("shield_audit_desc") if st.audit else t("shield_off_desc")
        switch.set_enabled(not busy and bool(st and st.available))
        tk.Label(col, text=title, font=FONT_LARGE, fg=C.TEXT, bg=C.CARD, anchor="w").pack(anchor="w", fill="x")
        sub_label = tk.Label(col, text=sub, font=FONT, fg=C.TEXT_MUTED, bg=C.CARD, justify="left", anchor="w")
        sub_label.pack(anchor="w", fill="x")
        wrap_to_width(sub_label, col)
        if s["error"]:
            tk.Label(main.body, text=t("fw_failed", error=s["error"]), font=FONT_SMALL, fg=C.BAD, bg=C.CARD,
                     wraplength=640, justify="left").pack(anchor="w", pady=(10, 0))

        grid = tk.Frame(self.body, bg=C.BG)
        grid.pack(fill="both", expand=True, pady=(14, 0))
        grid.columnconfigure(0, weight=1, uniform="shield")
        grid.columnconfigure(1, weight=1, uniform="shield")
        grid.rowconfigure(0, weight=1)
        left = RoundedCard(grid, radius=16, padx=20, pady=16)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 7))
        right = RoundedCard(grid, radius=16, padx=20, pady=16)
        right.grid(row=0, column=1, sticky="nsew", padx=(7, 0))
        self._folders(left.body, st, busy)
        self._apps(right.body, busy)

    def _folders(self, body, st, busy):
        head = tk.Frame(body, bg=C.CARD)
        head.pack(fill="x")
        tk.Label(head, text=t("shield_folders"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left")
        add = ttk.Button(head, text=t("shield_add_folder"), style="Ghost.TButton", command=self._add_folder)
        add.pack(side="right")
        if busy or not (st and st.available):
            add.state(["disabled"])
        area = ScrollArea(body)
        area.pack(fill="both", expand=True, pady=(8, 0))
        for folder in shield.default_folders():
            self._folder_row(area.inner, str(folder), None)
        for folder in (st.folders if st else []):
            self._folder_row(area.inner, folder, None if busy else lambda f=folder: self._change(
                lambda: shield.remove_folder(f)))

    def _folder_row(self, parent, folder, remove):
        row = tk.Frame(parent, bg=C.CARD)
        row.pack(fill="x", pady=3, padx=(0, 6))
        icon_label(row, "folder", 12, fg=C.ACCENT).pack(side="left", padx=(0, 10))
        if remove:
            link = tk.Label(row, text=t("shield_remove"), font=FONT_SMALL, fg=C.BAD, bg=C.CARD, cursor="hand2")
            link.pack(side="right")
            link.bind("<Button-1>", lambda e: remove())
        else:
            tk.Label(row, text=t("shield_always"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(side="right")
        tk.Label(row, text=Path(folder).name or folder, font=FONT, fg=C.TEXT, bg=C.CARD, anchor="w").pack(
            side="left")

    def _apps(self, body, busy):
        tk.Label(body, text=t("shield_blocked_title"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        hint = tk.Label(body, text=t("shield_blocked_hint"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD,
                        justify="left", anchor="w")
        hint.pack(anchor="w", fill="x")
        wrap_to_width(hint, body, 180)
        area = ScrollArea(body)
        area.pack(fill="both", expand=True, pady=(8, 0))
        allowed = {os.path.normcase(a) for a in shield.allowed_apps()}
        blocked = [b for b in (self.state["blocked"] or []) if os.path.normcase(b.exe) not in allowed]
        if self.state["blocked"] is not None and not blocked and not allowed:
            tk.Label(area.inner, text=t("shield_nothing_blocked"), font=FONT, fg=C.TEXT_MUTED, bg=C.CARD).pack(
                anchor="w", pady=10)
        for app in blocked:
            row = tk.Frame(area.inner, bg=C.CARD)
            row.pack(fill="x", pady=3, padx=(0, 6))
            btn = ttk.Button(row, text=t("shield_allow"), style="Ghost.TButton",
                             command=lambda e=app.exe: self._change(lambda: shield.allow_app(e)))
            btn.pack(side="right")
            if busy:
                btn.state(["disabled"])
            col = tk.Frame(row, bg=C.CARD)
            col.pack(side="left", fill="x", expand=True)
            tk.Label(col, text=Path(app.exe).name, font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
            tk.Label(col, text=t("shield_blocked_line", n=number(app.count), when=relative(app.last)),
                     font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(anchor="w")
        for exe in shield.allowed_apps():
            row = tk.Frame(area.inner, bg=C.CARD)
            row.pack(fill="x", pady=3, padx=(0, 6))
            link = tk.Label(row, text=t("shield_remove"), font=FONT_SMALL, fg=C.BAD, bg=C.CARD, cursor="hand2")
            link.pack(side="right")
            if not busy:
                link.bind("<Button-1>", lambda e, x=exe: self._change(lambda: shield.disallow_app(x)))
            title = tk.Frame(row, bg=C.CARD)
            title.pack(side="left")
            tk.Label(title, text=Path(exe).name, font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left")
            pill(title, t("shield_allowed_pill"), C.GOOD).pack(side="left", padx=(8, 0))
