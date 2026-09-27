"""Recovery checklist page: what to do after password-stealing or remote-control
malware, in the order that matters, with a tick box and shortcuts for each step.
Opened from the dashboard banner, the scan summary or the Tools tab.
"""
import os
import threading
import tkinter as tk
import webbrowser
from datetime import datetime
from tkinter import ttk

import theme as C
from core import recovery
from core.i18n import relative, t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from tools_page import subpage_header, wrap_to_width
from widgets import Ring, RoundedCard, ScrollArea, icon_label


class RecoveryPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        self._browsers = None
        subpage_header(self, app, t("rec_title"), t("rec_sub"), "nav_tools", "tools")
        self.body = tk.Frame(self, bg=C.BG)
        self.body.pack(fill="both", expand=True)
        self._render()

    def refresh(self):
        if self._browsers is None:
            queue = self.app.event_queue
            threading.Thread(target=lambda: queue.put(("rec_browsers", recovery.browsers_with_passwords())),
                             daemon=True).start()
        self._render()

    def handle(self, kind, payload):
        if kind == "rec_browsers":
            self._browsers = payload
        if self.winfo_exists():
            self._render()

    def _render(self):
        for child in self.body.winfo_children():
            child.destroy()
        data = recovery.incident()
        active = data if data and not data.get("resolved") else None
        done = set(active.get("done", [])) if active else set()

        top = RoundedCard(self.body, radius=16, padx=24, pady=16)
        top.pack(fill="x")
        row = tk.Frame(top.body, bg=C.CARD)
        row.pack(fill="x")
        ring = Ring(row, size=64)
        ring.pack(side="left", padx=(0, 18))
        right = tk.Frame(row, bg=C.CARD)
        right.pack(side="right", anchor="n", padx=(12, 0))
        col = tk.Frame(row, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        all_done = len(done) == len(recovery.STEPS)
        if active and active.get("threat"):
            ring.show(C.GOOD if all_done else C.BAD, glyph="check" if all_done else "warning")
            title = t("rec_found_title")
            when = relative(datetime.fromisoformat(active["found"]).astimezone())
            sub = t("rec_found_sub", threat=active["threat"], when=when[0].lower() + when[1:])
        else:
            ring.show(C.GOOD if all_done else C.ACCENT, glyph="check" if all_done else "health")
            title, sub = t("rec_manual_title"), t("rec_manual_sub")
        tk.Label(col, text=title, font=FONT_LARGE, fg=C.TEXT, bg=C.CARD, anchor="w").pack(anchor="w", fill="x")
        sub_label = tk.Label(col, text=sub, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left", anchor="w")
        sub_label.pack(anchor="w", fill="x")
        wrap_to_width(sub_label, col)
        tk.Label(right, text=t("rec_progress", done=len(done), total=len(recovery.STEPS)), font=FONT_BOLD,
                 fg=C.GOOD if all_done else C.TEXT, bg=C.CARD).pack(anchor="e")
        if active:
            ttk.Button(right, text=t("rec_finish") if all_done else t("rec_close"),
                       style="Accent.TButton" if all_done else "Ghost.TButton",
                       command=self._finish).pack(anchor="e", pady=(8, 0))

        card = RoundedCard(self.body, radius=16, padx=18, pady=10)
        card.pack(fill="both", expand=True, pady=(14, 0))
        area = ScrollArea(card.body)
        area.pack(fill="both", expand=True)
        for i, step in enumerate(recovery.STEPS, 1):
            self._step(area.inner, i, step, step in done)

    def _step(self, parent, number, step, checked):
        row = tk.Frame(parent, bg=C.CARD)
        row.pack(fill="x", pady=7, padx=(0, 8))
        box = icon_label(row, "check" if checked else "info", 14, fg=C.GOOD if checked else C.TEXT_MUTED,
                         cursor="hand2")
        box.configure(text=box.cget("text") if checked else "○", font=box.cget("font") if checked else (C.UI, 15))
        box.pack(side="left", anchor="n", padx=(4, 14))
        box.bind("<Button-1>", lambda e: self._tick(step, not checked))
        col = tk.Frame(row, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        title = tk.Label(col, text=f"{number}. {t(f'rec_step_{step}')}", font=FONT_BOLD, bg=C.CARD, anchor="w",
                         fg=C.TEXT_MUTED if checked else C.TEXT, cursor="hand2")
        title.pack(anchor="w", fill="x")
        title.bind("<Button-1>", lambda e: self._tick(step, not checked))
        desc = t(f"rec_step_{step}_desc")
        if step == "passwords":
            if self._browsers:
                desc = t("rec_saved_in", browsers=", ".join(self._browsers)) + " " + desc
        text = tk.Label(col, text=desc, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left", anchor="w")
        text.pack(anchor="w", fill="x")
        wrap_to_width(text, col, 200)
        actions = self._actions(step)
        if actions and not checked:
            buttons = tk.Frame(col, bg=C.CARD)
            buttons.pack(anchor="w", pady=(6, 0))
            for label, command in actions:
                ttk.Button(buttons, text=label, style="Ghost.TButton", command=command).pack(side="left",
                                                                                              padx=(0, 6))

    def _actions(self, step):
        app = self.app
        if step == "remove":
            return [(t("rec_open_quarantine"), lambda: app._show_page("quarantine"))]
        if step == "defender":
            return [(t("rec_open_defender"), lambda: _open("windowsdefender://threat"))]
        if step == "sessions":
            return [(name, lambda u=url: webbrowser.open(u)) for name, url in recovery.SIGN_OUT_LINKS]
        if step == "leaks":
            return [(t("rec_open_pw_check"), lambda: app._show_page("security"))]
        return []

    def _tick(self, step, done):
        recovery.set_done(step, done)
        self._render()
        self.app.refresh_recovery_banner()

    def _finish(self):
        recovery.resolve()
        self._render()
        self.app.refresh_recovery_banner()


def _open(target):
    try:
        os.startfile(target)
    except OSError:
        pass
