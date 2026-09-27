"""Email breach check page: type an email, see which known data breaches it's in,
what leaked in each, and what to do about it. The lookup runs on a worker thread.
"""
import threading
import tkinter as tk
from tkinter import ttk

import theme as C
from core import breaches
from core.i18n import number, t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from tools_page import subpage_header, wrap_to_width
from widgets import Ring, RoundedCard, ScrollArea, icon_label, pill


def new_state() -> dict:
    return {"email": "", "result": None, "busy": False, "error": None}


class BreachPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        self.state = app.breach_state
        subpage_header(self, app, t("breach_title"), t("breach_sub"), "nav_tools", "tools")
        self.body = tk.Frame(self, bg=C.BG)
        self.body.pack(fill="both", expand=True)
        self._render()

    def _check(self):
        email = self.entry.get().strip()
        s = self.state
        if s["busy"] or not email:
            return
        if not breaches.valid(email):
            s.update(error=t("breach_invalid"), result=None, email=email)
            self._render()
            return
        s.update(busy=True, error=None, result=None, email=email)
        self._render()
        queue = self.app.event_queue

        def run():
            try:
                queue.put(("breach_done", breaches.check(email)))
            except breaches.BreachCheckError as e:
                queue.put(("breach_done", e))

        threading.Thread(target=run, daemon=True).start()

    def handle(self, kind, payload):
        s = self.state
        s["busy"] = False
        if isinstance(payload, Exception):
            reason = str(payload)
            s["error"] = t("breach_busy") if reason == "busy" else t("breach_failed", error=reason)
        else:
            s["result"] = payload
        if self.winfo_exists():
            self._render()

    def _render(self):
        for child in self.body.winfo_children():
            child.destroy()
        s = self.state
        result = s["result"]

        top = RoundedCard(self.body, radius=16, padx=24, pady=16)
        top.pack(fill="x")
        row = tk.Frame(top.body, bg=C.CARD)
        row.pack(fill="x")
        box = RoundedCard(row, bg=C.BG, outer=C.CARD, radius=8, padx=10, pady=4)
        box.pack(side="left", fill="x", expand=True)
        self.entry = tk.Entry(box.body, font=FONT, bg=C.BG, fg=C.TEXT, insertbackground=C.TEXT, relief="flat", bd=0,
                              highlightthickness=0)
        self.entry.pack(fill="x", ipady=6)
        self.entry.insert(0, s["email"])
        self.entry.bind("<Return>", lambda e: self._check())
        btn = ttk.Button(row, text=t("breach_checking") if s["busy"] else t("breach_check"), style="Accent.TButton",
                         command=self._check)
        btn.pack(side="left", padx=(10, 0))
        if s["busy"]:
            btn.state(["disabled"])
        note = tk.Label(top.body, text=t("breach_privacy"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD,
                        justify="left", anchor="w")
        note.pack(anchor="w", fill="x", pady=(8, 0))
        wrap_to_width(note, top.body)
        if s["error"]:
            tk.Label(top.body, text=s["error"], font=FONT_SMALL, fg=C.BAD, bg=C.CARD).pack(anchor="w", pady=(6, 0))

        if result is None:
            return
        card = RoundedCard(self.body, radius=16, padx=18, pady=12)
        card.pack(fill="both", expand=True, pady=(14, 0))
        head = tk.Frame(card.body, bg=C.CARD)
        head.pack(fill="x", pady=(0, 6))
        ring = Ring(head, size=56)
        ring.pack(side="left", padx=(4, 14))
        if result:  # packed before the text, so a long line wraps instead of squeezing the button
            ttk.Button(head, text=t("breach_next_steps"), style="Ghost.TButton",
                       command=lambda: self.app._show_page("recovery")).pack(side="right", anchor="n", padx=(12, 0))
        col = tk.Frame(head, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        if not result:
            ring.show(C.GOOD, glyph="check")
            title, sub = t("breach_none"), t("breach_none_sub")
        else:
            with_pw = sum(1 for b in result if b.passwords)
            ring.show(C.BAD if with_pw else C.WARN, glyph="warning")
            title = t("breach_found", n=number(len(result)))
            sub = t("breach_found_pw", n=number(with_pw)) if with_pw else t("breach_found_sub")
        tk.Label(col, text=title, font=FONT_LARGE, fg=C.TEXT, bg=C.CARD, anchor="w").pack(anchor="w", fill="x")
        sub_label = tk.Label(col, text=sub, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left", anchor="w")
        sub_label.pack(anchor="w", fill="x")
        wrap_to_width(sub_label, col)
        area = ScrollArea(card.body)
        area.pack(fill="both", expand=True)
        for b in result:
            line = tk.Frame(area.inner, bg=C.CARD)
            line.pack(fill="x", pady=5, padx=(0, 8))
            icon_label(line, "warning" if b.passwords else "info", 13,
                       fg=C.BAD if b.passwords else C.TEXT_MUTED).pack(side="left", anchor="n", padx=(4, 12), pady=2)
            text = tk.Frame(line, bg=C.CARD)
            text.pack(side="left", fill="x", expand=True)
            title_row = tk.Frame(text, bg=C.CARD)
            title_row.pack(anchor="w")
            tk.Label(title_row, text=b.name, font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left")
            if b.year:
                tk.Label(title_row, text=b.year, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(side="left", padx=(8, 0))
            if b.passwords:
                pill(title_row, t("breach_pw_pill"), C.BAD).pack(side="left", padx=(8, 0))
            leaked = ", ".join(b.data[:8]) + ("…" if len(b.data) > 8 else "")
            label = tk.Label(text, text=leaked, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left", anchor="w")
            label.pack(anchor="w", fill="x")
            wrap_to_width(label, text, 200)
