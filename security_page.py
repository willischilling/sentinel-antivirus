"""The Security Check page: the security score with a checklist of what
protects this PC (each with a Fix button), and the password leak check.
Opened from the score bar on the dashboard.
"""
import os
import threading
import tkinter as tk
from tkinter import ttk

import theme as C
from core import autostart, firewall, pwned, schedule, security_score
from core.i18n import number, plural, t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from widgets import Ring, RoundedCard, icon_label


def new_state() -> dict:
    return {"checks": None, "loading": False, "fixing": None, "pw_result": None, "pw_busy": False}


def score_color(value: int) -> str:
    return C.GOOD if value >= 85 else C.WARN if value >= 60 else C.BAD


class SecurityPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        self.state = app.sec_state
        tk.Label(self, text=t("sec_title"), font=(C.DISPLAY, 18), fg=C.TEXT, bg=C.BG).pack(anchor="w")
        tk.Label(self, text=t("sec_sub"), font=FONT, fg=C.TEXT_MUTED, bg=C.BG).pack(anchor="w", pady=(2, 16))
        self.body = tk.Frame(self, bg=C.BG)
        self.body.pack(fill="both", expand=True)
        self._render()

    # ------------------------------------------------------------- checks --
    def current_checks(self):
        """The gathered checks, with the app-update item kept live from the Updates tab."""
        checks = self.state["checks"]
        if checks is None:
            return None
        pending = self.app.outdated_app_count()
        for check in checks:
            if check.key == "apps":
                check.ok = None if pending is None else pending == 0
                check.detail = {"count": pending or 0}
            elif check.key == "sentinel":
                check.ok = {"current": True, "available": False}.get(self.app._update["state"])
            elif check.key == "protection":
                check.ok = bool(self.app.protection_on)
        return checks

    def refresh(self):
        s = self.state
        if s["loading"]:
            return
        s["loading"] = True
        if self.app.appupd_state["items"] is None:
            self.app.appupd_card.check()  # so the app-update item can be filled in
        queue = self.app.event_queue

        def run():
            try:
                checks = security_score.gather(bool(self.app.protection_on), None, None)
            except Exception:
                checks = []
            queue.put(("sec_checks", checks))

        threading.Thread(target=run, daemon=True).start()
        if self.winfo_exists():
            self._render()

    # ------------------------------------------------------------- render --
    def _render(self):
        typed = self.pw_entry.get() if getattr(self, "pw_entry", None) and self.pw_entry.winfo_exists() else ""
        for child in self.body.winfo_children():
            child.destroy()
        checks = self.current_checks()
        grid = tk.Frame(self.body, bg=C.BG)
        grid.pack(fill="both", expand=True)
        grid.columnconfigure(0, weight=3, uniform="sec")
        grid.columnconfigure(1, weight=2, uniform="sec")
        grid.rowconfigure(0, weight=1)

        left = RoundedCard(grid, radius=16, padx=22, pady=16)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        head = tk.Frame(left.body, bg=C.CARD)
        head.pack(fill="x")
        ring = Ring(head, size=96)
        ring.pack(side="left", padx=(0, 16))
        col = tk.Frame(head, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        if checks is None:
            ring.spin("…")
            tk.Label(col, text=t("sec_checking"), font=FONT_LARGE, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        else:
            value = security_score.score(checks)
            ring.show_value(score_color(value), str(value), "/100")
            todo = [c for c in checks if c.ok is False]
            title = t("sec_all_good") if not todo else plural("sec_todo", len(todo))
            tk.Label(col, text=title, font=FONT_LARGE, fg=C.TEXT, bg=C.CARD, justify="left",
                     anchor="w").pack(anchor="w", fill="x")
            hint = tk.Label(col, text=t("sec_score_hint"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD,
                            justify="left", anchor="w")
            hint.pack(anchor="w", fill="x", pady=(2, 0))
            col.bind("<Configure>", lambda e: hint.configure(wraplength=max(120, e.width - 4)))
        again = ttk.Button(head, text=t("check_again"), style="Ghost.TButton", command=self.refresh)
        again.pack(side="right", anchor="n")
        if self.state["loading"]:
            again.state(["disabled"])

        if checks:
            tk.Frame(left.body, bg=C.BORDER, height=1).pack(fill="x", pady=(12, 4))
            order = sorted(checks, key=lambda c: (c.ok is not False, -c.weight))  # things to fix first
            for check in order:
                self._check_row(left.body, check)

        right = RoundedCard(grid, radius=16, padx=20, pady=16)
        right.grid(row=0, column=1, sticky="nsew")
        self._password_card(right.body)
        if typed:
            self.pw_entry.insert(0, typed)

    def _check_row(self, parent, check):
        row = tk.Frame(parent, bg=C.CARD)
        row.pack(fill="x", pady=3)
        icon, color = {True: ("check", C.GOOD), False: ("warning", C.WARN), None: ("info", C.TEXT_MUTED)}[check.ok]
        icon_label(row, icon, 12, fg=color).pack(side="left", padx=(0, 10))
        text = t(f"score_{check.key}")
        if check.ok is False and check.key == "apps":
            text = plural("score_apps_bad", (check.detail or {}).get("count", 0))
        elif check.ok is False:
            text = t(f"score_{check.key}_bad", **(check.detail or {}))
        elif check.ok is None:
            text += "  ·  " + t("sec_unknown")
        tk.Label(row, text=text, font=FONT if check.ok is not False else FONT_BOLD,
                 fg=C.TEXT if check.ok is not None else C.TEXT_MUTED, bg=C.CARD, anchor="w").pack(side="left")
        if check.ok is False and check.fix:
            busy = self.state["fixing"] == check.key
            btn = ttk.Button(row, text=t("sec_fixing") if busy else t("sec_fix"), style="Ghost.TButton",
                             command=lambda c=check: self._fix(c))
            btn.pack(side="right")
            if self.state["fixing"]:
                btn.state(["disabled"])
        else:
            tk.Label(row, text=f"+{check.weight}" if check.ok else "", font=FONT_SMALL, fg=C.TEXT_MUTED,
                     bg=C.CARD).pack(side="right")

    def _password_card(self, body):
        top = tk.Frame(body, bg=C.CARD)
        top.pack(fill="x")
        icon_label(top, "lock", 16, fg=C.ACCENT).pack(side="left", padx=(0, 10))
        tk.Label(top, text=t("pw_title"), font=FONT_LARGE, fg=C.TEXT, bg=C.CARD).pack(side="left")
        tk.Label(body, text=t("pw_desc"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, wraplength=280,
                 justify="left").pack(anchor="w", pady=(8, 10))
        box = RoundedCard(body, bg=C.BG, outer=C.CARD, radius=8, padx=10, pady=4)
        box.pack(fill="x")
        self.pw_entry = tk.Entry(box.body, show="•", font=FONT, bg=C.BG, fg=C.TEXT, insertbackground=C.TEXT,
                                 relief="flat", bd=0, highlightthickness=0)
        self.pw_entry.pack(side="left", fill="x", expand=True, ipady=6)
        self.pw_entry.bind("<Return>", lambda e: self._check_password())
        eye = tk.Label(box.body, text=t("pw_show"), font=FONT_SMALL, fg=C.ACCENT, bg=C.BG, cursor="hand2")
        eye.pack(side="right", padx=(6, 0))
        eye.bind("<Button-1>", lambda e: self._toggle_reveal(eye))
        btn = ttk.Button(body, text=t("pw_check"), style="Accent.TButton", command=self._check_password)
        btn.pack(anchor="w", pady=(10, 0))
        if self.state["pw_busy"]:
            btn.state(["disabled"])
        result = self.state["pw_result"]
        if result is not None:
            kind, value = result
            if kind == "leaked":
                text, color = t("pw_leaked", n=number(value)), C.BAD
            elif kind == "safe":
                text, color = t("pw_safe"), C.GOOD
            else:
                text, color = t("pw_failed", error=value), C.WARN
            tk.Label(body, text=text, font=FONT_BOLD, fg=color, bg=C.CARD, wraplength=280,
                     justify="left").pack(anchor="w", pady=(12, 0))
        tk.Label(body, text=t("pw_privacy"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, wraplength=280,
                 justify="left").pack(anchor="w", side="bottom", pady=(12, 0))

    # ------------------------------------------------------------ actions --
    def _toggle_reveal(self, eye):
        hidden = self.pw_entry.cget("show") == "•"
        self.pw_entry.configure(show="" if hidden else "•")
        eye.configure(text=t("pw_hide") if hidden else t("pw_show"))

    def _check_password(self):
        password = self.pw_entry.get()
        if not password or self.state["pw_busy"]:
            return
        self.pw_entry.delete(0, "end")  # never kept around
        self.state.update(pw_busy=True, pw_result=None)
        self._render()
        queue = self.app.event_queue

        def run():
            try:
                count = pwned.times_leaked(password)
                queue.put(("sec_pw", ("leaked", count) if count else ("safe", 0)))
            except OSError as e:
                queue.put(("sec_pw", ("error", getattr(e, "reason", e))))

        threading.Thread(target=run, daemon=True).start()

    def _fix(self, check):
        app = self.app
        simple = {
            "protection": lambda: app.protection_on or app._toggle_protection(),
            "intel": app._start_intel_update,
            "web": lambda: app._show_page("web"),
            "apps": lambda: app._show_page("updates"),
            "updates": lambda: app._show_page("updates"),
            "scan": app._quick_scan,
            "defender": lambda: _open("windowsdefender://threat"),
            "uac": lambda: _open("UserAccountControlSettings.exe"),
            "schedule": lambda: (schedule.save(frequency="weekly"), self.refresh()),
            "autostart": lambda: (autostart.set_enabled(True), self.refresh()),
        }
        if check.fix in simple:
            simple[check.fix]()
            return
        if check.fix == "firewall":  # needs the admin prompt: run it off the UI thread
            self.state["fixing"] = check.key
            self._render()
            queue = app.event_queue

            def run():
                try:
                    firewall.turn_on() if not firewall.status().lockdown else firewall.set_mode("standard")
                except Exception:
                    pass
                queue.put(("sec_fixed", None))

            threading.Thread(target=run, daemon=True).start()

    # --------------------------------------------------- events from queue --
    def handle(self, kind, payload):
        s = self.state
        if kind == "sec_checks":
            s.update(checks=payload, loading=False)
        elif kind == "sec_pw":
            s.update(pw_result=payload, pw_busy=False)
        elif kind == "sec_fixed":
            s["fixing"] = None
            self.refresh()
            return
        if self.winfo_exists():
            self._render()
        self.app.update_score_bar()


def _open(target):
    try:
        os.startfile(target)
    except OSError:
        pass
