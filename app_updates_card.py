"""The "Your other apps" card on the Updates tab: apps with newer versions
available (via winget), with Update buttons and Update all.

Listing takes a few seconds and each update can take a minute, so both run on
worker threads; results come back through the app's event queue. Updates run
one at a time, in order.
"""
import threading
import tkinter as tk
import webbrowser
from tkinter import ttk

import theme as C
from core import app_updates
from core.i18n import number, t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from widgets import RoundedCard, icon_label, pill

APP_INSTALLER_URL = "ms-windows-store://pdp/?productid=9NBLGGH4NNS1"


def new_state() -> dict:
    return {"items": None, "loading": False, "error": None, "status": {}, "queue": [], "running": False}


class AppUpdatesCard(RoundedCard):
    def __init__(self, parent, app):
        super().__init__(parent, radius=16, padx=22, pady=16)
        self.app = app
        self.state = app.appupd_state
        self._render()

    # ------------------------------------------------------------- render --
    def _render(self):
        body = self.body
        for child in body.winfo_children():
            child.destroy()
        s = self.state
        head = tk.Frame(body, bg=C.CARD)
        head.pack(fill="x")
        icon_label(head, "apps", 20, fg=C.ACCENT).pack(side="left", padx=(0, 14), anchor="n")
        col = tk.Frame(head, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, text=t("appupd_title"), font=FONT_LARGE, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        items = s["items"] or []
        pending = [u for u in items if s["status"].get(u.id, ("",))[0] != "done"]
        if not app_updates.available():
            sub = t("appupd_no_winget")
        elif s["loading"]:
            sub = t("appupd_checking")
        elif s["error"]:
            sub = t("appupd_failed", error=s["error"])
        elif items and pending:
            sub = t("appupd_count", n=number(len(pending)))
        elif s["items"] is not None:
            sub = t("appupd_all_current")
        else:
            sub = ""
        tk.Label(col, text=sub, font=FONT, fg=C.TEXT_MUTED, bg=C.CARD, wraplength=480, justify="left").pack(anchor="w")

        buttons = tk.Frame(head, bg=C.CARD)
        buttons.pack(side="right", anchor="n")
        if not app_updates.available():
            ttk.Button(buttons, text=t("appupd_get_winget"), style="Accent.TButton",
                       command=lambda: webbrowser.open(APP_INSTALLER_URL)).pack(side="left")
            return
        busy = s["loading"] or s["running"]
        if pending:
            all_btn = ttk.Button(buttons, text=t("appupd_update_all"), style="Accent.TButton",
                                 command=lambda: self._update([u.id for u in pending]))
            all_btn.pack(side="left", padx=(0, 8))
            if busy:
                all_btn.state(["disabled"])
        again = ttk.Button(buttons, text=t("check_again"), style="Ghost.TButton", command=lambda: self.check(True))
        again.pack(side="left")
        if busy:
            again.state(["disabled"])
        if not items:
            return

        tk.Frame(body, bg=C.BORDER, height=1).pack(fill="x", pady=(12, 2))
        area = tk.Frame(body, bg=C.CARD)
        area.pack(fill="both", expand=True)
        canvas = tk.Canvas(area, bg=C.CARD, highlightthickness=0, bd=0)
        bar = ttk.Scrollbar(area, orient="vertical", command=canvas.yview, style="Slim.Vertical.TScrollbar")
        canvas.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        rows = tk.Frame(canvas, bg=C.CARD)
        window = canvas.create_window(0, 0, window=rows, anchor="nw")
        rows.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window, width=e.width))
        wheel = lambda e: canvas.yview_scroll(int(-e.delta / 120) * 3, "units")  # noqa: E731
        for update in items:
            row = tk.Frame(rows, bg=C.CARD)
            row.pack(fill="x", pady=5)
            text = tk.Frame(row, bg=C.CARD)
            text.pack(side="left", fill="x", expand=True)
            tk.Label(text, text=update.name, font=FONT_BOLD, fg=C.TEXT, bg=C.CARD, anchor="w").pack(anchor="w")
            tk.Label(text, text=f"{update.version}  →  {update.available}", font=FONT_SMALL, fg=C.TEXT_MUTED,
                     bg=C.CARD).pack(anchor="w")
            state, message = s["status"].get(update.id, ("", ""))
            if state == "updating":
                pill(row, t("appupd_updating"), C.ACCENT, fg=C.ON_ACCENT).pack(side="right", padx=4)
            elif state == "queued":
                pill(row, t("appupd_queued"), C.BORDER, fg=C.TEXT_MUTED).pack(side="right", padx=4)
            elif state == "done":
                pill(row, t("appupd_done"), C.GOOD).pack(side="right", padx=4)
            else:
                btn = ttk.Button(row, text=t("appupd_update"), style="Ghost.TButton",
                                 command=lambda i=update.id: self._update([i]))
                btn.pack(side="right", padx=4)
                if busy:
                    btn.state(["disabled"])
                if state == "failed":
                    pill(row, t("appupd_failed_pill"), C.BAD).pack(side="right", padx=4)
                    if message:
                        tk.Label(text, text=message[:120], font=FONT_SMALL, fg=C.BAD, bg=C.CARD, anchor="w",
                                 wraplength=460, justify="left").pack(anchor="w")
            for w in (row, text, *text.winfo_children()):
                w.bind("<MouseWheel>", wheel)
        canvas.bind("<MouseWheel>", wheel)
        rows.bind("<MouseWheel>", wheel)

    # ------------------------------------------------------------ actions --
    def check(self, force=False):
        s = self.state
        if s["loading"] or s["running"] or not app_updates.available():
            return
        s.update(loading=True, error=None)
        if force:
            s["status"] = {}
        self._render()
        queue = self.app.event_queue

        def run():
            try:
                queue.put(("appupd_list", app_updates.list_updates()))
            except Exception as e:  # winget missing pieces, timeouts...
                queue.put(("appupd_list_failed", str(e)))

        threading.Thread(target=run, daemon=True).start()

    def _update(self, ids):
        s = self.state
        if s["running"]:
            return
        s["running"] = True
        for pkg in ids:
            s["status"][pkg] = ("queued", "")
        self._render()
        queue = self.app.event_queue

        def run():
            for pkg in ids:
                queue.put(("appupd_status", (pkg, "updating", "")))
                try:
                    ok, message = app_updates.upgrade(pkg)
                except Exception as e:
                    ok, message = False, str(e)
                queue.put(("appupd_status", (pkg, "done" if ok else "failed", message)))
            queue.put(("appupd_finished", None))

        threading.Thread(target=run, daemon=True).start()

    # --------------------------------------------------- events from queue --
    def handle(self, kind, payload):
        s = self.state
        if kind == "appupd_list":
            s.update(items=payload, loading=False)
        elif kind == "appupd_list_failed":
            s.update(loading=False, error=payload)
        elif kind == "appupd_status":
            pkg, state, message = payload
            s["status"][pkg] = (state, message)
        elif kind == "appupd_finished":
            s["running"] = False
        if self.winfo_exists():
            self._render()
