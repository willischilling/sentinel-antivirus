"""The Firewall tab: a control panel for the built-in Windows Firewall.

Overview: mode (Standard / Lockdown), firewall state, inbound/outbound
defaults, network type, and a status ring. Blocked apps: programs Sentinel
has blocked from the network, with Unblock, plus "Block an app".
Reading is done on a worker thread (about a second); every change asks for
administrator approval through core/elevate.py.
"""
import os
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import theme as C
from core import firewall
from core.i18n import t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from widgets import Ring, RoundedCard, icon_label


class FirewallPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        self.state = app.fw_state  # survives page rebuilds
        tk.Label(self, text=t("nav_firewall"), font=("Segoe UI Semibold", 18), fg=C.TEXT, bg=C.BG).pack(anchor="w")
        tk.Label(self, text=t("fw_sub"), font=FONT, fg=C.TEXT_MUTED, bg=C.BG).pack(anchor="w", pady=(2, 14))

        tabs = tk.Frame(self, bg=C.BG)
        tabs.pack(fill="x")
        self.tab_labels = {}
        for key in ("overview", "apps"):
            lbl = tk.Label(tabs, text=t(f"fw_tab_{key}"), font=FONT_BOLD, bg=C.BG, cursor="hand2", padx=4, pady=6)
            lbl.pack(side="left", padx=(0, 22))
            lbl.bind("<Button-1>", lambda e, k=key: self._switch_tab(k))
            self.tab_labels[key] = lbl
        self.underline = tk.Frame(self, bg=C.ACCENT, height=2)
        tk.Frame(self, bg=C.BORDER, height=1).pack(fill="x")
        self.body = tk.Frame(self, bg=C.BG)
        self.body.pack(fill="both", expand=True, pady=(16, 0))
        self._render()
        if self.state["status"] is None:
            self.refresh()

    # --------------------------------------------------------------- tabs --
    def _switch_tab(self, key):
        self.state["tab"] = key
        self._render()

    def _render(self):
        tab = self.state["tab"]
        for key, lbl in self.tab_labels.items():
            lbl.configure(fg=C.ACCENT if key == tab else C.TEXT_MUTED)
        self.after_idle(self._place_underline)
        for child in self.body.winfo_children():
            child.destroy()
        if self.state["error"]:
            tk.Label(self.body, text=t("fw_failed", error=self.state["error"]), font=FONT_SMALL, fg=C.BAD, bg=C.BG,
                     wraplength=680, justify="left").pack(anchor="w", pady=(0, 10))
        if self.state["status"] is None:
            tk.Label(self.body, text=t("fw_reading"), font=FONT, fg=C.TEXT_MUTED, bg=C.BG).pack(anchor="w")
            return
        if tab == "overview":
            self._overview()
        else:
            self._apps()

    def _place_underline(self):
        lbl = self.tab_labels[self.state["tab"]]
        if lbl.winfo_exists():
            self.underline.place(in_=lbl, relx=0, rely=1.0, relwidth=1.0, y=1, height=2)

    # ----------------------------------------------------------- overview --
    def _overview(self):
        st: firewall.FirewallStatus = self.state["status"]
        busy = self.state["busy"]
        grid = tk.Frame(self.body, bg=C.BG)
        grid.pack(fill="both", expand=True)
        grid.columnconfigure(0, weight=3, uniform="fw")
        grid.columnconfigure(1, weight=2, uniform="fw")

        left = RoundedCard(grid, radius=16, padx=22, pady=18)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 16))
        head = tk.Frame(left.body, bg=C.CARD)
        head.pack(fill="x")
        icon_label(head, "shield", 14, fg=C.TEXT).pack(side="left", padx=(0, 8))
        tk.Label(head, text=t("fw_mode"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left")

        tiles = tk.Frame(left.body, bg=C.CARD)
        tiles.pack(fill="x", pady=(10, 4))
        for i, mode in enumerate(("standard", "lockdown")):
            tiles.columnconfigure(i, weight=1, uniform="mode")
            selected = st.mode == mode
            bg = (C.BAD if mode == "lockdown" else C.ACCENT_DARK) if selected else C.BORDER
            tile = RoundedCard(tiles, bg=bg, outer=C.CARD, radius=10, padx=12, pady=10,
                               hover_bg=None if busy else C.CARD_HOVER,
                               command=None if busy or selected else lambda m=mode: self._set_mode(m))
            tile.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 6, 0))
            fg = C.ON_ACCENT if selected else C.TEXT
            tk.Label(tile.body, text=t(f"fw_mode_{mode}"), font=FONT_BOLD, fg=fg, bg=bg).pack(anchor="w")
            tk.Label(tile.body, text=t(f"fw_mode_{mode}_desc"), font=FONT_SMALL, bg=bg, wraplength=190,
                     justify="left", fg=C.ON_ACCENT if selected else C.TEXT_MUTED).pack(anchor="w")
        if st.mode == "custom":
            tk.Label(left.body, text=t("fw_custom_note"), font=FONT_SMALL, fg=C.WARN, bg=C.CARD, wraplength=380,
                     justify="left").pack(anchor="w", pady=(4, 0))

        rows = [
            ("firewall", "fw_state", ("fw_active", C.GOOD) if st.enabled else ("fw_off", C.BAD)),
            ("download", "fw_inbound", ("fw_block", C.GOOD) if st.inbound_blocked or st.lockdown
             else ("fw_allow", C.WARN)),
            ("upload", "fw_outbound", ("fw_block", C.BAD) if st.lockdown or st.outbound_blocked
             else ("fw_allow", C.WARN)),
            ("globe", "fw_network", ((f"fw_net_{(st.network or 'unknown').lower()}"),
                                     C.GOOD if st.network in ("Private", "DomainAuthenticated") else C.WARN)),
        ]
        for icon, label, (value, color) in rows:
            line = tk.Frame(left.body, bg=C.CARD)
            line.pack(fill="x", pady=(12, 0))
            icon_label(line, icon, 14, fg=C.TEXT).pack(side="left", padx=(0, 10))
            tk.Label(line, text=t(label), font=FONT, fg=C.TEXT, bg=C.CARD).pack(side="left")
            tk.Label(line, text=t(value), font=("Segoe UI Semibold", 8), fg="#0b1120", bg=color,
                     padx=9, pady=2).pack(side="right")
        if st.network_name:
            tk.Label(left.body, text=t("fw_network_name", name=st.network_name), font=FONT_SMALL,
                     fg=C.TEXT_MUTED, bg=C.CARD).pack(anchor="e", pady=(4, 0))

        right = RoundedCard(grid, radius=16, padx=22, pady=18)
        right.grid(row=0, column=1, sticky="nsew")
        ok = st.enabled and st.mode != "lockdown"
        ring = Ring(right.body, size=132)
        ring.pack(pady=(8, 10))
        ring.show(C.GOOD if ok else (C.BAD if not st.enabled else C.WARN), glyph="lock")
        tk.Label(right.body, text=t("fw_title"), font=FONT_LARGE, fg=C.TEXT, bg=C.CARD).pack()
        word, color = (("fw_lockdown_word", C.BAD) if st.mode == "lockdown" else
                       ("fw_active", C.GOOD) if st.enabled else ("fw_off", C.BAD))
        tk.Label(right.body, text=t(word), font=("Segoe UI Semibold", 16), fg=color, bg=C.CARD).pack()
        if self.state["busy"]:
            tk.Label(right.body, text=t("fw_working"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(pady=(6, 0))
        elif not st.all_enabled:
            ttk.Button(right.body, text=t("fw_turn_on"), style="Accent.TButton",
                       command=lambda: self._change(firewall.turn_on)).pack(pady=(10, 0))
        tk.Frame(right.body, bg=C.BORDER, height=1).pack(fill="x", pady=14)
        for key, target in (("fw_open_security", "windowsdefender://network"), ("fw_open_advanced", "wf.msc")):
            link = tk.Label(right.body, text=t(key), font=FONT, fg=C.ACCENT, bg=C.CARD, cursor="hand2")
            link.pack(pady=2)
            link.bind("<Button-1>", lambda e, tg=target: _open(tg))

    # --------------------------------------------------------------- apps --
    def _apps(self):
        st: firewall.FirewallStatus = self.state["status"]
        card = RoundedCard(self.body, radius=16, padx=22, pady=18)
        card.pack(fill="both", expand=True)
        head = tk.Frame(card.body, bg=C.CARD)
        head.pack(fill="x")
        col = tk.Frame(head, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, text=t("fw_apps_title"), font=FONT_LARGE, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        tk.Label(col, text=t("fw_apps_desc"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(anchor="w")
        add = ttk.Button(head, text=t("fw_block_app"), style="Accent.TButton", command=self._block_app)
        add.pack(side="right")
        if self.state["busy"]:
            add.state(["disabled"])
        tk.Frame(card.body, bg=C.BORDER, height=1).pack(fill="x", pady=(14, 4))
        if not st.blocked_apps:
            tk.Label(card.body, text=t("fw_no_blocked"), font=FONT, fg=C.TEXT_MUTED, bg=C.CARD).pack(pady=30)
            return
        for app in st.blocked_apps:
            row = tk.Frame(card.body, bg=C.CARD)
            row.pack(fill="x", pady=6)
            icon_label(row, "blocked", 16, fg=C.BAD).pack(side="left", padx=(0, 12))
            text = tk.Frame(row, bg=C.CARD)
            text.pack(side="left", fill="x", expand=True)
            tk.Label(text, text=Path(app.path).name or app.name, font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
            tk.Label(text, text=app.path, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(anchor="w")
            btn = ttk.Button(row, text=t("fw_unblock"), style="Ghost.TButton",
                             command=lambda n=app.name: self._change(lambda: firewall.unblock_app(n)))
            btn.pack(side="right")
            if self.state["busy"]:
                btn.state(["disabled"])

    # ------------------------------------------------------------ actions --
    def _set_mode(self, mode):
        if mode == "lockdown" and not messagebox.askyesno("Sentinel", t("fw_lockdown_confirm")):
            return
        self._change(lambda: firewall.set_mode(mode))

    def _block_app(self):
        path = filedialog.askopenfilename(title=t("fw_block_app"), filetypes=[(t("fw_programs"), "*.exe")])
        if path:
            self._change(lambda: firewall.block_app(str(Path(path))))

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
            queue.put(("fw_done", error))
            self._read(queue)

        threading.Thread(target=run, daemon=True).start()

    def refresh(self):
        threading.Thread(target=self._read, args=(self.app.event_queue,), daemon=True).start()

    @staticmethod
    def _read(queue):
        try:
            queue.put(("fw_status", firewall.status()))
        except Exception as e:
            queue.put(("fw_read_failed", str(e)))

    # --------------------------------------------------- events from queue --
    def handle(self, kind, payload):
        s = self.state
        if kind == "fw_status":
            s["status"] = payload
        elif kind == "fw_done":
            s.update(busy=False, error=payload)
        elif kind == "fw_read_failed":
            s["error"] = payload
        if self.winfo_exists():
            self._render()


def _open(target):
    try:
        os.startfile(target)  # through the shell, so wf.msc gets its own admin prompt
    except OSError:
        pass


def new_state() -> dict:
    return {"status": None, "tab": "overview", "busy": False, "error": None}
