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
from core import apps as apps_module
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
        canvas = getattr(self, "list_canvas", None)
        if canvas is not None and canvas.winfo_exists():
            self.state["scroll"] = canvas.yview()[0]
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
        """Every installed app with a Block/Unblock button, blocked ones first, plus Browse."""
        state = self.state
        card = RoundedCard(self.body, radius=16, padx=22, pady=18)
        card.pack(fill="both", expand=True)
        head = tk.Frame(card.body, bg=C.CARD)
        head.pack(fill="x")
        col = tk.Frame(head, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, text=t("fw_apps_all_title"), font=FONT_LARGE, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        tk.Label(col, text=t("fw_apps_all_desc"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(anchor="w")
        browse = ttk.Button(head, text=t("fw_browse"), style="Accent.TButton", command=self._block_app)
        browse.pack(side="right")

        search_row = tk.Frame(card.body, bg=C.CARD)
        search_row.pack(fill="x", pady=(14, 8))
        box = tk.Frame(search_row, bg=C.BORDER)
        box.pack(side="left", fill="x", expand=True)
        inner = tk.Frame(box, bg=C.BG)
        inner.pack(fill="x", padx=1, pady=1)
        icon_label(inner, "scan", 11, fg=C.TEXT_MUTED, bg=C.BG).pack(side="left", padx=(10, 4))
        self.search = tk.Entry(inner, font=FONT, bg=C.BG, fg=C.TEXT, insertbackground=C.TEXT, relief="flat", bd=0,
                               highlightthickness=0)
        self.search.pack(side="left", fill="x", expand=True, ipady=7, padx=(0, 10))
        self.search.insert(0, state["query"])
        self.search.bind("<KeyRelease>", lambda e: self._on_search())
        self.count_label = tk.Label(search_row, text="", font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD)
        self.count_label.pack(side="right", padx=(12, 0))

        area = tk.Frame(card.body, bg=C.CARD)
        area.pack(fill="both", expand=True)
        self.list_canvas = tk.Canvas(area, bg=C.CARD, highlightthickness=0, bd=0)
        bar = ttk.Scrollbar(area, orient="vertical", command=self.list_canvas.yview, style="Slim.Vertical.TScrollbar")
        self.list_canvas.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        self.list_canvas.pack(side="left", fill="both", expand=True)
        self.rows = tk.Frame(self.list_canvas, bg=C.CARD)
        window = self.list_canvas.create_window(0, 0, window=self.rows, anchor="nw")
        self.rows.bind("<Configure>", lambda e: self.list_canvas.configure(scrollregion=self.list_canvas.bbox("all")))
        self.list_canvas.bind("<Configure>", lambda e: self.list_canvas.itemconfigure(window, width=e.width))
        for widget in (self.list_canvas, self.rows):
            widget.bind("<Enter>", lambda e: self.list_canvas.bind_all("<MouseWheel>", self._wheel))
            widget.bind("<Leave>", lambda e: self.list_canvas.unbind_all("<MouseWheel>"))
        self._fill_rows()
        self.after_idle(lambda: self._alive(self.list_canvas) and self.list_canvas.yview_moveto(state["scroll"]))
        if state["apps"] is None and not state["apps_loading"]:
            self.load_apps()

    def _entries(self):
        """(name, path, icon, blocked rule name or None) for every app, blocked first."""
        st: firewall.FirewallStatus = self.state["status"]
        rules = {os.path.normcase(b.path): b for b in st.blocked_apps}
        entries, listed = [], set()
        for app in self.state["apps"] or []:
            key = os.path.normcase(app.path)
            listed.add(key)
            entries.append((app.name, app.path, app.icon_png, rules.get(key)))
        for key, blocked in rules.items():  # blocked through Browse, or no longer installed
            if key not in listed:
                entries.append((Path(blocked.path).stem, blocked.path, None, blocked))
        return sorted(entries, key=lambda e: (e[3] is None, e[0].lower()))

    def _fill_rows(self):
        for child in self.rows.winfo_children():
            child.destroy()
        query = self.state["query"].strip().lower()
        entries = [e for e in self._entries()  # name or program file, not the whole path
                   if not query or query in e[0].lower() or query in Path(e[1]).name.lower()]
        blocked = sum(1 for e in entries if e[3])
        self.count_label.configure(text=t("fw_apps_count", n=len(entries), blocked=blocked))
        if self.state["apps"] is None:
            tk.Label(self.rows, text=t("fw_finding_apps"), font=FONT, fg=C.TEXT_MUTED, bg=C.CARD).pack(pady=24)
        elif not entries:
            tk.Label(self.rows, text=t("fw_no_match"), font=FONT, fg=C.TEXT_MUTED, bg=C.CARD).pack(pady=24)
        busy = self.state["busy"]
        for name, path, icon, rule in entries:
            row = tk.Frame(self.rows, bg=C.CARD)
            row.pack(fill="x", pady=4)
            image = self._icon(path, icon)
            if image:
                tk.Label(row, image=image, bg=C.CARD).pack(side="left", padx=(2, 12))
            else:
                icon_label(row, "apps", 16, fg=C.TEXT_MUTED).pack(side="left", padx=(6, 14))
            text = tk.Frame(row, bg=C.CARD)
            text.pack(side="left", fill="x", expand=True)
            title = tk.Frame(text, bg=C.CARD)
            title.pack(anchor="w")
            tk.Label(title, text=name, font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left")
            gaps = bool(rule and getattr(rule, "gaps", None))
            if rule:
                tk.Label(title, text=t("fw_blocked_pill"), font=("Segoe UI Semibold", 8), fg="#0b1120", bg=C.BAD,
                         padx=7, pady=1).pack(side="left", padx=(8, 0))
            if gaps:  # e.g. the app updated itself into a new folder the rules don't cover yet
                tk.Label(title, text=t("fw_updated_pill"), font=("Segoe UI Semibold", 8), fg="#0b1120", bg=C.WARN,
                         padx=7, pady=1).pack(side="left", padx=(6, 0))
            tk.Label(text, text=_shorten(path, 70), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(anchor="w")
            buttons = []
            if rule:
                buttons.append(ttk.Button(row, text=t("fw_unblock"), style="Ghost.TButton",
                                          command=lambda r=rule.name: self._change(lambda: firewall.unblock_app(r))))
            if not rule or gaps:
                buttons.append(ttk.Button(row, text=t("fw_block_again" if gaps else "fw_block"), style="Danger.TButton",
                                          command=lambda p=path, n=name: self._block(p, n)))
            for btn in buttons:
                btn.pack(side="right", padx=(10, 4) if btn is buttons[0] else (0, 0))
                if busy:
                    btn.state(["disabled"])
            for widget in (row, text, title):
                widget.bind("<Enter>", lambda e: self.list_canvas.bind_all("<MouseWheel>", self._wheel))

    def _icon(self, path, png):
        cache = self.state["icons"]
        if path not in cache:
            cache[path] = None
            if png:
                try:
                    import io

                    from PIL import Image, ImageTk

                    img = Image.open(io.BytesIO(png)).convert("RGBA").resize((24, 24), Image.LANCZOS)
                    cache[path] = ImageTk.PhotoImage(img)
                except (OSError, ValueError):
                    pass
        return cache[path]

    def _on_search(self):
        self.state["query"] = self.search.get()
        self.state["scroll"] = 0.0
        self._fill_rows()
        self.list_canvas.yview_moveto(0)

    def _wheel(self, event):
        if self._alive(getattr(self, "list_canvas", None)):
            self.list_canvas.yview_scroll(int(-event.delta / 120) * 3, "units")

    def load_apps(self, force=False):
        state = self.state
        if state["apps_loading"] or (state["apps"] is not None and not force):
            return
        state["apps_loading"] = True
        queue = self.app.event_queue

        def run():
            try:
                queue.put(("fw_apps", apps_module.installed_apps()))
            except Exception:  # the list is a convenience; Browse still works
                queue.put(("fw_apps", []))

        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def _alive(widget):
        return widget is not None and widget.winfo_exists()

    # ------------------------------------------------------------ actions --
    def _set_mode(self, mode):
        if mode == "lockdown" and not messagebox.askyesno("Sentinel", t("fw_lockdown_confirm")):
            return
        self._change(lambda: firewall.set_mode(mode))

    def _block_app(self):
        path = filedialog.askopenfilename(title=t("fw_block_app"), filetypes=[(t("fw_programs"), "*.exe")])
        if path:
            self._block(str(Path(path)), Path(path).stem)

    def _block(self, path, name):
        def after():
            # The firewall only stops new connections; if the app is open, offer to close it.
            running = firewall.running_processes(firewall.related_exes(path))
            return ("fw_running", (name, [proc.pid for proc in running])) if running else None

        self._change(lambda: firewall.block_app(path), after=after)

    def _change(self, action, after=None):
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
            if after and error is None:
                message = after()
                if message:
                    queue.put(message)

        threading.Thread(target=run, daemon=True).start()

    def refresh(self):
        threading.Thread(target=self._read, args=(self.app.event_queue,), daemon=True).start()

    @staticmethod
    def _read(queue):
        try:
            status = firewall.status()
            for blocked in status.blocked_apps:
                blocked.gaps = blocked.missing()
            queue.put(("fw_status", status))
        except Exception as e:
            queue.put(("fw_read_failed", str(e)))

    # --------------------------------------------------- events from queue --
    def handle(self, kind, payload):
        s = self.state
        if kind == "fw_status":
            s["status"] = payload
        elif kind == "fw_done":
            s.update(busy=False, error=payload)
        elif kind == "fw_apps":
            s.update(apps=payload, apps_loading=False)
        elif kind == "fw_read_failed":
            s["error"] = payload
        elif kind == "fw_running":
            name, pids = payload
            if messagebox.askyesno("Sentinel", t("fw_close_app", name=name)):
                threading.Thread(target=_close, args=(pids,), daemon=True).start()
            return
        if self.winfo_exists():
            self._render()


def _close(pids):
    import psutil

    procs = []
    for pid in pids:
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            procs.append(proc)
        except psutil.Error:
            pass
    psutil.wait_procs(procs, timeout=5)


def _shorten(text, limit):
    return text if len(text) <= limit else text[:limit // 2 - 1] + "…" + text[-(limit // 2):]


def _open(target):
    try:
        os.startfile(target)  # through the shell, so wf.msc gets its own admin prompt
    except OSError:
        pass


def new_state() -> dict:
    return {"status": None, "tab": "overview", "busy": False, "error": None, "apps": None, "apps_loading": False,
            "icons": {}, "query": "", "scroll": 0.0}
