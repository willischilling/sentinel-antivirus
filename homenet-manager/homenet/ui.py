"""The Home Network Manager window: a self-contained Tkinter GUI.

Scan your network, give devices names and profiles, pause or resume their
internet, and block websites. Long or privileged jobs run on worker threads
and report back through a queue the UI polls, so the window never freezes.
"""
import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from . import APP_NAME, control, dns, firewall, netscan, watcher


def _resource(rel: str) -> str:
    """Path to a bundled file, both when run from source and from a PyInstaller
    one-file build (which unpacks data into sys._MEIPASS)."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, rel)

# ---- palette -------------------------------------------------------------
BG = "#0b1120"
CARD = "#151f33"
BORDER = "#24324d"
TEXT = "#e7ecf5"
MUTED = "#8b97ad"
ACCENT = "#3b82f6"
GOOD = "#22c55e"
WARN = "#f59e0b"
BAD = "#ef4444"

KIND_ICON = {"router": "🌐", "computer": "💻", "phone": "📱", "apple": "📱", "console": "🎮",
             "tv": "📺", "printer": "🖨", "speaker": "🔊", "camera": "📷", "smart": "💡", "unknown": "❔"}
PROFILE_LABELS = {"me": "Me", "family": "Family", "kids": "Kids", "guest": "Guest", "other": "Other"}
PROFILE_COLOR = {"me": ACCENT, "family": GOOD, "kids": WARN, "guest": MUTED, "other": MUTED}
CATEGORY_LABELS = {"adult": "Adult content", "social": "Social media", "gaming": "Games",
                   "streaming": "Video streaming", "ads": "Ads & trackers"}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("760x820")
        self.minsize(620, 560)
        self.configure(bg=BG)
        try:
            self.iconbitmap(_resource("assets/icon.ico"))  # Windows window/taskbar icon
        except Exception:
            pass
        self._style()
        self.events: "queue.Queue" = queue.Queue()
        self.result: netscan.ScanResult | None = None
        self.busy = False          # a scan is running
        self.action = None         # a privileged action label, or None
        self.status_text = "Scan your network to begin."
        self._build()
        self.after(150, self._pump)
        watcher.start(on_reapplied=lambda n: self.events.put(("note", f"Put back {n} blocked site(s) that were changed.")),
                      on_error=lambda e: None)

    # ---- styling ---------------------------------------------------------
    def _style(self):
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("TButton", background=CARD, foreground=TEXT, borderwidth=1, focusthickness=0,
                    bordercolor=BORDER, padding=(12, 6))
        s.map("TButton", background=[("active", "#1b2842")])
        s.configure("Accent.TButton", background=ACCENT, foreground="#ffffff", bordercolor=ACCENT)
        s.map("Accent.TButton", background=[("active", "#2563eb")])
        s.configure("Danger.TButton", background=CARD, foreground=BAD, bordercolor=BORDER)
        s.configure("TCombobox", fieldbackground=CARD, background=CARD, foreground=TEXT,
                    arrowcolor=TEXT, bordercolor=BORDER, selectbackground=CARD, selectforeground=TEXT)

    # ---- layout ----------------------------------------------------------
    def _build(self):
        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=20, pady=(18, 6))
        tk.Label(header, text=APP_NAME, bg=BG, fg=TEXT, font=("Segoe UI Semibold", 20)).pack(side="left")
        self.scan_btn = ttk.Button(header, text="Scan my network", style="Accent.TButton", command=self.scan)
        self.scan_btn.pack(side="right")
        tk.Label(self, text="Manage your own network: pause or resume devices, and block websites.",
                 bg=BG, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", padx=20)
        self.status = tk.Label(self, text=self.status_text, bg=BG, fg=MUTED, font=("Segoe UI", 10),
                               anchor="w", justify="left", wraplength=700)
        self.status.pack(anchor="w", padx=20, pady=(8, 4))

        self.scroll = _ScrollArea(self)
        self.scroll.pack(fill="both", expand=True, padx=14, pady=(4, 14))
        self.body = self.scroll.inner
        self._render()

    def _render(self):
        for child in self.body.winfo_children():
            child.destroy()
        self._access_card()
        self._blocking_card()
        self._devices_card()
        self.status.configure(text=self.status_text)
        self.scan_btn.configure(text="Scan again" if self.result else "Scan my network")

    # ---- access / PIN ----------------------------------------------------
    def _access_card(self):
        card, body = _card(self.body, "Your access")
        _pill(card.header, "PIN on" if control.has_pin() else "No PIN",
              GOOD if control.has_pin() else MUTED)
        tk.Label(body, text=("Set an admin PIN to protect your own device. Once set, pausing or resuming the "
                             "admin device needs the PIN — so no one else can keep you offline, and you can "
                             "always turn your own internet back on."),
                 bg=CARD, fg=MUTED, font=("Segoe UI", 9), justify="left", wraplength=660).pack(anchor="w", pady=(0, 10))
        row = tk.Frame(body, bg=CARD)
        row.pack(fill="x")
        if control.has_pin():
            ttk.Button(row, text="Change PIN", command=self._change_pin).pack(side="left")
            ttk.Button(row, text="Remove PIN", style="Danger.TButton", command=self._remove_pin).pack(side="left", padx=(8, 0))
        else:
            ttk.Button(row, text="Set admin PIN", style="Accent.TButton", command=self._set_pin).pack(side="left")

    def _set_pin(self):
        pin = simpledialog.askstring(APP_NAME, "Choose an admin PIN:", show="•", parent=self)
        if pin and pin.strip():
            again = simpledialog.askstring(APP_NAME, "Enter the PIN again:", show="•", parent=self)
            if again != pin:
                messagebox.showwarning(APP_NAME, "The PINs did not match. Nothing was changed.", parent=self)
                return
            control.set_pin(pin.strip())
            self._render()

    def _change_pin(self):
        if self._ask_pin():
            self._set_pin()

    def _remove_pin(self):
        if self._ask_pin():
            control.clear_pin()
            self._render()

    def _ask_pin(self) -> bool:
        if not control.has_pin():
            return True
        pin = simpledialog.askstring(APP_NAME, "Enter your admin PIN:", show="•", parent=self)
        if pin is None:
            return False
        if control.check_pin(pin):
            return True
        messagebox.showwarning(APP_NAME, "That PIN is not correct.", parent=self)
        return False

    # ---- website blocking ------------------------------------------------
    def _blocking_card(self):
        card, body = _card(self.body, "Block websites")
        busy = self.action == "block"
        apply_btn = ttk.Button(card.header, text="Apply blocking", style="Accent.TButton",
                               command=self._apply_blocking, state=("disabled" if busy or not self.result else "normal"))
        apply_btn.pack(side="right")
        tk.Label(body, text=("Blocks the chosen categories and sites on this PC (every browser and app), and "
                             "switches on a family DNS filter for adult content. For other devices this is kept "
                             "as a network policy to apply at your router."),
                 bg=CARD, fg=MUTED, font=("Segoe UI", 9), justify="left", wraplength=660).pack(anchor="w", pady=(0, 10))

        if not self.result:
            tk.Label(body, text="Scan your network first.", bg=CARD, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w")
            return
        nid = self.result.network_id

        enf = tk.Frame(body, bg=CARD)
        enf.pack(fill="x", pady=(0, 8))
        self._checkrow(enf, "Keep these blocks enforced", control.enforce_on(), self._toggle_enforce,
                       sub="Checks every few minutes and puts the blocks back if something changes them.")
        tk.Frame(body, bg=BORDER, height=1).pack(fill="x", pady=(2, 8))

        active = set(control.net_config(nid)[1].get("categories", []))
        for key in control.CATEGORIES:
            self._checkrow(body, CATEGORY_LABELS.get(key, key), key in active,
                           lambda k=key: self._toggle_cat(k))

        tk.Frame(body, bg=BORDER, height=1).pack(fill="x", pady=(8, 8))
        tk.Label(body, text="Your blocked sites", bg=CARD, fg=TEXT, font=("Segoe UI Semibold", 10)).pack(anchor="w")
        addrow = tk.Frame(body, bg=CARD)
        addrow.pack(fill="x", pady=(6, 4))
        ttk.Button(addrow, text="Add a site", command=self._add_site).pack(side="left")
        tk.Label(addrow, text="e.g. example.com", bg=CARD, fg=MUTED, font=("Segoe UI", 9)).pack(side="left", padx=(10, 0))
        sites = control.net_config(nid)[1].get("sites", [])
        if not sites:
            tk.Label(body, text="No extra sites blocked yet.", bg=CARD, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w")
        for domain in sites:
            srow = tk.Frame(body, bg=CARD)
            srow.pack(fill="x", pady=1)
            tk.Label(srow, text="⛔  " + domain, bg=CARD, fg=TEXT, font=("Segoe UI", 9)).pack(side="left")
            rm = tk.Label(srow, text="Remove", bg=CARD, fg=BAD, font=("Segoe UI", 9), cursor="hand2")
            rm.pack(side="right")
            rm.bind("<Button-1>", lambda e, d=domain: (control.remove_site(nid, d), self._render()))

    def _checkrow(self, parent, label, on, command, sub=None):
        row = tk.Frame(parent, bg=CARD)
        row.pack(fill="x", pady=3)
        var = tk.BooleanVar(value=on)
        cb = tk.Checkbutton(row, variable=var, command=command, bg=CARD, activebackground=CARD,
                            selectcolor=CARD, bd=0, highlightthickness=0, cursor="hand2")
        cb.pack(side="right")
        col = tk.Frame(row, bg=CARD)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, text=label, bg=CARD, fg=TEXT, font=("Segoe UI", 10), anchor="w").pack(anchor="w")
        if sub:
            tk.Label(col, text=sub, bg=CARD, fg=MUTED, font=("Segoe UI", 8), anchor="w",
                     justify="left", wraplength=560).pack(anchor="w")

    def _toggle_enforce(self):
        control.set_enforce(not control.enforce_on())
        self._render()

    def _toggle_cat(self, key):
        conf = control.net_config(self.result.network_id)[1]
        control.toggle_category(self.result.network_id, key, key not in set(conf.get("categories", [])))
        self._render()

    def _add_site(self):
        raw = simpledialog.askstring(APP_NAME, "Website to block (e.g. example.com):", parent=self)
        if raw:
            control.add_site(self.result.network_id, raw)
            self._render()

    def _apply_blocking(self):
        nid = self.result.network_id
        self._run("block", lambda: control.apply_site_blocks(nid), "Website blocks applied.")

    # ---- devices ---------------------------------------------------------
    def _devices_card(self):
        card, body = _card(self.body, "Devices")
        if not self.result:
            tk.Label(body, text="Scan your network to list the devices on it.",
                     bg=CARD, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w")
            return
        for dev in self.result.devices:
            self._device_row(body, dev)

    def _device_row(self, parent, dev):
        nid = self.result.network_id
        info = control.device(nid, dev.mac)
        is_admin = control.is_admin_device(nid, dev.mac)
        row = tk.Frame(parent, bg=CARD)
        row.pack(fill="x", pady=6)
        tk.Label(row, text=KIND_ICON.get(dev.kind, "❔"), bg=CARD, fg=TEXT, font=("Segoe UI", 14)).pack(side="left", padx=(0, 10))

        right = tk.Frame(row, bg=CARD)
        right.pack(side="right")
        self._pause_control(right, dev, info, is_admin)

        col = tk.Frame(row, bg=CARD)
        col.pack(side="left", fill="x", expand=True)
        name = info["label"] or self._default_name(dev)
        head = tk.Frame(col, bg=CARD)
        head.pack(anchor="w", fill="x")
        tk.Label(head, text=name, bg=CARD, fg=TEXT, font=("Segoe UI Semibold", 10)).pack(side="left")
        if dev.this_pc:
            _pill(head, "This PC", ACCENT)
        if is_admin:
            _pill(head, "Admin", GOOD)
        meta = tk.Frame(col, bg=CARD)
        meta.pack(anchor="w", fill="x")
        if not dev.router:
            prof = ttk.Combobox(meta, values=[PROFILE_LABELS[p] for p in control.PROFILES], state="readonly",
                                width=8)
            prof.set(PROFILE_LABELS[info["profile"]])
            prof.pack(side="left")
            prof.bind("<<ComboboxSelected>>", lambda e, d=dev, c=prof: self._set_profile(d, c.get()))
        tk.Label(meta, text=f"   {dev.ip}   ·   {dev.mac.upper()}", bg=CARD, fg=MUTED,
                 font=("Segoe UI", 8)).pack(side="left")
        if not dev.router:
            rn = tk.Label(meta, text="   Rename", bg=CARD, fg=ACCENT, font=("Segoe UI", 8), cursor="hand2")
            rn.pack(side="left")
            rn.bind("<Button-1>", lambda e, d=dev: self._rename(d))

    def _pause_control(self, parent, dev, info, is_admin):
        if dev.router:
            tk.Label(parent, text="Router", bg=CARD, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="e")
            return
        paused = info["paused"]
        busy = self.action == "pause:" + dev.mac
        text = "Resume" if paused else "Pause"
        btn = ttk.Button(parent, text=text, style=("Accent.TButton" if paused else "TButton"),
                         command=lambda: self._toggle_pause(dev, is_admin),
                         state=("disabled" if busy else "normal"))
        btn.pack(anchor="e")
        label = ("Paused" if paused else "Internet on") + ("" if dev.this_pc else "  ·  managed")
        tk.Label(parent, text=label, bg=CARD, fg=(WARN if paused else GOOD), font=("Segoe UI", 8)).pack(anchor="e")

    def _toggle_pause(self, dev, is_admin):
        nid = self.result.network_id
        info = control.device(nid, dev.mac)
        want = not info["paused"]
        if is_admin and not self._ask_pin():
            return
        if dev.this_pc:
            def apply(nid=nid, mac=dev.mac, pause=want):
                control.enforce_this_pc(pause)
                control.set_paused(nid, mac, pause)
            self._run("pause:" + dev.mac, apply,
                      "This PC's internet " + ("paused." if want else "resumed."))
        else:
            control.set_paused(nid, dev.mac, want)
            self.status_text = ("Marked as paused (managed — applies at your router)." if want
                                else "Marked as on (managed — applies at your router).")
            self._render()

    def _set_profile(self, dev, label):
        key = next((k for k, v in PROFILE_LABELS.items() if v == label), "other")
        control.set_profile(self.result.network_id, dev.mac, key)
        if key == "me":
            control.set_admin_device(self.result.network_id, dev.mac)
        self._render()

    def _rename(self, dev):
        current = control.device(self.result.network_id, dev.mac)["label"] or ""
        name = simpledialog.askstring(APP_NAME, "Name for this device:", initialvalue=current, parent=self)
        if name is not None:
            control.set_label(self.result.network_id, dev.mac, name)
            self._render()

    @staticmethod
    def _default_name(dev):
        if dev.router:
            return "Your router"
        if dev.this_pc:
            return "This PC"
        return dev.name or dev.maker or ("Private device" if dev.private_mac else "Unknown device")

    # ---- scanning & worker jobs ------------------------------------------
    def scan(self):
        if self.busy:
            return
        self.busy = True
        self.status_text = "Scanning your network…"
        self.scan_btn.configure(state="disabled")
        self.status.configure(text=self.status_text)

        def run():
            try:
                self.events.put(("scan", netscan.scan()))
            except Exception as e:
                self.events.put(("scan", e))
        threading.Thread(target=run, daemon=True).start()

    def _run(self, label, fn, done_msg):
        if self.action:
            return
        self.action = label
        self.status_text = "Asking for administrator permission…"
        self._render()

        def run():
            try:
                fn()
                self.events.put(("done", (label, None, done_msg)))
            except Exception as e:
                self.events.put(("done", (label, str(e), None)))
        threading.Thread(target=run, daemon=True).start()

    def _pump(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "scan":
                    self.busy = False
                    self.scan_btn.configure(state="normal")
                    if isinstance(payload, Exception):
                        self.status_text = ("No network found — connect to Wi-Fi and try again."
                                            if str(payload) == "no_network" else f"Scan failed: {payload}")
                        self.result = None
                    else:
                        self.result = payload
                        self._learn_admin(payload)
                        self.status_text = f"{len(payload.devices)} devices on {payload.network}."
                    self._render()
                elif kind == "done":
                    label, error, msg = payload
                    self.action = None
                    self.status_text = f"Couldn't finish: {error}" if error else msg
                    self._render()
                elif kind == "note":
                    self.status_text = payload
                    self.status.configure(text=self.status_text)
        except queue.Empty:
            pass
        self.after(150, self._pump)

    def _learn_admin(self, result):
        conf = control.net_config(result.network_id)[1]
        if not conf.get("admin_mac"):
            for dev in result.devices:
                if dev.this_pc:
                    control.set_admin_device(result.network_id, dev.mac)
                    break


# ---- small helpers -------------------------------------------------------
class _Card(tk.Frame):
    pass


def _card(parent, title):
    outer = tk.Frame(parent, bg=BG)
    outer.pack(fill="x", pady=(0, 12))
    card = _Card(outer, bg=CARD, highlightbackground=BORDER, highlightthickness=1)
    card.pack(fill="x")
    card.header = tk.Frame(card, bg=CARD)
    card.header.pack(fill="x", padx=16, pady=(12, 6))
    tk.Label(card.header, text=title, bg=CARD, fg=TEXT, font=("Segoe UI Semibold", 12)).pack(side="left")
    body = tk.Frame(card, bg=CARD)
    body.pack(fill="x", padx=16, pady=(0, 14))
    return card, body


def _pill(parent, text, color):
    tk.Label(parent, text=" " + text + " ", bg=color, fg="#0b1120",
             font=("Segoe UI Semibold", 8)).pack(side="left", padx=(8, 0))


class _ScrollArea(tk.Frame):
    """A vertically scrolling frame; put content in `.inner`."""

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self.canvas = tk.Canvas(self, bg=BG, highlightthickness=0)
        self.canvas.pack(side="left", fill="both", expand=True)
        bar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        bar.pack(side="right", fill="y")
        self.canvas.configure(yscrollcommand=bar.set)
        self.inner = tk.Frame(self.canvas, bg=BG)
        self._win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self._win, width=e.width))
        self.canvas.bind_all("<MouseWheel>", self._wheel)

    def _wheel(self, event):
        self.canvas.yview_scroll(int(-event.delta / 120), "units")


def run():
    App().mainloop()
