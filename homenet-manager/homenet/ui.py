"""The Home Network Manager window: a sidebar dashboard drawn with plain Tkinter.

Pages: Overview, Devices, Block sites, Schedule, Activity, Your access and
Settings. Long or privileged jobs run on worker threads and report back through
a queue the UI polls, so the window never freezes. Rebuilds triggered by clicks
are deferred to idle, so a widget is never destroyed while handling its event.
Colours come from ``palette`` at draw time, so the theme can switch live.
"""
import os
import queue
import sys
import threading
import traceback
import webbrowser
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, simpledialog

from . import APP_NAME, control, history, netscan, palette as P, report, settings, speedtest, watcher
from . import widgets as W
from .widgets import EMOJI, MONO, Banner, Card, Pill, Toggle, avatar, bars, chip, dot, font, meter, mix


def _resource(rel: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, rel)


KIND_ICON = {"router": "🌐", "computer": "💻", "phone": "📱", "apple": "📱", "console": "🎮",
             "tv": "📺", "printer": "🖨", "speaker": "🔊", "camera": "📷", "smart": "💡", "unknown": "❔"}
PROFILE_LABELS = {"me": "Me", "family": "Family", "kids": "Kids", "guest": "Guest", "other": "Other"}
CATEGORIES = {
    "adult": ("🔞", "Adult content", "Also turns on a family DNS filter"),
    "social": ("💬", "Social media", "Facebook, Instagram, TikTok, X…"),
    "gaming": ("🎮", "Games", "Roblox, Steam, Epic, Xbox…"),
    "streaming": ("🎬", "Video streaming", "YouTube, Netflix, Twitch…"),
    "ads": ("🚫", "Ads & trackers", "Common ad and tracking networks"),
}
EVENT_ICON = {"focus": "🎯", "schedule": "🗓", "auto": "🤖", "block": "🛡", "pause": "⏸",
              "resume": "▶", "pin": "🔒", "scan": "📶"}
PAGES = [("overview", "🏠", "Overview"), ("devices", "📶", "Devices"), ("block", "🛡", "Block sites"),
         ("schedule", "🗓", "Schedule"), ("activity", "🕑", "Activity"), ("access", "🔒", "Your access"),
         ("settings", "⚙", "Settings")]
PAGE_TEXT = {
    "overview": ("Overview", "Your network at a glance."),
    "devices": ("Devices", "Name devices, set who they belong to, and pause their internet."),
    "block": ("Block sites", "Block categories or your own list of websites."),
    "schedule": ("Schedule", "Automatically pause this PC during off-hours."),
    "activity": ("Activity", "What the app has done, and a report you can save."),
    "access": ("Your access", "Protect your own device with an admin PIN."),
    "settings": ("Settings", "Theme and app options."),
}


def _profile_color(key):
    return {"me": P.ACCENT, "family": P.GOOD, "kids": P.WARN, "guest": P.PURPLE, "other": P.MUTED}.get(key, P.MUTED)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        P.use(control.ui_settings().get("theme", "dark"))
        self.title(APP_NAME)
        self.geometry("1120x780")
        self.minsize(940, 640)
        self.configure(bg=P.BG)
        try:
            self.iconbitmap(_resource("assets/icon.ico"))
        except Exception:
            pass
        self.report_callback_exception = self._on_tk_error
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.events: "queue.Queue" = queue.Queue()
        self.result: netscan.ScanResult | None = None
        self.hist = {}
        self.busy = False
        self.action = None
        self.speed = None
        self.speed_busy = False
        self.query = ""
        self.sort = "name"
        self.expanded_cat = None
        self.status_text, self.status_kind = "Scan your network to begin.", "info"
        self.page = "overview"
        self._pulse = 0
        self._build()
        self.after(150, self._pump)
        self.after(1000, self._tick)
        watcher.start(on_event=lambda m: self.events.put(("note", (m, "good"))))
        if control.ui_settings().get("scan_on_launch", True):
            self.after(400, self.scan)

    # ================================================================ layout
    def _build(self):
        for child in self.winfo_children():
            child.destroy()
        self.configure(bg=P.BG)
        self.sidebar = tk.Frame(self, bg=P.SIDEBAR, width=232)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        tk.Frame(self, bg=P.BORDER, width=1).pack(side="left", fill="y")

        brand = tk.Frame(self.sidebar, bg=P.SIDEBAR)
        brand.pack(fill="x", padx=20, pady=(22, 22))
        logo = tk.Canvas(brand, width=40, height=40, bg=P.SIDEBAR, highlightthickness=0)
        logo.pack(side="left")
        for i in range(40):
            logo.create_line(i, 0, i, 40, fill=mix("#2c64ff", P.PURPLE, i / 39))
        for x, y in ((0, 0), (40, 0), (0, 40), (40, 40)):
            logo.create_oval(x - 9, y - 9, x + 9, y + 9, fill=P.SIDEBAR, outline=P.SIDEBAR)
        logo.create_text(20, 21, text="🏠", font=(EMOJI, 15), fill="#ffffff")
        names = tk.Frame(brand, bg=P.SIDEBAR)
        names.pack(side="left", padx=(12, 0))
        tk.Label(names, text="Home Network", bg=P.SIDEBAR, fg=P.TEXT, font=font(12, "bold")).pack(anchor="w")
        tk.Label(names, text="MANAGER", bg=P.SIDEBAR, fg=P.MUTED, font=font(8, "bold")).pack(anchor="w")

        tk.Label(self.sidebar, text="MENU", bg=P.SIDEBAR, fg=P.FAINT, font=font(8, "bold")).pack(
            anchor="w", padx=24, pady=(0, 6))
        self.nav = {}
        for key, icon, label in PAGES:
            self.nav[key] = self._nav_item(key, icon, label)
        self.side_status = tk.Frame(self.sidebar, bg=P.SIDEBAR)
        self.side_status.pack(side="bottom", fill="x", padx=16, pady=16)

        main = tk.Frame(self, bg=P.BG)
        main.pack(side="left", fill="both", expand=True)
        header = tk.Frame(main, bg=P.BG)
        header.pack(fill="x", padx=32, pady=(24, 4))
        titles = tk.Frame(header, bg=P.BG)
        titles.pack(side="left", fill="x", expand=True)
        self.h_title = tk.Label(titles, bg=P.BG, fg=P.TEXT, font=font(22, "bold"), anchor="w")
        self.h_title.pack(anchor="w")
        self.h_sub = tk.Label(titles, bg=P.BG, fg=P.MUTED, font=font(10), anchor="w")
        self.h_sub.pack(anchor="w", pady=(2, 0))
        self.h_actions = tk.Frame(header, bg=P.BG)
        self.h_actions.pack(side="right", anchor="n", pady=(6, 0))

        status = tk.Frame(main, bg=P.BG)
        status.pack(fill="x", padx=32, pady=(10, 6))
        self.s_dot = dot(status, P.ACCENT, 9, bg=P.BG)
        self.s_dot.pack(side="left", padx=(0, 8))
        self.s_text = tk.Label(status, bg=P.BG, fg=P.MUTED, font=font(9), anchor="w", justify="left", wraplength=820)
        self.s_text.pack(side="left", fill="x")

        self.scroll = W.ScrollArea(main)
        self.scroll.pack(fill="both", expand=True, padx=(26, 14), pady=(0, 14))
        self.body = self.scroll.inner
        self._render()

    def _nav_item(self, key, icon, label):
        row = tk.Frame(self.sidebar, bg=P.SIDEBAR, cursor="hand2")
        row.pack(fill="x", padx=12, pady=1)
        bar = tk.Frame(row, bg=P.SIDEBAR, width=4)
        bar.pack(side="left", fill="y")
        ic = tk.Label(row, text=icon, bg=P.SIDEBAR, fg=P.TEXT, font=(EMOJI, 12), width=3)
        ic.pack(side="left", padx=(8, 2), pady=8)
        lb = tk.Label(row, text=label, bg=P.SIDEBAR, fg=P.MUTED, font=font(10, "bold"), anchor="w")
        lb.pack(side="left", fill="x", expand=True)
        parts = (row, ic, lb)

        def paint(active, hover=False):
            bg = P.CARD_HI if active else (mix(P.SIDEBAR, P.CARD_HI, 0.6) if hover else P.SIDEBAR)
            for w in parts:
                w.configure(bg=bg)
            bar.configure(bg=P.ACCENT if active else bg)
            lb.configure(fg=P.TEXT if active else P.MUTED)

        for w in parts:
            w.bind("<Button-1>", lambda e, k=key: self._go(k))
            w.bind("<Enter>", lambda e, k=key: paint(self.page == k, True))
            w.bind("<Leave>", lambda e, k=key: paint(self.page == k))
        row.paint = paint
        return row

    def _go(self, key):
        if key != self.page:
            self.page = key
            self._rerender(to_top=True)

    # ================================================================ render
    def _rerender(self, to_top=False):
        def go():
            self._render()
            if to_top:
                self.scroll.to_top()
        self.after_idle(go)

    def _render(self):
        try:
            for key, row in self.nav.items():
                row.paint(key == self.page)
            title, sub = PAGE_TEXT[self.page]
            self.h_title.configure(text=title)
            self.h_sub.configure(text=sub)
            for child in self.h_actions.winfo_children():
                child.destroy()
            Pill(self.h_actions, self._scan_label(), self.scan, kind="primary", disabled=self.busy).pack()
            self._paint_status()
            self._side_status()
            for child in self.body.winfo_children():
                child.destroy()
            getattr(self, "_page_" + self.page)(self.body)
        except Exception:
            settings.log_crash("render", traceback.format_exc())

    def _scan_label(self):
        return "Scanning…" if self.busy else ("↻  Scan again" if self.result else "⌕  Scan network")

    def _paint_status(self):
        color = {"good": P.GOOD, "warn": P.WARN, "bad": P.BAD}.get(self.status_kind, P.ACCENT)
        self.s_dot.itemconfigure("dot", fill=color)
        self.s_text.configure(text=self.status_text,
                              fg=P.TEXT if self.status_kind in ("good", "bad", "warn") else P.MUTED)

    def _set_status(self, text, kind="info"):
        self.status_text, self.status_kind = text, kind
        self._paint_status()

    def _side_status(self):
        for child in self.side_status.winfo_children():
            child.destroy()
        card = Card(self.side_status, fill=P.CARD, radius=14, pad=14)
        card.pack(fill="x")
        b = card.body
        online = self.result is not None
        top = tk.Frame(b, bg=P.CARD)
        top.pack(fill="x")
        reason = control.pause_reason()
        color = P.WARN if reason else (P.GOOD if online else P.FAINT)
        dot(top, color, 9, bg=P.CARD).pack(side="left", padx=(0, 8))
        label = "Paused" if reason else ("Connected" if online else "Not scanned")
        tk.Label(top, text=label, bg=P.CARD, fg=P.TEXT, font=font(9, "bold")).pack(side="left")
        tk.Label(b, text=self.result.network if online else "Scan to find your network",
                 bg=P.CARD, fg=P.MUTED, font=font(8), anchor="w").pack(anchor="w", pady=(4, 0))
        rem = control.focus_remaining()
        if rem:
            tk.Label(b, text=f"🎯  Focus {self._mmss(rem)}", bg=P.CARD, fg=P.PURPLE, font=font(8, "bold"),
                     anchor="w").pack(anchor="w", pady=(2, 0))
        elif control.enforce_on():
            tk.Label(b, text=f"🛡  {len(control.active_blocklist())} sites blocked", bg=P.CARD, fg=P.MUTED,
                     font=font(8), anchor="w").pack(anchor="w", pady=(2, 0))

    def _on_tk_error(self, exc, val, tb):
        settings.log_crash("tk-callback", "".join(traceback.format_exception(exc, val, tb)))

    @staticmethod
    def _mmss(seconds):
        return f"{seconds // 60}:{seconds % 60:02d}"

    # ============================================================== helpers
    def _section(self, parent, text, pady=(18, 10)):
        tk.Label(parent, text=text.upper(), bg=P.BG, fg=P.FAINT, font=font(8, "bold")).pack(
            anchor="w", padx=6, pady=pady)

    def _card(self, parent, pady=(0, 12), **kw):
        card = Card(parent, **kw)
        card.pack(fill="x", padx=6, pady=pady)
        return card.body

    def _empty(self, parent, glyph, title, text):
        body = self._card(parent, pad=36)
        tk.Label(body, text=glyph, bg=P.CARD, fg=P.TEXT, font=(EMOJI, 34)).pack()
        tk.Label(body, text=title, bg=P.CARD, fg=P.TEXT, font=font(14, "bold")).pack(pady=(8, 2))
        tk.Label(body, text=text, bg=P.CARD, fg=P.MUTED, font=font(10), justify="center", wraplength=460).pack()
        Pill(body, self._scan_label(), self.scan, disabled=self.busy).pack(pady=(16, 0))

    def _nid(self):
        return self.result.network_id

    # ============================================================ overview
    def _page_overview(self, parent):
        banner = Banner(parent, height=172)
        banner.pack(fill="x", padx=6, pady=(4, 6))
        if self.result:
            title, sub = "Your home network", (f"{len(self.result.devices)} devices on {self.result.network}"
                                               f"   ·   router {self.result.gateway}")
        else:
            title, sub = "Welcome home", "Scan your Wi‑Fi to see every device and take control of it."
        banner.create_text(30, 32, text=title, anchor="nw", fill="#ffffff", font=font(21, "bold"))
        banner.create_text(30, 72, text=sub, anchor="nw", fill=mix("#ffffff", P.PURPLE, 0.18), font=font(10))
        banner.create_window(30, 110, anchor="nw",
                             window=Pill(banner, self._scan_label(), self.scan, kind="light", disabled=self.busy,
                                         bg=mix("#2c64ff", P.PURPLE, 0.08)))

        tiles = tk.Frame(parent, bg=P.BG)
        tiles.pack(fill="x", pady=(10, 0))
        nid = self.result.network_id if self.result else None
        stats = [("📶", str(len(self.result.devices)) if self.result else "—", "Devices", P.ACCENT),
                 ("⏸", str(control.paused_count(nid)) if nid else "—", "Paused", P.WARN),
                 ("🛡", str(len(control.active_blocklist())) if control.enforce_on() else "0", "Blocked", P.PURPLE),
                 ("🔒", "On" if control.has_pin() else "Off", "Admin PIN", P.GOOD if control.has_pin() else P.MUTED)]
        for i, (icon, value, label, color) in enumerate(stats):
            tiles.columnconfigure(i, weight=1, uniform="tile")
            card = Card(tiles, pad=16)
            card.grid(row=0, column=i, sticky="nsew", padx=6)
            avatar(card.body, icon, color, 34, bg=P.CARD).pack(anchor="w")
            tk.Label(card.body, text=value, bg=P.CARD, fg=P.TEXT, font=font(24, "bold"), anchor="w").pack(
                anchor="w", pady=(10, 0))
            tk.Label(card.body, text=label, bg=P.CARD, fg=P.MUTED, font=font(9), anchor="w").pack(anchor="w")

        if not self.result:
            self._section(parent, "How it works")
            body = self._card(parent)
            for glyph, head, text in (("🔍", "Scan", "Find every phone, laptop, console and gadget on your Wi‑Fi."),
                                      ("⏸", "Pause", "Turn this PC's internet off and back on, now or on a schedule."),
                                      ("🛡", "Block", "Block whole categories of sites, or your own list, on this PC."),
                                      ("🎯", "Focus", "Cut distractions for a set time, then auto‑resume.")):
                row = tk.Frame(body, bg=P.CARD)
                row.pack(fill="x", pady=6)
                avatar(row, glyph, P.ACCENT, 36, bg=P.CARD).pack(side="left", padx=(0, 14))
                col = tk.Frame(row, bg=P.CARD)
                col.pack(side="left", fill="x", expand=True)
                tk.Label(col, text=head, bg=P.CARD, fg=P.TEXT, font=font(10, "bold"), anchor="w").pack(anchor="w")
                tk.Label(col, text=text, bg=P.CARD, fg=P.MUTED, font=font(9), anchor="w").pack(anchor="w")
            return

        two = tk.Frame(parent, bg=P.BG)
        two.pack(fill="x", pady=(16, 0))
        two.columnconfigure(0, weight=1, uniform="ov")
        two.columnconfigure(1, weight=1, uniform="ov")
        self._focus_card(two, 0)
        self._speed_card(two, 1)

        this_pc = next((d for d in self.result.devices if d.this_pc), None)
        if this_pc:
            self._section(parent, "This PC")
            self._device_card(parent, this_pc)

    def _focus_card(self, parent, col):
        card = Card(parent, pad=18)
        card.grid(row=0, column=col, sticky="nsew", padx=6)
        b = card.body
        head = tk.Frame(b, bg=P.CARD)
        head.pack(fill="x")
        avatar(head, "🎯", P.PURPLE, 36, bg=P.CARD).pack(side="left", padx=(0, 12))
        tk.Label(head, text="Focus mode", bg=P.CARD, fg=P.TEXT, font=font(12, "bold")).pack(side="left")
        rem = control.focus_remaining()
        if rem:
            self._focus_label = tk.Label(b, text=self._mmss(rem), bg=P.CARD, fg=P.PURPLE, font=font(30, "bold"))
            self._focus_label.pack(anchor="w", pady=(10, 0))
            tk.Label(b, text="This PC is paused until the timer ends.", bg=P.CARD, fg=P.MUTED,
                     font=font(9), anchor="w").pack(anchor="w")
            Pill(b, "Stop focus", lambda: self._focus(0), kind="danger", size=9).pack(anchor="w", pady=(12, 0))
        else:
            tk.Label(b, text="Cut this PC's internet for a set time, then it comes back on by itself.",
                     bg=P.CARD, fg=P.MUTED, font=font(9), justify="left", wraplength=360,
                     anchor="w").pack(anchor="w", pady=(10, 10))
            row = tk.Frame(b, bg=P.CARD)
            row.pack(anchor="w")
            for mins in (25, 60, 120):
                Pill(row, f"{mins} min", lambda m=mins: self._focus(m), kind="ghost", size=9).pack(side="left",
                                                                                                 padx=(0, 8))

    def _speed_card(self, parent, col):
        card = Card(parent, pad=18)
        card.grid(row=0, column=col, sticky="nsew", padx=6)
        b = card.body
        head = tk.Frame(b, bg=P.CARD)
        head.pack(fill="x")
        avatar(head, "⚡", P.ACCENT, 36, bg=P.CARD).pack(side="left", padx=(0, 12))
        tk.Label(head, text="Speed test", bg=P.CARD, fg=P.TEXT, font=font(12, "bold")).pack(side="left")
        if not self.speed_busy:
            Pill(head, "Test", self._speedtest, size=9).pack(side="right")
        if self.speed_busy:
            tk.Label(b, text=self.speed.get("msg", "Testing…") if self.speed else "Testing…", bg=P.CARD,
                     fg=P.MUTED, font=font(9), anchor="w").pack(anchor="w", pady=(12, 0))
        elif self.speed:
            down = self.speed.get("down")
            pingv = self.speed.get("ping")
            row = tk.Frame(b, bg=P.CARD)
            row.pack(fill="x", pady=(10, 0))
            tk.Label(row, text=f"{down}" if down else "—", bg=P.CARD, fg=P.TEXT, font=font(28, "bold")).pack(
                side="left")
            tk.Label(row, text=" Mbps down", bg=P.CARD, fg=P.MUTED, font=font(9)).pack(side="left", pady=(14, 0))
            meter(b, min(1.0, (down or 0) / 300), P.ACCENT, w=300, bg=P.CARD).pack(anchor="w", pady=(8, 0))
            tk.Label(b, text=(f"Ping {pingv} ms" if pingv else "Ping —") + "   ·   approximate",
                     bg=P.CARD, fg=P.MUTED, font=font(9), anchor="w").pack(anchor="w", pady=(8, 0))
        else:
            tk.Label(b, text="Check your internet's download speed and latency.", bg=P.CARD, fg=P.MUTED,
                     font=font(9), justify="left", wraplength=360, anchor="w").pack(anchor="w", pady=(12, 0))

    # ============================================================= devices
    def _page_devices(self, parent):
        if not self.result:
            self._empty(parent, "📡", "No devices yet", "Scan your network to list every device on your Wi‑Fi.")
            return
        bar = self._card(parent, pad=12)
        row = tk.Frame(bar, bg=P.CARD)
        row.pack(fill="x")
        tk.Label(row, text="🔍", bg=P.CARD, fg=P.MUTED, font=(EMOJI, 11)).pack(side="left", padx=(2, 8))
        entry = tk.Entry(row, bg=P.CARD, fg=P.TEXT, insertbackground=P.TEXT, relief="flat", font=font(10),
                         highlightthickness=0, bd=4)
        entry.pack(side="left", fill="x", expand=True)
        entry.insert(0, self.query)
        entry.bind("<KeyRelease>", lambda e: self._set_query(entry.get()))
        sort_label = {"name": "Name", "profile": "Who", "ip": "IP address"}[self.sort]
        sb = tk.Label(row, text=f"Sort: {sort_label}  ▾", bg=P.CARD_HI, fg=P.TEXT, font=font(9, "bold"),
                      padx=10, pady=4, cursor="hand2")
        sb.pack(side="right")
        sb.bind("<Button-1>", self._sort_menu)

        devices = self._visible_devices()
        self._section(parent, f"{len(devices)} of {len(self.result.devices)} devices", pady=(14, 10))
        if not devices:
            tk.Label(self._card(parent), text="No devices match your search.", bg=P.CARD, fg=P.MUTED,
                     font=font(10)).pack(anchor="w")
        for dev in devices:
            self._device_card(parent, dev)

    def _visible_devices(self):
        devs = list(self.result.devices)
        nid = self._nid()
        if self.sort == "name":
            devs.sort(key=lambda d: (not d.router, not d.this_pc,
                                     (control.device(nid, d.mac)["label"] or self._default_name(d)).lower()))
        elif self.sort == "profile":
            order = {k: i for i, k in enumerate(control.PROFILES)}
            devs.sort(key=lambda d: (not d.this_pc, order.get(control.device(nid, d.mac)["profile"], 9)))
        elif self.sort == "ip":
            import ipaddress
            devs.sort(key=lambda d: ipaddress.ip_address(d.ip))
        q = self.query.strip().lower()
        if q:
            def matches(d):
                info = control.device(nid, d.mac)
                hay = " ".join([info["label"] or "", d.name or "", d.maker or "", d.ip, d.mac,
                                self._default_name(d), PROFILE_LABELS.get(info["profile"], "")]).lower()
                return q in hay
            devs = [d for d in devs if matches(d)]
        return devs

    def _set_query(self, text):
        self.query = text
        # filter without losing focus: just rebuild the list area via full rerender
        self._rerender()

    def _sort_menu(self, event):
        menu = tk.Menu(self, tearoff=0, bg=P.CARD_HI, fg=P.TEXT, activebackground=P.ACCENT,
                       activeforeground="#ffffff", bd=0, font=font(10))
        for key, label in (("name", "Name"), ("profile", "Who it belongs to"), ("ip", "IP address")):
            menu.add_command(label=f"  {label}", command=lambda k=key: self._set_sort(k))
        menu.tk_popup(event.x_root, event.y_root)

    def _set_sort(self, key):
        self.sort = key
        self._rerender()

    def _device_card(self, parent, dev):
        nid = self._nid()
        info = control.device(nid, dev.mac)
        is_admin = control.is_admin_device(nid, dev.mac)
        color = P.ACCENT if dev.router else _profile_color(info["profile"])
        body = self._card(parent, pad=16, pady=(0, 10))
        row = tk.Frame(body, bg=P.CARD)
        row.pack(fill="x")
        avatar(row, KIND_ICON.get(dev.kind, "❔"), color, 46, bg=P.CARD).pack(side="left", padx=(0, 14))
        right = tk.Frame(row, bg=P.CARD)
        right.pack(side="right")
        mid = tk.Frame(row, bg=P.CARD)
        mid.pack(side="left", fill="x", expand=True)

        top = tk.Frame(mid, bg=P.CARD)
        top.pack(anchor="w", fill="x")
        tk.Label(top, text=info["label"] or self._default_name(dev), bg=P.CARD, fg=P.TEXT,
                 font=font(11, "bold")).pack(side="left")
        if dev.this_pc:
            chip(top, "THIS PC", P.ACCENT, bg=P.CARD).pack(side="left", padx=(8, 0))
        if is_admin:
            chip(top, "ADMIN", P.GOOD, bg=P.CARD).pack(side="left", padx=(6, 0))
        if dev.router:
            chip(top, "ROUTER", P.PURPLE, bg=P.CARD).pack(side="left", padx=(8, 0))
        if self.hist.get(dev.mac, {}).get("new"):
            chip(top, "NEW", P.WARN, bg=P.CARD).pack(side="left", padx=(6, 0))

        meta = tk.Frame(mid, bg=P.CARD)
        meta.pack(anchor="w", fill="x", pady=(5, 0))
        if not dev.router:
            prof = tk.Label(meta, text=f"{PROFILE_LABELS[info['profile']]}  ▾", bg=mix(color, P.CARD, 0.82),
                            fg=color, font=font(8, "bold"), padx=8, pady=1, cursor="hand2")
            prof.pack(side="left", padx=(0, 10))
            prof.bind("<Button-1>", lambda e, d=dev: self._profile_menu(e, d))
        tk.Label(meta, text=f"{dev.ip}   {dev.mac.upper()}", bg=P.CARD, fg=P.FAINT, font=MONO).pack(side="left")
        if not dev.router:
            rn = tk.Label(meta, text="✎ Rename", bg=P.CARD, fg=P.MUTED, font=font(8), cursor="hand2")
            rn.pack(side="left", padx=(12, 0))
            rn.bind("<Enter>", lambda e: rn.configure(fg=P.ACCENT))
            rn.bind("<Leave>", lambda e: rn.configure(fg=P.MUTED))
            rn.bind("<Button-1>", lambda e, d=dev: self._rename(d))

        if dev.router:
            return
        paused = info["paused"] or (dev.this_pc and control.desired_pc_paused())
        busy = self.action == "pause:" + dev.mac
        state = tk.Frame(right, bg=P.CARD)
        state.pack(side="left", padx=(0, 14))
        chip(state, "PAUSED" if paused else "● ONLINE", P.WARN if paused else P.GOOD, bg=P.CARD).pack(anchor="e")
        if not dev.this_pc:
            tk.Label(state, text="managed at router", bg=P.CARD, fg=P.FAINT, font=font(7)).pack(anchor="e",
                                                                                              pady=(3, 0))
        Pill(right, "Working…" if busy else ("▶  Resume" if paused else "⏸  Pause"),
             lambda: self._toggle_pause(dev, is_admin), kind="good" if paused else "ghost", size=9,
             disabled=busy).pack(side="left")

    def _profile_menu(self, event, dev):
        menu = tk.Menu(self, tearoff=0, bg=P.CARD_HI, fg=P.TEXT, activebackground=P.ACCENT,
                       activeforeground="#ffffff", bd=0, font=font(10))
        for key in control.PROFILES:
            menu.add_command(label=f"  {PROFILE_LABELS[key]}", command=lambda k=key: self._set_profile(dev, k))
        menu.tk_popup(event.x_root, event.y_root)

    # ======================================================= block sites
    def _page_block(self, parent):
        if not self.result:
            self._empty(parent, "🛡", "Scan first",
                        "Website blocking is saved per network, so scan your Wi‑Fi first.")
            return
        nid = self._nid()
        conf = control.net_config(nid)[1]
        body = self._card(parent, pad=20)
        head = tk.Frame(body, bg=P.CARD)
        head.pack(fill="x")
        avatar(head, "🛡", P.PURPLE, 44, bg=P.CARD).pack(side="left", padx=(0, 14))
        Pill(head, "Applying…" if self.action == "block" else "Apply blocking", self._apply_blocking,
             disabled=self.action == "block").pack(side="right")
        col = tk.Frame(head, bg=P.CARD)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, text="Website blocking", bg=P.CARD, fg=P.TEXT, font=font(13, "bold"),
                 anchor="w").pack(anchor="w")
        active = control.active_blocklist()
        tk.Label(col, text=(f"{len(active)} sites blocked on this PC right now" if control.enforce_on() and active
                            else "Choose what to block, then apply it to this PC"),
                 bg=P.CARD, fg=P.MUTED, font=font(9), anchor="w").pack(anchor="w")
        tk.Frame(body, bg=P.BORDER, height=1).pack(fill="x", pady=16)
        row = tk.Frame(body, bg=P.CARD)
        row.pack(fill="x")
        Toggle(row, on=control.enforce_setting(), command=lambda on: control.set_enforce(on)).pack(side="right")
        tk.Label(row, text="Keep blocks enforced", bg=P.CARD, fg=P.TEXT, font=font(10, "bold"),
                 anchor="w").pack(anchor="w")
        tk.Label(row, text="Checks every few minutes and puts the blocks back if something removes them.",
                 bg=P.CARD, fg=P.MUTED, font=font(9), anchor="w").pack(anchor="w")

        self._section(parent, "Categories")
        grid = tk.Frame(parent, bg=P.BG)
        grid.pack(fill="x")
        cats = set(conf.get("categories", []))
        for i, key in enumerate(control.CATEGORIES):
            emoji, label, blurb = CATEGORIES.get(key, ("•", key, ""))
            grid.columnconfigure(i % 2, weight=1, uniform="cat")
            card = Card(grid, pad=16)
            card.grid(row=i // 2, column=i % 2, sticky="nsew", padx=6, pady=(0, 12))
            r = tk.Frame(card.body, bg=P.CARD)
            r.pack(fill="x")
            avatar(r, emoji, P.PURPLE, 38, bg=P.CARD).pack(side="left", padx=(0, 12))
            Toggle(r, on=key in cats,
                   command=lambda on, k=key: control.toggle_category(nid, k, on)).pack(side="right")
            c = tk.Frame(r, bg=P.CARD)
            c.pack(side="left", fill="x", expand=True)
            tk.Label(c, text=label, bg=P.CARD, fg=P.TEXT, font=font(10, "bold"), anchor="w").pack(anchor="w")
            site_lbl = tk.Label(c, text=f"{blurb}  ·  {len(control.CATEGORIES[key])} sites  ·  see list",
                                bg=P.CARD, fg=P.MUTED, font=font(8), anchor="w", cursor="hand2")
            site_lbl.pack(anchor="w")
            site_lbl.bind("<Button-1>", lambda e, k=key: self._toggle_expand(k))
            if self.expanded_cat == key:
                tk.Label(card.body, text="\n".join(control.CATEGORIES[key]), bg=P.CARD, fg=P.FAINT, font=MONO,
                         justify="left", anchor="w").pack(anchor="w", pady=(8, 0))

        self._section(parent, "Your blocked sites", pady=(6, 10))
        body = self._card(parent, pad=18)
        add = tk.Frame(body, bg=P.CARD)
        add.pack(fill="x")
        wrap = tk.Frame(add, bg=P.BORDER, padx=1, pady=1)
        wrap.pack(side="left", fill="x", expand=True, padx=(0, 10))
        entry = tk.Entry(wrap, bg=P.CARD_HI, fg=P.FAINT, insertbackground=P.TEXT, relief="flat", font=font(10),
                         highlightthickness=0, bd=8)
        entry.pack(fill="x")
        placeholder = "Type a website, like example.com"
        entry.insert(0, placeholder)

        def fin(_e):
            if entry.get() == placeholder:
                entry.delete(0, "end")
                entry.configure(fg=P.TEXT)
            wrap.configure(bg=P.ACCENT)

        def fout(_e):
            if not entry.get():
                entry.insert(0, placeholder)
                entry.configure(fg=P.FAINT)
            wrap.configure(bg=P.BORDER)

        def submit(_e=None):
            if entry.get() and entry.get() != placeholder:
                self._add_site(entry.get())
        entry.bind("<FocusIn>", fin)
        entry.bind("<FocusOut>", fout)
        entry.bind("<Return>", submit)
        Pill(add, "+  Add", submit, size=9).pack(side="left")
        for domain in conf.get("sites", []):
            srow = tk.Frame(body, bg=P.CARD_HI)
            srow.pack(fill="x", pady=(10, 0))
            tk.Label(srow, text="⛔", bg=P.CARD_HI, fg=P.BAD, font=(EMOJI, 10)).pack(side="left", padx=(12, 8),
                                                                                  pady=8)
            tk.Label(srow, text=domain, bg=P.CARD_HI, fg=P.TEXT, font=font(10)).pack(side="left")
            rm = tk.Label(srow, text="Remove", bg=P.CARD_HI, fg=P.MUTED, font=font(9), cursor="hand2")
            rm.pack(side="right", padx=12)
            rm.bind("<Enter>", lambda e, w=rm: w.configure(fg=P.BAD))
            rm.bind("<Leave>", lambda e, w=rm: w.configure(fg=P.MUTED))
            rm.bind("<Button-1>", lambda e, d=domain: self._remove_site(d))
        if not conf.get("sites"):
            tk.Label(body, text="No extra sites yet.", bg=P.CARD, fg=P.FAINT, font=font(9)).pack(anchor="w",
                                                                                               pady=(14, 0))

    def _toggle_expand(self, key):
        self.expanded_cat = None if self.expanded_cat == key else key
        self._rerender()

    # ============================================================ schedule
    def _page_schedule(self, parent):
        sch = control.schedule()
        body = self._card(parent, pad=20)
        head = tk.Frame(body, bg=P.CARD)
        head.pack(fill="x")
        avatar(head, "🗓", P.ACCENT, 44, bg=P.CARD).pack(side="left", padx=(0, 14))
        Toggle(head, on=sch["enabled"], command=self._toggle_schedule).pack(side="right")
        col = tk.Frame(head, bg=P.CARD)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, text="Off-hours schedule", bg=P.CARD, fg=P.TEXT, font=font(13, "bold"),
                 anchor="w").pack(anchor="w")
        tk.Label(col, text="Automatically pause THIS PC's internet during the times you set.",
                 bg=P.CARD, fg=P.MUTED, font=font(9), anchor="w").pack(anchor="w")
        if control.schedule_active():
            tk.Frame(body, bg=P.BORDER, height=1).pack(fill="x", pady=12)
            tk.Label(body, text="⏸  A schedule window is active now — this PC is set to paused.", bg=P.CARD,
                     fg=P.WARN, font=font(9, "bold")).pack(anchor="w")

        self._section(parent, "Windows")
        windows = sch["windows"]
        if not windows:
            tk.Label(self._card(parent), text="No windows yet. Add one below (for example, Bedtime 11pm–7am).",
                     bg=P.CARD, fg=P.MUTED, font=font(10)).pack(anchor="w")
        for i, win in enumerate(windows):
            body = self._card(parent, pad=14)
            row = tk.Frame(body, bg=P.CARD)
            row.pack(fill="x")
            active = control._window_active(win, datetime.now())
            avatar(row, "🌙" if win["start"] > win["end"] else "⏰", P.WARN if active else P.MUTED, 38,
                   bg=P.CARD).pack(side="left", padx=(0, 12))
            col = tk.Frame(row, bg=P.CARD)
            col.pack(side="left", fill="x", expand=True)
            name = win.get("label") or "Window"
            tk.Label(col, text=f"{name}   {win['start']} – {win['end']}", bg=P.CARD, fg=P.TEXT,
                     font=font(10, "bold"), anchor="w").pack(anchor="w")
            days = ", ".join(control.DAYS[d] for d in win.get("days", [])) or "no days"
            tk.Label(col, text=days, bg=P.CARD, fg=P.MUTED, font=font(9), anchor="w").pack(anchor="w")
            rm = tk.Label(row, text="Remove", bg=P.CARD, fg=P.MUTED, font=font(9), cursor="hand2")
            rm.pack(side="right")
            rm.bind("<Enter>", lambda e, w=rm: w.configure(fg=P.BAD))
            rm.bind("<Leave>", lambda e, w=rm: w.configure(fg=P.MUTED))
            rm.bind("<Button-1>", lambda e, idx=i: self._remove_window(idx))
        Pill(parent, "+  Add a window", self._add_window_dialog, kind="ghost", size=9).pack(anchor="w", padx=6,
                                                                                          pady=(6, 0))
        tk.Label(parent, text="When a window starts, pausing asks for the Windows admin prompt once. If you're "
                              "away and don't answer it, it stays as it was.", bg=P.BG, fg=P.FAINT, font=font(8),
                 wraplength=720, justify="left").pack(anchor="w", padx=8, pady=(12, 8))

    # ============================================================ activity
    def _page_activity(self, parent):
        head = tk.Frame(parent, bg=P.BG)
        head.pack(fill="x", padx=6, pady=(4, 10))
        tk.Label(head, text="RECENT ACTIVITY", bg=P.BG, fg=P.FAINT, font=font(8, "bold")).pack(side="left")
        if self.result:
            Pill(head, "⬇  Save report", self._save_report, kind="ghost", size=9).pack(side="right")
        evs = control.events()
        if not evs:
            tk.Label(self._card(parent), text="Nothing yet. Your actions will show up here.", bg=P.CARD,
                     fg=P.MUTED, font=font(10)).pack(anchor="w")
            return
        body = self._card(parent, pad=8)
        for ev in evs[:80]:
            row = tk.Frame(body, bg=P.CARD)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=EVENT_ICON.get(ev.get("kind"), "•"), bg=P.CARD, fg=P.MUTED, font=(EMOJI, 11),
                     width=3).pack(side="left")
            tk.Label(row, text=ev.get("text", ""), bg=P.CARD, fg=P.TEXT, font=font(9), anchor="w").pack(side="left",
                                                                                                      fill="x")
            tk.Label(row, text=self._ago(ev.get("t")), bg=P.CARD, fg=P.FAINT, font=font(8)).pack(side="right")

    @staticmethod
    def _ago(iso):
        try:
            from datetime import timezone
            t = datetime.fromisoformat(iso)
            secs = (datetime.now(timezone.utc) - t).total_seconds()
        except (ValueError, TypeError):
            return ""
        if secs < 60:
            return "just now"
        if secs < 3600:
            return f"{int(secs // 60)}m ago"
        if secs < 86400:
            return f"{int(secs // 3600)}h ago"
        return f"{int(secs // 86400)}d ago"

    # ============================================================ access
    def _page_access(self, parent):
        on = control.has_pin()
        body = self._card(parent, pad=24)
        head = tk.Frame(body, bg=P.CARD)
        head.pack(fill="x")
        avatar(head, "🔒", P.GOOD if on else P.MUTED, 56, bg=P.CARD).pack(side="left", padx=(0, 16))
        col = tk.Frame(head, bg=P.CARD)
        col.pack(side="left", fill="x", expand=True)
        t = tk.Frame(col, bg=P.CARD)
        t.pack(anchor="w")
        tk.Label(t, text="Admin PIN", bg=P.CARD, fg=P.TEXT, font=font(14, "bold")).pack(side="left")
        chip(t, "ON" if on else "OFF", P.GOOD if on else P.MUTED, bg=P.CARD).pack(side="left", padx=(10, 0))
        tk.Label(col, text=("Once set, pausing or resuming the admin device needs the PIN — so no one else can keep "
                            "you offline, and you can always turn your own internet back on."),
                 bg=P.CARD, fg=P.MUTED, font=font(9), justify="left", wraplength=560, anchor="w").pack(
            anchor="w", pady=(4, 0))
        btns = tk.Frame(body, bg=P.CARD)
        btns.pack(anchor="w", pady=(18, 0), padx=(72, 0))
        if on:
            Pill(btns, "Change PIN", self._change_pin, kind="ghost", size=9).pack(side="left")
            Pill(btns, "Remove PIN", self._remove_pin, kind="danger", size=9).pack(side="left", padx=(10, 0))
        else:
            Pill(btns, "Set admin PIN", self._set_pin, size=9).pack(side="left")

        self._section(parent, "Help")
        body = self._card(parent)
        tk.Label(body, text="If something goes wrong, details are saved to:", bg=P.CARD, fg=P.MUTED,
                 font=font(9)).pack(anchor="w")
        tk.Label(body, text=str(settings.CRASH_LOG), bg=P.CARD, fg=P.TEXT, font=MONO, wraplength=640,
                 justify="left", anchor="w").pack(anchor="w", pady=(4, 0))

    # ============================================================ settings
    def _page_settings(self, parent):
        ui = control.ui_settings()
        self._section(parent, "Appearance", pady=(4, 10))
        body = self._card(parent, pad=18)
        for name, value, label, blurb in (
                ("theme", ui["theme"] == "light", "Light mode", "Switch between the dark and light look."),
                ("scan_on_launch", ui["scan_on_launch"], "Scan on launch", "Scan the network when the app opens."),
                ("minimize_to_tray", ui["minimize_to_tray"], "Keep running when closed",
                 "Closing the window minimizes it instead of quitting, so schedules keep working.")):
            row = tk.Frame(body, bg=P.CARD)
            row.pack(fill="x", pady=6)
            Toggle(row, on=value, command=lambda on, n=name: self._set_setting(n, on)).pack(side="right")
            c = tk.Frame(row, bg=P.CARD)
            c.pack(side="left", fill="x", expand=True)
            tk.Label(c, text=label, bg=P.CARD, fg=P.TEXT, font=font(10, "bold"), anchor="w").pack(anchor="w")
            tk.Label(c, text=blurb, bg=P.CARD, fg=P.MUTED, font=font(9), anchor="w").pack(anchor="w")

        self._section(parent, "About")
        body = self._card(parent)
        from . import __version__
        tk.Label(body, text=f"Home Network Manager {__version__}", bg=P.CARD, fg=P.TEXT,
                 font=font(10, "bold")).pack(anchor="w")
        tk.Label(body, text="Manages your own home network only. Settings are saved in\n" + str(settings.data_dir()),
                 bg=P.CARD, fg=P.MUTED, font=font(9), justify="left", anchor="w").pack(anchor="w", pady=(4, 10))
        Pill(body, "Quit the app", self.destroy, kind="danger", size=9).pack(anchor="w")

    def _set_setting(self, name, on):
        control.set_ui(**{name: on})
        if name == "theme":
            P.use("light" if on else "dark")
            self._build()  # full repaint
        else:
            self._rerender()

    # ============================================================ actions
    def _focus(self, minutes):
        if minutes <= 0:
            control.focus_cancel()
            self._enforce_pc("Focus ended.")
        else:
            control.focus_start(minutes)
            self._enforce_pc(f"Focus on for {minutes} min.")

    def _toggle_schedule(self, on):
        control.set_schedule_enabled(on)
        self._enforce_pc()

    def _add_window_dialog(self):
        AddWindowDialog(self, self._add_window_done)

    def _add_window_done(self, days, start, end, label):
        control.add_window(days, start, end, label)
        self._set_status("Schedule window added.", "good")
        self._enforce_pc()

    def _remove_window(self, idx):
        control.remove_window(idx)
        self._enforce_pc()

    def _enforce_pc(self, msg=None):
        """Apply the combined pause state to this PC now (one admin prompt if it changes)."""
        if msg:
            self._set_status(msg, "info")
        want = control.desired_pc_paused()
        try:
            from . import firewall
            if firewall.internet_paused() != want:
                self._run("pcpause", lambda: control.enforce_this_pc(want),
                          "This PC " + ("paused." if want else "resumed."))
                return
        except Exception:
            pass
        self._rerender()

    def _set_pin(self):
        pin = simpledialog.askstring(APP_NAME, "Choose an admin PIN:", show="•", parent=self)
        if pin and pin.strip():
            again = simpledialog.askstring(APP_NAME, "Enter the PIN again:", show="•", parent=self)
            if again != pin:
                messagebox.showwarning(APP_NAME, "The PINs did not match. Nothing was changed.", parent=self)
                return
            control.set_pin(pin.strip())
            control.log("pin", "Admin PIN set")
            self._set_status("Admin PIN set.", "good")
            self._rerender()

    def _change_pin(self):
        if self._ask_pin():
            self._set_pin()

    def _remove_pin(self):
        if self._ask_pin():
            control.clear_pin()
            control.log("pin", "Admin PIN removed")
            self._set_status("Admin PIN removed.", "warn")
            self._rerender()

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

    def _add_site(self, raw):
        before = len(control.net_config(self._nid())[1].get("sites", []))
        control.add_site(self._nid(), raw)
        if len(control.net_config(self._nid())[1].get("sites", [])) == before:
            self._set_status(f"“{raw.strip()}” doesn't look like a new website (try example.com).", "warn")
        else:
            self._set_status("Site added — press Apply blocking to block it on this PC.", "info")
        self._rerender()

    def _remove_site(self, domain):
        control.remove_site(self._nid(), domain)
        self._rerender()

    def _apply_blocking(self):
        nid = self._nid()
        self._run("block", lambda: control.apply_site_blocks(nid), "Website blocks applied to this PC.")

    def _toggle_pause(self, dev, is_admin):
        nid = self._nid()
        if dev.this_pc:
            want = not control.desired_pc_paused()
            if is_admin and not self._ask_pin():
                return
            control.set_pc_paused_manual(want)
            control.log("pause" if want else "resume", "This PC " + ("paused" if want else "resumed") + " by hand")
            self._run("pause:" + dev.mac, lambda: control.enforce_this_pc(control.desired_pc_paused()),
                      "This PC's internet " + ("paused." if want else "resumed."))
        else:
            want = not control.device(nid, dev.mac)["paused"]
            control.set_paused(nid, dev.mac, want)
            self._set_status(("Marked as paused" if want else "Marked as on") + " — managed, applies at your router.",
                             "info")
            self._rerender()

    def _set_profile(self, dev, key):
        control.set_profile(self._nid(), dev.mac, key)
        if key == "me":
            control.set_admin_device(self._nid(), dev.mac)
        self._rerender()

    def _rename(self, dev):
        current = control.device(self._nid(), dev.mac)["label"] or ""
        name = simpledialog.askstring(APP_NAME, "Name for this device:", initialvalue=current, parent=self)
        if name is not None:
            control.set_label(self._nid(), dev.mac, name)
            self._rerender()

    def _save_report(self):
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".html",
                                            initialfile="home-network-report.html",
                                            filetypes=[("Web page", "*.html")])
        if path:
            try:
                report.save(self.result, path)
                webbrowser.open("file://" + os.path.abspath(path))
                self._set_status("Report saved.", "good")
            except OSError as e:
                self._set_status(f"Couldn't save the report: {e}", "bad")

    def _speedtest(self):
        if self.speed_busy:
            return
        self.speed_busy = True
        self.speed = {"msg": "Starting…"}
        self._rerender()

        def run():
            res = speedtest.run(progress=lambda m: self.events.put(("speedmsg", m)))
            self.events.put(("speed", res))
        threading.Thread(target=run, daemon=True).start()

    @staticmethod
    def _default_name(dev):
        if dev.router:
            return "Your router"
        if dev.this_pc:
            return "This PC"
        return dev.name or dev.maker or ("Private device" if dev.private_mac else "Unknown device")

    # =============================================== scanning & workers
    def scan(self):
        if self.busy:
            return
        self.busy = True
        self.status_text, self.status_kind = "Scanning your network… this takes a few seconds.", "info"
        self._rerender()

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
        self.status_text, self.status_kind = "Asking Windows for permission…", "info"
        self._rerender()

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
                    if isinstance(payload, Exception):
                        self.result = None
                        self.status_text = ("No network found — connect to Wi‑Fi and try again."
                                            if str(payload) == "no_network" else f"Scan failed: {payload}")
                        self.status_kind = "bad"
                    else:
                        self.result = payload
                        self._learn_admin(payload)
                        try:
                            self.hist = history.record(payload.network_id, payload.devices)
                        except Exception:
                            self.hist = {}
                        new = sum(1 for v in self.hist.values() if v.get("new"))
                        control.log("scan", f"Scanned {payload.network}: {len(payload.devices)} devices")
                        self.status_text = (f"Found {len(payload.devices)} devices on {payload.network}."
                                            + (f"  {new} new." if new else ""))
                        self.status_kind = "good"
                    self._render()
                elif kind == "done":
                    label, error, msg = payload
                    self.action = None
                    if error:
                        self.status_text, self.status_kind = f"Couldn't finish: {error}", "bad"
                        if label.startswith(("pause", "pcpause")):
                            messagebox.showwarning(APP_NAME, error, parent=self)
                    else:
                        self.status_text, self.status_kind = msg, "good"
                    self._render()
                elif kind == "speedmsg":
                    if self.speed_busy:
                        self.speed = {"msg": payload}
                        if self.page == "overview":
                            self._render()
                elif kind == "speed":
                    self.speed_busy = False
                    self.speed = payload
                    self._render()
                elif kind == "note":
                    self._set_status(*payload)
                    if self.page in ("overview", "activity", "devices"):
                        self._render()
        except queue.Empty:
            pass
        except Exception:
            settings.log_crash("pump", traceback.format_exc())
        if self.busy:
            self._pulse += 1
            t = (self._pulse % 10) / 10
            self.s_dot.itemconfigure("dot", fill=mix(P.ACCENT, P.BG, abs(0.5 - t) * 1.4))
        try:
            self.after(150, self._pump)
        except tk.TclError:
            pass

    def _tick(self):
        """Once a second: update the focus countdown without a full rebuild."""
        try:
            rem = control.focus_remaining()
            lbl = getattr(self, "_focus_label", None)
            if lbl is not None and lbl.winfo_exists():
                if rem:
                    lbl.configure(text=self._mmss(rem))
                else:
                    self._focus_label = None
                    if self.page == "overview":
                        self._enforce_pc()  # focus ended → resume
        except tk.TclError:
            pass
        try:
            self.after(1000, self._tick)
        except tk.TclError:
            pass

    def _on_close(self):
        if control.ui_settings().get("minimize_to_tray"):
            self.iconify()
        else:
            self.destroy()

    def _learn_admin(self, result):
        conf = control.net_config(result.network_id)[1]
        if not conf.get("admin_mac"):
            for dev in result.devices:
                if dev.this_pc:
                    control.set_admin_device(result.network_id, dev.mac)
                    break


class AddWindowDialog(tk.Toplevel):
    """A small dialog to add a schedule window: days + start/end time + name."""

    def __init__(self, parent, on_done):
        super().__init__(parent)
        self.on_done = on_done
        self.title("Add a window")
        self.configure(bg=P.BG)
        self.resizable(False, False)
        self.transient(parent)
        try:
            self.grab_set()
        except tk.TclError:
            pass
        pad = tk.Frame(self, bg=P.BG)
        pad.pack(padx=20, pady=18)
        tk.Label(pad, text="New schedule window", bg=P.BG, fg=P.TEXT, font=font(13, "bold")).pack(anchor="w")
        tk.Label(pad, text="This PC's internet will pause during this time.", bg=P.BG, fg=P.MUTED,
                 font=font(9)).pack(anchor="w", pady=(2, 12))

        tk.Label(pad, text="Name (optional)", bg=P.BG, fg=P.MUTED, font=font(8, "bold")).pack(anchor="w")
        self.name = tk.Entry(pad, bg=P.CARD_HI, fg=P.TEXT, insertbackground=P.TEXT, relief="flat", font=font(10),
                             bd=6, highlightthickness=1, highlightbackground=P.BORDER)
        self.name.pack(fill="x", pady=(2, 10))
        self.name.insert(0, "Bedtime")

        times = tk.Frame(pad, bg=P.BG)
        times.pack(fill="x", pady=(0, 12))
        self.start = self._time_box(times, "From", "23:00")
        self.end = self._time_box(times, "To", "07:00")

        tk.Label(pad, text="Days", bg=P.BG, fg=P.MUTED, font=font(8, "bold")).pack(anchor="w")
        daysrow = tk.Frame(pad, bg=P.BG)
        daysrow.pack(fill="x", pady=(4, 14))
        self.day_vars = []
        for i, d in enumerate(control.DAYS):
            v = tk.IntVar(value=1 if i < 5 else 0)
            self.day_vars.append(v)
            cb = tk.Checkbutton(daysrow, text=d, variable=v, bg=P.BG, fg=P.TEXT, selectcolor=P.CARD_HI,
                                activebackground=P.BG, activeforeground=P.TEXT, font=font(9),
                                highlightthickness=0, bd=0)
            cb.pack(side="left", padx=2)

        btns = tk.Frame(pad, bg=P.BG)
        btns.pack(fill="x")
        Pill(btns, "Cancel", self.destroy, kind="ghost", size=9, bg=P.BG).pack(side="right", padx=(8, 0))
        Pill(btns, "Add window", self._ok, size=9, bg=P.BG).pack(side="right")

    def _time_box(self, parent, label, default):
        col = tk.Frame(parent, bg=P.BG)
        col.pack(side="left", padx=(0, 16))
        tk.Label(col, text=label, bg=P.BG, fg=P.MUTED, font=font(8, "bold")).pack(anchor="w")
        e = tk.Entry(col, bg=P.CARD_HI, fg=P.TEXT, insertbackground=P.TEXT, relief="flat", font=font(11), bd=6,
                     width=7, justify="center", highlightthickness=1, highlightbackground=P.BORDER)
        e.pack(pady=(2, 0))
        e.insert(0, default)
        return e

    def _ok(self):
        days = [i for i, v in enumerate(self.day_vars) if v.get()]
        start, end = self.start.get().strip(), self.end.get().strip()
        if not days or not control._parse_hhmm(start) or not control._parse_hhmm(end):
            messagebox.showwarning(APP_NAME, "Pick at least one day and times like 23:00.", parent=self)
            return
        self.on_done(days, start, end, self.name.get().strip())
        self.destroy()




def run():
    App().mainloop()
