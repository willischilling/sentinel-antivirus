"""The Home Network Manager window: a sidebar dashboard drawn with plain Tkinter.

Pages: Overview, Devices, Block sites and Your access. Long or privileged jobs
run on worker threads and report back through a queue the UI polls, so the
window never freezes. Rebuilds triggered by clicks are deferred to idle, so a
widget is never destroyed while it's handling its own event.
"""
import os
import queue
import sys
import threading
import tkinter as tk
import traceback
from tkinter import messagebox, simpledialog

from . import APP_NAME, control, netscan, settings, watcher
from .widgets import (ACCENT, BAD, BG, BORDER, CARD, CARD_HI, EMOJI, FAINT, GOOD, MONO, MUTED, PURPLE, SIDEBAR,
                      TEXT, WARN, Banner, Card, Pill, ScrollArea, Toggle, avatar, chip, dot, font, mix)


def _resource(rel: str) -> str:
    """Path to a bundled file, both from source and from a PyInstaller build."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, rel)


KIND_ICON = {"router": "🌐", "computer": "💻", "phone": "📱", "apple": "📱", "console": "🎮",
             "tv": "📺", "printer": "🖨", "speaker": "🔊", "camera": "📷", "smart": "💡", "unknown": "❔"}
PROFILE_LABELS = {"me": "Me", "family": "Family", "kids": "Kids", "guest": "Guest", "other": "Other"}
PROFILE_COLOR = {"me": ACCENT, "family": GOOD, "kids": WARN, "guest": PURPLE, "other": MUTED}
CATEGORIES = {  # key: (emoji, label, blurb)
    "adult": ("🔞", "Adult content", "Also turns on a family DNS filter"),
    "social": ("💬", "Social media", "Facebook, Instagram, TikTok, X…"),
    "gaming": ("🎮", "Games", "Roblox, Steam, Epic, Xbox…"),
    "streaming": ("🎬", "Video streaming", "YouTube, Netflix, Twitch…"),
    "ads": ("🚫", "Ads & trackers", "Common ad and tracking networks"),
}
PAGES = [("overview", "🏠", "Overview"), ("devices", "📶", "Devices"),
         ("block", "🛡", "Block sites"), ("access", "🔒", "Your access")]
PAGE_TEXT = {
    "overview": ("Overview", "Your network at a glance."),
    "devices": ("Devices", "Name devices, set who they belong to, and pause their internet."),
    "block": ("Block sites", "Block categories or your own list of websites."),
    "access": ("Your access", "Protect your own device with an admin PIN."),
}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1080x760")
        self.minsize(900, 620)
        self.configure(bg=BG)
        try:
            self.iconbitmap(_resource("assets/icon.ico"))
        except Exception:
            pass
        self.report_callback_exception = self._on_tk_error
        self.events: "queue.Queue" = queue.Queue()
        self.result: netscan.ScanResult | None = None
        self.busy = False
        self.action = None
        self.status_text, self.status_kind = "Scan your network to begin.", "info"
        self.page = "overview"
        self._pulse = 0
        self._build()
        self.after(150, self._pump)
        watcher.start(on_reapplied=lambda n: self.events.put(
            ("note", (f"Put back {n} blocked site(s) that were changed.", "good"))), on_error=lambda e: None)

    # ================================================================ layout
    def _build(self):
        # --- sidebar
        self.sidebar = tk.Frame(self, bg=SIDEBAR, width=230)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        tk.Frame(self, bg=BORDER, width=1).pack(side="left", fill="y")

        brand = tk.Frame(self.sidebar, bg=SIDEBAR)
        brand.pack(fill="x", padx=20, pady=(24, 26))
        logo = tk.Canvas(brand, width=40, height=40, bg=SIDEBAR, highlightthickness=0)
        logo.pack(side="left")
        for i in range(40):  # little gradient tile
            logo.create_line(i, 0, i, 40, fill=mix("#2c64ff", PURPLE, i / 39))
        for x, y in ((0, 0), (40, 0), (0, 40), (40, 40)):  # soften the corners
            logo.create_oval(x - 9, y - 9, x + 9, y + 9, fill=SIDEBAR, outline=SIDEBAR)
        logo.create_text(20, 21, text="🏠", font=(EMOJI, 15), fill="#ffffff")
        names = tk.Frame(brand, bg=SIDEBAR)
        names.pack(side="left", padx=(12, 0))
        tk.Label(names, text="Home Network", bg=SIDEBAR, fg=TEXT, font=font(12, "bold")).pack(anchor="w")
        tk.Label(names, text="MANAGER", bg=SIDEBAR, fg=MUTED, font=font(8, "bold")).pack(anchor="w")

        tk.Label(self.sidebar, text="MENU", bg=SIDEBAR, fg=FAINT, font=font(8, "bold")).pack(anchor="w", padx=24,
                                                                                          pady=(0, 6))
        self.nav = {}
        for key, icon, label in PAGES:
            self.nav[key] = self._nav_item(key, icon, label)

        self.side_status = tk.Frame(self.sidebar, bg=SIDEBAR)
        self.side_status.pack(side="bottom", fill="x", padx=16, pady=18)

        # --- main area
        main = tk.Frame(self, bg=BG)
        main.pack(side="left", fill="both", expand=True)
        header = tk.Frame(main, bg=BG)
        header.pack(fill="x", padx=32, pady=(26, 4))
        titles = tk.Frame(header, bg=BG)
        titles.pack(side="left", fill="x", expand=True)
        self.h_title = tk.Label(titles, bg=BG, fg=TEXT, font=font(22, "bold"), anchor="w")
        self.h_title.pack(anchor="w")
        self.h_sub = tk.Label(titles, bg=BG, fg=MUTED, font=font(10), anchor="w")
        self.h_sub.pack(anchor="w", pady=(2, 0))
        self.h_actions = tk.Frame(header, bg=BG)
        self.h_actions.pack(side="right", anchor="n", pady=(6, 0))

        status = tk.Frame(main, bg=BG)
        status.pack(fill="x", padx=32, pady=(10, 8))
        self.s_dot = dot(status, ACCENT, 9, bg=BG)
        self.s_dot.pack(side="left", padx=(0, 8))
        self.s_text = tk.Label(status, bg=BG, fg=MUTED, font=font(9), anchor="w")
        self.s_text.pack(side="left", fill="x")

        self.scroll = ScrollArea(main)
        self.scroll.pack(fill="both", expand=True, padx=(26, 14), pady=(0, 16))
        self.body = self.scroll.inner
        self._render()

    def _nav_item(self, key, icon, label):
        row = tk.Frame(self.sidebar, bg=SIDEBAR, cursor="hand2")
        row.pack(fill="x", padx=12, pady=2)
        bar = tk.Frame(row, bg=SIDEBAR, width=4)
        bar.pack(side="left", fill="y")
        ic = tk.Label(row, text=icon, bg=SIDEBAR, fg=TEXT, font=(EMOJI, 12), width=3)
        ic.pack(side="left", padx=(8, 2), pady=9)
        lb = tk.Label(row, text=label, bg=SIDEBAR, fg=MUTED, font=font(10, "bold"), anchor="w")
        lb.pack(side="left", fill="x", expand=True)
        parts = (row, ic, lb)

        def paint(active, hover=False):
            bg = CARD_HI if active else (mix(SIDEBAR, CARD_HI, 0.6) if hover else SIDEBAR)
            for w in parts:
                w.configure(bg=bg)
            bar.configure(bg=ACCENT if active else bg)
            lb.configure(fg=TEXT if active else MUTED)

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
        return "Scanning…" if self.busy else ("Scan again" if self.result else "Scan network")

    def _paint_status(self):
        color = {"good": GOOD, "warn": WARN, "bad": BAD}.get(self.status_kind, ACCENT)
        self.s_dot.itemconfigure("dot", fill=color)
        self.s_text.configure(text=self.status_text,
                              fg=TEXT if self.status_kind in ("good", "bad", "warn") else MUTED)

    def _set_status(self, text, kind="info"):
        self.status_text, self.status_kind = text, kind
        self._paint_status()

    def _side_status(self):
        for child in self.side_status.winfo_children():
            child.destroy()
        card = Card(self.side_status, fill=CARD, radius=14, pad=14)
        card.pack(fill="x")
        b = card.body
        top = tk.Frame(b, bg=CARD)
        top.pack(fill="x")
        online = self.result is not None
        dot(top, GOOD if online else FAINT, 9, bg=CARD).pack(side="left", padx=(0, 8))
        tk.Label(top, text="Connected" if online else "Not scanned", bg=CARD, fg=TEXT,
                 font=font(9, "bold")).pack(side="left")
        tk.Label(b, text=self.result.network if online else "Scan to find your network",
                 bg=CARD, fg=MUTED, font=font(8), anchor="w").pack(anchor="w", pady=(4, 0))
        if control.enforce_on():
            tk.Label(b, text=f"🛡  {len(control.active_blocklist())} sites blocked", bg=CARD, fg=MUTED,
                     font=font(8), anchor="w").pack(anchor="w", pady=(2, 0))

    def _on_tk_error(self, exc, val, tb):
        settings.log_crash("tk-callback", "".join(traceback.format_exception(exc, val, tb)))

    # ============================================================== helpers
    def _section(self, parent, text, pady=(18, 10)):
        tk.Label(parent, text=text.upper(), bg=BG, fg=FAINT, font=font(8, "bold")).pack(anchor="w", padx=6,
                                                                                      pady=pady)

    def _card(self, parent, pady=(0, 12), **kw):
        card = Card(parent, **kw)
        card.pack(fill="x", padx=6, pady=pady)
        return card.body

    def _empty(self, parent, glyph, title, text):
        body = self._card(parent, pad=36)
        tk.Label(body, text=glyph, bg=CARD, fg=TEXT, font=(EMOJI, 34)).pack()
        tk.Label(body, text=title, bg=CARD, fg=TEXT, font=font(14, "bold")).pack(pady=(8, 2))
        tk.Label(body, text=text, bg=CARD, fg=MUTED, font=font(10), justify="center", wraplength=460).pack()
        Pill(body, self._scan_label(), self.scan, disabled=self.busy).pack(pady=(16, 0))

    def _nid(self):
        return self.result.network_id

    # ============================================================ overview
    def _page_overview(self, parent):
        banner = Banner(parent, height=176)
        banner.pack(fill="x", padx=6, pady=(4, 6))
        if self.result:
            title = "Your home network"
            sub = f"{len(self.result.devices)} devices on {self.result.network}   ·   router {self.result.gateway}"
        else:
            title = "Welcome home"
            sub = "Scan your Wi‑Fi to see every device and take control of it."
        banner.create_text(30, 34, text=title, anchor="nw", fill="#ffffff", font=font(21, "bold"))
        banner.create_text(30, 74, text=sub, anchor="nw", fill=mix("#ffffff", PURPLE, 0.18), font=font(10))
        banner.create_window(30, 112, anchor="nw",
                             window=Pill(banner, self._scan_label(), self.scan, kind="light", disabled=self.busy,
                                         bg=mix("#2c64ff", PURPLE, 0.08)))

        tiles = tk.Frame(parent, bg=BG)
        tiles.pack(fill="x", pady=(10, 0))
        nid = self.result.network_id if self.result else None
        stats = [
            ("📶", str(len(self.result.devices)) if self.result else "—", "Devices", ACCENT),
            ("⏸", str(control.paused_count(nid)) if nid else "—", "Paused", WARN),
            ("🛡", str(len(control.active_blocklist())) if control.enforce_on() else "0", "Sites blocked", PURPLE),
            ("🔒", "On" if control.has_pin() else "Off", "Admin PIN", GOOD if control.has_pin() else MUTED),
        ]
        for i, (icon, value, label, color) in enumerate(stats):
            tiles.columnconfigure(i, weight=1, uniform="tile")
            card = Card(tiles, pad=16)
            card.grid(row=0, column=i, sticky="nsew", padx=6)
            b = card.body
            avatar(b, icon, color, 34, bg=CARD).pack(anchor="w")
            tk.Label(b, text=value, bg=CARD, fg=TEXT, font=font(24, "bold"), anchor="w").pack(anchor="w",
                                                                                            pady=(10, 0))
            tk.Label(b, text=label, bg=CARD, fg=MUTED, font=font(9), anchor="w").pack(anchor="w")

        if not self.result:
            self._section(parent, "How it works")
            body = self._card(parent)
            for glyph, head, text in (
                    ("🔍", "Scan", "Find every phone, laptop, console and gadget on your Wi‑Fi."),
                    ("⏸", "Pause", "Turn this PC's internet off and back on. Other devices are kept as a plan "
                                   "for your router."),
                    ("🛡", "Block", "Block whole categories of sites, or your own list, on this PC."),
                    ("🔒", "Protect", "Set an admin PIN so nobody else can keep you offline.")):
                row = tk.Frame(body, bg=CARD)
                row.pack(fill="x", pady=6)
                avatar(row, glyph, ACCENT, 36, bg=CARD).pack(side="left", padx=(0, 14))
                col = tk.Frame(row, bg=CARD)
                col.pack(side="left", fill="x", expand=True)
                tk.Label(col, text=head, bg=CARD, fg=TEXT, font=font(10, "bold"), anchor="w").pack(anchor="w")
                tk.Label(col, text=text, bg=CARD, fg=MUTED, font=font(9), anchor="w").pack(anchor="w")
            return

        this_pc = next((d for d in self.result.devices if d.this_pc), None)
        if this_pc:
            self._section(parent, "This PC")
            self._device_card(parent, this_pc)
        paused = [d for d in self.result.devices if control.device(nid, d.mac)["paused"] and not d.this_pc]
        self._section(parent, "Paused devices")
        if paused:
            for d in paused:
                self._device_card(parent, d)
        else:
            body = self._card(parent)
            tk.Label(body, text="Nothing is paused right now.", bg=CARD, fg=MUTED, font=font(10)).pack(anchor="w")

    # ============================================================= devices
    def _page_devices(self, parent):
        if not self.result:
            self._empty(parent, "📡", "No devices yet", "Scan your network to list every device on your Wi‑Fi.")
            return
        self._section(parent, f"{len(self.result.devices)} devices on {self.result.network}", pady=(4, 10))
        for dev in self.result.devices:
            self._device_card(parent, dev)

    def _device_card(self, parent, dev):
        nid = self._nid()
        info = control.device(nid, dev.mac)
        is_admin = control.is_admin_device(nid, dev.mac)
        color = PROFILE_COLOR.get(info["profile"], MUTED) if not dev.router else ACCENT
        body = self._card(parent, pad=16, pady=(0, 10))
        row = tk.Frame(body, bg=CARD)
        row.pack(fill="x")
        avatar(row, KIND_ICON.get(dev.kind, "❔"), color, 46, bg=CARD).pack(side="left", padx=(0, 14))

        right = tk.Frame(row, bg=CARD)
        right.pack(side="right")
        mid = tk.Frame(row, bg=CARD)
        mid.pack(side="left", fill="x", expand=True)

        top = tk.Frame(mid, bg=CARD)
        top.pack(anchor="w", fill="x")
        tk.Label(top, text=info["label"] or self._default_name(dev), bg=CARD, fg=TEXT,
                 font=font(11, "bold")).pack(side="left")
        if dev.this_pc:
            chip(top, "THIS PC", ACCENT, bg=CARD).pack(side="left", padx=(8, 0))
        if is_admin:
            chip(top, "ADMIN", GOOD, bg=CARD).pack(side="left", padx=(6, 0))
        if dev.router:
            chip(top, "ROUTER", PURPLE, bg=CARD).pack(side="left", padx=(8, 0))

        meta = tk.Frame(mid, bg=CARD)
        meta.pack(anchor="w", fill="x", pady=(5, 0))
        if not dev.router:
            prof = tk.Label(meta, text=f"{PROFILE_LABELS[info['profile']]}  ▾", bg=mix(color, CARD, 0.82),
                            fg=color, font=font(8, "bold"), padx=8, pady=1, cursor="hand2")
            prof.pack(side="left", padx=(0, 10))
            prof.bind("<Button-1>", lambda e, d=dev: self._profile_menu(e, d))
        tk.Label(meta, text=f"{dev.ip}   {dev.mac.upper()}", bg=CARD, fg=FAINT, font=MONO).pack(side="left")
        if not dev.router:
            rn = tk.Label(meta, text="✎ Rename", bg=CARD, fg=MUTED, font=font(8), cursor="hand2")
            rn.pack(side="left", padx=(12, 0))
            rn.bind("<Enter>", lambda e: rn.configure(fg=ACCENT))
            rn.bind("<Leave>", lambda e: rn.configure(fg=MUTED))
            rn.bind("<Button-1>", lambda e, d=dev: self._rename(d))

        if dev.router:
            return
        paused = info["paused"]
        busy = self.action == "pause:" + dev.mac
        state = tk.Frame(right, bg=CARD)
        state.pack(side="left", padx=(0, 14))
        chip(state, "PAUSED" if paused else "● ONLINE", WARN if paused else GOOD, bg=CARD).pack(anchor="e")
        if not dev.this_pc:
            tk.Label(state, text="managed at router", bg=CARD, fg=FAINT, font=font(7)).pack(anchor="e", pady=(3, 0))
        Pill(right, "Working…" if busy else ("▶  Resume" if paused else "Pause"),
             lambda: self._toggle_pause(dev, is_admin), kind="good" if paused else "ghost", size=9,
             disabled=busy).pack(side="left")

    def _profile_menu(self, event, dev):
        menu = tk.Menu(self, tearoff=0, bg=CARD_HI, fg=TEXT, activebackground=ACCENT, activeforeground="#ffffff",
                       bd=0, font=font(10))
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
        head = tk.Frame(body, bg=CARD)
        head.pack(fill="x")
        avatar(head, "🛡", PURPLE, 44, bg=CARD).pack(side="left", padx=(0, 14))
        Pill(head, "Applying…" if self.action == "block" else "Apply blocking", self._apply_blocking,
             disabled=self.action == "block").pack(side="right")
        col = tk.Frame(head, bg=CARD)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, text="Website blocking", bg=CARD, fg=TEXT, font=font(13, "bold"), anchor="w").pack(anchor="w")
        active = control.active_blocklist()
        tk.Label(col, text=(f"{len(active)} sites blocked on this PC right now" if control.enforce_on() and active
                            else "Choose what to block, then apply it to this PC"),
                 bg=CARD, fg=MUTED, font=font(9), anchor="w").pack(anchor="w")
        tk.Frame(body, bg=BORDER, height=1).pack(fill="x", pady=16)
        row = tk.Frame(body, bg=CARD)
        row.pack(fill="x")
        Toggle(row, on=control.enforce_setting(), command=lambda on: control.set_enforce(on)).pack(side="right")
        tk.Label(row, text="Keep blocks enforced", bg=CARD, fg=TEXT, font=font(10, "bold"),
                 anchor="w").pack(anchor="w")
        tk.Label(row, text="Checks every few minutes and puts the blocks back if something removes them.",
                 bg=CARD, fg=MUTED, font=font(9), anchor="w").pack(anchor="w")

        self._section(parent, "Categories")
        grid = tk.Frame(parent, bg=BG)
        grid.pack(fill="x")
        cats = set(conf.get("categories", []))
        for i, key in enumerate(control.CATEGORIES):
            emoji, label, blurb = CATEGORIES.get(key, ("•", key, ""))
            grid.columnconfigure(i % 2, weight=1, uniform="cat")
            card = Card(grid, pad=16)
            card.grid(row=i // 2, column=i % 2, sticky="nsew", padx=6, pady=(0, 12))
            r = tk.Frame(card.body, bg=CARD)
            r.pack(fill="x")
            avatar(r, emoji, PURPLE, 38, bg=CARD).pack(side="left", padx=(0, 12))
            Toggle(r, on=key in cats,
                   command=lambda on, k=key: control.toggle_category(nid, k, on)).pack(side="right")
            c = tk.Frame(r, bg=CARD)
            c.pack(side="left", fill="x", expand=True)
            tk.Label(c, text=label, bg=CARD, fg=TEXT, font=font(10, "bold"), anchor="w").pack(anchor="w")
            tk.Label(c, text=f"{blurb}  ·  {len(control.CATEGORIES[key])} sites", bg=CARD, fg=MUTED,
                     font=font(8), anchor="w").pack(anchor="w")

        self._section(parent, "Your blocked sites", pady=(6, 10))
        body = self._card(parent, pad=18)
        add = tk.Frame(body, bg=CARD)
        add.pack(fill="x")
        entry_wrap = tk.Frame(add, bg=BORDER, padx=1, pady=1)
        entry_wrap.pack(side="left", fill="x", expand=True, padx=(0, 10))
        entry = tk.Entry(entry_wrap, bg=CARD_HI, fg=FAINT, insertbackground=TEXT, relief="flat", font=font(10),
                         highlightthickness=0, bd=8)
        entry.pack(fill="x")
        placeholder = "Type a website, like example.com"
        entry.insert(0, placeholder)

        def focus_in(_e):
            if entry.get() == placeholder:
                entry.delete(0, "end")
                entry.configure(fg=TEXT)
            entry_wrap.configure(bg=ACCENT)

        def focus_out(_e):
            if not entry.get():
                entry.insert(0, placeholder)
                entry.configure(fg=FAINT)
            entry_wrap.configure(bg=BORDER)

        def submit(_e=None):
            text = entry.get()
            if text and text != placeholder:
                self._add_site(text)

        entry.bind("<FocusIn>", focus_in)
        entry.bind("<FocusOut>", focus_out)
        entry.bind("<Return>", submit)
        Pill(add, "+  Add", submit, size=9).pack(side="left")

        sites = conf.get("sites", [])
        if not sites:
            tk.Label(body, text="No extra sites yet.", bg=CARD, fg=FAINT, font=font(9)).pack(anchor="w",
                                                                                          pady=(14, 0))
        for domain in sites:
            srow = tk.Frame(body, bg=CARD_HI)
            srow.pack(fill="x", pady=(10, 0))
            tk.Label(srow, text="⛔", bg=CARD_HI, fg=BAD, font=(EMOJI, 10)).pack(side="left", padx=(12, 8), pady=8)
            tk.Label(srow, text=domain, bg=CARD_HI, fg=TEXT, font=font(10)).pack(side="left")
            rm = tk.Label(srow, text="Remove", bg=CARD_HI, fg=MUTED, font=font(9), cursor="hand2")
            rm.pack(side="right", padx=12)
            rm.bind("<Enter>", lambda e, w=rm: w.configure(fg=BAD))
            rm.bind("<Leave>", lambda e, w=rm: w.configure(fg=MUTED))
            rm.bind("<Button-1>", lambda e, d=domain: self._remove_site(d))
        tk.Label(parent, text="Changes take effect on this PC when you press Apply blocking. Other devices keep "
                              "this as a plan for your router.", bg=BG, fg=FAINT, font=font(8),
                 wraplength=700, justify="left").pack(anchor="w", padx=8, pady=(4, 8))

    # ============================================================ access
    def _page_access(self, parent):
        on = control.has_pin()
        body = self._card(parent, pad=24)
        head = tk.Frame(body, bg=CARD)
        head.pack(fill="x")
        avatar(head, "🔒", GOOD if on else MUTED, 56, bg=CARD).pack(side="left", padx=(0, 16))
        col = tk.Frame(head, bg=CARD)
        col.pack(side="left", fill="x", expand=True)
        t = tk.Frame(col, bg=CARD)
        t.pack(anchor="w")
        tk.Label(t, text="Admin PIN", bg=CARD, fg=TEXT, font=font(14, "bold")).pack(side="left")
        chip(t, "ON" if on else "OFF", GOOD if on else MUTED, bg=CARD).pack(side="left", padx=(10, 0))
        tk.Label(col, text=("Once set, pausing or resuming the admin device needs the PIN — so no one else can keep "
                            "you offline, and you can always turn your own internet back on."),
                 bg=CARD, fg=MUTED, font=font(9), justify="left", wraplength=560, anchor="w").pack(anchor="w",
                                                                                                  pady=(4, 0))
        btns = tk.Frame(body, bg=CARD)
        btns.pack(anchor="w", pady=(18, 0), padx=(72, 0))
        if on:
            Pill(btns, "Change PIN", self._change_pin, kind="ghost", size=9).pack(side="left")
            Pill(btns, "Remove PIN", self._remove_pin, kind="danger", size=9).pack(side="left", padx=(10, 0))
        else:
            Pill(btns, "Set admin PIN", self._set_pin, size=9).pack(side="left")

        self._section(parent, "Admin device")
        body = self._card(parent)
        admin = None
        if self.result:
            admin = next((d for d in self.result.devices if control.is_admin_device(self._nid(), d.mac)), None)
        if admin:
            row = tk.Frame(body, bg=CARD)
            row.pack(fill="x")
            avatar(row, KIND_ICON.get(admin.kind, "❔"), ACCENT, 40, bg=CARD).pack(side="left", padx=(0, 14))
            c = tk.Frame(row, bg=CARD)
            c.pack(side="left")
            tk.Label(c, text=control.device(self._nid(), admin.mac)["label"] or self._default_name(admin), bg=CARD,
                     fg=TEXT, font=font(10, "bold")).pack(anchor="w")
            tk.Label(c, text="Set a device's profile to “Me” to make it the admin device.", bg=CARD, fg=MUTED,
                     font=font(8)).pack(anchor="w")
        else:
            tk.Label(body, text="Scan your network — this PC becomes the admin device automatically.", bg=CARD,
                     fg=MUTED, font=font(9)).pack(anchor="w")

        self._section(parent, "Help")
        body = self._card(parent)
        tk.Label(body, text="If something goes wrong, details are saved to:", bg=CARD, fg=MUTED,
                 font=font(9)).pack(anchor="w")
        tk.Label(body, text=str(settings.CRASH_LOG), bg=CARD, fg=TEXT, font=MONO, wraplength=640, justify="left",
                 anchor="w").pack(anchor="w", pady=(4, 0))

    # ============================================================ actions
    def _set_pin(self):
        pin = simpledialog.askstring(APP_NAME, "Choose an admin PIN:", show="•", parent=self)
        if pin and pin.strip():
            again = simpledialog.askstring(APP_NAME, "Enter the PIN again:", show="•", parent=self)
            if again != pin:
                messagebox.showwarning(APP_NAME, "The PINs did not match. Nothing was changed.", parent=self)
                return
            control.set_pin(pin.strip())
            self._set_status("Admin PIN set.", "good")
            self._rerender()

    def _change_pin(self):
        if self._ask_pin():
            self._set_pin()

    def _remove_pin(self):
        if self._ask_pin():
            control.clear_pin()
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
        want = not control.device(nid, dev.mac)["paused"]
        if is_admin and not self._ask_pin():
            return
        if dev.this_pc:
            def apply(nid=nid, mac=dev.mac, pause=want):
                control.enforce_this_pc(pause)
                control.set_paused(nid, mac, pause)
            self._run("pause:" + dev.mac, apply, "This PC's internet " + ("paused." if want else "resumed."))
        else:
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
                        if str(payload) == "no_network":
                            self.status_text = "No network found — connect to Wi‑Fi and try again."
                        else:
                            self.status_text = f"Scan failed: {payload}"
                        self.status_kind = "bad"
                    else:
                        self.result = payload
                        self._learn_admin(payload)
                        self.status_text = f"Found {len(payload.devices)} devices on {payload.network}."
                        self.status_kind = "good"
                    self._render()
                elif kind == "done":
                    label, error, msg = payload
                    self.action = None
                    if error:
                        self.status_text, self.status_kind = f"Couldn't finish: {error}", "bad"
                    else:
                        self.status_text, self.status_kind = msg, "good"
                    self._render()
                elif kind == "note":
                    self._set_status(*payload)
        except queue.Empty:
            pass
        except Exception:
            settings.log_crash("pump", traceback.format_exc())
        if self.busy:  # pulse the status dot while scanning
            self._pulse += 1
            t = (self._pulse % 10) / 10
            self.s_dot.itemconfigure("dot", fill=mix(ACCENT, BG, abs(0.5 - t) * 1.4))
        try:
            self.after(150, self._pump)
        except tk.TclError:
            pass

    def _learn_admin(self, result):
        conf = control.net_config(result.network_id)[1]
        if not conf.get("admin_mac"):
            for dev in result.devices:
                if dev.this_pc:
                    control.set_admin_device(result.network_id, dev.mac)
                    break


def run():
    App().mainloop()
