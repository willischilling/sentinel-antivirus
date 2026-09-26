"""The VPN tab: one card with an on/off switch, the server's country, a
world map with a pin, and this PC's public IP; plus the one-time setup
(free Proton VPN account -> WireGuard config file -> import).

All slow work (sc.exe, downloads, IP lookups, the admin prompt) runs on
worker threads and reports back through the app's event queue.
"""
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk

import theme as C
from core import paths, settings, vpn
from core.i18n import t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from widgets import RoundedCard, ToggleSwitch, icon_label

MAP_W, MAP_H = 300, 120
LAT_TOP, LAT_SPAN = 75.0, 131.0  # the dot grid covers 75N..56S


def render_map(lat=None, lon=None, width=MAP_W, height=MAP_H):
    """Dotted world map in the theme's colors, with a pin at lat/lon."""
    from PIL import Image, ImageDraw, ImageTk

    mask = Image.open(paths.resource("assets/world_dots.png")).convert("1")
    cols, rows = mask.size
    scale = 3
    img = Image.new("RGB", (width * scale, height * scale), C.CARD)
    d = ImageDraw.Draw(img)
    cw, ch = width * scale / cols, height * scale / rows
    r = min(cw, ch) * 0.36
    dot = _mix(C.TEXT_MUTED, C.CARD, 0.42)
    for y in range(rows):
        for x in range(cols):
            if mask.getpixel((x, y)):
                cx, cy = (x + .5) * cw, (y + .5) * ch
                d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=dot)
    if lat is not None and lon is not None:
        px = (lon + 180) / 360 * width * scale
        py = (LAT_TOP - lat) / LAT_SPAN * height * scale
        for radius, color in ((22, _mix(C.ACCENT, C.CARD, 0.25)), (13, C.ACCENT), (5, C.CARD)):
            d.ellipse((px - radius, py - radius, px + radius, py + radius), fill=color)
    return ImageTk.PhotoImage(img.resize((width, height), Image.LANCZOS))


def _mix(a, b, amount):
    """a blended toward b; amount is how much of a remains."""
    ca = [int(a[i:i + 2], 16) for i in (1, 3, 5)]
    cb = [int(b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x * amount + y * (1 - amount)):02x}" for x, y in zip(ca, cb))


class VpnPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        self.state = app.vpn_state  # survives page rebuilds
        tk.Label(self, text=t("nav_vpn"), font=("Segoe UI Semibold", 18), fg=C.TEXT, bg=C.BG).pack(anchor="w")
        tk.Label(self, text=t("vpn_sub"), font=FONT, fg=C.TEXT_MUTED, bg=C.BG).pack(anchor="w", pady=(2, 18))
        self._build_main_card()
        self.lower = tk.Frame(self, bg=C.BG)
        self.lower.pack(fill="both", expand=True, pady=(16, 0))
        self._render()
        self.refresh(ip=True)

    # ---------------------------------------------------------- main card --
    def _build_main_card(self):
        card = RoundedCard(self, radius=16, padx=24, pady=20)
        card.pack(fill="x")
        body = card.body
        body.columnconfigure(0, weight=1)

        top = tk.Frame(body, bg=C.CARD)
        top.grid(row=0, column=0, sticky="ew")
        badge = tk.Frame(top, bg=C.BORDER, width=48, height=48)
        badge.pack(side="left", padx=(0, 14))
        badge.pack_propagate(False)
        self.badge_icon = icon_label(badge, "globe", 18, fg=C.TEXT_MUTED, bg=C.BORDER)
        self.badge_icon.place(relx=.5, rely=.5, anchor="center")
        col = tk.Frame(top, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, text=t("vpn_title"), font=FONT_LARGE, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        tk.Label(col, text=t("vpn_activity_is"), font=FONT, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        self.status_word = tk.Label(col, text="", font=FONT_BOLD, fg=C.BAD, bg=C.CARD)
        self.status_word.pack(anchor="w")
        switch_col = tk.Frame(top, bg=C.CARD)
        switch_col.pack(side="right", anchor="n")
        self.switch = ToggleSwitch(switch_col, command=self._toggle)
        self.switch.pack(side="left")
        self.switch_label = tk.Label(switch_col, text="", font=FONT_BOLD, fg=C.TEXT_MUTED, bg=C.CARD, width=4)
        self.switch_label.pack(side="left", padx=(8, 0))

        mid = tk.Frame(body, bg=C.CARD)
        mid.grid(row=1, column=0, sticky="ew", pady=(18, 0))
        loc = RoundedCard(mid, bg=C.BG, outer=C.CARD, radius=12, padx=14, pady=10)
        loc.pack(side="left", anchor="n")
        self.country_pill = tk.Label(loc.body, text="", font=("Segoe UI Semibold", 9), bg=C.ACCENT_DARK,
                                     fg=C.ON_ACCENT, padx=7, pady=2)
        self.country_pill.pack(side="left", padx=(0, 10))
        self.server_label = tk.Label(loc.body, text="", font=FONT_BOLD, fg=C.TEXT, bg=C.BG)
        self.server_label.pack(side="left")
        self.change_link = tk.Label(loc.body, text=t("vpn_change"), font=FONT, fg=C.ACCENT, bg=C.BG,
                                    cursor="hand2")
        self.change_link.pack(side="left", padx=(24, 0))
        self.change_link.bind("<Button-1>", lambda e: self._import())
        self.map_label = tk.Label(mid, bg=C.CARD, bd=0)
        self.map_label.pack(side="right")

        self.ip_label = tk.Label(body, text="", font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD)
        self.ip_label.grid(row=2, column=0, sticky="w", pady=(10, 0))

    # ------------------------------------------------------------- render --
    def _render(self):
        s, info = self.state, self._configured()
        status = s["status"]
        connected = status == "running"
        busy = s["busy"] or status in ("starting", "stopping")
        words = {"running": ("vpn_protected", C.GOOD), "starting": ("vpn_connecting", C.TEXT_MUTED),
                 "stopping": ("vpn_disconnecting", C.TEXT_MUTED)}
        key, color = words.get(status, ("vpn_exposed", C.BAD))
        if s["busy"] and s["busy_text"]:
            key, color = s["busy_text"], C.TEXT_MUTED
        self.status_word.configure(text=t(key, **s.get("busy_values", {})), fg=color)
        self.switch.set(connected or status == "starting")
        self.switch.set_enabled(not busy)
        self.switch_label.configure(text=(t("on") if connected else t("off")).upper(),
                                    fg=C.GOOD if connected else C.TEXT_MUTED)
        self.badge_icon.configure(fg=C.GOOD if connected else C.TEXT_MUTED)

        if info:
            self.country_pill.configure(text=info.get("country") or "VPN")
            self.country_pill.pack(side="left", padx=(0, 10), before=self.server_label)
            self.server_label.configure(text=info.get("city") and f"{info['city']} · {info['server']}"
                                        or info.get("server", ""))
            self.change_link.configure(text=t("vpn_change"))
        else:
            self.country_pill.pack_forget()
            self.server_label.configure(text=t("vpn_no_server"))
            self.change_link.configure(text=t("vpn_import"))
        self._map_img = render_map(info.get("lat"), info.get("lon"))
        self.map_label.configure(image=self._map_img)

        ip = s["ip"]
        if ip:
            where = ", ".join(x for x in (ip.get("city"), ip.get("country")) if x)
            self.ip_label.configure(text=t("vpn_ip", ip=ip["ip"], where=where))
        else:
            self.ip_label.configure(text=t("vpn_ip_unknown"))
        self._render_lower(bool(info))

    def _render_lower(self, configured):
        for child in self.lower.winfo_children():
            child.destroy()
        card = RoundedCard(self.lower, radius=16, padx=24, pady=18)
        card.pack(fill="x")
        body = card.body
        if s_error := self.state["error"]:
            tk.Label(body, text=s_error, font=FONT_SMALL, fg=C.BAD, bg=C.CARD, wraplength=640,
                     justify="left").pack(anchor="w", pady=(0, 10))
        if not configured:
            tk.Label(body, text=t("vpn_setup_title"), font=FONT_LARGE, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
            tk.Label(body, text=t("vpn_setup_desc"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, wraplength=640,
                     justify="left").pack(anchor="w", pady=(2, 10))
            steps = [("vpn_step1", "vpn_step1_btn", lambda: webbrowser.open(vpn.PROTON_SIGNUP)),
                     ("vpn_step2", "vpn_step2_btn", lambda: webbrowser.open(vpn.PROTON_DOWNLOADS)),
                     ("vpn_step3", "vpn_import", self._import)]
            for n, (text_key, btn_key, command) in enumerate(steps, 1):
                row = tk.Frame(body, bg=C.CARD)
                row.pack(fill="x", pady=4)
                tk.Label(row, text=f"{n}", font=FONT_BOLD, fg=C.ACCENT, bg=C.CARD, width=2).pack(side="left")
                tk.Label(row, text=t(text_key), font=FONT, fg=C.TEXT, bg=C.CARD, wraplength=440,
                         justify="left").pack(side="left", padx=(4, 10))
                style = "Accent.TButton" if n == 3 else "Ghost.TButton"
                btn = ttk.Button(row, text=t(btn_key), style=style, command=command)
                btn.pack(side="right")
                if self.state["busy"]:
                    btn.state(["disabled"])
        else:
            row = tk.Frame(body, bg=C.CARD)
            row.pack(fill="x")
            icon_label(row, "info", 14, fg=C.TEXT_MUTED).pack(side="left", padx=(0, 10), anchor="n")
            tk.Label(row, text=t("vpn_about"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, wraplength=520,
                     justify="left", anchor="w").pack(side="left", fill="x", expand=True)
            remove = ttk.Button(row, text=t("vpn_remove"), style="Danger.TButton", command=self._remove)
            remove.pack(side="right")
            if self.state["busy"]:
                remove.state(["disabled"])

    def _configured(self) -> dict:
        """The saved server info, if the tunnel really exists. If it was removed outside
        Sentinel (Windows reset, WireGuard uninstalled...), setup is shown again."""
        info = settings.load().get("vpn") or {}
        return {} if self.state["status"] == "not_setup" else info

    # ------------------------------------------------------------ actions --
    def _toggle(self):
        if not self._configured():
            self._import()
            return
        turning_on = self.state["status"] != "running"
        self._work("vpn_connecting" if turning_on else "vpn_disconnecting",
                   vpn.connect if turning_on else vpn.disconnect, refresh_ip=True)

    def _import(self):
        if self.state["busy"]:
            return
        path = filedialog.askopenfilename(title=t("vpn_import"), filetypes=[(t("vpn_conf_files"), "*.conf"),
                                                                            ("*", "*.*")])
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                config = vpn.parse_config(f.read(), path)
        except (OSError, UnicodeDecodeError, ValueError) as e:
            messagebox.showerror("Sentinel", t("vpn_bad_conf", error=e))
            return
        if not config.full_tunnel and not messagebox.askyesno("Sentinel", t("vpn_split_warning")):
            return
        queue = self.app.event_queue

        def job():
            msi = None
            if not vpn.wireguard_installed():
                queue.put(("vpn_busy", ("vpn_getting_wireguard", {})))
                msi = vpn.download_wireguard()
            queue.put(("vpn_busy", ("vpn_waiting_admin", {})))
            server = vpn.ip_info(config.host) or {}
            vpn.setup(config, msi)
            if msi:
                msi.unlink(missing_ok=True)
            settings.save(vpn={"server": config.server, "country": config.country or server.get("country_code"),
                               "city": server.get("city"), "lat": server.get("latitude"),
                               "lon": server.get("longitude"), "endpoint": config.endpoint})

        self._work("vpn_setting_up", job, refresh_ip=True)

    def _remove(self):
        if not messagebox.askyesno("Sentinel", t("vpn_remove_confirm")):
            return

        def job():
            vpn.remove()
            settings.save(vpn=None)

        self._work("vpn_removing", job, refresh_ip=True)

    def _work(self, busy_text, job, refresh_ip=False):
        s = self.state
        s.update(busy=True, busy_text=busy_text, busy_values={}, error=None)
        self._render()
        queue = self.app.event_queue

        def run():
            try:
                job()
                queue.put(("vpn_done", None))
            except Exception as e:  # shown on the page; the switch goes back to the real state
                queue.put(("vpn_done", str(e)))
            if refresh_ip:
                queue.put(("vpn_status", _settled_status()))
                time.sleep(1.5)  # let the new routes take effect, or the lookup sees the old IP
                queue.put(("vpn_ip", vpn.ip_info()))

        threading.Thread(target=run, daemon=True).start()

    def refresh(self, ip=False):
        """Re-reads the tunnel status (and the public IP) in the background."""
        queue = self.app.event_queue

        def run():
            queue.put(("vpn_status", vpn.status()))
            if ip:
                queue.put(("vpn_ip", vpn.ip_info()))

        threading.Thread(target=run, daemon=True).start()

    # --------------------------------------------------- events from queue --
    def handle(self, kind, payload):
        s = self.state
        if kind == "vpn_status":
            changed = payload != s["status"]
            s["status"] = payload
            if changed and payload in ("running", "stopped", "not_setup") and not s["busy"]:
                # The IP changes with the tunnel (e.g. switched from the tray or WireGuard's own app).
                self.after(2000, lambda: self.winfo_exists() and self.refresh(ip=True))
        elif kind == "vpn_ip":
            s["ip"] = payload
        elif kind == "vpn_busy":
            s["busy_text"], s["busy_values"] = payload
        elif kind == "vpn_done":
            s.update(busy=False, busy_text=None, error=t("vpn_failed", error=payload) if payload else None)
        if self.winfo_exists():
            self._render()


def _settled_status(timeout=15) -> str:
    """The tunnel status once it has finished starting or stopping."""
    end = time.monotonic() + timeout
    status = vpn.status()
    while status in ("starting", "stopping") and time.monotonic() < end:
        time.sleep(0.3)
        status = vpn.status()
    return status


def new_state() -> dict:
    return {"status": None, "ip": None, "busy": False, "busy_text": None, "busy_values": {}, "error": None}
