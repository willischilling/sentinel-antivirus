"""Wi-Fi devices page: every device on the home network with its maker, new
ones highlighted, a few router checks, and the switch for new-device alerts.
The scan runs on a worker thread.
"""
import threading
import tkinter as tk
from tkinter import ttk

import theme as C
from core import netscan, settings
from core.i18n import number, t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from tools_page import subpage_header, wrap_to_width
from widgets import Ring, RoundedCard, ScrollArea, ToggleSwitch, icon_label, pill

KIND_ICONS = {"router": "globe", "computer": "apps", "phone": "usb", "apple": "usb", "console": "game",
              "tv": "web", "printer": "download", "speaker": "health", "camera": "scan", "smart": "power"}


def new_state() -> dict:
    return {"result": None, "busy": False, "error": None}


class NetworkPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        self.state = app.net_state
        subpage_header(self, app, t("net_title"), t("net_sub"), "nav_tools", "tools")
        self.body = tk.Frame(self, bg=C.BG)
        self.body.pack(fill="both", expand=True)
        self._render()

    def scan(self):
        s = self.state
        if s["busy"]:
            return
        s.update(busy=True, error=None)
        queue = self.app.event_queue

        def run():
            try:
                queue.put(("net_done", netscan.scan()))
            except Exception as e:
                queue.put(("net_done", e))

        threading.Thread(target=run, daemon=True).start()
        if self.winfo_exists():
            self._render()

    def handle(self, kind, payload):
        s = self.state
        s["busy"] = False
        if isinstance(payload, Exception):
            s["error"] = t("net_offline") if str(payload) == "no_network" else str(payload)
        else:
            s["result"] = payload
        if self.winfo_exists():
            self._render()
        self.app.tools_page.handle(kind, payload)

    def _render(self):
        for child in self.body.winfo_children():
            child.destroy()
        s = self.state
        result = s["result"]

        top = RoundedCard(self.body, radius=16, padx=24, pady=16)
        top.pack(fill="x")
        row = tk.Frame(top.body, bg=C.CARD)
        row.pack(fill="x")
        ring = Ring(row, size=64)
        ring.pack(side="left", padx=(0, 18))
        again = ttk.Button(row, text=t("net_scan_again") if result else t("net_scan"), style="Accent.TButton",
                           command=self.scan)
        again.pack(side="right", anchor="n", padx=(12, 0))
        if s["busy"]:
            again.state(["disabled"])
        col = tk.Frame(row, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        if s["busy"]:
            ring.spin("")
            title, sub = t("net_scanning"), t("net_scanning_sub")
        elif result is None:
            ring.show(C.BORDER, glyph="globe", glyph_color=C.TEXT_MUTED)
            title, sub = t("net_ready"), t("net_ready_sub")
        else:
            new = sum(1 for d in result.devices if d.new)
            color = C.WARN if new or result.router_issues else C.GOOD
            ring.show(color, glyph="globe", glyph_color=color)
            title = t("net_found", n=number(len(result.devices)))
            sub = t("net_found_sub", network=result.network) + (" " + t("net_new_count", n=number(new)) if new else "")
        tk.Label(col, text=title, font=FONT_LARGE, fg=C.TEXT, bg=C.CARD, anchor="w").pack(anchor="w", fill="x")
        sub_label = tk.Label(col, text=sub, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left", anchor="w")
        sub_label.pack(anchor="w", fill="x")
        wrap_to_width(sub_label, col)
        if s["error"]:
            tk.Label(top.body, text=s["error"], font=FONT_SMALL, fg=C.BAD, bg=C.CARD, wraplength=640,
                     justify="left").pack(anchor="w", pady=(8, 0))
        alerts = tk.Frame(top.body, bg=C.CARD)
        alerts.pack(fill="x", pady=(10, 0))
        ToggleSwitch(alerts, command=self._toggle_alerts, on=netscan.alerts_on()).pack(side="right")
        tk.Label(alerts, text=t("net_alerts"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(side="left")

        card = RoundedCard(self.body, radius=16, padx=18, pady=12)
        card.pack(fill="both", expand=True, pady=(14, 0))
        area = ScrollArea(card.body)
        area.pack(fill="both", expand=True)
        if result:
            for key in result.router_issues:
                issue = tk.Frame(area.inner, bg=C.CARD)
                issue.pack(fill="x", pady=(2, 6), padx=(0, 8))
                icon_label(issue, "warning", 13, fg=C.WARN).pack(side="left", anchor="n", padx=(4, 12), pady=2)
                col = tk.Frame(issue, bg=C.CARD)
                col.pack(side="left", fill="x", expand=True)
                tk.Label(col, text=t(key), font=FONT_BOLD, fg=C.WARN, bg=C.CARD, anchor="w").pack(anchor="w")
                desc = tk.Label(col, text=t(key + "_desc"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD,
                                justify="left", anchor="w")
                desc.pack(anchor="w", fill="x")
                wrap_to_width(desc, col, 200)
            if result.router_issues:
                tk.Frame(area.inner, bg=C.BORDER, height=1).pack(fill="x", padx=(0, 8), pady=(0, 4))
            for dev in result.devices:
                self._device_row(area.inner, dev)
        elif not s["busy"]:
            tk.Label(area.inner, text=t("net_privacy_note"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD,
                     wraplength=560, justify="left").pack(anchor="w", pady=10)

    def _device_row(self, parent, dev):
        row = tk.Frame(parent, bg=C.CARD)
        row.pack(fill="x", pady=4, padx=(0, 8))
        icon_label(row, KIND_ICONS.get(dev.kind, "info"), 14,
                   fg=C.ACCENT if not dev.new else C.WARN).pack(side="left", padx=(4, 14))
        tk.Label(row, text=dev.ip, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(side="right")
        text = tk.Frame(row, bg=C.CARD)
        text.pack(side="left", fill="x", expand=True)
        head = tk.Frame(text, bg=C.CARD)
        head.pack(anchor="w")
        if dev.router:
            title = t("net_router")
        elif dev.this_pc:
            title = t("net_this_pc")
        else:
            title = dev.name or dev.maker or (t("net_private_device") if dev.private_mac else t("net_unknown_device"))
        tk.Label(head, text=title, font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left")
        if dev.new:
            pill(head, t("net_new"), C.WARN).pack(side="left", padx=(8, 0))
        details = [t(f"net_kind_{dev.kind}")]
        if dev.maker and dev.maker != title:
            details.append(dev.maker)
        if dev.name and dev.name != title:
            details.append(dev.name)
        details.append(dev.mac.upper())
        tk.Label(text, text="  ·  ".join(details), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, anchor="w").pack(
            anchor="w")

    def _toggle_alerts(self):
        settings.save(network_alerts=not netscan.alerts_on())  # the background agent reads it
        self._render()
