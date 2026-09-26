"""The Web Protection tab: an on/off switch for DNS filtering, the filter
level, which network adapters use it, and a live "is it working" test.
Slow work (PowerShell, the admin prompt, the test lookup) runs on worker
threads and reports back through the app's event queue.
"""
import threading
import tkinter as tk
from tkinter import ttk

import theme as C
from core import vpn, webprotect
from core.i18n import t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from widgets import Ring, RoundedCard, ToggleSwitch, icon_label, pill


def new_state() -> dict:
    return {"status": None, "busy": False, "error": None, "level": "standard", "test": None}


class WebProtectPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        self.state = app.web_state
        tk.Label(self, text=t("nav_web"), font=(C.DISPLAY, 18), fg=C.TEXT, bg=C.BG).pack(anchor="w")
        tk.Label(self, text=t("web_sub"), font=FONT, fg=C.TEXT_MUTED, bg=C.BG).pack(anchor="w", pady=(2, 18))
        self.body = tk.Frame(self, bg=C.BG)
        self.body.pack(fill="both", expand=True)
        self._render()

    def _render(self):
        for child in self.body.winfo_children():
            child.destroy()
        s = self.state
        st: webprotect.WebStatus | None = s["status"]
        on = bool(st and st.on)
        busy = s["busy"] or st is None

        main = RoundedCard(self.body, radius=16, padx=24, pady=20)
        main.pack(fill="x")
        top = tk.Frame(main.body, bg=C.CARD)
        top.pack(fill="x")
        ring = Ring(top, size=76)
        ring.pack(side="left", padx=(0, 18))
        ring.show(C.GOOD if on else C.BORDER, glyph="web", glyph_color=C.GOOD if on else C.TEXT_MUTED)
        col = tk.Frame(top, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        title = t("web_on") if on else t("web_off")
        tk.Label(col, text=title, font=FONT_LARGE, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        if st is None:
            sub = t("fw_reading")
        elif s["busy"]:
            sub = t("fw_working")
        elif on:
            sub = t(f"web_level_{st.level}_on")
        else:
            sub = t("web_off_desc")
        tk.Label(col, text=sub, font=FONT, fg=C.TEXT_MUTED, bg=C.CARD, wraplength=420,
                 justify="left").pack(anchor="w")
        switch = ToggleSwitch(top, command=self._toggle, on=on)
        switch.pack(side="right", anchor="n")
        switch.set_enabled(not busy)
        if s["error"]:
            tk.Label(main.body, text=t("fw_failed", error=s["error"]), font=FONT_SMALL, fg=C.BAD, bg=C.CARD,
                     wraplength=640, justify="left").pack(anchor="w", pady=(12, 0))

        levels = RoundedCard(self.body, radius=16, padx=24, pady=18)
        levels.pack(fill="x", pady=(14, 0))
        tk.Label(levels.body, text=t("web_level"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        tiles = tk.Frame(levels.body, bg=C.CARD)
        tiles.pack(fill="x", pady=(10, 0))
        chosen = st.level if on else s["level"]
        for i, level in enumerate(webprotect.LEVELS):
            tiles.columnconfigure(i, weight=1, uniform="lvl")
            selected = level == chosen
            bg = C.ACCENT_DARK if selected else C.BORDER
            tile = RoundedCard(tiles, bg=bg, outer=C.CARD, radius=10, padx=14, pady=12,
                               hover_bg=None if busy or selected else C.CARD_HOVER,
                               command=None if busy or selected else lambda lv=level: self._pick_level(lv))
            tile.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            fg = C.ON_ACCENT if selected else C.TEXT
            tk.Label(tile.body, text=t(f"web_level_{level}"), font=FONT_BOLD, fg=fg, bg=bg).pack(anchor="w")
            tk.Label(tile.body, text=t(f"web_level_{level}_desc"), font=FONT_SMALL, bg=bg, wraplength=300,
                     justify="left", fg=C.ON_ACCENT if selected else C.TEXT_MUTED).pack(anchor="w")

        info = RoundedCard(self.body, radius=16, padx=24, pady=16)
        info.pack(fill="x", pady=(14, 0))
        if st and st.adapters:
            row = tk.Frame(info.body, bg=C.CARD)
            row.pack(fill="x")
            tk.Label(row, text=t("web_adapters"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left")
            for adapter in st.adapters:
                uses = on and bool(set(adapter.servers) & set(webprotect.LEVELS[st.level]["v4"]))
                color = C.GOOD if uses else (C.WARN if on and adapter.up else C.BORDER)
                pill(row, adapter.name, color, fg="#0b1120" if uses or (on and adapter.up) else C.TEXT_MUTED
                     ).pack(side="left", padx=(8, 0))
            if on and st.missing:
                again = ttk.Button(row, text=t("web_apply_again"), style="Ghost.TButton",
                                   command=lambda: self._change(lambda: webprotect.enable(st.level)))
                again.pack(side="right")
        test_row = tk.Frame(info.body, bg=C.CARD)
        test_row.pack(fill="x", pady=(10, 0))
        test_btn = ttk.Button(test_row, text=t("web_test"), style="Ghost.TButton", command=self._test)
        test_btn.pack(side="left")
        if not on or busy:
            test_btn.state(["disabled"])
        result = s["test"]
        if result is not None:
            text, color = (t("web_test_ok"), C.GOOD) if result else (t("web_test_fail"), C.WARN)
            tk.Label(test_row, text=text, font=FONT, fg=color, bg=C.CARD, wraplength=460,
                     justify="left").pack(side="left", padx=(12, 0))
        note = t("web_note")
        if vpn.status() == "running":
            note = t("web_vpn_note") + " " + note
        row = tk.Frame(info.body, bg=C.CARD)
        row.pack(fill="x", pady=(12, 0))
        icon_label(row, "info", 12, fg=C.TEXT_MUTED).pack(side="left", anchor="n", padx=(0, 8), pady=2)
        tk.Label(row, text=note, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, wraplength=640,
                 justify="left").pack(side="left", fill="x")

    # ------------------------------------------------------------ actions --
    def _toggle(self):
        st = self.state["status"]
        if st and st.on:
            self._change(webprotect.disable)
        else:
            level = self.state["level"]
            self._change(lambda: webprotect.enable(level))

    def _pick_level(self, level):
        self.state["level"] = level
        st = self.state["status"]
        if st and st.on:  # switch the running filter straight away
            self._change(lambda: webprotect.enable(level))
        else:
            self._render()

    def _change(self, action):
        if self.state["busy"]:
            return
        self.state.update(busy=True, error=None, test=None)
        self._render()
        queue = self.app.event_queue

        def run():
            error = None
            try:
                action()
            except Exception as e:  # declined prompt, or Windows refused
                error = str(e)
            queue.put(("web_done", error))
            self._read(queue)

        threading.Thread(target=run, daemon=True).start()

    def _test(self):
        st = self.state["status"]
        if not (st and st.on):
            return
        queue = self.app.event_queue
        threading.Thread(target=lambda: queue.put(("web_test", webprotect.check_blocking(st.level))),
                         daemon=True).start()

    def refresh(self):
        threading.Thread(target=self._read, args=(self.app.event_queue,), daemon=True).start()

    @staticmethod
    def _read(queue):
        try:
            queue.put(("web_status", webprotect.status()))
        except Exception as e:
            queue.put(("web_done", str(e)))

    def handle(self, kind, payload):
        s = self.state
        if kind == "web_status":
            s["status"] = payload
            if payload.on:
                s["level"] = payload.level
        elif kind == "web_done":
            s.update(busy=False, error=payload)
        elif kind == "web_test":
            s["test"] = payload
        if self.winfo_exists():
            self._render()
