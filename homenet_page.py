"""Home Network page: a GVTC-style control panel for your own home network.

See every device, give it a name and a profile (who it belongs to), pause or
resume its internet, and block whole categories of websites or your own list
of sites across the network. Enforcement for *this PC* is real (firewall +
hosts file + family DNS); other devices are managed as policy, the same way an
ISP's router app is a front-end to the router.

An admin PIN protects your own access: once set, pausing or resuming the admin
device needs the PIN, so no one else can keep you offline.
"""
import threading
import tkinter as tk
from tkinter import simpledialog, ttk

import theme as C
from core import homenet, netscan
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from tools_page import subpage_header, wrap_to_width
from widgets import Ring, RoundedCard, ScrollArea, ToggleSwitch, icon_label, pill

KIND_ICONS = {"router": "globe", "computer": "apps", "phone": "usb", "apple": "usb", "console": "game",
              "tv": "web", "printer": "download", "speaker": "health", "camera": "scan", "smart": "power"}
PROFILE_KEYS = {"me": "hn_prof_me", "family": "hn_prof_family", "kids": "hn_prof_kids",
                "guest": "hn_prof_guest", "other": "hn_prof_other"}
# Attribute names (not values): resolved against theme at draw time so the
# palette follows a dark/light switch.
_PROFILE_COLOR_ATTR = {"me": "ACCENT", "family": "GOOD", "kids": "WARN", "guest": "TEXT_MUTED", "other": "TEXT_MUTED"}


def _pcolor(profile):
    return getattr(C, _PROFILE_COLOR_ATTR.get(profile, "ACCENT"))


def new_state() -> dict:
    return {"result": None, "busy": False, "error": None, "action": None, "action_error": None}


def _t(key, **kw):
    from core.i18n import t
    return t(key, **kw)


class HomeNetPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        self.state = app.homenet_state
        subpage_header(self, app, _t("hn_title"), _t("hn_sub"), "nav_tools", "tools")
        self.body = tk.Frame(self, bg=C.BG)
        self.body.pack(fill="both", expand=True)
        self._render()

    # ------------------------------------------------------------- scanning --
    def scan(self):
        s = self.state
        if s["busy"]:
            return
        s.update(busy=True, error=None)
        queue = self.app.event_queue

        def run():
            try:
                queue.put(("homenet_scan", netscan.scan()))
            except Exception as e:
                queue.put(("homenet_scan", e))

        threading.Thread(target=run, daemon=True).start()
        self._render()

    def handle(self, kind, payload):
        s = self.state
        if kind == "homenet_scan":
            s["busy"] = False
            if isinstance(payload, Exception):
                s["error"] = _t("net_offline") if str(payload) == "no_network" else str(payload)
            else:
                s["result"] = payload
                self._learn_admin_device(payload)
        elif kind == "homenet_done":
            s["action"] = None
            s["action_error"] = payload or None
        if self.winfo_exists():
            self._render()

    def _learn_admin_device(self, result):
        """The first time a network is seen, this PC is its admin device."""
        conf = homenet.net_config(result.network_id)[1]
        if not conf.get("admin_mac"):
            for dev in result.devices:
                if dev.this_pc:
                    homenet.set_admin_device(result.network_id, dev.mac)
                    break

    # ---------------------------------------------- enforcement (threaded) --
    def _run_action(self, label, fn):
        """Run an admin action (firewall / hosts) off the UI thread."""
        s = self.state
        if s["action"]:
            return
        s.update(action=label, action_error=None)
        queue = self.app.event_queue
        self._render()

        def run():
            try:
                fn()
                queue.put(("homenet_done", None))
            except Exception as e:
                queue.put(("homenet_done", str(e)))

        threading.Thread(target=run, daemon=True).start()

    # --------------------------------------------------------------- render --
    def _render(self):
        for child in self.body.winfo_children():
            child.destroy()
        s = self.state
        result = s["result"]

        self._status_card()
        if s["action_error"]:
            tk.Label(self.body, text=s["action_error"], font=FONT_SMALL, fg=C.BAD, bg=C.BG,
                     wraplength=640, justify="left").pack(anchor="w", pady=(8, 0))

        if result is None:
            return

        self._access_card(result)
        self._blocking_card(result)
        self._devices_card(result)

    def _status_card(self):
        s, result = self.state, self.state["result"]
        top = RoundedCard(self.body, radius=16, padx=24, pady=16)
        top.pack(fill="x")
        row = tk.Frame(top.body, bg=C.CARD)
        row.pack(fill="x")
        ring = Ring(row, size=64)
        ring.pack(side="left", padx=(0, 18))
        btn = ttk.Button(row, text=_t("net_scan_again") if result else _t("hn_scan"),
                         style="Accent.TButton", command=self.scan)
        btn.pack(side="right", anchor="n", padx=(12, 0))
        if s["busy"]:
            btn.state(["disabled"])
        col = tk.Frame(row, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        if s["busy"]:
            ring.spin("")
            title, sub = _t("net_scanning"), _t("net_scanning_sub")
        elif result is None:
            ring.show(C.BORDER, glyph="globe", glyph_color=C.TEXT_MUTED)
            title, sub = _t("hn_ready"), _t("hn_ready_sub")
        else:
            paused = homenet.paused_count(result.network_id)
            color = C.WARN if paused else C.GOOD
            ring.show(color, glyph="globe", glyph_color=color)
            title = _t("hn_found", n=len(result.devices))
            sub = _t("hn_found_sub", network=result.network)
            if paused:
                sub += "  ·  " + _t("hn_paused_n", n=paused)
        tk.Label(col, text=title, font=FONT_LARGE, fg=C.TEXT, bg=C.CARD, anchor="w").pack(anchor="w", fill="x")
        sub_label = tk.Label(col, text=sub, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left", anchor="w")
        sub_label.pack(anchor="w", fill="x")
        wrap_to_width(sub_label, col)
        if s["error"]:
            tk.Label(top.body, text=s["error"], font=FONT_SMALL, fg=C.BAD, bg=C.CARD, wraplength=640,
                     justify="left").pack(anchor="w", pady=(8, 0))

    # --------------------------------------------------- your access (admin) --
    def _access_card(self, result):
        card = RoundedCard(self.body, radius=16, padx=22, pady=16)
        card.pack(fill="x", pady=(14, 0))
        head = tk.Frame(card.body, bg=C.CARD)
        head.pack(fill="x")
        icon_label(head, "lock", 14, fg=C.ACCENT).pack(side="left", padx=(0, 10))
        tk.Label(head, text=_t("hn_access_title"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left")
        state = _t("hn_pin_on") if homenet.has_pin() else _t("hn_pin_off")
        pill(head, state, C.GOOD if homenet.has_pin() else C.TEXT_MUTED).pack(side="right")
        desc = tk.Label(card.body, text=_t("hn_access_desc"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD,
                        justify="left", anchor="w")
        desc.pack(anchor="w", fill="x", pady=(8, 10))
        wrap_to_width(desc, card.body)
        btns = tk.Frame(card.body, bg=C.CARD)
        btns.pack(fill="x")
        if homenet.has_pin():
            ttk.Button(btns, text=_t("hn_pin_change"), style="PageGhost.TButton",
                       command=self._change_pin).pack(side="left")
            ttk.Button(btns, text=_t("hn_pin_remove"), style="PageGhost.TButton",
                       command=self._remove_pin).pack(side="left", padx=(8, 0))
        else:
            ttk.Button(btns, text=_t("hn_pin_set"), style="Accent.TButton",
                       command=self._set_pin).pack(side="left")

    def _set_pin(self):
        pin = simpledialog.askstring("Sentinel", _t("hn_pin_prompt_new"), show="•", parent=self)
        if pin and pin.strip():
            again = simpledialog.askstring("Sentinel", _t("hn_pin_prompt_again"), show="•", parent=self)
            if again != pin:
                self._warn(_t("hn_pin_mismatch"))
                return
            homenet.set_pin(pin.strip())
            self._render()

    def _change_pin(self):
        if not self._ask_pin():
            return
        self._set_pin()

    def _remove_pin(self):
        if self._ask_pin():
            homenet.clear_pin()
            self._render()

    def _ask_pin(self) -> bool:
        """Prompt for the current PIN; True if correct (or none set)."""
        if not homenet.has_pin():
            return True
        pin = simpledialog.askstring("Sentinel", _t("hn_pin_prompt"), show="•", parent=self)
        if pin is None:
            return False
        if homenet.check_pin(pin):
            return True
        self._warn(_t("hn_pin_wrong"))
        return False

    def _warn(self, text):
        from tkinter import messagebox
        messagebox.showwarning("Sentinel", text, parent=self)

    # ----------------------------------------------------- website blocking --
    def _blocking_card(self, result):
        card = RoundedCard(self.body, radius=16, padx=22, pady=16)
        card.pack(fill="x", pady=(14, 0))
        head = tk.Frame(card.body, bg=C.CARD)
        head.pack(fill="x")
        icon_label(head, "web", 14, fg=C.ACCENT).pack(side="left", padx=(0, 10))
        tk.Label(head, text=_t("hn_block_title"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left")
        busy = self.state["action"] == "block"
        apply_btn = ttk.Button(head, text=_t("hn_block_apply"), style="Accent.TButton",
                               command=lambda: self._apply_blocking(result))
        apply_btn.pack(side="right")
        if busy:
            apply_btn.state(["disabled"])
        desc = tk.Label(card.body, text=_t("hn_block_desc"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD,
                        justify="left", anchor="w")
        desc.pack(anchor="w", fill="x", pady=(8, 12))
        wrap_to_width(desc, card.body)

        conf = homenet.net_config(result.network_id)[1]
        active = set(conf.get("categories", []))
        for key in homenet.CATEGORIES:
            row = tk.Frame(card.body, bg=C.CARD)
            row.pack(fill="x", pady=3)
            ToggleSwitch(row, on=key in active,
                         command=lambda k=key: self._toggle_cat(result, k)).pack(side="right")
            tk.Label(row, text=_t("hn_cat_" + key), font=FONT, fg=C.TEXT, bg=C.CARD).pack(side="left")

        tk.Frame(card.body, bg=C.BORDER, height=1).pack(fill="x", pady=(12, 10))
        tk.Label(card.body, text=_t("hn_sites_title"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD,
                 anchor="w").pack(anchor="w")
        add = tk.Frame(card.body, bg=C.CARD)
        add.pack(fill="x", pady=(8, 6))
        ttk.Button(add, text=_t("hn_sites_add"), style="PageGhost.TButton",
                   command=lambda: self._add_site(result)).pack(side="left")
        tk.Label(add, text=_t("hn_sites_hint"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(
            side="left", padx=(10, 0))
        sites = conf.get("sites", [])
        if not sites:
            tk.Label(card.body, text=_t("hn_sites_none"), font=FONT_SMALL, fg=C.TEXT_MUTED,
                     bg=C.CARD, anchor="w").pack(anchor="w", pady=(2, 0))
        for domain in sites:
            srow = tk.Frame(card.body, bg=C.CARD)
            srow.pack(fill="x", pady=2)
            remove = tk.Label(srow, text=_t("hn_sites_remove"), font=FONT_SMALL, fg=C.BAD, bg=C.CARD,
                              cursor="hand2")
            remove.pack(side="right")
            remove.bind("<Button-1>", lambda e, d=domain: self._remove_site(result, d))
            icon_label(srow, "warning", 11, fg=C.WARN).pack(side="left", padx=(2, 8))
            tk.Label(srow, text=domain, font=FONT_SMALL, fg=C.TEXT, bg=C.CARD).pack(side="left")

    def _toggle_cat(self, result, key):
        conf = homenet.net_config(result.network_id)[1]
        homenet.toggle_category(result.network_id, key, key not in set(conf.get("categories", [])))
        self._render()

    def _add_site(self, result):
        raw = simpledialog.askstring("Sentinel", _t("hn_sites_prompt"), parent=self)
        if raw:
            homenet.add_site(result.network_id, raw)
            self._render()

    def _remove_site(self, result, domain):
        homenet.remove_site(result.network_id, domain)
        self._render()

    def _apply_blocking(self, result):
        self._run_action("block", lambda: homenet.apply_site_blocks(result.network_id))

    # ---------------------------------------------------------- the devices --
    def _devices_card(self, result):
        card = RoundedCard(self.body, radius=16, padx=18, pady=12)
        card.pack(fill="both", expand=True, pady=(14, 0))
        tk.Label(card.body, text=_t("hn_devices_title"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD,
                 anchor="w").pack(anchor="w", pady=(2, 6), padx=4)
        area = ScrollArea(card.body)
        area.pack(fill="both", expand=True)
        for dev in result.devices:
            self._device_row(area.inner, result, dev)

    def _device_row(self, parent, result, dev):
        info = homenet.device(result.network_id, dev.mac)
        is_admin = homenet.is_admin_device(result.network_id, dev.mac)
        row = tk.Frame(parent, bg=C.CARD)
        row.pack(fill="x", pady=5, padx=(0, 8))

        icon_label(row, KIND_ICONS.get(dev.kind, "info"), 14,
                   fg=_pcolor(info["profile"])).pack(side="left", padx=(4, 14), anchor="n")

        # Right side: pause/resume control.
        ctrl = tk.Frame(row, bg=C.CARD)
        ctrl.pack(side="right", anchor="n")
        self._pause_control(ctrl, result, dev, info, is_admin)

        text = tk.Frame(row, bg=C.CARD)
        text.pack(side="left", fill="x", expand=True)
        head = tk.Frame(text, bg=C.CARD)
        head.pack(anchor="w", fill="x")
        name = info["label"] or self._default_name(dev)
        tk.Label(head, text=name, font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left")
        if dev.this_pc:
            pill(head, _t("hn_this_pc"), C.ACCENT).pack(side="left", padx=(8, 0))
        if is_admin:
            pill(head, _t("hn_admin"), C.GOOD).pack(side="left", padx=(8, 0))
        if dev.new:
            pill(head, _t("net_new"), C.WARN).pack(side="left", padx=(8, 0))

        meta = tk.Frame(text, bg=C.CARD)
        meta.pack(anchor="w", fill="x")
        prof = tk.Label(meta, text=_t(PROFILE_KEYS[info["profile"]]), font=FONT_SMALL,
                        fg=_pcolor(info["profile"]), bg=C.CARD, cursor="hand2")
        prof.pack(side="left")
        prof.bind("<Button-1>", lambda e, d=dev: self._choose_profile(result, d))
        tk.Label(meta, text="  ·  " + dev.ip + "  ·  " + dev.mac.upper(), font=FONT_SMALL,
                 fg=C.TEXT_MUTED, bg=C.CARD).pack(side="left")
        rename = tk.Label(meta, text="  ·  " + _t("hn_rename"), font=FONT_SMALL, fg=C.ACCENT, bg=C.CARD,
                          cursor="hand2")
        rename.pack(side="left")
        rename.bind("<Button-1>", lambda e, d=dev: self._rename(result, d))

    def _pause_control(self, parent, result, dev, info, is_admin):
        """This PC gets a real pause with a status line; other devices are managed."""
        if dev.router:
            tk.Label(parent, text=_t("hn_router_note"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(anchor="e")
            return
        paused = info["paused"]
        sw = ToggleSwitch(parent, on=not paused,  # on = internet allowed
                          command=lambda: self._toggle_pause(result, dev, is_admin))
        sw.pack(anchor="e")
        if self.state["action"] == "pause:" + dev.mac:
            sw.set_enabled(False)
        label = _t("hn_on") if not paused else _t("hn_paused")
        note = ""
        if not dev.this_pc:
            note = "  ·  " + _t("hn_managed")
        tk.Label(parent, text=label + note, font=FONT_SMALL,
                 fg=C.GOOD if not paused else C.WARN, bg=C.CARD).pack(anchor="e", pady=(2, 0))

    def _toggle_pause(self, result, dev, is_admin):
        info = homenet.device(result.network_id, dev.mac)
        want_pause = not info["paused"]
        # The admin device is PIN-protected both ways, so no one can keep you off.
        if is_admin and not self._ask_pin():
            self._render()
            return
        if dev.this_pc:
            # Only record the new state once the firewall change actually goes through,
            # so a declined admin prompt can't leave a false "paused" record.
            def apply(nid=result.network_id, mac=dev.mac, pause=want_pause):
                homenet.enforce_this_pc(pause)
                homenet.set_paused(nid, mac, pause)
            self._run_action("pause:" + dev.mac, apply)
        else:
            homenet.set_paused(result.network_id, dev.mac, want_pause)
            self._render()  # managed-only for other devices

    def _choose_profile(self, result, dev):
        menu = tk.Menu(self, tearoff=0)
        for key in homenet.PROFILES:
            menu.add_command(label=_t(PROFILE_KEYS[key]),
                             command=lambda k=key: self._set_profile(result, dev, k))
        menu.tk_popup(self.winfo_pointerx(), self.winfo_pointery())

    def _set_profile(self, result, dev, key):
        homenet.set_profile(result.network_id, dev.mac, key)
        if key == "me":
            homenet.set_admin_device(result.network_id, dev.mac)
        self._render()

    def _rename(self, result, dev):
        current = homenet.device(result.network_id, dev.mac)["label"] or ""
        name = simpledialog.askstring("Sentinel", _t("hn_rename_prompt"), initialvalue=current, parent=self)
        if name is not None:
            homenet.set_label(result.network_id, dev.mac, name)
            self._render()

    @staticmethod
    def _default_name(dev):
        if dev.router:
            return _t("net_router")
        if dev.this_pc:
            return _t("net_this_pc")
        return dev.name or dev.maker or (_t("net_private_device") if dev.private_mac else _t("net_unknown_device"))
