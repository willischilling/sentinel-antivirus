"""Main window: dashboard, on-demand scanning, quarantine management, settings,
and the switch for real-time protection. Protection itself runs in a separate
background agent process (agent.py) so it survives this window closing.
"""
import queue
import re
import sys
import threading
import tkinter as tk
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import launcher
import single_instance
from core import (
    activity, app_update, assistant, autostart, database, i18n, paths, quarantine, scanner, schedule, settings,
    signatures, threat_intel,
)
from core.i18n import duration, number, plural, relative, t
from core.version import VERSION
import theme as C
from theme import FONT, FONT_BOLD, FONT_HERO, FONT_LARGE, FONT_MONO, FONT_SMALL, FONT_TITLE
from widgets import (
    EmptyState, NavItem, Ring, RoundedCard, ToggleSwitch, icon_label, pill as rounded_pill, rounded_rect_image,
    set_pill_style,
)
from ask_page import AskPage, ChatState
from vpn_page import VpnPage, new_state as new_vpn_state
from firewall_page import FirewallPage, new_state as new_fw_state
from app_updates_card import AppUpdatesCard, new_state as new_appupd_state
from webprotect_page import WebProtectPage, new_state as new_web_state


def configure_style(root: tk.Tk):
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", background=C.BG, foreground=C.TEXT, font=FONT)

    def button(name, bg, fg, active, pressed, border=None, font=FONT_BOLD, padding=(16, 9), radius=8, outer=None):
        # Rounded, antialiased button shapes: one image per state, stretched by ttk (9-slice).
        size = radius * 2 + 4
        outer = C.CARD if outer is None else outer  # most buttons sit on cards
        shapes = [rounded_rect_image(size, size, radius, color, outer, border)
                  for color in (bg, active, pressed, C.BORDER if not border else C.CARD)]
        element = f"Rounded{abs(hash((name, bg, active, pressed, border, outer, radius)))}.border"
        if element not in _created_elements:
            style.element_create(element, "image", shapes[0], ("disabled", shapes[3]), ("pressed", shapes[2]),
                                 ("active", shapes[1]), border=radius, padding=2, sticky="nsew")
            _created_elements.add(element)
        style.layout(name, [(element, {"sticky": "nsew", "children": [
            ("Button.padding", {"sticky": "nsew", "children": [("Button.label", {"sticky": "nsew"})]})]})])
        style.configure(name, foreground=fg, background=bg, font=font, padding=padding, anchor="center")
        style.map(name, foreground=[("disabled", C.TEXT_MUTED)], background=[("active", active)])

    button("Accent.TButton", C.ACCENT, "#ffffff", C.ACCENT_DARK, C.ACCENT_DARK)
    button("Hero.TButton", C.ACCENT, "#ffffff", C.ACCENT_DARK, C.ACCENT_DARK,
           font=(C.DISPLAY, 11), padding=(26, 11), radius=10)
    button("Ghost.TButton", C.CARD, C.TEXT, C.CARD_HOVER, C.BORDER, border=C.BORDER, font=FONT)
    button("Danger.TButton", C.CARD, C.BAD, C.CARD_HOVER, C.BORDER, border=C.BORDER, font=FONT)
    # The same two for buttons placed straight on the page background
    button("PageGhost.TButton", C.CARD, C.TEXT, C.CARD_HOVER, C.BORDER, border=C.BORDER, font=FONT, outer=C.BG)
    button("PageDanger.TButton", C.CARD, C.BAD, C.CARD_HOVER, C.BORDER, border=C.BORDER, font=FONT, outer=C.BG)

    style.configure("Treeview", background=C.CARD, fieldbackground=C.CARD, foreground=C.TEXT,
                    borderwidth=0, font=FONT_SMALL, rowheight=30)
    style.configure("Treeview.Heading", background=C.CARD, foreground=C.TEXT_MUTED, borderwidth=0,
                    relief="flat", font=(C.UI_SEMIBOLD, 9), padding=(6, 8))
    style.map("Treeview.Heading", background=[("active", C.CARD)])
    style.map("Treeview", background=[("selected", C.ACCENT_DARK)], foreground=[("selected", "#ffffff")])
    style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
    # Slim scrollbar with no arrows, in the theme's colors
    style.layout("Slim.Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {"sticky": "ns", "children": [
        ("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})]})])
    style.configure("Slim.Vertical.TScrollbar", troughcolor=C.CARD, background=C.BORDER, bordercolor=C.CARD,
                    lightcolor=C.BORDER, darkcolor=C.BORDER, gripcount=0, arrowsize=8, width=8)
    style.map("Slim.Vertical.TScrollbar", background=[("active", C.TEXT_MUTED)])
    style.configure("TEntry", fieldbackground=C.CARD, foreground=C.TEXT, insertcolor=C.TEXT, borderwidth=1)
    style.configure("Horizontal.TProgressbar", background=C.ACCENT, troughcolor=C.BORDER, borderwidth=0,
                    bordercolor=C.BORDER, lightcolor=C.ACCENT, darkcolor=C.ACCENT, thickness=8)


def default_watch_path() -> str:
    downloads = paths.known_folder("downloads")
    return str(downloads if downloads.exists() else Path.home())


def format_time(db_timestamp: str) -> str:
    """SQLite datetime('now') is UTC; show it in local time, relative where it reads better."""
    try:
        utc = datetime.strptime(db_timestamp.split(".")[0], "%Y-%m-%d %H:%M:%S")
    except (ValueError, AttributeError):
        return db_timestamp or ""
    return i18n.relative(utc.replace(tzinfo=timezone.utc).astimezone())


def shorten(text: str, limit: int) -> str:
    """Middle-ellipsis so both the drive and the file name stay visible."""
    if len(text) <= limit:
        return text
    keep = limit - 1
    head = keep // 2
    return text[:head] + "…" + text[-(keep - head):]


def clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def page_header(parent, title, subtitle):
    tk.Label(parent, text=title, font=FONT_TITLE, fg=C.TEXT, bg=C.BG).pack(anchor="w")
    tk.Label(parent, text=subtitle, font=FONT, fg=C.TEXT_MUTED, bg=C.BG).pack(anchor="w", pady=(2, 18))


_created_elements: set = set()  # ttk element names can only be created once per process


def pill(parent, bg=None):
    return rounded_pill(parent, "", C.BORDER, outer=C.CARD if bg is None else bg)


def set_pill(label, on: bool):
    set_pill_style(label, t("pill_active") if on else t("off"), C.GOOD if on else C.BORDER,
                   fg="#0b1120" if on else C.TEXT_MUTED, outer=label.cget("bg"))


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.settings = settings.load()
        i18n.set_language(self.settings.get("language"))
        C.apply(C.resolve(self.settings.get("theme", "dark")))
        self.title(t("app_title"))
        self.geometry("1080x700")
        self.minsize(980, 640)
        self.configure(bg=C.BG)
        C.style_title_bar(self)
        try:
            self.iconbitmap(default=str(paths.resource("assets/icon.ico")))
        except tk.TclError:
            pass
        configure_style(self)

        database.init_db()
        if database.signature_count() == 0:
            signatures.seed_default_signatures()

        self.event_queue: "queue.Queue" = queue.Queue()
        self.protection_on = None  # unknown until the first agent check
        self._transitioning = False
        self._scanning = False
        saved_path = self.settings.get("watch_path")
        self.watch_path = saved_path if saved_path and Path(saved_path).exists() else default_watch_path()
        self.activity_tail = activity.Tail()
        self._load_images()
        # App update status, kept outside the widgets so it survives a language rebuild.
        self._update = {"state": "checking", "release": None, "error": None, "progress": (0, 0)}
        self.ask_state = ChatState()  # the Ask Sentinel conversation, also kept across rebuilds
        self.vpn_state = new_vpn_state()
        self.fw_state = new_fw_state()
        self.appupd_state = new_appupd_state()
        self.web_state = new_web_state()

        self._build_layout()
        self._show_page("dashboard")
        self.after(200, self._pump_queue)
        self.after(2500, self._check_for_updates)  # quietly, in the background
        self.after(3000, self._poll_vpn)
        self.after(60_000, self._unload_idle_ai)
        self.after(3000, self._follow_windows_theme)

        if autostart.supported() and autostart.is_enabled():
            autostart.set_enabled(True)  # re-point at this exe in case it was reinstalled elsewhere
        if self.settings["protection_on"]:
            launcher.start_agent()  # e.g. first launch after install, or it crashed
        elif threat_intel.needs_update():
            self._start_intel_update()  # the agent normally does this, but it isn't running
        self._poll_agent()

    def _poll_vpn(self, tick=0):
        if self.current_page == "firewall" and tick % 7 == 0 and not self.fw_state["busy"]:
            self.firewall_page.refresh()  # every ~20 s, to pick up changes made elsewhere
        if self.current_page == "vpn" and not self.vpn_state["busy"]:
            # Status every 3 s (picks up changes made outside Sentinel too), the IP every 30 s.
            self.vpn_page.refresh(ip=tick % 10 == 0)
        self.after(3000, self._poll_vpn, tick + 1)

    def _unload_idle_ai(self):
        assistant.Assistant.unload_if_idle()  # frees ~3 GB of memory a few minutes after the last question
        self.after(60_000, self._unload_idle_ai)

    def _load_images(self):
        self._logo_small = self._logo_big = None
        try:
            from PIL import Image, ImageTk

            logo = Image.open(paths.resource("assets/icon.png"))
            self._logo_small = ImageTk.PhotoImage(logo.resize((38, 38), Image.LANCZOS))
            emblem = Image.open(paths.resource("assets/emblem.png"))
            height = 86
            width = round(emblem.width * height / emblem.height)
            self._logo_big = ImageTk.PhotoImage(emblem.resize((width, height), Image.LANCZOS))
        except (OSError, ImportError):
            pass

    # ------------------------------------------------------------- layout --
    def _build_layout(self):
        sidebar = tk.Frame(self, bg=C.PANEL, width=232)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        brand = tk.Frame(sidebar, bg=C.PANEL)
        brand.pack(anchor="w", padx=20, pady=(22, 26))
        if self._logo_small:
            tk.Label(brand, image=self._logo_small, bg=C.PANEL).pack(side="left", padx=(0, 11))
        brand_text = tk.Frame(brand, bg=C.PANEL)
        brand_text.pack(side="left")
        tk.Label(brand_text, text="SENTINEL", bg=C.PANEL, fg=C.TEXT,
                 font=(C.DISPLAY, 14)).pack(anchor="w")
        tk.Label(brand_text, text=t("brand_sub"), bg=C.PANEL, fg=C.TEXT_MUTED, font=FONT_SMALL).pack(anchor="w")

        self.nav = {}
        for key, icon, label in [
            ("dashboard", "home", "nav_dashboard"),
            ("scan", "scan", "nav_scanner"),
            ("ask", "chat", "nav_ask"),
            ("vpn", "globe", "nav_vpn"),
            ("firewall", "firewall", "nav_firewall"),
            ("web", "web", "nav_web"),
            ("protection", "shield", "nav_protection"),
            ("quarantine", "lock", "nav_quarantine"),
            ("activity", "history", "nav_history"),
            ("updates", "refresh", "nav_updates"),
            ("settings", "settings", "nav_settings"),
        ]:
            item = NavItem(sidebar, icon, t(label), lambda k=key: self._show_page(k))
            item.pack(fill="x")
            self.nav[key] = item

        status = RoundedCard(sidebar, bg=C.CARD, outer=C.PANEL, radius=10, padx=14, pady=12)
        status.pack(side="bottom", fill="x", padx=16, pady=18)
        self.side_status_icon = icon_label(status.body, "shield", 16, fg=C.BAD)
        self.side_status_icon.pack(side="left", padx=(0, 10))
        col = tk.Frame(status.body, bg=C.CARD)
        col.pack(side="left")
        self.side_status_title = tk.Label(col, text=t("status_checking"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD,
                                          wraplength=150, justify="left")
        self.side_status_title.pack(anchor="w")
        self.side_status_sub = tk.Label(col, text="", font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD,
                                        wraplength=150, justify="left")
        self.side_status_sub.pack(anchor="w")

        self.content = tk.Frame(self, bg=C.BG)
        self.content.pack(side="left", fill="both", expand=True, padx=30, pady=26)

        self.pages = {}
        self._build_dashboard_page()
        self._build_scan_page()
        self.ask_page = AskPage(self.content, self, logo=self._logo_big)
        self.pages["ask"] = self.ask_page
        self.vpn_page = VpnPage(self.content, self)
        self.pages["vpn"] = self.vpn_page
        self.firewall_page = FirewallPage(self.content, self)
        self.pages["firewall"] = self.firewall_page
        self.web_page = WebProtectPage(self.content, self)
        self.pages["web"] = self.web_page
        self._build_protection_page()
        self._build_quarantine_page()
        self._build_activity_page()
        self._build_updates_page()
        self._build_settings_page()
        self._render_update_state()

    def _show_page(self, key):
        self.current_page = key
        for k, item in self.nav.items():
            item.set_active(k == key)
        for frame in self.pages.values():
            frame.pack_forget()
        self.pages[key].pack(fill="both", expand=True)
        if key == "dashboard":
            self._refresh_dashboard()
        elif key == "quarantine":
            self._refresh_quarantine()
        elif key == "activity":
            self._refresh_activity()
        elif key == "updates" and self.appupd_state["items"] is None:
            self.appupd_card.check()
        elif key == "web" and not self.web_state["busy"]:
            self.web_page.refresh()

    # ---------------------------------------------------------- dashboard --
    def _build_dashboard_page(self):
        page = tk.Frame(self.content, bg=C.BG)
        self.pages["dashboard"] = page

        hero = RoundedCard(page, radius=16, padx=34, pady=30)
        hero.pack(fill="x")
        self.hero_ring = Ring(hero.body, size=156)
        self.hero_ring.pack(side="left")
        text = tk.Frame(hero.body, bg=C.CARD)
        text.pack(side="left", fill="x", expand=True, padx=(34, 0))
        self.hero_title = tk.Label(text, text=t("hero_checking"), font=FONT_HERO, fg=C.TEXT, bg=C.CARD,
                                   justify="left", anchor="w")
        self.hero_title.pack(anchor="w", fill="x")
        self.hero_sub = tk.Label(text, text="", font=FONT, fg=C.TEXT_MUTED, bg=C.CARD,
                                 wraplength=420, justify="left", anchor="w")
        self.hero_sub.pack(anchor="w", fill="x", pady=(6, 20))

        def rewrap(e):  # wrap to whatever width the hero text column actually gets
            width = max(200, e.width - 10)
            self.hero_sub.configure(wraplength=width)
            self.hero_title.configure(wraplength=width)

        text.bind("<Configure>", rewrap)
        buttons = tk.Frame(text, bg=C.CARD)
        buttons.pack(anchor="w")
        ttk.Button(buttons, text=t("scan_now"), style="Hero.TButton",
                   command=self._quick_scan).pack(side="left")
        self.hero_protect_btn = ttk.Button(buttons, text=t("turn_on_protection"), style="Ghost.TButton",
                                           command=self._toggle_protection)

        cards = tk.Frame(page, bg=C.BG)
        cards.pack(fill="x", pady=(18, 0))
        for i in range(3):
            cards.columnconfigure(i, weight=1, uniform="cards")

        scan_card = RoundedCard(cards, command=lambda: self._show_page("scan"))
        scan_card.grid(row=0, column=0, sticky="nsew", padx=(0, 9))
        self._card_header(scan_card.body, "scan", t("card_scanner"))
        self.dash_scan_value = tk.Label(scan_card.body, text=t("never"), font=FONT_LARGE, fg=C.TEXT, bg=C.CARD)
        self.dash_scan_value.pack(anchor="w", pady=(14, 0))
        self.dash_scan_sub = tk.Label(scan_card.body, text="", font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD,
                                      justify="left", anchor="w")
        self.dash_scan_sub.pack(anchor="w", fill="x")

        rtp_card = RoundedCard(cards, command=lambda: self._show_page("protection"))
        rtp_card.grid(row=0, column=1, sticky="nsew", padx=9)
        self._card_header(rtp_card.body, "shield", t("card_protection"))
        value_row = tk.Frame(rtp_card.body, bg=C.CARD)
        value_row.pack(fill="x", pady=(14, 0))
        self.dash_rtp_value = tk.Label(value_row, text="—", font=FONT_LARGE, fg=C.TEXT, bg=C.CARD)
        self.dash_rtp_value.pack(side="left")
        self.dash_switch = ToggleSwitch(value_row, command=self._toggle_protection)
        self.dash_switch.pack(side="right")
        self.dash_rtp_sub = tk.Label(rtp_card.body, text="", font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD)
        self.dash_rtp_sub.pack(anchor="w")

        q_card = RoundedCard(cards, command=lambda: self._show_page("quarantine"))
        q_card.grid(row=0, column=2, sticky="nsew", padx=(9, 0))
        self._card_header(q_card.body, "lock", t("card_quarantine"))
        self.dash_q_value = tk.Label(q_card.body, text="", font=FONT_LARGE, fg=C.TEXT, bg=C.CARD)
        self.dash_q_value.pack(anchor="w", pady=(14, 0))
        q_sub = tk.Label(q_card.body, text=t("isolated_cant_run"), font=FONT_SMALL,
                         fg=C.TEXT_MUTED, bg=C.CARD, justify="left", anchor="w")
        q_sub.pack(anchor="w", fill="x")

        # Card text can wrap in longer languages; keep it inside each card.
        for card, labels in ((scan_card, (self.dash_scan_sub,)), (rtp_card, (self.dash_rtp_sub,)),
                             (q_card, (q_sub,))):
            card.body.bind("<Configure>", lambda e, ls=labels: [
                lb.configure(wraplength=max(120, e.width - 4)) for lb in ls], add="+")

        recent = RoundedCard(page, radius=16, padx=22, pady=16)
        recent.pack(fill="both", expand=True, pady=(18, 0))
        head = tk.Frame(recent.body, bg=C.CARD)
        head.pack(fill="x")
        tk.Label(head, text=t("recent_detections"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left")
        see_all = tk.Label(head, text=t("see_all"), font=FONT_SMALL, fg=C.ACCENT, bg=C.CARD, cursor="hand2")
        see_all.pack(side="right")
        see_all.bind("<Button-1>", lambda e: self._show_page("activity"))
        self.recent_list = tk.Frame(recent.body, bg=C.CARD)
        self.recent_list.pack(fill="both", expand=True, pady=(8, 0))

        footer = tk.Frame(page, bg=C.BG)
        footer.pack(fill="x", pady=(12, 0))
        self.dash_footer = tk.Label(footer, text="", font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.BG)
        self.dash_footer.pack(side="left")
        self.update_link = tk.Label(footer, text=t("update_now"), font=FONT_SMALL, fg=C.ACCENT, bg=C.BG,
                                    cursor="hand2")
        self.update_link.bind("<Button-1>", lambda e: self._start_intel_update())
        if not getattr(self, "_updating", False):
            self.update_link.pack(side="left", padx=(10, 0))
        self._updating = getattr(self, "_updating", False)

    def _refresh_recent(self):
        for child in self.recent_list.winfo_children():
            child.destroy()
        rows, seen = [], set()
        for r in database.get_recent_scans(40):
            if r[1] in ("signature_match", "suspicious") and r[0] not in seen:
                seen.add(r[0])
                rows.append(r)
        rows = rows[:4]
        if not rows:
            icon_label(self.recent_list, "check", 18, fg=C.GOOD).pack(pady=(18, 6))
            tk.Label(self.recent_list, text=t("no_recent_threats"), font=FONT,
                     fg=C.TEXT_MUTED, bg=C.CARD).pack()
            return
        for path, verdict, detail, when in rows:
            is_threat = verdict == "signature_match"
            row = tk.Frame(self.recent_list, bg=C.CARD)
            row.pack(fill="x", pady=5)
            icon_label(row, "warning", 13, fg=C.BAD if is_threat else C.WARN).pack(side="left", padx=(0, 12))
            tk.Label(row, text=Path(path).name, font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left")
            tk.Label(row, text=clip(detail, 44), font=FONT_SMALL, fg=C.TEXT_MUTED,
                     bg=C.CARD).pack(side="left", padx=(10, 0))
            tk.Label(row, text=format_time(when), font=FONT_SMALL, fg=C.TEXT_MUTED,
                     bg=C.CARD).pack(side="right")

    def _card_header(self, body, icon, title):
        row = tk.Frame(body, bg=C.CARD)
        row.pack(fill="x")
        badge = tk.Frame(row, bg=C.BORDER, width=34, height=34)
        badge.pack(side="left")
        badge.pack_propagate(False)
        icon_label(badge, icon, 14, fg=C.ACCENT, bg=C.BORDER).pack(expand=True)
        tk.Label(row, text=title, font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left", padx=(12, 0))
        return row

    def _refresh_dashboard(self):
        self.settings = settings.load()  # the agent's scheduled scans update last_scan too
        last = self.settings.get("last_scan")
        if last:
            when = datetime.fromisoformat(last["time"])
            found = last["flagged"]
            self.dash_scan_value.configure(text=i18n.relative(when))
            self.dash_scan_sub.configure(
                text=t("last_scan_clean", files=number(last["files"])) if not found
                else t("last_scan_flagged", files=number(last["files"]), count=number(found)))
        else:
            self.dash_scan_value.configure(text=t("never"))
            self.dash_scan_sub.configure(text=t("run_first_scan"))
        self.dash_q_value.configure(text=plural("items", database.quarantine_count()))
        self._refresh_intel_footer()
        self._refresh_recent()

    # ------------------------------------------------------ threat updates --
    def _refresh_intel_footer(self):
        if self._updating:
            return
        info = threat_intel.stats()
        if info["updated"]:
            age = i18n.relative(info["updated"].astimezone())
            self.dash_footer.configure(
                text=t("intel_summary", hashes=number(info["hashes"]), rules=number(info["rules"]),
                       when=age[0].lower() + age[1:]), fg=C.TEXT_MUTED)
        else:
            self.dash_footer.configure(text=t("intel_missing"), fg=C.WARN)

    def _start_intel_update(self):
        if self._updating:
            return
        self._updating = True
        self.update_link.pack_forget()
        self.dash_footer.configure(text=t("intel_starting"), fg=C.TEXT_MUTED)

        def work():
            try:
                result = threat_intel.update(lambda key: self.event_queue.put(("intel_progress", key)))
                self.event_queue.put(("intel_done", result))
            except Exception as e:
                self.event_queue.put(("intel_done", e))

        threading.Thread(target=work, daemon=True).start()

    def _on_intel_done(self, result):
        self._updating = False
        self.update_link.pack(side="left", padx=(10, 0))
        if isinstance(result, Exception):
            self.dash_footer.configure(text=t("intel_failed", error=result), fg=C.BAD)
        else:
            self._refresh_intel_footer()

    # ---------------------------------------------------------------- scan --
    def _build_scan_page(self):
        page = tk.Frame(self.content, bg=C.BG)
        self.pages["scan"] = page
        page_header(page, t("scanner_title"), t("scanner_sub"))

        card = RoundedCard(page, radius=16, padx=30, pady=26)
        card.pack(fill="x")
        self.scan_ring = Ring(card.body, size=150)
        self.scan_ring.pack(side="left")
        self.scan_ring.show(C.BORDER, glyph="scan", glyph_color=C.TEXT_MUTED)
        right = tk.Frame(card.body, bg=C.CARD)
        right.pack(side="left", fill="x", expand=True, padx=(30, 0))

        tk.Label(right, text=t("what_to_scan"), font=FONT_LARGE, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        chips = tk.Frame(right, bg=C.CARD)
        chips.pack(anchor="w", pady=(12, 8))
        self.scan_target = tk.StringVar(value=default_watch_path())
        self._chips = {}
        for key, label in (("downloads", "folder_downloads"), ("desktop", "folder_desktop"),
                           ("documents", "folder_documents")):
            folder = str(paths.known_folder(key))
            chip = RoundedCard(chips, bg=C.BORDER, outer=C.CARD, radius=8, padx=14, pady=7,
                               hover_bg=C.CARD_HOVER, command=lambda f=folder: self._pick_target(f))
            chip.label = tk.Label(chip.body, text=t(label), font=FONT, fg=C.TEXT, bg=C.BORDER)
            chip.label.pack()
            chip.pack(side="left", padx=(0, 8))
            self._chips[folder] = chip
        other = RoundedCard(chips, bg=C.BORDER, outer=C.CARD, radius=8, padx=14, pady=7,
                            hover_bg=C.CARD_HOVER, command=self._browse_scan_path)
        tk.Label(other.body, text=t("choose_folder"), font=FONT, fg=C.TEXT, bg=C.BORDER).pack()
        other.pack(side="left")
        self.scan_target_label = tk.Label(right, text="", font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD)
        self.scan_target_label.pack(anchor="w", pady=(0, 16))

        action = tk.Frame(right, bg=C.CARD)
        action.pack(anchor="w")
        self.scan_btn = ttk.Button(action, text=t("scan_now"), style="Hero.TButton", command=self._start_scan)
        self.scan_btn.pack(side="left")
        self.scan_status = tk.Label(action, text="", font=FONT, fg=C.TEXT_MUTED, bg=C.CARD)
        self.scan_status.pack(side="left", padx=(16, 0))
        self._pick_target(self.scan_target.get())

        self.sched_bar = RoundedCard(page, radius=12, padx=20, pady=10)
        self.sched_bar.pack(fill="x", pady=(12, 0))
        self._sched_open = False
        self._render_schedule()

        results = RoundedCard(page, radius=16, padx=22, pady=18)
        results.pack(fill="both", expand=True, pady=(12, 0))
        head = tk.Frame(results.body, bg=C.CARD)
        head.pack(fill="x", pady=(0, 8))
        tk.Label(head, text=t("results"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left")
        ttk.Button(head, text=t("quarantine_selected"), style="Danger.TButton",
                   command=self._quarantine_selected_scan_results).pack(side="right")

        table = tk.Frame(results.body, bg=C.CARD)
        table.pack(fill="both", expand=True)
        self.scan_tree = ttk.Treeview(table, columns=("file", "verdict", "detail"),
                                      show="headings", selectmode="extended")
        for col, label, width in (("file", "col_file", 360), ("verdict", "col_verdict", 110),
                                  ("detail", "col_detail", 260)):
            self.scan_tree.heading(col, text=t(label), anchor="w")
            self.scan_tree.column(col, width=width, anchor="w", stretch=col == "file")
        self.scan_tree.pack(fill="both", expand=True)
        self.scan_tree.tag_configure("threat", foreground=C.BAD)
        self.scan_tree.tag_configure("suspicious", foreground=C.WARN)
        self.scan_tree.tag_configure("skipped", foreground=C.TEXT_MUTED)
        self.scan_empty = EmptyState(table, "scan", t("scan_empty_title"), t("scan_empty_msg"))
        self.scan_empty.show()
        self._scan_result_map = {}

    # ------------------------------------------------------ scheduled scan --
    def _render_schedule(self):
        body = self.sched_bar.body
        for child in body.winfo_children():
            child.destroy()
        sch = schedule.get()
        row = tk.Frame(body, bg=C.CARD)
        row.pack(fill="x")
        icon_label(row, "history", 13, fg=C.ACCENT).pack(side="left", padx=(0, 10))
        tk.Label(row, text=t("sched_title"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left")
        nxt = schedule.next_slot(sch, datetime.now())
        if sch["frequency"] == "off":
            summary = t("sched_summary_off")
        else:
            clock = i18n.time_of_day(datetime.now().replace(hour=sch["hour"], minute=0))
            summary = (t("sched_summary_daily", time=clock) if sch["frequency"] == "daily"
                       else t("sched_summary_weekly", day=t(f"day_{sch['weekday']}"), time=clock))
            summary += "  ·  " + t("sched_next", when=i18n.relative(nxt.astimezone()))
        tk.Label(row, text=summary, font=FONT, fg=C.TEXT_MUTED, bg=C.CARD).pack(side="left", padx=(12, 0))
        link = tk.Label(row, text=t("sched_done") if self._sched_open else t("sched_change"), font=FONT,
                        fg=C.ACCENT, bg=C.CARD, cursor="hand2")
        link.pack(side="right")
        link.bind("<Button-1>", lambda e: self._toggle_schedule_editor())
        if not self._sched_open:
            return
        tk.Label(body, text=t("sched_note"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(anchor="w",
                                                                                              pady=(8, 2))
        self._chip_row(body, t("sched_how_often"),
                       [(t(f"sched_{f}"), sch["frequency"] == f, lambda f=f: self._set_schedule(frequency=f))
                        for f in schedule.FREQUENCIES])
        if sch["frequency"] != "off":
            self._chip_row(body, t("sched_time"),
                           [(i18n.time_of_day(datetime.now().replace(hour=h, minute=0)), sch["hour"] == h,
                             lambda h=h: self._set_schedule(hour=h)) for h in schedule.HOURS])
        if sch["frequency"] == "weekly":
            self._chip_row(body, t("sched_day"),
                           [(t(f"day_{d}"), sch["weekday"] == d, lambda d=d: self._set_schedule(weekday=d))
                            for d in range(7)])

    def _chip_row(self, parent, label, chips):
        row = tk.Frame(parent, bg=C.CARD)
        row.pack(fill="x", pady=(6, 0))
        tk.Label(row, text=label, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, width=14, anchor="w").pack(side="left")
        for text, selected, command in chips:
            bg = C.ACCENT_DARK if selected else C.BORDER
            chip = RoundedCard(row, bg=bg, outer=C.CARD, radius=8, padx=10, pady=4,
                               hover_bg=None if selected else C.CARD_HOVER, command=None if selected else command)
            tk.Label(chip.body, text=text, font=FONT_SMALL, fg=C.ON_ACCENT if selected else C.TEXT,
                     bg=bg).pack()
            chip.pack(side="left", padx=(0, 6))

    def _toggle_schedule_editor(self):
        self._sched_open = not self._sched_open
        self._render_schedule()

    def _set_schedule(self, **changes):
        schedule.save(**changes)
        self._render_schedule()

    def _pick_target(self, folder):
        self.scan_target.set(folder)
        for path, chip in self._chips.items():
            selected = path == folder
            chip.set_rest(C.ACCENT_DARK if selected else C.BORDER)
            chip.label.configure(fg=C.ON_ACCENT if selected else C.TEXT)
        self.scan_target_label.configure(text=shorten(folder, 80))

    def _browse_scan_path(self):
        path = filedialog.askdirectory(initialdir=self.scan_target.get() or str(Path.home()))
        if path:
            self._pick_target(str(Path(path)))

    def _quick_scan(self):
        self._show_page("scan")
        self._pick_target(self.watch_path)
        self._start_scan()

    def _start_scan(self):
        target = Path(self.scan_target.get())
        if not target.exists():
            messagebox.showerror("Sentinel", t("folder_missing", path=target))
            return
        self._scanning = True
        self._close_scan_summary()
        self._scan_started = datetime.now().astimezone()
        self.scan_tree.delete(*self.scan_tree.get_children())
        self._scan_result_map.clear()
        self.scan_empty.hide()
        self.scan_btn.configure(state="disabled", text=t("scanning_btn"))
        self.scan_ring.spin("0", t("files_checked"))
        self.scan_status.configure(text=t("scanning_folder", name=target.name or target), fg=C.TEXT_MUTED)
        threading.Thread(target=self._scan_worker, args=(target,), daemon=True).start()

    def _scan_worker(self, target: Path):
        total = flagged = 0
        counts = {"signature_match": 0, "suspicious": 0, "error": 0}
        for result in scanner.scan_directory(target, recursive=True):
            total += 1
            if result.verdict in counts:
                counts[result.verdict] += 1
            if result.verdict in ("signature_match", "suspicious"):
                flagged += 1
                self.event_queue.put(("scan_result", result))
            elif result.verdict == "error":
                self.event_queue.put(("scan_result", result))
            if total % 25 == 0:
                self.event_queue.put(("scan_progress", (total, flagged)))
        self.event_queue.put(("scan_done", (target, total, flagged, counts)))

    def _on_scan_result(self, result):
        if result.verdict == "signature_match":
            tag, verdict, detail = "threat", t("verdict_threat"), result.signature_name
        elif result.verdict == "suspicious":
            tag, verdict, detail = "suspicious", t("verdict_suspicious"), "; ".join(result.heuristic_flags)
        else:
            tag, verdict, detail = "skipped", t("verdict_skipped"), result.error or ""
        item_id = self.scan_tree.insert("", "end", values=(shorten(str(result.path), 70), verdict, detail),
                                        tags=(tag,))
        if tag != "skipped":
            self._scan_result_map[item_id] = result

    def _on_scan_progress(self, payload):
        total, flagged = payload
        self.scan_ring.set_text(number(total))
        self.scan_status.configure(
            text=t("flagged_so_far", n=number(flagged)) if flagged else t("nothing_flagged_so_far"))

    def _on_scan_done(self, payload):
        target, total, flagged, counts = payload
        self._scanning = False
        self.scan_btn.configure(state="normal", text=t("scan_now"))
        if flagged:
            self.scan_ring.show(C.BAD, glyph="warning", text=t("ring_flagged", n=number(flagged)))
            self.scan_status.configure(text=plural("found_items", flagged, files=number(total)), fg=C.BAD)
        else:
            self.scan_ring.show(C.GOOD, glyph="check", text=t("ring_no_threats"))
            self.scan_status.configure(text=t("no_threats_in", files=number(total)), fg=C.GOOD)
            if not self.scan_tree.get_children():
                self.scan_empty.show(t("no_threats_title"),
                                     t("checked_files_in", files=number(total), path=shorten(str(target), 60)))
        settings.save(last_scan={"time": datetime.now().astimezone().isoformat(),
                                 "files": total, "flagged": flagged, "path": str(target)})
        self.settings = settings.load()
        self._refresh_dashboard()
        self._show_scan_summary(target, total, counts)

    # ------------------------------------------------------ scan summary --
    def _show_scan_summary(self, target: Path, total: int, counts: dict):
        """A summary card over the scanner page, shown when a scan finishes."""
        self._close_scan_summary()
        finished = datetime.now().astimezone()
        seconds = int((finished - self._scan_started).total_seconds())
        threats, suspicious, unreadable = counts["signature_match"], counts["suspicious"], counts["error"]

        overlay = tk.Frame(self.pages["scan"], bg=C.BG)
        overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._scan_summary = overlay
        card = RoundedCard(overlay, outer=C.BG, radius=18, padx=30, pady=24)
        card.place(relx=0.5, rely=0.5, anchor="center", width=420)
        body = card.body

        ring = Ring(body, size=72)
        ring.pack()
        if threats:
            ring.show(C.BAD, glyph="warning")
        elif suspicious:
            ring.show(C.WARN, glyph="warning")
        else:
            ring.show(C.GOOD, glyph="check")
        tk.Label(body, text=t("summary_title"), font=FONT_TITLE, fg=C.TEXT, bg=C.CARD).pack(pady=(10, 0))
        tk.Label(body, text=relative(finished), font=FONT, fg=C.TEXT_MUTED, bg=C.CARD).pack(pady=(2, 10))

        def divider():
            tk.Frame(body, bg=C.BORDER, height=1).pack(fill="x", pady=7)

        def row(label, value, color=None):
            line = tk.Frame(body, bg=C.CARD)
            line.pack(fill="x", pady=2)
            tk.Label(line, text=label, font=FONT, fg=C.TEXT, bg=C.CARD).pack(side="left")
            tk.Label(line, text=value, font=FONT_BOLD if color else FONT, fg=color or C.TEXT,
                     bg=C.CARD).pack(side="right")

        divider()
        row(t("summary_duration"), duration(seconds))
        row(t("summary_files"), number(total))
        row(t("summary_folder"), shorten(target.name or str(target), 34))
        divider()
        row(t("summary_threats"), number(threats), C.BAD if threats else None)
        row(t("summary_suspicious"), number(suspicious), C.WARN if suspicious else None)
        row(t("summary_unreadable"), number(unreadable))
        divider()

        buttons = tk.Frame(body, bg=C.CARD)
        buttons.pack(fill="x", pady=(14, 0))
        ttk.Button(buttons, text=t("summary_view"), style="Ghost.TButton",
                   command=self._view_scan_results).pack(side="left", fill="x", expand=True, padx=(0, 6))
        done = ttk.Button(buttons, text=t("summary_done"), style="Accent.TButton",
                          command=self._finish_scan_summary)
        done.pack(side="left", fill="x", expand=True, padx=(6, 0))
        done.focus_set()
        done.bind("<Escape>", lambda e: self._close_scan_summary())

    def _close_scan_summary(self):
        overlay = getattr(self, "_scan_summary", None)
        if overlay is not None and overlay.winfo_exists():
            overlay.destroy()
        self._scan_summary = None

    def _view_scan_results(self):
        self._close_scan_summary()
        flagged = [i for i in self.scan_tree.get_children() if i in self._scan_result_map]
        if flagged:
            self.scan_tree.selection_set(flagged[0])
            self.scan_tree.see(flagged[0])
            self.scan_tree.focus_set()

    def _finish_scan_summary(self):
        self._close_scan_summary()
        self._show_page("dashboard")

    def _quarantine_selected_scan_results(self):
        selected = [i for i in self.scan_tree.selection() if i in self._scan_result_map]
        if not selected:
            return
        count = 0
        for item_id in selected:
            result = self._scan_result_map.pop(item_id)
            try:
                quarantine.quarantine_file(result.path, result.signature_name or "manual")
                self.scan_tree.set(item_id, "verdict", t("verdict_quarantined"))
                self.scan_tree.item(item_id, tags=("skipped",))
                count += 1
            except (OSError, RuntimeError) as e:  # RuntimeError: admin approval declined or failed
                messagebox.showerror("Sentinel", t("quarantine_failed", path=result.path, error=e))
        if count:
            self._refresh_dashboard()

    # --------------------------------------------------------- protection --
    def _build_protection_page(self):
        page = tk.Frame(self.content, bg=C.BG)
        self.pages["protection"] = page
        page_header(page, t("rtp_page_title"), t("rtp_page_sub"))

        main = RoundedCard(page, radius=16, padx=24, pady=16)
        main.pack(fill="x")
        top = tk.Frame(main.body, bg=C.CARD)
        top.pack(fill="x")
        self.rtp_icon = icon_label(top, "shield", 26, fg=C.BAD)
        self.rtp_icon.pack(side="left", padx=(0, 16))
        col = tk.Frame(top, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        self.rtp_title = tk.Label(col, text=t("rtp_page_title"), font=FONT_LARGE, fg=C.TEXT, bg=C.CARD)
        self.rtp_title.pack(anchor="w")
        self.rtp_sub = tk.Label(col, text="", font=FONT, fg=C.TEXT_MUTED, bg=C.CARD)
        self.rtp_sub.pack(anchor="w")
        self.rtp_switch = ToggleSwitch(top, command=self._toggle_protection)
        self.rtp_switch.pack(side="right")

        tk.Frame(main.body, bg=C.BORDER, height=1).pack(fill="x", pady=12)
        startup = tk.Frame(main.body, bg=C.CARD)
        startup.pack(fill="x")
        # The switch is packed first so longer translations wrap instead of covering it.
        self.autostart_switch = ToggleSwitch(startup, command=self._on_autostart_toggled,
                                             on=autostart.is_enabled())
        self.autostart_switch.pack(side="right", padx=(12, 0))
        self.autostart_switch.set_enabled(autostart.supported())
        tk.Label(startup, text=t("start_with_windows"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left")
        startup_text = t("start_with_windows_desc")
        if not autostart.supported():
            startup_text += t("installed_only")
        startup_desc = tk.Label(startup, text=startup_text, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD,
                                justify="left", anchor="w")
        startup_desc.pack(side="left", fill="x", expand=True, padx=(10, 0))
        startup_desc.bind("<Configure>", lambda e: startup_desc.configure(wraplength=max(120, e.width - 4)))

        layers = RoundedCard(page, radius=16, padx=24, pady=6)
        layers.pack(fill="x", pady=(12, 0))
        self.layer_pills = []
        self.download_desc = self._layer_row(layers.body, "download", t("layer_download"), "", change=True)
        self._layer_row(layers.body, "apps", t("layer_program"), t("layer_program_desc"))
        self._layer_row(layers.body, "power", t("layer_startup"), t("layer_startup_desc"))
        self._layer_row(layers.body, "lock", t("layer_ransomware"), t("layer_ransomware_desc"), last=True)

        log_card = RoundedCard(page, radius=16, padx=20, pady=14)
        log_card.pack(fill="both", expand=True, pady=(12, 0))
        tk.Label(log_card.body, text=t("live_activity"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        self.protection_log = tk.Text(
            log_card.body, bg=C.CARD, fg=C.TEXT_MUTED, insertbackground=C.TEXT, relief="flat",
            font=FONT_MONO, wrap="word", height=6, bd=0, highlightthickness=0,
        )
        self.protection_log.pack(fill="both", expand=True, pady=(8, 0))
        self.protection_log.configure(state="disabled")
        self.protection_log.tag_configure("threat", foreground=C.BAD)
        self.protection_log.tag_configure("warn", foreground=C.WARN)
        self.protection_log.tag_configure("info", foreground=C.TEXT)

    def _layer_row(self, body, icon, title, desc, change=False, last=False):
        row = tk.Frame(body, bg=C.CARD)
        row.pack(fill="x", pady=8)
        icon_label(row, icon, 16, fg=C.ACCENT).pack(side="left", padx=(0, 16))
        status = pill(row)
        status.pack(side="right")
        self.layer_pills.append(status)
        if change:
            ttk.Button(row, text=t("change_folder"), style="Ghost.TButton",
                       command=self._change_watch_folder).pack(side="right", padx=(0, 12))
        col = tk.Frame(row, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, text=title, font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        desc_label = tk.Label(col, text=desc, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD,
                              justify="left", anchor="w")
        desc_label.pack(anchor="w", fill="x")
        # Longer languages wrap instead of pushing the status pill off the card.
        col.bind("<Configure>", lambda e: desc_label.configure(wraplength=max(150, e.width - 4)))
        if not last:
            tk.Frame(body, bg=C.BORDER, height=1).pack(fill="x")
        return desc_label

    def _change_watch_folder(self):
        path = filedialog.askdirectory(initialdir=self.watch_path)
        if not path:
            return
        self.watch_path = str(Path(path))
        settings.save(watch_path=self.watch_path)
        self._update_protection_texts()
        if launcher.agent_running():  # restart so the agent picks up the new folder
            self._set_transitioning(t("restarting_protection"))
            self.update_idletasks()
            launcher.stop_agent()
            launcher.start_agent()
            self._wait_for_agent(True, deadline=40)

    def _append_activity(self, entries):
        if not entries:
            return
        self.protection_log.configure(state="normal")
        for ts, level, text in entries:
            tag = level if level in ("threat", "warn") else "info" if level == "info" else ()
            self.protection_log.insert("end", f"{ts}  {text}\n", tag)
        self.protection_log.see("end")
        self.protection_log.configure(state="disabled")

    def _poll_agent(self):
        """Keeps the status and live activity in sync with the background agent,
        including changes made from the tray menu."""
        if not self._transitioning:
            running = launcher.agent_running()
            if running != self.protection_on:
                self._set_protection_indicator(running)
        self._append_activity(self.activity_tail.read_new())
        self.after(500, self._poll_agent)

    def _set_protection_indicator(self, on: bool):
        self.protection_on = on
        self._transitioning = False
        color = C.GOOD if on else C.BAD
        folder = Path(self.watch_path).name or self.watch_path

        self.side_status_icon.configure(fg=color)
        self.side_status_title.configure(text=t("status_protected") if on else t("status_not_protected"))
        self.side_status_sub.configure(text=t("status_rtp_on") if on else t("status_rtp_off"))

        self.hero_ring.show(color, image=self._logo_big)
        self.hero_title.configure(text=t("hero_on_title") if on else t("hero_off_title"),
                                  fg=C.TEXT if on else C.BAD)
        self.hero_sub.configure(text=t("hero_on_sub", folder=folder) if on else t("hero_off_sub"))
        if on:
            self.hero_protect_btn.pack_forget()
        else:
            self.hero_protect_btn.pack(side="left", padx=(10, 0))

        for switch in (self.dash_switch, self.rtp_switch):
            switch.set(on)
            switch.set_enabled(True)
        self.dash_rtp_value.configure(text=t("on") if on else t("off"), fg=C.GOOD if on else C.BAD)
        self.rtp_icon.configure(fg=color)
        self.rtp_title.configure(text=t("rtp_on_title") if on else t("rtp_off_title"))
        for p in self.layer_pills:
            set_pill(p, on)
        self._update_protection_texts()

    def _update_protection_texts(self):
        on = bool(self.protection_on)
        folder = Path(self.watch_path).name or self.watch_path
        self.dash_rtp_sub.configure(text=t("watching_folder", folder=folder) if on else t("not_watching"))
        self.rtp_sub.configure(text=t("rtp_on_sub") if on else t("rtp_off_sub"))
        self.download_desc.configure(text=t("layer_download_desc", folder=self.watch_path))

    def _toggle_protection(self):
        if self._transitioning:
            return
        if launcher.agent_running():
            self._stop_protection()
        else:
            self._start_protection()

    def _set_transitioning(self, text):
        self._transitioning = True
        for switch in (self.dash_switch, self.rtp_switch):
            switch.set_enabled(False)
        self.rtp_sub.configure(text=text)
        self.side_status_sub.configure(text=text)

    def _start_protection(self):
        if not Path(self.watch_path).exists():
            messagebox.showerror("Sentinel", t("folder_missing", path=self.watch_path))
            return
        settings.save(protection_on=True, watch_path=self.watch_path)
        self._set_transitioning(t("starting_protection"))
        launcher.start_agent()
        self._wait_for_agent(True, deadline=40)

    def _stop_protection(self):
        settings.save(protection_on=False)
        self._set_transitioning(t("stopping_protection"))
        self.update_idletasks()
        if not launcher.stop_agent():
            messagebox.showerror("Sentinel", t("stop_timeout"))
        self._set_protection_indicator(launcher.agent_running())

    def _wait_for_agent(self, want_running, deadline):
        if launcher.agent_running() == want_running:
            self._set_protection_indicator(want_running)
        elif deadline <= 0:
            self._set_protection_indicator(launcher.agent_running())
            messagebox.showerror("Sentinel", t("start_failed"))
        else:
            self.after(250, self._wait_for_agent, want_running, deadline - 1)

    def _on_autostart_toggled(self):
        want = not self.autostart_switch.on
        try:
            autostart.set_enabled(want)
        except OSError as e:
            messagebox.showerror("Sentinel", t("autostart_failed", error=e))
        self.autostart_switch.set(autostart.is_enabled())

    # -------------------------------------------------------- quarantine --
    def _table_card(self, page, columns, empty):
        card = RoundedCard(page, radius=16, padx=22, pady=16)
        card.pack(fill="both", expand=True)
        table = tk.Frame(card.body, bg=C.CARD)
        table.pack(fill="both", expand=True)
        tree = ttk.Treeview(table, columns=[c[0] for c in columns], show="headings")
        for i, (col, label, width) in enumerate(columns):
            tree.heading(col, text=t(label), anchor="w")
            # Only the first (file) column stretches, so the rest never get pushed off-screen.
            tree.column(col, width=width, minwidth=width if i else 120, anchor="w", stretch=i == 0)
        tree.pack(fill="both", expand=True)
        tree.tag_configure("threat", foreground=C.BAD)
        tree.tag_configure("suspicious", foreground=C.WARN)
        tree.tag_configure("muted", foreground=C.TEXT_MUTED)
        icon, title, message = empty
        return tree, EmptyState(table, icon, t(title), t(message))

    def _build_quarantine_page(self):
        page = tk.Frame(self.content, bg=C.BG)
        self.pages["quarantine"] = page
        page_header(page, t("quarantine_title"), t("quarantine_sub"))

        self.q_tree, self.q_empty = self._table_card(
            page,
            (("file", "col_file", 300), ("reason", "col_reason", 200), ("when", "col_quarantined", 160)),
            ("lock", "quarantine_empty_title", "quarantine_empty_msg"),
        )
        self.q_tree.configure(selectmode="browse")
        btn_row = tk.Frame(page, bg=C.BG)
        btn_row.pack(fill="x", pady=(14, 0))
        ttk.Button(btn_row, text=t("restore"), style="PageGhost.TButton",
                   command=self._restore_selected_quarantine).pack(side="left")
        ttk.Button(btn_row, text=t("delete_permanently"), style="PageDanger.TButton",
                   command=self._delete_selected_quarantine).pack(side="left", padx=(8, 0))

    def _refresh_quarantine(self):
        self.q_tree.delete(*self.q_tree.get_children())
        rows = quarantine.list_quarantine()
        for qid, original, _qpath, reason, when in rows:
            self.q_tree.insert("", "end", iid=str(qid),
                               values=(shorten(original, 60), reason, format_time(when)))
        self.q_empty.show() if not rows else self.q_empty.hide()

    def _restore_selected_quarantine(self):
        sel = self.q_tree.selection()
        if not sel:
            return
        try:
            result = quarantine.restore_file(int(sel[0]))
        except (OSError, RuntimeError) as e:  # e.g. admin approval declined
            messagebox.showerror("Sentinel", f"{t('restore_failed')}\n\n{e}")
            return
        if result:
            messagebox.showinfo("Sentinel", t("restored_to", path=result))
            self._refresh_quarantine()
        else:
            messagebox.showerror("Sentinel", t("restore_failed"))

    def _delete_selected_quarantine(self):
        sel = self.q_tree.selection()
        if not sel:
            return
        if messagebox.askyesno("Sentinel", t("confirm_delete")):
            quarantine.delete_permanently(int(sel[0]))
            self._refresh_quarantine()

    # ----------------------------------------------------------- activity --
    def _build_activity_page(self):
        page = tk.Frame(self.content, bg=C.BG)
        self.pages["activity"] = page
        page_header(page, t("history_title"), t("history_sub"))
        self.activity_tree, self.activity_empty = self._table_card(
            page,
            (("file", "col_file", 260), ("verdict", "col_verdict", 100), ("detail", "col_detail", 230),
             ("when", "col_when", 140)),
            ("history", "history_empty_title", "history_empty_msg"),
        )

    def _refresh_activity(self):
        self.activity_tree.delete(*self.activity_tree.get_children())
        rows = database.get_recent_scans()
        labels = {"signature_match": ("verdict_threat", "threat"), "suspicious": ("verdict_suspicious", "suspicious"),
                  "deleted": ("verdict_deleted", "muted")}
        for path, verdict, detail, when in rows:
            key, tag = labels.get(verdict, (None, ""))
            label = t(key) if key else verdict.title()
            self.activity_tree.insert("", "end", values=(shorten(path, 44), label, clip(detail, 36),
                                                         format_time(when)), tags=(tag,))
        self.activity_empty.show() if not rows else self.activity_empty.hide()

    # ------------------------------------------------------------ updates --
    def _build_updates_page(self):
        page = tk.Frame(self.content, bg=C.BG)
        self.pages["updates"] = page
        page_header(page, t("updates_title"), t("updates_sub"))

        card = RoundedCard(page, radius=16, padx=24, pady=20)
        card.pack(fill="x")
        top = tk.Frame(card.body, bg=C.CARD)
        top.pack(fill="x")
        self.upd_icon = icon_label(top, "cloud", 26, fg=C.ACCENT)
        self.upd_icon.pack(side="left", padx=(0, 16))
        buttons = tk.Frame(top, bg=C.CARD)
        buttons.pack(side="right")
        self.upd_action_btn = ttk.Button(buttons, text=t("install_update"), style="Accent.TButton",
                                         command=self._start_app_update)
        self.upd_check_btn = ttk.Button(buttons, text=t("check_again"), style="Ghost.TButton",
                                        command=self._check_for_updates)
        col = tk.Frame(top, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        self.upd_title = tk.Label(col, text="", font=FONT_LARGE, fg=C.TEXT, bg=C.CARD, justify="left", anchor="w")
        self.upd_title.pack(anchor="w", fill="x")
        self.upd_sub = tk.Label(col, text="", font=FONT, fg=C.TEXT_MUTED, bg=C.CARD, justify="left", anchor="w")
        self.upd_sub.pack(anchor="w", fill="x")
        col.bind("<Configure>", lambda e: self.upd_sub.configure(wraplength=max(200, e.width - 4)))

        self.upd_progress_row = tk.Frame(card.body, bg=C.CARD)
        self.upd_progress = ttk.Progressbar(self.upd_progress_row, mode="determinate", maximum=100)
        self.upd_progress.pack(fill="x", pady=(16, 4))
        self.upd_progress_label = tk.Label(self.upd_progress_row, text="", font=FONT_SMALL,
                                           fg=C.TEXT_MUTED, bg=C.CARD)
        self.upd_progress_label.pack(anchor="w")
        tk.Label(card.body, text=t("installed_version", version=VERSION), font=FONT_SMALL,
                 fg=C.TEXT_MUTED, bg=C.CARD).pack(anchor="w", pady=(14, 0))

        self.appupd_card = AppUpdatesCard(page, self)  # other apps with updates (winget)
        self.appupd_card.pack(fill="both", expand=True, pady=(14, 0))

        self.upd_notes_card = RoundedCard(page, radius=16, padx=22, pady=16)
        self.upd_notes_title = tk.Label(self.upd_notes_card.body, text="", font=FONT_BOLD, fg=C.TEXT, bg=C.CARD)
        self.upd_notes_title.pack(anchor="w")
        self.upd_notes = tk.Text(self.upd_notes_card.body, bg=C.CARD, fg=C.TEXT_MUTED, relief="flat", bd=0,
                                 highlightthickness=0, font=FONT, wrap="word", height=8)
        self.upd_notes.pack(fill="both", expand=True, pady=(8, 0))

    @staticmethod
    def _plain_notes(markdown: str) -> str:
        """Release notes are Markdown; show them as readable plain text."""
        text = re.sub(r"`{3}.*?`{3}", "", markdown, flags=re.S)       # code blocks (checksums)
        text = re.sub(r"^#+\s*", "", text, flags=re.M)                 # headings
        text = text.replace("**", "").replace("`", "")
        text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)          # links -> their text
        text = re.sub(r"^(\s*)- ", r"\1• ", text, flags=re.M)
        return re.sub(r"\n{3,}", "\n\n", text).strip()

    def _render_update_state(self):
        u = self._update
        state, release = u["state"], u["release"]
        self.upd_action_btn.pack_forget()
        self.upd_check_btn.pack_forget()
        self.upd_progress_row.pack_forget()
        self.upd_notes_card.pack_forget()
        self.nav["updates"].set_badge(state == "available")

        if state == "checking":
            self.upd_icon.configure(fg=C.TEXT_MUTED)
            self.upd_title.configure(text=t("checking_updates"), fg=C.TEXT)
            self.upd_sub.configure(text="")
        elif state == "current":
            self.upd_icon.configure(fg=C.GOOD)
            self.upd_title.configure(text=t("up_to_date"), fg=C.TEXT)
            self.upd_sub.configure(text=t("up_to_date_sub", version=VERSION))
            self.upd_check_btn.pack(side="left")
        elif state == "error":
            self.upd_icon.configure(fg=C.WARN)
            self.upd_title.configure(text=t("update_check_failed"), fg=C.TEXT)
            self.upd_sub.configure(text=str(u["error"]))
            self.upd_check_btn.pack(side="left")
        elif state in ("available", "downloading", "installing", "failed"):
            self.upd_icon.configure(fg=C.ACCENT)
            self.upd_title.configure(text=t("update_available", version=release.version), fg=C.TEXT)
            if not app_update.can_self_update():
                self.upd_sub.configure(text=t("update_from_source"))
                self.upd_action_btn.configure(text=t("open_release_page"), state="normal")
                self.upd_action_btn.pack(side="left")
            else:
                sub = t("update_available_sub", current=VERSION)
                if state == "failed":
                    sub = t("update_failed", error=u["error"])
                self.upd_sub.configure(text=sub, fg=C.BAD if state == "failed" else C.TEXT_MUTED)
                busy = state in ("downloading", "installing")
                self.upd_action_btn.configure(text=t("install_update"), state="disabled" if busy else "normal")
                self.upd_action_btn.pack(side="left")
            if state in ("downloading", "installing"):
                done, total = u["progress"]
                self.upd_progress.configure(value=100 * done / total if total else 0)
                self.upd_progress_label.configure(
                    text=t("installing_update") if state == "installing"
                    else t("downloading_update", done=number(round(done / 1e6)), total=number(round(total / 1e6))))
                self.upd_progress_row.pack(fill="x")
            self.upd_notes_title.configure(text=t("whats_new", version=release.version))
            self.upd_notes.configure(state="normal")
            self.upd_notes.delete("1.0", "end")
            self.upd_notes.insert("1.0", self._plain_notes(release.notes))
            self.upd_notes.configure(state="disabled")
            self.upd_notes_card.pack(fill="x", pady=(14, 0), before=self.appupd_card)
        if state != "failed":
            self.upd_sub.configure(fg=C.TEXT_MUTED)

    def _check_for_updates(self):
        if self._update["state"] in ("downloading", "installing"):
            return
        self._update.update(state="checking", error=None)
        self._render_update_state()

        def work():
            try:
                self.event_queue.put(("update_info", app_update.latest_release()))
            except Exception as e:
                self.event_queue.put(("update_info", e))

        threading.Thread(target=work, daemon=True).start()

    def _on_update_info(self, result):
        if isinstance(result, Exception):
            self._update.update(state="error", error=result)
        elif app_update.is_newer(result.version):
            self._update.update(state="available", release=result)
        else:
            self._update.update(state="current", release=result)
        self._render_update_state()

    def _start_app_update(self):
        release = self._update["release"]
        if not app_update.can_self_update():
            webbrowser.open(release.page)
            return
        self._update.update(state="downloading", progress=(0, release.size))
        self._render_update_state()

        def work():
            try:
                path = app_update.download(
                    release, lambda done, total: self.event_queue.put(("update_progress", (done, total))))
                self.event_queue.put(("update_ready", path))
            except Exception as e:
                self.event_queue.put(("update_ready", e))

        threading.Thread(target=work, daemon=True).start()

    def _on_update_progress(self, payload):
        self._update["progress"] = payload
        done, total = payload
        self.upd_progress.configure(value=100 * done / total if total else 0)
        self.upd_progress_label.configure(
            text=t("downloading_update", done=number(round(done / 1e6)), total=number(round(total / 1e6))))

    def _on_update_ready(self, result):
        if isinstance(result, Exception):
            self._update.update(state="failed", error=result)
            self._render_update_state()
            return
        self._update["state"] = "installing"
        self._render_update_state()
        self.update_idletasks()
        app_update.launch_installer(result)
        # Close so the installer can replace this app; it reopens Sentinel when done.
        self.after(1500, self.destroy)

    # ----------------------------------------------------------- settings --
    def _build_settings_page(self):
        page = tk.Frame(self.content, bg=C.BG)
        self.pages["settings"] = page
        page_header(page, t("settings_title"), t("settings_sub"))

        theme_choice = self.settings.get("theme", "dark")
        self._settings_card(page, "settings", t("appearance"), t("appearance_desc"), [
            (key, t(f"theme_{key}"), t(f"theme_{key}_desc"), key == theme_choice,
             lambda k=key: self._change_theme(k))
            for key in C.CHOICES
        ])
        self._settings_card(page, "globe", t("language"), t("language_desc"), [
            (code, native, i18n.ENGLISH_NAMES[code], code == i18n.current(),
             lambda c=code: self._change_language(c))
            for code, native in i18n.LANGUAGES.items()
        ], pady=(14, 0))

        about = RoundedCard(page, radius=16, padx=24, pady=18)
        about.pack(fill="x", pady=(14, 0))
        icon_label(about.body, "info", 18, fg=C.ACCENT).pack(side="left", padx=(0, 14))
        col = tk.Frame(about.body, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, text=t("about_version", version=VERSION), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        tk.Label(col, text=t("about_desc"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(anchor="w")

    def _settings_card(self, page, icon, title, desc, options, pady=(0, 0)):
        """A card with a row of selectable option tiles: (key, label, sublabel, selected, command)."""
        card = RoundedCard(page, radius=16, padx=24, pady=20)
        card.pack(fill="x", pady=pady)
        head = tk.Frame(card.body, bg=C.CARD)
        head.pack(fill="x")
        icon_label(head, icon, 18, fg=C.ACCENT).pack(side="left", padx=(0, 14))
        col = tk.Frame(head, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, text=title, font=FONT_LARGE, fg=C.TEXT, bg=C.CARD).pack(anchor="w")
        tk.Label(col, text=desc, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(anchor="w")

        row = tk.Frame(card.body, bg=C.CARD)
        row.pack(fill="x", pady=(16, 0))
        for i, (_key, label, sub, selected, command) in enumerate(options):
            row.columnconfigure(i, weight=1, uniform=title)
            bg = C.ACCENT_DARK if selected else C.BORDER
            tile = RoundedCard(row, bg=bg, outer=C.CARD, radius=10, padx=14, pady=12,
                               hover_bg=C.CARD_HOVER, command=command)
            tile.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 6, 0))
            tk.Label(tile.body, text=label, font=FONT_BOLD, fg=C.ON_ACCENT if selected else C.TEXT,
                     bg=bg).pack(anchor="w")
            tk.Label(tile.body, text=sub, font=FONT_SMALL, fg=C.ON_ACCENT if selected else C.TEXT_MUTED,
                     bg=bg).pack(anchor="w")

    def _busy(self) -> bool:
        if self._scanning or self._update["state"] in ("downloading", "installing"):
            messagebox.showinfo("Sentinel", t("language_busy"))
            return True
        return False

    def _rebuild(self):
        """Redraws every page (after a language or theme change), staying on the same page."""
        page = self.current_page
        for child in self.winfo_children():
            child.destroy()
        self.title(t("app_title"))
        configure_style(self)
        self.configure(bg=C.BG)
        C.style_title_bar(self)
        self._build_layout()
        self._show_page(page)
        self.protection_on = None  # forces the status texts to be redrawn
        self._set_protection_indicator(launcher.agent_running())

    def _change_language(self, code):
        if code == i18n.current() or self._busy():
            return
        settings.save(language=code)  # the background agent follows the settings file
        self.settings = settings.load()
        i18n.set_language(code)
        self._rebuild()

    def _change_theme(self, choice):
        if choice == self.settings.get("theme", "dark") or self._busy():
            return
        settings.save(theme=choice)
        self.settings = settings.load()
        C.apply(C.resolve(choice))
        self._rebuild()

    def _follow_windows_theme(self):
        """In 'Match Windows' mode, switch when the Windows setting changes."""
        if self.settings.get("theme") == "system" and C.resolve("system") != C.current and not self._busy_quiet():
            C.apply(C.resolve("system"))
            self._rebuild()
        self.after(3000, self._follow_windows_theme)

    def _busy_quiet(self) -> bool:
        return self._scanning or self._update["state"] in ("downloading", "installing")

    # ------------------------------------------------------------- queue --
    def _pump_queue(self):
        # Cap work done per tick so a burst of queued events can't stall the
        # UI thread in one go — remaining items are picked up on the next tick.
        processed = 0
        try:
            while processed < 40:
                kind, payload = self.event_queue.get_nowait()
                if kind == "scan_result":
                    self._on_scan_result(payload)
                elif kind == "scan_progress":
                    self._on_scan_progress(payload)
                elif kind == "scan_done":
                    self._on_scan_done(payload)
                elif kind.startswith("ask_"):
                    self.ask_page.handle(kind, payload)
                elif kind.startswith("vpn_"):
                    self.vpn_page.handle(kind, payload)
                elif kind.startswith("fw_"):
                    self.firewall_page.handle(kind, payload)
                elif kind.startswith("appupd_"):
                    self.appupd_card.handle(kind, payload)
                elif kind.startswith("web_"):
                    self.web_page.handle(kind, payload)
                elif kind == "show":
                    self._show_window()
                elif kind == "intel_progress":
                    self.dash_footer.configure(text=t(payload), fg=C.TEXT_MUTED)
                elif kind == "intel_done":
                    self._on_intel_done(payload)
                elif kind == "update_info":
                    self._on_update_info(payload)
                elif kind == "update_progress":
                    self._on_update_progress(payload)
                elif kind == "update_ready":
                    self._on_update_ready(payload)
                    if self._update["state"] == "installing":
                        return  # the window is closing
                processed += 1
        except queue.Empty:
            pass
        self.after(50, self._pump_queue)

    def _show_window(self):
        self.deiconify()
        self.lift()
        self.attributes("-topmost", True)
        self.after(200, lambda: self.attributes("-topmost", False))
        self.focus_force()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--elevated":  # one admin action, then exit
        from core import elevate

        sys.exit(elevate.main(sys.argv[2:]))
    if "--check-ai" in sys.argv:  # diagnostics: exit code 0 if the local AI engine loads
        from core import assistant as ai

        sys.exit(0 if ai.engine_available() else 1)
    if "--agent" in sys.argv:
        import agent

        agent.main()
        return
    if not single_instance.UI.acquire():
        single_instance.UI.signal()  # bring the open window to the front instead
        return
    app = App()
    single_instance.UI.listen(lambda: app.event_queue.put(("show", None)))
    app.mainloop()


if __name__ == "__main__":
    main()
