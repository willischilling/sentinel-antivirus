"""Main window: dashboard, on-demand scanning, quarantine management, and the
switch for real-time protection. Protection itself runs in a separate
background agent process (agent.py) so it survives this window closing.
"""
import queue
import sys
import threading
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import launcher
import single_instance
from core import (
    activity, autostart, database, paths, quarantine, scanner, settings, signatures, threat_intel,
)
from theme import (
    ACCENT, ACCENT_DARK, BAD, BG, BORDER, CARD, CARD_HOVER, FONT, FONT_BOLD, FONT_HERO,
    FONT_LARGE, FONT_MONO, FONT_SMALL, FONT_TITLE, GOOD, PANEL, TEXT, TEXT_MUTED, WARN,
)
from widgets import EmptyState, NavItem, Ring, RoundedCard, ToggleSwitch, icon_label


def configure_style(root: tk.Tk):
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure(".", background=BG, foreground=TEXT, font=FONT)

    def button(name, bg, fg, active, border=None, font=FONT_BOLD, padding=(16, 9)):
        style.configure(name, background=bg, foreground=fg, borderwidth=1 if border else 0,
                        bordercolor=border or bg, lightcolor=bg, darkcolor=bg,
                        focuscolor=bg, font=font, padding=padding)
        style.map(name, background=[("disabled", BORDER), ("active", active)],
                  foreground=[("disabled", TEXT_MUTED)])

    button("Accent.TButton", ACCENT, "#ffffff", ACCENT_DARK)
    button("Hero.TButton", ACCENT, "#ffffff", ACCENT_DARK,
           font=("Segoe UI Semibold", 11), padding=(26, 11))
    button("Ghost.TButton", CARD, TEXT, CARD_HOVER, border=BORDER, font=FONT)
    button("Danger.TButton", CARD, BAD, CARD_HOVER, border=BORDER, font=FONT)

    style.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT,
                    borderwidth=0, font=FONT_SMALL, rowheight=30)
    style.configure("Treeview.Heading", background=CARD, foreground=TEXT_MUTED, borderwidth=0,
                    relief="flat", font=("Segoe UI Semibold", 9), padding=(6, 8))
    style.map("Treeview.Heading", background=[("active", CARD)])
    style.map("Treeview", background=[("selected", ACCENT_DARK)], foreground=[("selected", "#ffffff")])
    style.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
    style.configure("TEntry", fieldbackground=CARD, foreground=TEXT, insertcolor=TEXT, borderwidth=1)


def default_watch_path() -> str:
    downloads = paths.known_folder("downloads")
    return str(downloads if downloads.exists() else Path.home())


def format_time(db_timestamp: str) -> str:
    """SQLite datetime('now') is UTC; show it in local time, relative where it reads better."""
    try:
        utc = datetime.strptime(db_timestamp.split(".")[0], "%Y-%m-%d %H:%M:%S")
    except (ValueError, AttributeError):
        return db_timestamp or ""
    local = utc.replace(tzinfo=timezone.utc).astimezone()
    return _relative(local)


def _relative(local: datetime) -> str:
    now = datetime.now().astimezone()
    clock = local.strftime("%I:%M %p").lstrip("0")
    days = (now.date() - local.date()).days
    if days == 0:
        return f"Today, {clock}"
    if days == 1:
        return f"Yesterday, {clock}"
    return local.strftime("%b %d, %Y ") + clock


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
    tk.Label(parent, text=title, font=FONT_TITLE, fg=TEXT, bg=BG).pack(anchor="w")
    tk.Label(parent, text=subtitle, font=FONT, fg=TEXT_MUTED, bg=BG).pack(anchor="w", pady=(2, 18))


def pill(parent, bg=CARD):
    return tk.Label(parent, font=("Segoe UI Semibold", 8), bg=bg, padx=9, pady=2)


def set_pill(label, on: bool, on_text="Active", off_text="Off"):
    label.configure(text=on_text if on else off_text,
                    fg="#0b1120" if on else TEXT_MUTED, bg=GOOD if on else BORDER)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Sentinel — Antivirus")
        self.geometry("1080x700")
        self.minsize(980, 640)
        self.configure(bg=BG)
        try:
            self.iconbitmap(default=str(paths.resource("assets/icon.ico")))
        except tk.TclError:
            pass
        configure_style(self)

        database.init_db()
        if database.signature_count() == 0:
            signatures.seed_default_signatures()

        self.settings = settings.load()
        self.event_queue: "queue.Queue" = queue.Queue()
        self.protection_on = None  # unknown until the first agent check
        self._transitioning = False
        saved_path = self.settings.get("watch_path")
        self.watch_path = saved_path if saved_path and Path(saved_path).exists() else default_watch_path()
        self.activity_tail = activity.Tail()
        self._load_images()

        self._build_layout()
        self._show_page("dashboard")
        self.after(200, self._pump_queue)

        if autostart.supported() and autostart.is_enabled():
            autostart.set_enabled(True)  # re-point at this exe in case it was reinstalled elsewhere
        if self.settings["protection_on"]:
            launcher.start_agent()  # e.g. first launch after install, or it crashed
        elif threat_intel.needs_update():
            self._start_intel_update()  # the agent normally does this, but it isn't running
        self._poll_agent()

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
        sidebar = tk.Frame(self, bg=PANEL, width=232)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        brand = tk.Frame(sidebar, bg=PANEL)
        brand.pack(anchor="w", padx=20, pady=(22, 26))
        if self._logo_small:
            tk.Label(brand, image=self._logo_small, bg=PANEL).pack(side="left", padx=(0, 11))
        brand_text = tk.Frame(brand, bg=PANEL)
        brand_text.pack(side="left")
        tk.Label(brand_text, text="SENTINEL", bg=PANEL, fg=TEXT,
                 font=("Segoe UI Semibold", 14)).pack(anchor="w")
        tk.Label(brand_text, text="Antivirus", bg=PANEL, fg=TEXT_MUTED, font=FONT_SMALL).pack(anchor="w")

        self.nav = {}
        for key, icon, label in [
            ("dashboard", "home", "Dashboard"),
            ("scan", "scan", "Scanner"),
            ("protection", "shield", "Real-Time Protection"),
            ("quarantine", "lock", "Quarantine"),
            ("activity", "history", "Detection History"),
        ]:
            item = NavItem(sidebar, icon, label, lambda k=key: self._show_page(k))
            item.pack(fill="x")
            self.nav[key] = item

        status = RoundedCard(sidebar, bg=CARD, outer=PANEL, radius=10, padx=14, pady=12)
        status.pack(side="bottom", fill="x", padx=16, pady=18)
        self.side_status_icon = icon_label(status.body, "shield", 16, fg=BAD)
        self.side_status_icon.pack(side="left", padx=(0, 10))
        col = tk.Frame(status.body, bg=CARD)
        col.pack(side="left")
        self.side_status_title = tk.Label(col, text="Checking...", font=FONT_BOLD, fg=TEXT, bg=CARD)
        self.side_status_title.pack(anchor="w")
        self.side_status_sub = tk.Label(col, text="", font=FONT_SMALL, fg=TEXT_MUTED, bg=CARD)
        self.side_status_sub.pack(anchor="w")

        self.content = tk.Frame(self, bg=BG)
        self.content.pack(side="left", fill="both", expand=True, padx=30, pady=26)

        self.pages = {}
        self._build_dashboard_page()
        self._build_scan_page()
        self._build_protection_page()
        self._build_quarantine_page()
        self._build_activity_page()

    def _show_page(self, key):
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

    # ---------------------------------------------------------- dashboard --
    def _build_dashboard_page(self):
        page = tk.Frame(self.content, bg=BG)
        self.pages["dashboard"] = page

        hero = RoundedCard(page, radius=16, padx=34, pady=30)
        hero.pack(fill="x")
        self.hero_ring = Ring(hero.body, size=156)
        self.hero_ring.pack(side="left")
        text = tk.Frame(hero.body, bg=CARD)
        text.pack(side="left", fill="x", expand=True, padx=(34, 0))
        self.hero_title = tk.Label(text, text="Checking protection...", font=FONT_HERO, fg=TEXT, bg=CARD)
        self.hero_title.pack(anchor="w")
        self.hero_sub = tk.Label(text, text="", font=FONT, fg=TEXT_MUTED, bg=CARD,
                                 wraplength=420, justify="left", anchor="w")
        self.hero_sub.pack(anchor="w", fill="x", pady=(6, 20))
        # Wrap to whatever width the hero text column actually gets.
        text.bind("<Configure>", lambda e: self.hero_sub.configure(wraplength=max(200, e.width - 10)))
        buttons = tk.Frame(text, bg=CARD)
        buttons.pack(anchor="w")
        ttk.Button(buttons, text="Scan now", style="Hero.TButton",
                   command=self._quick_scan).pack(side="left")
        self.hero_protect_btn = ttk.Button(buttons, text="Turn on protection", style="Ghost.TButton",
                                           command=self._toggle_protection)

        cards = tk.Frame(page, bg=BG)
        cards.pack(fill="x", pady=(18, 0))
        for i in range(3):
            cards.columnconfigure(i, weight=1, uniform="cards")

        scan_card = RoundedCard(cards, command=lambda: self._show_page("scan"))
        scan_card.grid(row=0, column=0, sticky="nsew", padx=(0, 9))
        self._card_header(scan_card.body, "scan", "Scanner")
        self.dash_scan_value = tk.Label(scan_card.body, text="Never", font=FONT_LARGE, fg=TEXT, bg=CARD)
        self.dash_scan_value.pack(anchor="w", pady=(14, 0))
        self.dash_scan_sub = tk.Label(scan_card.body, text="Last scan", font=FONT_SMALL,
                                      fg=TEXT_MUTED, bg=CARD)
        self.dash_scan_sub.pack(anchor="w")

        rtp_card = RoundedCard(cards, command=lambda: self._show_page("protection"))
        rtp_card.grid(row=0, column=1, sticky="nsew", padx=9)
        self._card_header(rtp_card.body, "shield", "Protection")
        value_row = tk.Frame(rtp_card.body, bg=CARD)
        value_row.pack(fill="x", pady=(14, 0))
        self.dash_rtp_value = tk.Label(value_row, text="—", font=FONT_LARGE, fg=TEXT, bg=CARD)
        self.dash_rtp_value.pack(side="left")
        self.dash_switch = ToggleSwitch(value_row, command=self._toggle_protection)
        self.dash_switch.pack(side="right")
        self.dash_rtp_sub = tk.Label(rtp_card.body, text="", font=FONT_SMALL, fg=TEXT_MUTED, bg=CARD)
        self.dash_rtp_sub.pack(anchor="w")

        q_card = RoundedCard(cards, command=lambda: self._show_page("quarantine"))
        q_card.grid(row=0, column=2, sticky="nsew", padx=(9, 0))
        self._card_header(q_card.body, "lock", "Quarantine")
        self.dash_q_value = tk.Label(q_card.body, text="0 items", font=FONT_LARGE, fg=TEXT, bg=CARD)
        self.dash_q_value.pack(anchor="w", pady=(14, 0))
        tk.Label(q_card.body, text="Isolated so they can't run", font=FONT_SMALL,
                 fg=TEXT_MUTED, bg=CARD).pack(anchor="w")

        recent = RoundedCard(page, radius=16, padx=22, pady=16)
        recent.pack(fill="both", expand=True, pady=(18, 0))
        head = tk.Frame(recent.body, bg=CARD)
        head.pack(fill="x")
        tk.Label(head, text="Recent detections", font=FONT_BOLD, fg=TEXT, bg=CARD).pack(side="left")
        see_all = tk.Label(head, text="See all", font=FONT_SMALL, fg=ACCENT, bg=CARD, cursor="hand2")
        see_all.pack(side="right")
        see_all.bind("<Button-1>", lambda e: self._show_page("activity"))
        self.recent_list = tk.Frame(recent.body, bg=CARD)
        self.recent_list.pack(fill="both", expand=True, pady=(8, 0))

        footer = tk.Frame(page, bg=BG)
        footer.pack(fill="x", pady=(12, 0))
        self.dash_footer = tk.Label(footer, text="", font=FONT_SMALL, fg=TEXT_MUTED, bg=BG)
        self.dash_footer.pack(side="left")
        self.update_link = tk.Label(footer, text="Update now", font=FONT_SMALL, fg=ACCENT, bg=BG,
                                    cursor="hand2")
        self.update_link.pack(side="left", padx=(10, 0))
        self.update_link.bind("<Button-1>", lambda e: self._start_intel_update())
        self._updating = False

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
            icon_label(self.recent_list, "check", 18, fg=GOOD).pack(pady=(18, 6))
            tk.Label(self.recent_list, text="No threats detected recently", font=FONT,
                     fg=TEXT_MUTED, bg=CARD).pack()
            return
        for path, verdict, detail, when in rows:
            is_threat = verdict == "signature_match"
            row = tk.Frame(self.recent_list, bg=CARD)
            row.pack(fill="x", pady=5)
            icon_label(row, "warning", 13, fg=BAD if is_threat else WARN).pack(side="left", padx=(0, 12))
            tk.Label(row, text=Path(path).name, font=FONT_BOLD, fg=TEXT, bg=CARD).pack(side="left")
            tk.Label(row, text=clip(detail, 44), font=FONT_SMALL, fg=TEXT_MUTED,
                     bg=CARD).pack(side="left", padx=(10, 0))
            tk.Label(row, text=format_time(when), font=FONT_SMALL, fg=TEXT_MUTED,
                     bg=CARD).pack(side="right")

    def _card_header(self, body, icon, title):
        row = tk.Frame(body, bg=CARD)
        row.pack(fill="x")
        badge = tk.Frame(row, bg=BORDER, width=34, height=34)
        badge.pack(side="left")
        badge.pack_propagate(False)
        icon_label(badge, icon, 14, fg=ACCENT, bg=BORDER).pack(expand=True)
        tk.Label(row, text=title, font=FONT_BOLD, fg=TEXT, bg=CARD).pack(side="left", padx=(12, 0))
        return row

    def _refresh_dashboard(self):
        last = self.settings.get("last_scan")
        if last:
            when = datetime.fromisoformat(last["time"])
            found = last["flagged"]
            self.dash_scan_value.configure(text=_relative(when))
            self.dash_scan_sub.configure(
                text=f"{last['files']:,} files checked · "
                     + ("no threats found" if not found else f"{found} flagged"))
        else:
            self.dash_scan_value.configure(text="Never")
            self.dash_scan_sub.configure(text="Run your first scan")
        count = database.quarantine_count()
        self.dash_q_value.configure(text=f"{count} item{'s' if count != 1 else ''}")
        self._refresh_intel_footer()
        self._refresh_recent()

    # ------------------------------------------------------ threat updates --
    def _refresh_intel_footer(self):
        if self._updating:
            return
        info = threat_intel.stats()
        if info["updated"]:
            age = _relative(info["updated"].astimezone())
            self.dash_footer.configure(
                text=f"{info['hashes']:,} malware fingerprints · {info['rules']:,} YARA rules "
                     f"· Updated {age[0].lower() + age[1:]}", fg=TEXT_MUTED)
        else:
            self.dash_footer.configure(text="Threat database not downloaded yet", fg=WARN)

    def _start_intel_update(self):
        if self._updating:
            return
        self._updating = True
        self.update_link.pack_forget()
        self.dash_footer.configure(text="Starting update...", fg=TEXT_MUTED)

        def work():
            try:
                result = threat_intel.update(lambda msg: self.event_queue.put(("intel_progress", msg)))
                self.event_queue.put(("intel_done", result))
            except Exception as e:
                self.event_queue.put(("intel_done", e))

        threading.Thread(target=work, daemon=True).start()

    def _on_intel_done(self, result):
        self._updating = False
        self.update_link.pack(side="left", padx=(10, 0))
        if isinstance(result, Exception):
            self.dash_footer.configure(text=f"Update failed: {result}", fg=BAD)
        else:
            self._refresh_intel_footer()

    # ---------------------------------------------------------------- scan --
    def _build_scan_page(self):
        page = tk.Frame(self.content, bg=BG)
        self.pages["scan"] = page
        page_header(page, "Scanner", "Check a folder for known threats and suspicious files.")

        card = RoundedCard(page, radius=16, padx=30, pady=26)
        card.pack(fill="x")
        self.scan_ring = Ring(card.body, size=150)
        self.scan_ring.pack(side="left")
        self.scan_ring.show(BORDER, glyph="scan", glyph_color=TEXT_MUTED)
        right = tk.Frame(card.body, bg=CARD)
        right.pack(side="left", fill="x", expand=True, padx=(30, 0))

        tk.Label(right, text="What do you want to scan?", font=FONT_LARGE, fg=TEXT, bg=CARD).pack(anchor="w")
        chips = tk.Frame(right, bg=CARD)
        chips.pack(anchor="w", pady=(12, 8))
        self.scan_target = tk.StringVar(value=default_watch_path())
        self._chips = {}
        for key, label in (("downloads", "Downloads"), ("desktop", "Desktop"), ("documents", "Documents")):
            folder = str(paths.known_folder(key))
            chip = RoundedCard(chips, bg=BORDER, outer=CARD, radius=8, padx=14, pady=7,
                               hover_bg=CARD_HOVER, command=lambda f=folder: self._pick_target(f))
            tk.Label(chip.body, text=label, font=FONT, fg=TEXT, bg=BORDER).pack()
            chip.pack(side="left", padx=(0, 8))
            self._chips[folder] = chip
        other = RoundedCard(chips, bg=BORDER, outer=CARD, radius=8, padx=14, pady=7,
                            hover_bg=CARD_HOVER, command=self._browse_scan_path)
        tk.Label(other.body, text="Choose folder...", font=FONT, fg=TEXT, bg=BORDER).pack()
        other.pack(side="left")
        self.scan_target_label = tk.Label(right, text="", font=FONT_SMALL, fg=TEXT_MUTED, bg=CARD)
        self.scan_target_label.pack(anchor="w", pady=(0, 16))

        action = tk.Frame(right, bg=CARD)
        action.pack(anchor="w")
        self.scan_btn = ttk.Button(action, text="Scan now", style="Hero.TButton", command=self._start_scan)
        self.scan_btn.pack(side="left")
        self.scan_status = tk.Label(action, text="", font=FONT, fg=TEXT_MUTED, bg=CARD)
        self.scan_status.pack(side="left", padx=(16, 0))
        self._pick_target(self.scan_target.get())

        results = RoundedCard(page, radius=16, padx=22, pady=18)
        results.pack(fill="both", expand=True, pady=(16, 0))
        head = tk.Frame(results.body, bg=CARD)
        head.pack(fill="x", pady=(0, 8))
        tk.Label(head, text="Results", font=FONT_BOLD, fg=TEXT, bg=CARD).pack(side="left")
        ttk.Button(head, text="Quarantine selected", style="Danger.TButton",
                   command=self._quarantine_selected_scan_results).pack(side="right")

        table = tk.Frame(results.body, bg=CARD)
        table.pack(fill="both", expand=True)
        self.scan_tree = ttk.Treeview(table, columns=("file", "verdict", "detail"),
                                      show="headings", selectmode="extended")
        for col, label, width in (("file", "File", 360), ("verdict", "Verdict", 110), ("detail", "Detail", 260)):
            self.scan_tree.heading(col, text=label, anchor="w")
            self.scan_tree.column(col, width=width, anchor="w", stretch=col == "file")
        self.scan_tree.pack(fill="both", expand=True)
        self.scan_tree.tag_configure("threat", foreground=BAD)
        self.scan_tree.tag_configure("suspicious", foreground=WARN)
        self.scan_tree.tag_configure("skipped", foreground=TEXT_MUTED)
        self.scan_empty = EmptyState(table, "scan", "No results yet",
                                     "Pick a folder and press Scan now. Anything flagged shows up here.")
        self.scan_empty.show()
        self._scan_result_map = {}

    def _pick_target(self, folder):
        self.scan_target.set(folder)
        for path, chip in self._chips.items():
            chip.set_rest(ACCENT_DARK if path == folder else BORDER)
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
            messagebox.showerror("Sentinel", f"Folder does not exist:\n{target}")
            return
        self.scan_tree.delete(*self.scan_tree.get_children())
        self._scan_result_map.clear()
        self.scan_empty.hide()
        self.scan_btn.configure(state="disabled", text="Scanning...")
        self.scan_ring.spin("0", "files checked")
        self.scan_status.configure(text=f"Scanning {target.name or target}...", fg=TEXT_MUTED)
        threading.Thread(target=self._scan_worker, args=(target,), daemon=True).start()

    def _scan_worker(self, target: Path):
        total = flagged = 0
        for result in scanner.scan_directory(target, recursive=True):
            total += 1
            if result.verdict in ("signature_match", "suspicious"):
                flagged += 1
                self.event_queue.put(("scan_result", result))
            elif result.verdict == "error":
                self.event_queue.put(("scan_result", result))
            if total % 25 == 0:
                self.event_queue.put(("scan_progress", (total, flagged)))
        self.event_queue.put(("scan_done", (target, total, flagged)))

    def _on_scan_result(self, result):
        if result.verdict == "signature_match":
            tag, verdict, detail = "threat", "Threat", result.signature_name
        elif result.verdict == "suspicious":
            tag, verdict, detail = "suspicious", "Suspicious", "; ".join(result.heuristic_flags)
        else:
            tag, verdict, detail = "skipped", "Skipped", result.error or ""
        item_id = self.scan_tree.insert("", "end", values=(shorten(str(result.path), 70), verdict, detail),
                                        tags=(tag,))
        if tag != "skipped":
            self._scan_result_map[item_id] = result

    def _on_scan_progress(self, payload):
        total, flagged = payload
        self.scan_ring.set_text(f"{total:,}")
        self.scan_status.configure(
            text=f"{flagged} flagged so far" if flagged else "Nothing flagged so far")

    def _on_scan_done(self, payload):
        target, total, flagged = payload
        self.scan_btn.configure(state="normal", text="Scan now")
        if flagged:
            self.scan_ring.show(BAD, glyph="warning", text=f"{flagged} flagged")
            self.scan_status.configure(text=f"Found {flagged} item{'s' if flagged != 1 else ''} "
                                            f"in {total:,} files", fg=BAD)
        else:
            self.scan_ring.show(GOOD, glyph="check", text="No threats")
            self.scan_status.configure(text=f"No threats found in {total:,} files", fg=GOOD)
            if not self.scan_tree.get_children():
                self.scan_empty.show("No threats found",
                                     f"Checked {total:,} files in {shorten(str(target), 60)}.")
        settings.save(last_scan={"time": datetime.now().astimezone().isoformat(),
                                 "files": total, "flagged": flagged, "path": str(target)})
        self.settings = settings.load()
        self._refresh_dashboard()

    def _quarantine_selected_scan_results(self):
        selected = [i for i in self.scan_tree.selection() if i in self._scan_result_map]
        if not selected:
            return
        count = 0
        for item_id in selected:
            result = self._scan_result_map.pop(item_id)
            try:
                quarantine.quarantine_file(result.path, result.signature_name or "manual")
                self.scan_tree.set(item_id, "verdict", "Quarantined")
                self.scan_tree.item(item_id, tags=("skipped",))
                count += 1
            except OSError as e:
                messagebox.showerror("Sentinel", f"Could not quarantine {result.path}:\n{e}")
        if count:
            self._refresh_dashboard()

    # --------------------------------------------------------- protection --
    def _build_protection_page(self):
        page = tk.Frame(self.content, bg=BG)
        self.pages["protection"] = page
        page_header(page, "Real-Time Protection",
                    "Blocks threats as they arrive, even when this window is closed.")

        main = RoundedCard(page, radius=16, padx=24, pady=16)
        main.pack(fill="x")
        top = tk.Frame(main.body, bg=CARD)
        top.pack(fill="x")
        self.rtp_icon = icon_label(top, "shield", 26, fg=BAD)
        self.rtp_icon.pack(side="left", padx=(0, 16))
        col = tk.Frame(top, bg=CARD)
        col.pack(side="left", fill="x", expand=True)
        self.rtp_title = tk.Label(col, text="Real-Time Protection", font=FONT_LARGE, fg=TEXT, bg=CARD)
        self.rtp_title.pack(anchor="w")
        self.rtp_sub = tk.Label(col, text="", font=FONT, fg=TEXT_MUTED, bg=CARD)
        self.rtp_sub.pack(anchor="w")
        self.rtp_switch = ToggleSwitch(top, command=self._toggle_protection)
        self.rtp_switch.pack(side="right")

        tk.Frame(main.body, bg=BORDER, height=1).pack(fill="x", pady=12)
        startup = tk.Frame(main.body, bg=CARD)
        startup.pack(fill="x")
        tk.Label(startup, text="Start with Windows", font=FONT_BOLD, fg=TEXT, bg=CARD).pack(side="left")
        startup_text = "Turns protection back on when you sign in"
        if not autostart.supported():
            startup_text += " (installed app only)"
        tk.Label(startup, text=startup_text, font=FONT_SMALL, fg=TEXT_MUTED,
                 bg=CARD).pack(side="left", padx=(10, 0))
        self.autostart_switch = ToggleSwitch(startup, command=self._on_autostart_toggled,
                                             on=autostart.is_enabled())
        self.autostart_switch.pack(side="right")
        self.autostart_switch.set_enabled(autostart.supported())

        layers = RoundedCard(page, radius=16, padx=24, pady=6)
        layers.pack(fill="x", pady=(12, 0))
        self.layer_pills = []
        self.download_desc = self._layer_row(layers.body, "download", "Download protection", "", change=True)
        self._layer_row(layers.body, "apps", "Program protection",
                        "Checks every program the moment it starts against known threats.")
        self._layer_row(layers.body, "power", "Startup protection",
                        "Alerts you when a program adds itself to startup or scheduled tasks.")
        self._layer_row(layers.body, "lock", "Ransomware protection",
                        "Watches Documents, Desktop, Pictures, Music, Videos and Downloads.", last=True)

        log_card = RoundedCard(page, radius=16, padx=20, pady=14)
        log_card.pack(fill="both", expand=True, pady=(12, 0))
        tk.Label(log_card.body, text="Live activity", font=FONT_BOLD, fg=TEXT, bg=CARD).pack(anchor="w")
        self.protection_log = tk.Text(
            log_card.body, bg=CARD, fg=TEXT_MUTED, insertbackground=TEXT, relief="flat",
            font=FONT_MONO, wrap="word", height=6, bd=0, highlightthickness=0,
        )
        self.protection_log.pack(fill="both", expand=True, pady=(8, 0))
        self.protection_log.configure(state="disabled")
        self.protection_log.tag_configure("threat", foreground=BAD)
        self.protection_log.tag_configure("warn", foreground=WARN)
        self.protection_log.tag_configure("info", foreground=TEXT)

    def _layer_row(self, body, icon, title, desc, change=False, last=False):
        row = tk.Frame(body, bg=CARD)
        row.pack(fill="x", pady=8)
        icon_label(row, icon, 16, fg=ACCENT).pack(side="left", padx=(0, 16))
        col = tk.Frame(row, bg=CARD)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, text=title, font=FONT_BOLD, fg=TEXT, bg=CARD).pack(anchor="w")
        desc_label = tk.Label(col, text=desc, font=FONT_SMALL, fg=TEXT_MUTED, bg=CARD)
        desc_label.pack(anchor="w")
        status = pill(row)
        status.pack(side="right")
        self.layer_pills.append(status)
        if change:
            ttk.Button(row, text="Change folder", style="Ghost.TButton",
                       command=self._change_watch_folder).pack(side="right", padx=(0, 12))
        if not last:
            tk.Frame(body, bg=BORDER, height=1).pack(fill="x")
        return desc_label

    def _change_watch_folder(self):
        path = filedialog.askdirectory(initialdir=self.watch_path)
        if not path:
            return
        self.watch_path = str(Path(path))
        settings.save(watch_path=self.watch_path)
        self._update_protection_texts()
        if launcher.agent_running():  # restart so the agent picks up the new folder
            self._set_transitioning("Restarting protection...")
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
        color = GOOD if on else BAD
        folder = Path(self.watch_path).name or self.watch_path

        self.side_status_icon.configure(fg=color)
        self.side_status_title.configure(text="Protected" if on else "Not protected")
        self.side_status_sub.configure(text="Real-time protection on" if on else "Protection is off")

        self.hero_ring.show(color, image=self._logo_big)
        self.hero_title.configure(text="You're protected" if on else "Protection is off",
                                  fg=TEXT if on else BAD)
        self.hero_sub.configure(
            text=f"Sentinel is watching {folder}, running programs, startup and your personal "
                 f"files for threats."
            if on else "New downloads and running programs aren't being checked. "
                       "Turn real-time protection on to stay protected.")
        if on:
            self.hero_protect_btn.pack_forget()
        else:
            self.hero_protect_btn.pack(side="left", padx=(10, 0))

        for switch in (self.dash_switch, self.rtp_switch):
            switch.set(on)
            switch.set_enabled(True)
        self.dash_rtp_value.configure(text="On" if on else "Off", fg=GOOD if on else BAD)
        self.rtp_icon.configure(fg=color)
        self.rtp_title.configure(text="Real-Time Protection is on" if on else "Real-Time Protection is off")
        for p in self.layer_pills:
            set_pill(p, on)
        self._update_protection_texts()

    def _update_protection_texts(self):
        on = bool(self.protection_on)
        folder = Path(self.watch_path).name or self.watch_path
        self.dash_rtp_sub.configure(text=f"Watching {folder}" if on else "Not watching")
        self.rtp_sub.configure(text="Running in the background, even when this window is closed."
                               if on else "Threats won't be caught until you turn this on.")
        self.download_desc.configure(text=f"Scans new files in {self.watch_path} the moment they arrive.")

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
            messagebox.showerror("Sentinel", f"Folder does not exist:\n{self.watch_path}")
            return
        settings.save(protection_on=True, watch_path=self.watch_path)
        self._set_transitioning("Starting protection...")
        launcher.start_agent()
        self._wait_for_agent(True, deadline=40)

    def _stop_protection(self):
        settings.save(protection_on=False)
        self._set_transitioning("Stopping protection...")
        self.update_idletasks()
        if not launcher.stop_agent():
            messagebox.showerror("Sentinel", "Protection didn't stop in time. Try again.")
        self._set_protection_indicator(launcher.agent_running())

    def _wait_for_agent(self, want_running, deadline):
        if launcher.agent_running() == want_running:
            self._set_protection_indicator(want_running)
        elif deadline <= 0:
            self._set_protection_indicator(launcher.agent_running())
            messagebox.showerror("Sentinel", "Real-time protection couldn't start. Try again.")
        else:
            self.after(250, self._wait_for_agent, want_running, deadline - 1)

    def _on_autostart_toggled(self):
        want = not self.autostart_switch.on
        try:
            autostart.set_enabled(want)
        except OSError as e:
            messagebox.showerror("Sentinel", f"Couldn't change the startup setting:\n{e}")
        self.autostart_switch.set(autostart.is_enabled())

    # -------------------------------------------------------- quarantine --
    def _table_card(self, page, columns, empty):
        card = RoundedCard(page, radius=16, padx=22, pady=16)
        card.pack(fill="both", expand=True)
        table = tk.Frame(card.body, bg=CARD)
        table.pack(fill="both", expand=True)
        tree = ttk.Treeview(table, columns=[c[0] for c in columns], show="headings")
        for i, (col, label, width) in enumerate(columns):
            tree.heading(col, text=label, anchor="w")
            # Only the first (file) column stretches, so the rest never get pushed off-screen.
            tree.column(col, width=width, minwidth=width if i else 120, anchor="w", stretch=i == 0)
        tree.pack(fill="both", expand=True)
        tree.tag_configure("threat", foreground=BAD)
        tree.tag_configure("suspicious", foreground=WARN)
        tree.tag_configure("muted", foreground=TEXT_MUTED)
        return tree, EmptyState(table, *empty)

    def _build_quarantine_page(self):
        page = tk.Frame(self.content, bg=BG)
        self.pages["quarantine"] = page
        page_header(page, "Quarantine", "Files isolated so they can't run. Restore anything you trust.")

        self.q_tree, self.q_empty = self._table_card(
            page,
            (("file", "File", 300), ("reason", "Reason", 200), ("when", "Quarantined", 160)),
            ("lock", "Quarantine is empty", "Threats you quarantine are moved here, where they can't run."),
        )
        self.q_tree.configure(selectmode="browse")
        btn_row = tk.Frame(page, bg=BG)
        btn_row.pack(fill="x", pady=(14, 0))
        ttk.Button(btn_row, text="Restore", style="Ghost.TButton",
                   command=self._restore_selected_quarantine).pack(side="left")
        ttk.Button(btn_row, text="Delete permanently", style="Danger.TButton",
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
        result = quarantine.restore_file(int(sel[0]))
        if result:
            messagebox.showinfo("Sentinel", f"Restored to:\n{result}")
            self._refresh_quarantine()
        else:
            messagebox.showerror("Sentinel", "Could not restore that entry.")

    def _delete_selected_quarantine(self):
        sel = self.q_tree.selection()
        if not sel:
            return
        if messagebox.askyesno("Sentinel", "Permanently delete this file? This cannot be undone."):
            quarantine.delete_permanently(int(sel[0]))
            self._refresh_quarantine()

    # ----------------------------------------------------------- activity --
    def _build_activity_page(self):
        page = tk.Frame(self.content, bg=BG)
        self.pages["activity"] = page
        page_header(page, "Detection History", "Everything Sentinel has flagged, newest first.")
        self.activity_tree, self.activity_empty = self._table_card(
            page,
            (("file", "File", 260), ("verdict", "Verdict", 100), ("detail", "Detail", 230),
             ("when", "When", 140)),
            ("history", "Nothing detected yet", "Threats and suspicious files Sentinel finds will be listed here."),
        )

    def _refresh_activity(self):
        self.activity_tree.delete(*self.activity_tree.get_children())
        rows = database.get_recent_scans()
        labels = {"signature_match": ("Threat", "threat"), "suspicious": ("Suspicious", "suspicious"),
                  "deleted": ("Deleted", "muted")}
        for path, verdict, detail, when in rows:
            label, tag = labels.get(verdict, (verdict.title(), ""))
            self.activity_tree.insert("", "end", values=(shorten(path, 44), label, clip(detail, 36),
                                                         format_time(when)), tags=(tag,))
        self.activity_empty.show() if not rows else self.activity_empty.hide()

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
                elif kind == "show":
                    self._show_window()
                elif kind == "intel_progress":
                    self.dash_footer.configure(text=payload, fg=TEXT_MUTED)
                elif kind == "intel_done":
                    self._on_intel_done(payload)
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
