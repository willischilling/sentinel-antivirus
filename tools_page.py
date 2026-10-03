"""The Tools tab: a hub for the browser extension checker, the junk cleaner, the
recovery checklist and the password leak check, each with a live summary.
Also the small helpers the tool pages share.
"""
import tkinter as tk

import theme as C
from core import privacy, recovery
from core.i18n import number, t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from widgets import RoundedCard, ScrollArea, icon_label


def size_text(size: int) -> str:
    if size >= 1024 ** 3:
        return f"{size / 1024 ** 3:.1f} GB"
    if size >= 1024 ** 2:
        return f"{size / 1024 ** 2:.0f} MB"
    return f"{max(size, 0) / 1024:.0f} KB"


def subpage_header(page, app, title, subtitle, back_key, back_page):
    """A page title with a small "‹ Back" link above it."""
    back = tk.Label(page, text="‹  " + t(back_key), font=FONT_SMALL, fg=C.ACCENT, bg=C.BG, cursor="hand2")
    back.pack(anchor="w")
    back.bind("<Button-1>", lambda e: app._show_page(back_page))
    tk.Label(page, text=title, font=(C.DISPLAY, 18), fg=C.TEXT, bg=C.BG).pack(anchor="w")
    tk.Label(page, text=subtitle, font=FONT, fg=C.TEXT_MUTED, bg=C.BG).pack(anchor="w", pady=(2, 16))


def wrap_to_width(label, container, minimum=150, reserve=4):
    """Wraps the label to the container's width, minus `reserve` pixels used by other widgets beside it."""
    container.bind("<Configure>", lambda e: label.configure(wraplength=max(minimum, e.width - reserve)), add="+")


class ToolsPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        tk.Label(self, text=t("nav_tools"), font=(C.DISPLAY, 18), fg=C.TEXT, bg=C.BG).pack(anchor="w")
        tk.Label(self, text=t("tools_sub"), font=FONT, fg=C.TEXT_MUTED, bg=C.BG).pack(anchor="w", pady=(2, 16))
        self.scroll = ScrollArea(self, bg=C.BG)
        self.scroll.pack(fill="both", expand=True)
        self.grid_frame = self.scroll.inner
        self._render()
        self.scroll.to_top()

    def refresh(self):
        """Fills in the cards' summaries (both checks are quick and read-only)."""
        if self.app.ext_state["items"] is None:
            self.app.ext_page.scan()
        if self.app.clean_state["found"] is None:
            self.app.cleaner_page.analyze()
        if self.app.guard_state["items"] is None:
            self.app.guard_page.refresh()
        if self.app.startup_state["apps"] is None:
            self.app.startup_page.refresh()
        self._render()

    def _render(self):
        for child in self.grid_frame.winfo_children():
            child.destroy()
        sections = [
            ("tools_sec_accounts", [
                ("key", t("pw_title"), t("tools_pw_desc"), (t("tools_pw_status"), C.TEXT_MUTED), "security"),
                ("lock", t("breach_title"), t("tools_breach_desc"), self._breach_status(), "breach"),
                ("health", t("rec_title"), t("tools_rec_desc"), self._rec_status(), "recovery"),
            ]),
            ("tools_sec_privacy", [
                ("scan", t("privacy_title"), t("tools_privacy_desc"), self._privacy_status(), "privacy"),
                ("globe", t("net_title"), t("tools_net_desc"), self._net_status(), "network"),
                ("power", t("hn_title"), t("tools_hn_desc"), self._homenet_status(), "homenet"),
                ("web", t("guard_title"), t("tools_guard_desc"), self._guard_status(), "guard"),
                ("warning", t("link_title"), t("tools_link_desc"), self._link_status(), "linkguard"),
            ]),
            ("tools_sec_speed", [
                ("broom", t("clean_title"), t("tools_clean_desc"), self._clean_status(), "cleaner"),
                ("power", t("startup_title"), t("tools_startup_desc"), self._startup_status(), "startup"),
            ]),
            ("tools_sec_files", [
                ("web", t("browser_title"), t("tools_browser_desc"), self._browser_status(), "browser"),
                ("puzzle", t("ext_title"), t("tools_ext_desc"), self._ext_status(), "extensions"),
                ("delete", t("shred_title"), t("tools_shred_desc"), (t("tools_shred_status"), C.TEXT_MUTED), "shred"),
                ("shield", t("sandbox_title"), t("tools_sandbox_desc"), self._sandbox_status(), "sandbox"),
            ]),
            ("tools_sec_report", [
                ("history", t("report_title"), t("tools_report_desc"), self._report_status(), "report"),
            ]),
        ]
        for s_i, (heading, cards) in enumerate(sections):
            tk.Label(self.grid_frame, text=t(heading).upper(), font=(C.UI_SEMIBOLD, 9), fg=C.TEXT_MUTED,
                     bg=C.BG).pack(anchor="w", pady=(0 if s_i == 0 else 14, 6))
            grid = tk.Frame(self.grid_frame, bg=C.BG)
            grid.pack(fill="x", padx=(0, 8))
            for i in range(2):
                grid.columnconfigure(i, weight=1, uniform="tools")
            for i, (icon, title, desc, (status, color), target) in enumerate(cards):
                card = RoundedCard(grid, radius=14, padx=18, pady=12, command=lambda p=target: self._open(p))
                card.grid(row=i // 2, column=i % 2, sticky="nsew", padx=(0 if i % 2 == 0 else 6, 6 if i % 2 == 0 else 0),
                          pady=(0, 12))
                head = tk.Frame(card.body, bg=C.CARD)
                head.pack(fill="x")
                badge = tk.Frame(head, bg=C.BORDER, width=34, height=34)
                badge.pack(side="left")
                badge.pack_propagate(False)
                icon_label(badge, icon, 14, fg=C.ACCENT, bg=C.BORDER).pack(expand=True)
                tk.Label(head, text=title, font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left", padx=(12, 0))
                tk.Label(head, text="›", font=FONT_LARGE, fg=C.TEXT_MUTED, bg=C.CARD).pack(side="right")
                text = tk.Label(card.body, text=desc, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left",
                                anchor="w")
                text.pack(anchor="w", fill="x", pady=(8, 0))
                wrap_to_width(text, card.body, 180)
                tk.Label(card.body, text=status, font=FONT_BOLD, fg=color, bg=C.CARD, anchor="w").pack(
                    anchor="sw", side="bottom", fill="x", pady=(6, 0))

    def _open(self, page):
        if page == "browser":
            open_browser()
        else:
            self.app._show_page(page)

    @staticmethod
    def _browser_status():
        return (t("tools_browser_open"), C.ACCENT) if browser_command() else (t("tools_browser_missing"), C.TEXT_MUTED)

    def _privacy_status(self):
        try:
            live = privacy.in_use()
        except OSError:
            live = []
        if live:
            return t("tools_privacy_live", app=live[0].name), C.WARN
        return t("tools_privacy_idle"), C.GOOD

    def _net_status(self):
        result = self.app.net_state["result"]
        if result is None:
            return t("tools_net_none"), C.TEXT_MUTED
        return t("net_found", n=number(len(result.devices))), C.ACCENT

    def _homenet_status(self):
        result = self.app.homenet_state["result"]
        if result is None:
            return t("tools_hn_none"), C.TEXT_MUTED
        from core import homenet
        paused = homenet.paused_count(result.network_id)
        if paused:
            return t("hn_paused_n", n=number(paused)), C.WARN
        return t("hn_all_on"), C.GOOD

    def _breach_status(self):
        result = self.app.breach_state["result"]
        if result is None:
            return t("tools_breach_none"), C.TEXT_MUTED
        return (t("breach_found", n=number(len(result))), C.WARN) if result else (t("breach_none"), C.GOOD)

    @staticmethod
    def _link_status():
        from core import linkguard

        if not linkguard.enabled():
            return t("link_off"), C.TEXT_MUTED
        warned = len(linkguard.recent())
        return (t("tools_link_warned", n=number(warned)), C.WARN) if warned else (t("tools_link_on"), C.GOOD)

    def _startup_status(self):
        apps = self.app.startup_state["apps"]
        if apps is None:
            return t("tools_checking"), C.TEXT_MUTED
        return t("startup_count", on=number(sum(1 for a in apps if a.enabled)), total=number(len(apps))), C.ACCENT

    @staticmethod
    def _sandbox_status():
        from core import sandbox

        state = sandbox.status()
        return {"ready": (t("tools_sandbox_ready"), C.GOOD), "off": (t("tools_sandbox_off"), C.TEXT_MUTED)}.get(
            state, (t("sandbox_unsupported"), C.TEXT_MUTED))

    @staticmethod
    def _report_status():
        from core import report

        data = report.latest()
        if not data:
            return t("tools_report_none"), C.TEXT_MUTED
        return t("tools_report_score", score=data.get("score") if data.get("score") is not None else "–"), C.ACCENT

    def _guard_status(self):
        items = self.app.guard_state["items"]
        if items is None:
            return t("tools_checking"), C.TEXT_MUTED
        if items:
            return t("guard_found", n=number(len(items))), C.WARN
        return t("tools_guard_ok"), C.GOOD

    def _ext_status(self):
        s = self.app.ext_state
        if s["items"] is None:
            return t("tools_checking"), C.TEXT_MUTED
        bad = sum(1 for e in s["items"] if e.level in ("malicious", "flagged", "risky"))
        if bad:
            return t("ext_attention", n=number(bad)), C.BAD
        return t("tools_ext_ok", n=number(len(s["items"]))), C.GOOD

    def _clean_status(self):
        s = self.app.clean_state
        if s["found"] is None:
            return t("tools_checking"), C.TEXT_MUTED
        total = sum(f.size for k, f in s["found"].items() if k in s["selected"])
        return t("tools_clean_found", size=size_text(total)), C.ACCENT if total else C.GOOD

    @staticmethod
    def _rec_status():
        data = recovery.incident()
        if data and not data.get("resolved"):
            return t("rec_progress", done=len(data.get("done", [])), total=len(recovery.STEPS)), C.WARN
        return t("tools_rec_none"), C.TEXT_MUTED

    def handle(self, kind, payload):
        if self.winfo_exists():
            self._render()


def browser_command() -> list[str] | None:
    """How to start Sentinel Browser: the installed exe next to Sentinel's folder, or from source."""
    import sys
    from pathlib import Path

    if getattr(sys, "frozen", False):
        exe = Path(sys.executable).resolve().parent.parent / "browser" / "SentinelBrowser.exe"
        return [str(exe)] if exe.exists() else None
    script = Path(__file__).resolve().parent / "browser_main.py"
    return [sys.executable, str(script)] if script.exists() else None


def open_browser(url: str | None = None):
    import subprocess

    command = browser_command()
    if command:
        subprocess.Popen(command + ([url] if url else []))
