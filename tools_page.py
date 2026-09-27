"""The Tools tab: a hub for the browser extension checker, the junk cleaner, the
recovery checklist and the password leak check, each with a live summary.
Also the small helpers the tool pages share.
"""
import tkinter as tk

import theme as C
from core import recovery
from core.i18n import number, t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from widgets import RoundedCard, icon_label


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
        self.grid_frame = tk.Frame(self, bg=C.BG)
        self.grid_frame.pack(fill="both", expand=True)
        self._render()

    def refresh(self):
        """Fills in the cards' summaries (both checks are quick and read-only)."""
        if self.app.ext_state["items"] is None:
            self.app.ext_page.scan()
        if self.app.clean_state["found"] is None:
            self.app.cleaner_page.analyze()
        self._render()

    def _render(self):
        for child in self.grid_frame.winfo_children():
            child.destroy()
        grid = self.grid_frame
        for i in range(2):
            grid.columnconfigure(i, weight=1, uniform="tools")
            grid.rowconfigure(i, weight=1, uniform="toolrows")
        cards = [
            ("puzzle", t("ext_title"), t("tools_ext_desc"), self._ext_status(), "extensions"),
            ("broom", t("clean_title"), t("tools_clean_desc"), self._clean_status(), "cleaner"),
            ("health", t("rec_title"), t("tools_rec_desc"), self._rec_status(), "recovery"),
            ("key", t("pw_title"), t("tools_pw_desc"), (t("tools_pw_status"), C.TEXT_MUTED), "security"),
        ]
        for i, (icon, title, desc, (status, color), target) in enumerate(cards):
            card = RoundedCard(grid, radius=16, padx=22, pady=18, command=lambda p=target: self._open(p))
            card.grid(row=i // 2, column=i % 2, sticky="nsew", padx=(0 if i % 2 == 0 else 7, 7 if i % 2 == 0 else 0),
                      pady=(0 if i < 2 else 7, 7 if i < 2 else 0))
            head = tk.Frame(card.body, bg=C.CARD)
            head.pack(fill="x")
            badge = tk.Frame(head, bg=C.BORDER, width=40, height=40)
            badge.pack(side="left")
            badge.pack_propagate(False)
            icon_label(badge, icon, 16, fg=C.ACCENT, bg=C.BORDER).pack(expand=True)
            tk.Label(head, text=title, font=FONT_LARGE, fg=C.TEXT, bg=C.CARD).pack(side="left", padx=(14, 0))
            tk.Label(head, text="›", font=FONT_LARGE, fg=C.TEXT_MUTED, bg=C.CARD).pack(side="right")
            text = tk.Label(card.body, text=desc, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left",
                            anchor="w")
            text.pack(anchor="w", fill="x", pady=(12, 0))
            wrap_to_width(text, card.body, 180)
            tk.Label(card.body, text=status, font=FONT_BOLD, fg=color, bg=C.CARD, anchor="w").pack(
                anchor="sw", side="bottom", fill="x", pady=(10, 0))

    def _open(self, page):
        self.app._show_page(page)

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
