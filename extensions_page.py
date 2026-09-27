"""Browser extension checker page: every extension in every browser profile,
riskiest first, with why it was flagged and a button to manage it in the
browser. The list download and the scan run on worker threads.
"""
import threading
import tkinter as tk
from tkinter import messagebox, ttk

import theme as C
from core import extensions
from core.i18n import number, t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from tools_page import subpage_header, wrap_to_width
from widgets import Ring, RoundedCard, ScrollArea, icon_label, pill

LEVEL_STYLE = {  # level -> (pill key, color)
    "malicious": ("ext_level_malicious", "BAD"),
    "flagged": ("ext_level_flagged", "WARN"),
    "risky": ("ext_level_risky", "WARN"),
    "powerful": ("ext_level_powerful", "BORDER"),
}


def new_state() -> dict:
    return {"items": None, "busy": False, "error": None}


class ExtensionsPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        self.state = app.ext_state
        subpage_header(self, app, t("ext_title"), t("ext_sub"), "nav_tools", "tools")
        self.body = tk.Frame(self, bg=C.BG)
        self.body.pack(fill="both", expand=True)
        self._render()

    # ------------------------------------------------------------- work --
    def scan(self):
        s = self.state
        if s["busy"]:
            return
        s.update(busy=True, error=None)
        queue = self.app.event_queue

        def run():
            try:
                if not extensions.list_installed():
                    try:
                        extensions.install()
                    except Exception:
                        pass  # still show the list, rated without the known-bad list
                queue.put(("ext_done", (extensions.scan(), extensions.list_installed())))
            except Exception as e:
                queue.put(("ext_done", e))

        threading.Thread(target=run, daemon=True).start()
        if self.winfo_exists():
            self._render()

    def handle(self, kind, payload):
        s = self.state
        if isinstance(payload, Exception):
            s.update(busy=False, error=str(payload), items=s["items"] or [])
        else:
            items, have_list = payload
            s.update(busy=False, items=items, have_list=have_list)
        if self.winfo_exists():
            self._render()
        self.app.tools_page.handle(kind, payload)

    # ----------------------------------------------------------- render --
    def _render(self):
        for child in self.body.winfo_children():
            child.destroy()
        s = self.state
        items = s["items"]

        top = RoundedCard(self.body, radius=16, padx=24, pady=18)
        top.pack(fill="x")
        row = tk.Frame(top.body, bg=C.CARD)
        row.pack(fill="x")
        ring = Ring(row, size=72)
        ring.pack(side="left", padx=(0, 18))
        again = ttk.Button(row, text=t("check_again"), style="Ghost.TButton", command=self.scan)
        again.pack(side="right", anchor="n", padx=(12, 0))
        col = tk.Frame(row, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        if items is None:
            ring.spin("")
            title, sub = t("ext_checking"), t("ext_checking_sub")
        else:
            bad = [e for e in items if e.level in ("malicious", "flagged", "risky")]
            worst = bad[0].level if bad else None
            color = C.BAD if worst == "malicious" else C.WARN if bad else C.GOOD
            ring.show(color, glyph="warning" if bad else "check")
            browsers = len({e.browser_name for e in items})
            title = t("ext_attention", n=number(len(bad))) if bad else t("ext_all_good")
            sub = t("ext_summary", n=number(len(items)), browsers=number(browsers)) if items else t("ext_none_found")
            if not s.get("have_list", True):
                sub += " " + t("ext_no_list")
        tk.Label(col, text=title, font=FONT_LARGE, fg=C.TEXT, bg=C.CARD, anchor="w").pack(anchor="w", fill="x")
        sub_label = tk.Label(col, text=sub, font=FONT, fg=C.TEXT_MUTED, bg=C.CARD, justify="left", anchor="w")
        sub_label.pack(anchor="w", fill="x")
        wrap_to_width(sub_label, col)
        if s["busy"]:
            again.state(["disabled"])
        if s["error"]:
            tk.Label(top.body, text=t("fw_failed", error=s["error"]), font=FONT_SMALL, fg=C.BAD, bg=C.CARD,
                     wraplength=640, justify="left").pack(anchor="w", pady=(10, 0))

        card = RoundedCard(self.body, radius=16, padx=18, pady=14)
        card.pack(fill="both", expand=True, pady=(14, 0))
        area = ScrollArea(card.body)
        area.pack(fill="both", expand=True)
        for ext in items or []:
            self._row(area.inner, ext)
        note = tk.Frame(card.body, bg=C.CARD)
        note.pack(fill="x", pady=(8, 0))
        icon_label(note, "info", 11, fg=C.TEXT_MUTED).pack(side="left", anchor="n", padx=(0, 8), pady=1)
        text = tk.Label(note, text=t("ext_note"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left",
                        anchor="w")
        text.pack(side="left", fill="x", expand=True)
        wrap_to_width(text, note, 200, reserve=30)

    def _row(self, parent, ext):
        row = tk.Frame(parent, bg=C.CARD)
        row.pack(fill="x", pady=5, padx=(0, 8))
        style = LEVEL_STYLE.get(ext.level)
        color = getattr(C, style[1]) if style else C.TEXT_MUTED
        icon_label(row, "puzzle", 15, fg=color if ext.level != "powerful" else C.TEXT_MUTED).pack(
            side="left", anchor="n", padx=(4, 14), pady=3)
        manage = ttk.Button(row, text=t("ext_manage"), style="Ghost.TButton", command=lambda e=ext: self._manage(e))
        manage.pack(side="right", anchor="n")
        text = tk.Frame(row, bg=C.CARD)
        text.pack(side="left", fill="x", expand=True)
        title = tk.Frame(text, bg=C.CARD)
        title.pack(anchor="w")
        tk.Label(title, text=ext.name, font=FONT_BOLD, fg=C.TEXT if ext.enabled else C.TEXT_MUTED,
                 bg=C.CARD).pack(side="left")
        if style:
            pill(title, t(style[0]), color, fg="#0b1120" if ext.level != "powerful" else C.TEXT_MUTED).pack(
                side="left", padx=(8, 0))
        where = [ext.browser_name] + ([ext.profile] if ext.profile else [])
        if not ext.enabled:
            where.append(t("ext_off"))
        tk.Label(text, text="  ·  ".join(where), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, anchor="w").pack(
            anchor="w")
        details = []
        if ext.reason:
            details.append(t(ext.reason))
        if ext.source == "policy":
            details.append(t("ext_src_policy"))
        elif ext.source == "outside":
            details.append(t("ext_src_outside"))
        if ext.broad:
            details.append(t("ext_perm_all_sites"))
        details += [t(k) for k in ext.permissions]
        if details:
            label = tk.Label(text, text=" · ".join(details), font=FONT_SMALL, bg=C.CARD, justify="left", anchor="w",
                             fg=color if ext.level in ("malicious", "flagged", "risky") else C.TEXT_MUTED)
            label.pack(anchor="w", fill="x")
            wrap_to_width(label, text, 200)
        tk.Frame(parent, bg=C.BORDER, height=1).pack(fill="x", padx=(0, 8))

    def _manage(self, ext):
        try:
            opened = extensions.open_manager(ext)
        except OSError:
            opened = False
        if not opened:
            messagebox.showinfo("Sentinel", t("ext_manage_manual", browser=ext.browser_name, name=ext.name))
