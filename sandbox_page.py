"""Sandbox page: open a file inside Windows Sandbox (a throwaway copy of Windows),
or turn the Sandbox feature on if this Windows has it but it's off."""
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import theme as C
from core import context_menu, sandbox, settings
from core.i18n import t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from tools_page import subpage_header, wrap_to_width
from widgets import Ring, RoundedCard, ToggleSwitch, icon_label


class SandboxPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        self._busy = False
        self._error = None
        subpage_header(self, app, t("sandbox_title"), t("sandbox_sub"), "nav_tools", "tools")
        self.body = tk.Frame(self, bg=C.BG)
        self.body.pack(fill="both", expand=True)
        self._render()

    def refresh(self):
        self._render()

    def _render(self):
        for child in self.body.winfo_children():
            child.destroy()
        state = sandbox.status()
        pending = settings.load().get("sandbox_restart_needed") and state != "ready"

        card = RoundedCard(self.body, radius=16, padx=26, pady=20)
        card.pack(fill="x")
        row = tk.Frame(card.body, bg=C.CARD)
        row.pack(fill="x")
        ring = Ring(row, size=72)
        ring.pack(side="left", padx=(0, 20))
        col = tk.Frame(row, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        if state == "ready":
            ring.show(C.GOOD, glyph="shield", glyph_color=C.GOOD)
            title, sub = t("sandbox_ready"), t("sandbox_ready_sub")
        elif pending:
            ring.show(C.WARN, glyph="refresh", glyph_color=C.WARN)
            title, sub = t("sandbox_restart"), t("sandbox_restart_sub")
        elif state == "off":
            ring.show(C.BORDER, glyph="shield", glyph_color=C.TEXT_MUTED)
            title, sub = t("sandbox_off"), t("sandbox_off_sub")
        else:
            ring.show(C.BORDER, glyph="info", glyph_color=C.TEXT_MUTED)
            title, sub = t("sandbox_unsupported"), t("sandbox_unsupported_sub")
        tk.Label(col, text=title, font=FONT_LARGE, fg=C.TEXT, bg=C.CARD, anchor="w").pack(anchor="w", fill="x")
        desc = tk.Label(col, text=sub, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left", anchor="w")
        desc.pack(anchor="w", fill="x")
        wrap_to_width(desc, col)
        buttons = tk.Frame(card.body, bg=C.CARD)
        buttons.pack(anchor="w", pady=(16, 0))
        if state == "ready":
            ttk.Button(buttons, text=t("sandbox_pick"), style="Accent.TButton", command=self._pick).pack(side="left")
        elif state == "off" and not pending:
            btn = ttk.Button(buttons, text=t("sandbox_working") if self._busy else t("sandbox_turn_on"),
                             style="Accent.TButton", command=self._turn_on)
            btn.pack(side="left")
            if self._busy:
                btn.state(["disabled"])
        if self._error:
            tk.Label(card.body, text=t("fw_failed", error=self._error), font=FONT_SMALL, fg=C.BAD, bg=C.CARD,
                     wraplength=640, justify="left").pack(anchor="w", pady=(10, 0))
        if state == "ready":
            net = tk.Frame(card.body, bg=C.CARD)
            net.pack(fill="x", pady=(14, 0))
            ToggleSwitch(net, command=self._toggle_net, on=settings.load().get("sandbox_internet", False)).pack(
                side="right")
            tk.Label(net, text=t("sandbox_internet"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(side="left")

        notes = RoundedCard(self.body, radius=16, padx=24, pady=16)
        notes.pack(fill="x", pady=(14, 0))
        for icon, key in (("shield", "sandbox_note_how"), ("scan", "sandbox_note_menu"), ("info", "sandbox_note_close")):
            line = tk.Frame(notes.body, bg=C.CARD)
            line.pack(fill="x", pady=4)
            icon_label(line, icon, 12, fg=C.TEXT_MUTED).pack(side="left", anchor="n", padx=(0, 12), pady=2)
            text = tk.Label(line, text=t(key), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left", anchor="w")
            text.pack(side="left", fill="x", expand=True)
            wrap_to_width(text, line, 200, reserve=34)

    def _pick(self):
        path = filedialog.askopenfilename(title=t("sandbox_pick"))
        if path:
            open_in_sandbox(path)

    def _toggle_net(self):
        settings.save(sandbox_internet=not settings.load().get("sandbox_internet", False))
        self._render()

    def _turn_on(self):
        if self._busy:
            return
        self._busy, self._error = True, None
        self._render()

        def run():
            error = None
            try:
                sandbox.turn_on()
                settings.save(sandbox_restart_needed=True)
            except Exception as e:
                error = str(e)
            self.after(0, lambda: self._turned_on(error))

        threading.Thread(target=run, daemon=True).start()

    def _turned_on(self, error):
        self._busy, self._error = False, error
        if self.winfo_exists():
            self._render()


def open_in_sandbox(path: str):
    """Shared by this page and the right-click menu. Shows any problem in a message box."""
    try:
        sandbox.open_file(path, internet=settings.load().get("sandbox_internet", False))
    except RuntimeError as e:
        messagebox.showwarning(t("sandbox_title"), t(str(e)) if str(e).startswith("sandbox_") else str(e))
    except OSError as e:
        messagebox.showwarning(t("sandbox_title"), str(e))
