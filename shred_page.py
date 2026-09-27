"""File shredder page: pick files or a folder to delete for good. The actual
confirmation and shredding are in the main window (shared with the
right-click menu's "Shred with Sentinel")."""
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

import theme as C
from core.i18n import t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from tools_page import subpage_header, wrap_to_width
from widgets import Ring, RoundedCard, icon_label


class ShredPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        subpage_header(self, app, t("shred_title"), t("shred_sub"), "nav_tools", "tools")

        card = RoundedCard(self, radius=16, padx=26, pady=22)
        card.pack(fill="x")
        row = tk.Frame(card.body, bg=C.CARD)
        row.pack(fill="x")
        ring = Ring(row, size=72)
        ring.pack(side="left", padx=(0, 20))
        ring.show(C.BAD, glyph="delete", glyph_color=C.BAD)
        col = tk.Frame(row, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, text=t("shred_headline"), font=FONT_LARGE, fg=C.TEXT, bg=C.CARD, anchor="w").pack(anchor="w")
        desc = tk.Label(col, text=t("shred_how"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left",
                        anchor="w")
        desc.pack(anchor="w", fill="x")
        wrap_to_width(desc, col)
        buttons = tk.Frame(card.body, bg=C.CARD)
        buttons.pack(anchor="w", pady=(18, 0))
        ttk.Button(buttons, text=t("shred_pick_files"), style="Accent.TButton", command=self._files).pack(side="left")
        ttk.Button(buttons, text=t("shred_pick_folder"), style="Ghost.TButton",
                   command=self._folder).pack(side="left", padx=(10, 0))

        notes = RoundedCard(self, radius=16, padx=24, pady=16)
        notes.pack(fill="x", pady=(14, 0))
        for icon, key in (("info", "shred_note_ssd"), ("scan", "shred_note_menu"), ("lock", "shred_note_safe")):
            line = tk.Frame(notes.body, bg=C.CARD)
            line.pack(fill="x", pady=4)
            icon_label(line, icon, 12, fg=C.TEXT_MUTED).pack(side="left", anchor="n", padx=(0, 12), pady=2)
            text = tk.Label(line, text=t(key), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left", anchor="w")
            text.pack(side="left", fill="x", expand=True)
            wrap_to_width(text, line, 200, reserve=34)

    def _files(self):
        files = filedialog.askopenfilenames(title=t("shred_pick_files"))
        if files:
            self.app.shred_confirm(list(files))

    def _folder(self):
        folder = filedialog.askdirectory(title=t("shred_pick_folder"))
        if folder:
            self.app.shred_confirm([str(Path(folder))])
