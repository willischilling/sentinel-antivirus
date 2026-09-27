"""Weekly report page: the latest security report (made by the background agent
once a week), with a button to make one now and the on/off switch."""
import threading
import tkinter as tk
from datetime import datetime
from tkinter import ttk

import theme as C
from core import report, settings
from core.i18n import number, relative, t
from theme import FONT, FONT_BOLD, FONT_LARGE, FONT_SMALL
from tools_page import subpage_header, wrap_to_width
from widgets import Ring, RoundedCard, ScrollArea, ToggleSwitch, icon_label


class ReportPage(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=C.BG)
        self.app = app
        self._busy = False
        subpage_header(self, app, t("report_title"), t("report_sub"), "nav_tools", "tools")
        self.body = tk.Frame(self, bg=C.BG)
        self.body.pack(fill="both", expand=True)
        self._render()

    def refresh(self):
        self._render()

    def _make_now(self):
        if self._busy:
            return
        self._busy = True
        self._render()
        queue = self.app.event_queue
        protection = bool(self.app.protection_on)

        def run():
            made = report.build(protection)
            report.save(made)
            queue.put(("report_done", made))

        threading.Thread(target=run, daemon=True).start()

    def handle(self, kind, payload):
        self._busy = False
        if self.winfo_exists():
            self._render()

    def _render(self):
        for child in self.body.winfo_children():
            child.destroy()
        data = report.latest()

        top = RoundedCard(self.body, radius=16, padx=24, pady=16)
        top.pack(fill="x")
        row = tk.Frame(top.body, bg=C.CARD)
        row.pack(fill="x")
        ring = Ring(row, size=72)
        ring.pack(side="left", padx=(0, 18))
        btn = ttk.Button(row, text=t("report_making") if self._busy else t("report_now"), style="Ghost.TButton",
                         command=self._make_now)
        btn.pack(side="right", anchor="n", padx=(12, 0))
        if self._busy:
            btn.state(["disabled"])
        col = tk.Frame(row, bg=C.CARD)
        col.pack(side="left", fill="x", expand=True)
        if self._busy:
            ring.spin("")
            title, sub = t("report_making"), ""
        elif not data:
            ring.show(C.BORDER, glyph="history", glyph_color=C.TEXT_MUTED)
            title, sub = t("report_none"), t("report_none_sub")
        else:
            score = data.get("score")
            color = C.GOOD if (score or 0) >= 85 else C.WARN if (score or 0) >= 60 else C.BAD
            ring.show_value(color, str(score) if score is not None else "–", "/100")
            when = relative(datetime.fromisoformat(data["made"]).astimezone())
            title = t("report_heading", when=when[0].lower() + when[1:])
            prev = data.get("previous_score")
            if score is not None and prev is not None and score != prev:
                sub = t("report_score_up" if score > prev else "report_score_down", before=prev, now=score)
            else:
                sub = t("report_score_same")
        tk.Label(col, text=title, font=FONT_LARGE, fg=C.TEXT, bg=C.CARD, anchor="w").pack(anchor="w", fill="x")
        sub_label = tk.Label(col, text=sub, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left", anchor="w")
        sub_label.pack(anchor="w", fill="x")
        wrap_to_width(sub_label, col)
        weekly = tk.Frame(top.body, bg=C.CARD)
        weekly.pack(fill="x", pady=(10, 0))
        ToggleSwitch(weekly, command=self._toggle, on=report.enabled()).pack(side="right")
        tk.Label(weekly, text=t("report_weekly"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(side="left")

        if not data or self._busy:
            return
        card = RoundedCard(self.body, radius=16, padx=18, pady=12)
        card.pack(fill="both", expand=True, pady=(14, 0))
        area = ScrollArea(card.body)
        area.pack(fill="both", expand=True)
        threats = data.get("threats") or 0
        rows = [
            ("warning" if threats else "check", C.BAD if threats else C.GOOD,
             t("report_threats", n=number(threats)) if threats else t("report_no_threats"),
             ", ".join(data.get("threat_names") or [])),
            ("lock", C.ACCENT, t("report_quarantined", n=number(data.get("quarantined") or 0)), ""),
            ("globe", C.WARN if data.get("new_devices") else C.GOOD,
             t("report_devices", n=number(len(data.get("new_devices") or []))),
             ", ".join(data.get("new_devices") or [])),
            ("scan", C.ACCENT, t("report_camera", n=number(len(data.get("camera_mic") or []))),
             ", ".join(data.get("camera_mic") or [])),
            ("web", C.WARN if data.get("link_warnings") else C.GOOD,
             t("report_links", n=number(data.get("link_warnings") or 0)), ""),
            ("web", C.WARN if data.get("browser_items") else C.GOOD,
             t("report_browser_bad", n=number(data["browser_items"])) if data.get("browser_items")
             else t("report_browser_ok"), ""),
        ]
        if data.get("shield_blocks"):
            rows.append(("lock", C.WARN, t("report_shield", n=number(data["shield_blocks"])), ""))
        for key in data.get("todo") or []:  # security checks that needed fixing
            rows.append(("info", C.WARN, t("report_apps_todo") if key == "apps" else t(f"score_{key}_bad"),
                         t("report_todo")))
        for icon, color, title_text, detail in rows:
            line = tk.Frame(area.inner, bg=C.CARD)
            line.pack(fill="x", pady=5, padx=(0, 8))
            icon_label(line, icon, 13, fg=color).pack(side="left", anchor="n", padx=(4, 12), pady=2)
            text = tk.Frame(line, bg=C.CARD)
            text.pack(side="left", fill="x", expand=True)
            tk.Label(text, text=title_text, font=FONT_BOLD, fg=C.TEXT, bg=C.CARD, anchor="w").pack(anchor="w")
            if detail:
                label = tk.Label(text, text=detail, font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD, justify="left",
                                 anchor="w")
                label.pack(anchor="w", fill="x")
                wrap_to_width(label, text, 200)

    def _toggle(self):
        settings.save(weekly_report=not report.enabled())  # the background agent reads it
        self._render()
