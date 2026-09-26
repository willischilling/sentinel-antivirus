"""The Ask Sentinel tab: a scam checker chat.

Every message first goes through the built-in checks (core/scam_check.py),
shown instantly as a card. If the local AI is downloaded, it then answers,
streaming word by word, using those check results as facts.

The conversation lives in ChatState on the app, so it survives the page
being rebuilt after a language or theme change.
"""
import re
import threading
import tkinter as tk
from dataclasses import dataclass, field
from tkinter import ttk

import theme as C
from core import assistant, scam_check
from core.i18n import t
from theme import FONT, FONT_BOLD, FONT_SMALL
from widgets import RoundedCard, icon_label

WRAP = 470


@dataclass
class ChatState:
    messages: list = field(default_factory=list)  # [kind, payload]: user/checks/ai/error
    started: bool = False
    generating: bool = False
    gen_id: int = 0
    stop: bool = False
    download: dict = field(default_factory=lambda: {"state": "idle", "done": 0, "total": 0, "error": None})
    brain: assistant.Assistant = field(default_factory=assistant.Assistant)


def tidy(text: str) -> str:
    """Light Markdown cleanup for a plain label: no ** markers, bullets as •."""
    text = text.replace("**", "").replace("__", "")
    text = re.sub(r"(?m)^\s*[-*]\s+", "• ", text)
    text = re.sub(r"(?m)^#+\s*", "", text)
    return text.strip()


class AskPage(tk.Frame):
    def __init__(self, parent, app, logo=None):
        super().__init__(parent, bg=C.BG)
        self.app, self.logo = app, logo
        self.state: ChatState = app.ask_state
        self._ai_label = None
        self._status_label = None

        tk.Label(self, text=t("nav_ask"), font=("Segoe UI Semibold", 18), fg=C.TEXT, bg=C.BG).pack(anchor="w")
        tk.Label(self, text=t("ask_sub"), font=FONT, fg=C.TEXT_MUTED, bg=C.BG).pack(anchor="w", pady=(2, 18))
        self.card = RoundedCard(self, radius=16, padx=24, pady=18)
        self.card.pack(fill="both", expand=True)
        self.body = self.card.body
        self.render()

    # ------------------------------------------------------------ screens --
    def render(self):
        for child in self.body.winfo_children():
            child.destroy()
        self._ai_label = self._status_label = None
        if self.state.started:
            self._build_chat()
        else:
            self._build_welcome()

    def _build_welcome(self):
        box = tk.Frame(self.body, bg=C.CARD)
        box.place(relx=0.5, rely=0.47, anchor="center")
        if self.logo:
            tk.Label(box, image=self.logo, bg=C.CARD).pack(pady=(0, 16))
        tk.Label(box, text=t("ask_hello"), font=("Segoe UI Semibold", 16), fg=C.TEXT, bg=C.CARD,
                 justify="center").pack()
        tk.Label(box, text=t("ask_intro"), font=FONT, fg=C.TEXT, bg=C.CARD, wraplength=440,
                 justify="center").pack(pady=(12, 12))
        privacy = tk.Frame(box, bg=C.CARD)
        privacy.pack()
        icon_label(privacy, "lock", 11, fg=C.GOOD).pack(side="left", padx=(0, 6))
        tk.Label(privacy, text=t("ask_privacy"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD).pack(side="left")

        actions = tk.Frame(box, bg=C.CARD)
        actions.pack(pady=(22, 0))
        dl = self.state.download
        if not assistant.engine_available():
            tk.Label(box, text=t("ask_engine_missing"), font=FONT_SMALL, fg=C.WARN, bg=C.CARD,
                     wraplength=440, justify="center").pack(pady=(12, 0))
            ttk.Button(actions, text=t("ask_start"), style="Accent.TButton", command=self._start).pack()
        elif assistant.installed():
            ttk.Button(actions, text=t("ask_start"), style="Hero.TButton", command=self._start).pack()
        else:
            busy = dl["state"] in ("downloading", "verifying")
            self.dl_btn = ttk.Button(actions, text=t("ask_download"), style="Hero.TButton",
                                     command=self._download)
            self.dl_btn.pack(side="left", padx=(0, 10))
            if busy:
                self.dl_btn.state(["disabled"])
            ttk.Button(actions, text=t("ask_start"), style="Ghost.TButton", command=self._start).pack(side="left")
            self.dl_status = tk.Label(box, text="", font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD,
                                      wraplength=440, justify="center")
            self.dl_status.pack(pady=(12, 0))
            self._show_download_status()

    def _build_chat(self):
        top = tk.Frame(self.body, bg=C.CARD)
        top.pack(fill="x")
        ttk.Button(top, text=t("ask_new_chat"), style="Ghost.TButton", command=self._new_chat).pack(side="right")

        # Scrollable conversation
        area = tk.Frame(self.body, bg=C.CARD)
        area.pack(fill="both", expand=True, pady=(8, 8))
        self.canvas = tk.Canvas(area, bg=C.CARD, highlightthickness=0, bd=0)
        bar = ttk.Scrollbar(area, orient="vertical", command=self.canvas.yview, style="Slim.Vertical.TScrollbar")
        self.canvas.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.feed = tk.Frame(self.canvas, bg=C.CARD)
        window = self.canvas.create_window(0, 0, window=self.feed, anchor="nw")
        self.feed.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(window, width=e.width))
        for widget in (self.canvas, self.feed):
            widget.bind("<Enter>", lambda e: self.canvas.bind_all("<MouseWheel>", self._wheel))
            widget.bind("<Leave>", lambda e: self.canvas.unbind_all("<MouseWheel>"))

        if not self.state.messages:
            self._examples()
        label = None
        for kind, payload in self.state.messages:
            label = self._add(kind, payload)
        if self.state.generating:  # rebuilt mid-answer: keep streaming into the last bubble
            self._ai_label = label

        # Input
        entry_row = tk.Frame(self.body, bg=C.CARD)
        entry_row.pack(fill="x")
        border = tk.Frame(entry_row, bg=C.BORDER)
        border.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.entry = tk.Text(border, height=3, wrap="word", font=FONT, bg=C.BG, fg=C.TEXT, relief="flat",
                             insertbackground=C.TEXT, padx=10, pady=8, highlightthickness=0, bd=0,
                             undo=True)
        self.entry.pack(fill="both", padx=1, pady=1)
        self.entry.bind("<Return>", self._on_enter)
        self.entry.bind("<FocusIn>", lambda e: self._placeholder(False))
        self.entry.bind("<FocusOut>", lambda e: self._placeholder(True))
        self.send_btn = ttk.Button(entry_row, style="Accent.TButton", command=self._send_or_stop)
        self.send_btn.pack(side="right", fill="y")
        self._placeholder(True)
        self._sync_send_button()
        tk.Label(self.body, text=t("ask_disclaimer"), font=FONT_SMALL, fg=C.TEXT_MUTED, bg=C.CARD,
                 wraplength=620, justify="left").pack(anchor="w", pady=(8, 0))
        self.after(50, self._scroll_to_end)
        self.entry.focus_set()

    def _examples(self):
        self.examples = tk.Frame(self.feed, bg=C.CARD)
        self.examples.pack(anchor="w", pady=(4, 0))
        for key in ("ask_ex1", "ask_ex2", "ask_ex3"):
            chip = RoundedCard(self.examples, bg=C.BORDER, outer=C.CARD, radius=8, padx=12, pady=6,
                               hover_bg=C.CARD_HOVER, command=lambda k=key: self._use_example(k))
            tk.Label(chip.body, text=t(key).strip(), font=FONT, fg=C.TEXT, bg=C.BORDER).pack()
            chip.pack(side="left", padx=(0, 8))

    # ------------------------------------------------------------ bubbles --
    def _add(self, kind, payload):
        if getattr(self, "examples", None) is not None and self.examples.winfo_exists():
            self.examples.destroy()
        row = tk.Frame(self.feed, bg=C.CARD)
        row.pack(fill="x", pady=6)
        if kind == "user":
            bubble = RoundedCard(row, bg=C.ACCENT_DARK, outer=C.CARD, radius=12, padx=14, pady=10)
            bubble.pack(side="right", padx=(80, 4))
            tk.Label(bubble.body, text=payload, font=FONT, fg=C.ON_ACCENT, bg=C.ACCENT_DARK,
                     wraplength=WRAP, justify="left").pack(anchor="w")
        elif kind == "checks":
            self._checks_card(row, payload)
        elif kind in ("ai", "error", "note"):
            col = tk.Frame(row, bg=C.CARD)
            col.pack(side="left", fill="x", padx=(4, 80))
            head = tk.Frame(col, bg=C.CARD)
            head.pack(anchor="w")
            icon_label(head, "shield", 11, fg=C.ACCENT).pack(side="left", padx=(0, 6))
            tk.Label(head, text=t("nav_ask"), font=FONT_BOLD, fg=C.TEXT, bg=C.CARD).pack(side="left")
            color = {"ai": C.TEXT, "error": C.BAD, "note": C.TEXT_MUTED}[kind]
            label = AnswerLabel(col, color) if kind == "ai" else tk.Label(
                col, font=FONT, fg=color, bg=C.CARD, wraplength=WRAP + 60, justify="left")
            label.pack(anchor="w", pady=(4, 0))
            label.configure(text=payload)
            return label
        return None

    def _checks_card(self, row, report: scam_check.Report):
        card = RoundedCard(row, bg=C.BG, outer=C.CARD, radius=12, padx=16, pady=12)
        card.pack(side="left", padx=(4, 80))
        head = tk.Frame(card.body, bg=C.BG)
        head.pack(anchor="w", fill="x")
        tk.Label(head, text=t("ask_checks"), font=FONT_BOLD, fg=C.TEXT, bg=C.BG).pack(side="left")
        verdict = report.verdict
        if verdict:
            color = {"scam": C.BAD, "suspicious": C.WARN, "caution": C.WARN, "safe": C.GOOD}[verdict]
            tk.Label(head, text=t(f"ask_verdict_{verdict}"), font=("Segoe UI Semibold", 8), fg="#0b1120",
                     bg=color, padx=8, pady=1).pack(side="left", padx=(10, 0))
        icons = {"bad": ("warning", C.BAD), "warn": ("warning", C.WARN), "good": ("check", C.GOOD),
                 "info": ("info", C.TEXT_MUTED)}
        for finding in report.findings:
            line = tk.Frame(card.body, bg=C.BG)
            line.pack(anchor="w", fill="x", pady=(6, 0))
            name, color = icons[finding.level]
            icon_label(line, name, 11, fg=color, bg=C.BG).pack(side="left", anchor="n", padx=(0, 8), pady=2)
            tk.Label(line, text=t(finding.key, **finding.values), font=FONT, fg=C.TEXT, bg=C.BG,
                     wraplength=WRAP, justify="left").pack(side="left", anchor="w")

    # ------------------------------------------------------------- actions --
    def _start(self):
        self.state.started = True
        self.render()

    def _new_chat(self):
        if self.state.generating:
            self.state.stop = True
        self.state.messages.clear()
        self.state.brain.reset()
        self.render()

    def _use_example(self, key):
        self._placeholder(False)
        self.entry.delete("1.0", "end")
        self.entry.insert("1.0", t(key))
        self.entry.focus_set()

    def _placeholder(self, show):
        text = self.entry.get("1.0", "end-1c")
        if show and not text.strip():
            self.entry.insert("1.0", t("ask_placeholder"))
            self.entry.configure(fg=C.TEXT_MUTED)
            self._has_placeholder = True
        elif not show and getattr(self, "_has_placeholder", False):
            self.entry.delete("1.0", "end")
            self.entry.configure(fg=C.TEXT)
            self._has_placeholder = False

    def _on_enter(self, event):
        if event.state & 0x1:  # Shift+Enter: new line
            return None
        self._send_or_stop()
        return "break"

    def _send_or_stop(self):
        if self.state.generating:
            self.state.stop = True
            return
        if getattr(self, "_has_placeholder", False):
            return
        text = self.entry.get("1.0", "end-1c").strip()
        if not text:
            return
        self.entry.delete("1.0", "end")
        report = scam_check.analyze(text)
        self._record("user", text)
        if report.findings:
            self._record("checks", report)
        if assistant.engine_available() and assistant.installed():
            self._ask_ai(text, report)
        else:
            self._record("note", t("ask_no_ai"))
        self._scroll_to_end()

    def _record(self, kind, payload):
        self.state.messages.append([kind, payload])
        return self._add(kind, payload)

    def _ask_ai(self, text, report):
        state = self.state
        state.generating, state.stop = True, False
        state.gen_id += 1
        gen = state.gen_id
        state.messages.append(["ai", ""])
        self._ai_label = self._add("ai", "")
        self._ai_label.configure(text=t("ask_thinking" if assistant.Assistant._llm else "ask_loading"),
                                 fg=C.TEXT_MUTED)
        self._sync_send_button()
        facts = [f.english() for f in report.findings]
        queue = self.app.event_queue

        def work():
            try:
                reply = state.brain.ask(text, facts, lambda so_far: queue.put(("ask_token", (gen, so_far))),
                                        stop=lambda: state.stop or state.gen_id != gen)
                queue.put(("ask_done", (gen, reply, None)))
            except Exception as e:  # the model failed to load or crashed mid-answer
                queue.put(("ask_done", (gen, None, e)))

        threading.Thread(target=work, daemon=True).start()

    def _download(self):
        dl = self.state.download
        if dl["state"] in ("downloading", "verifying"):
            return
        dl.update(state="downloading", error=None)
        self.dl_btn.state(["disabled"])
        queue = self.app.event_queue

        def work():
            try:
                def progress(done, total):
                    queue.put(("ask_dl", ("verifying" if done >= total else "downloading", done, total)))
                assistant.download(progress)
                queue.put(("ask_dl", ("done", 0, 0)))
            except Exception as e:
                queue.put(("ask_dl", ("failed", 0, str(e))))

        threading.Thread(target=work, daemon=True).start()
        self._show_download_status()

    # --------------------------------------------------- events from queue --
    def handle(self, kind, payload):
        state = self.state
        if kind == "ask_token":
            gen, so_far = payload
            if gen != state.gen_id:
                return
            state.messages[-1][1] = so_far
            if self._alive(self._ai_label):
                self._ai_label.configure(text=so_far, fg=C.TEXT)
                self._scroll_to_end()
        elif kind == "ask_done":
            gen, reply, error = payload
            if gen != state.gen_id:
                return
            state.generating = False
            if error is not None:
                state.messages[-1] = ["error", t("ask_failed", error=error)]
                if self._alive(self._ai_label):
                    self._ai_label.configure(text=t("ask_failed", error=error), fg=C.BAD)
            elif reply is not None:
                state.messages[-1][1] = reply or "…"
                if self._alive(self._ai_label):
                    self._ai_label.configure(text=reply or "…", fg=C.TEXT)
            self._sync_send_button()
        elif kind == "ask_dl":
            status, done, extra = payload
            dl = state.download
            if status == "failed":
                dl.update(state="failed", error=extra)
            elif status == "done":
                dl.update(state="done")
                if not state.started:
                    self.render()
                return
            else:
                dl.update(state=status, done=done, total=extra)
            self._show_download_status()
            if status == "failed" and self._alive(getattr(self, "dl_btn", None)):
                self.dl_btn.state(["!disabled"])

    def _show_download_status(self):
        if not self._alive(getattr(self, "dl_status", None)):
            return
        dl = self.state.download
        if dl["state"] == "downloading":
            text = t("ask_downloading", done=_gb(dl["done"]), total=_gb(dl["total"] or assistant.MODEL_SIZE))
        elif dl["state"] == "verifying":
            text = t("ask_verifying")
        elif dl["state"] == "failed":
            text = t("ask_download_failed", error=dl["error"])
        else:
            text = t("ask_setup_note", size=assistant.model_size_text())
        self.dl_status.configure(text=text, fg=C.BAD if dl["state"] == "failed" else C.TEXT_MUTED)

    # ------------------------------------------------------------- helpers --
    def _sync_send_button(self):
        if self._alive(getattr(self, "send_btn", None)):
            self.send_btn.configure(text=t("ask_stop") if self.state.generating else t("ask_send"),
                                    style="Ghost.TButton" if self.state.generating else "Accent.TButton")

    def _scroll_to_end(self):
        if self._alive(getattr(self, "canvas", None)):
            self.canvas.update_idletasks()
            self.canvas.yview_moveto(1.0)

    def _wheel(self, event):
        self.canvas.yview_scroll(int(-event.delta / 120) * 3, "units")

    @staticmethod
    def _alive(widget):
        return widget is not None and widget.winfo_exists()


class AnswerLabel(tk.Frame):
    """An AI answer: the verdict line as a colored headline, then the rest. Acts like a Label
    for configure(text=..., fg=...)."""

    VERDICT_COLORS = (("scam", "BAD"), ("suspicious", "WARN"), ("safe", "GOOD"), ("can't tell", "TEXT_MUTED"))

    def __init__(self, parent, color):
        super().__init__(parent, bg=C.CARD)
        self.head = tk.Label(self, font=("Segoe UI Semibold", 11), bg=C.CARD, justify="left",
                             wraplength=WRAP + 60)
        self.rest = tk.Label(self, font=FONT, fg=color, bg=C.CARD, justify="left", wraplength=WRAP + 60)

    def configure(self, text=None, fg=None, **kw):
        if text is None:
            return super().configure(**kw)
        text = tidy(text)
        first, _, rest = text.partition("\n")
        # Headline only for a short first line that reads like a verdict ("Likely a scam").
        if fg is None or fg == C.TEXT:
            lower = first.lower()
            color = next((getattr(C, c) for word, c in self.VERDICT_COLORS if word in lower), None)
            if color and len(first) < 60:
                self.head.configure(text=first.rstrip(" .:"), fg=color)
                self.head.pack(anchor="w")
                self.rest.configure(text=rest.strip(), fg=C.TEXT)
                if rest.strip():
                    self.rest.pack(anchor="w", pady=(2, 0))
                else:
                    self.rest.pack_forget()
                return None
        self.head.pack_forget()
        self.rest.configure(text=text, fg=fg or C.TEXT)
        self.rest.pack(anchor="w")
        return None

    config = configure


def _gb(n):
    return f"{n / 1e9:.1f} GB"
