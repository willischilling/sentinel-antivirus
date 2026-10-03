"""Custom-drawn widgets that give plain Tkinter a modern look, with no extra
packages: rounded cards, pill buttons, animated toggle switches, a gradient
banner, chips, avatars and a mini bar chart. Everything is drawn on Tk canvases
and reads colours from ``palette`` at draw time, so a theme switch repaints.
"""
import tkinter as tk
import tkinter.font as tkfont

from . import palette as P
from .palette import mix  # re-export for callers

UI = "Segoe UI"
EMOJI = "Segoe UI Emoji"
MONO = ("Consolas", 9)


def font(size, weight="normal"):
    return (UI, size, weight)


def round_rect(canvas, x1, y1, x2, y2, r, **kw):
    r = max(0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return canvas.create_polygon(pts, smooth=True, **kw)


def pill_shape(canvas, x1, y1, x2, y2, fill, outline=None):
    """A crisp capsule: two circles and a rectangle (no polygon smoothing)."""
    def capsule(a, b, c, d, color):
        h = d - b
        canvas.create_oval(a, b, a + h, d, fill=color, outline=color)
        canvas.create_oval(c - h, b, c, d, fill=color, outline=color)
        canvas.create_rectangle(a + h / 2, b, c - h / 2, d, fill=color, outline=color)
    if outline and outline != fill:
        capsule(x1, y1, x2, y2, outline)
        capsule(x1 + 1, y1 + 1, x2 - 1, y2 - 1, fill)
    else:
        capsule(x1, y1, x2, y2, fill)


def _bg_of(widget):
    try:
        return widget.cget("bg")
    except tk.TclError:
        return P.BG


class Card(tk.Canvas):
    """A rounded card. Put content in `.body`; the card grows to fit it."""

    def __init__(self, parent, fill=None, border=None, radius=16, pad=18, outer=None):
        self.fill = fill or P.CARD
        self.border = P.BORDER if border is None else border
        super().__init__(parent, bg=outer or _bg_of(parent), highlightthickness=0, bd=0, height=2 * pad)
        self.radius, self.pad = radius, pad
        self.body = tk.Frame(self, bg=self.fill)
        self._win = self.create_window(pad, pad, window=self.body, anchor="nw")
        self.body.bind("<Configure>", self._sync, add="+")
        self.bind("<Configure>", self._sync, add="+")

    def _sync(self, _e=None):
        w = self.winfo_width()
        h = self.body.winfo_reqheight() + 2 * self.pad
        if int(float(self.cget("height"))) != h:
            self.configure(height=h)
        self.itemconfigure(self._win, width=max(1, w - 2 * self.pad))
        self.delete("bg")
        if w > 4:
            round_rect(self, 1, 1, w - 2, h - 2, self.radius, fill=self.fill,
                       outline=self.border or self.fill, tags="bg")
            self.tag_lower("bg")


def _pill_styles():
    return {
        "primary": (P.ACCENT, P.ACCENT_HI, "#ffffff", None),
        "ghost": (P.CARD_HI, mix(P.CARD_HI, P.ACCENT, 0.2), P.TEXT, P.BORDER),
        "danger": (P.CARD_HI, mix(P.CARD_HI, P.BAD, 0.25), P.BAD, P.BORDER),
        "light": ("#ffffff", "#e3eaff", "#1e40c8", None),
        "warn": (mix(P.WARN, P.BG, 0.72), mix(P.WARN, P.BG, 0.6), P.WARN, None),
        "good": (mix(P.GOOD, P.BG, 0.72), mix(P.GOOD, P.BG, 0.6), P.GOOD, None),
    }


class Pill(tk.Canvas):
    """A rounded button with hover, drawn on a canvas."""

    def __init__(self, parent, text, command=None, kind="primary", size=10, padx=18, pady=8,
                 disabled=False, bg=None):
        f = tkfont.Font(family=UI, size=size, weight="bold")
        w = f.measure(text) + 2 * padx
        h = f.metrics("linespace") + 2 * pady
        super().__init__(parent, width=w, height=h, bg=bg or _bg_of(parent), highlightthickness=0, bd=0,
                         cursor="arrow" if disabled else "hand2")
        self.text, self.command, self.font, self.disabled = text, command, f, disabled
        self.fill, self.hover, self.fg, self.outline = _pill_styles().get(kind, _pill_styles()["primary"])
        self._bw, self._bh = w, h
        self._draw(self.fill)
        if not disabled:
            self.bind("<Enter>", lambda e: self._draw(self.hover))
            self.bind("<Leave>", lambda e: self._draw(self.fill))
            self.bind("<ButtonRelease-1>", self._click)

    def _draw(self, fill):
        self.delete("all")
        fill_c = mix(fill, P.BG, 0.45) if self.disabled else fill
        pill_shape(self, 0, 0, self._bw - 1, self._bh - 1, fill_c, self.outline)
        self.create_text(self._bw / 2, self._bh / 2, text=self.text, font=self.font,
                         fill=mix(self.fg, P.BG, 0.4) if self.disabled else self.fg)

    def _click(self, e):
        if 0 <= e.x <= self._bw and 0 <= e.y <= self._bh and self.command:
            self.command()


class Toggle(tk.Canvas):
    """An animated on/off switch. command(on) is called after each flip."""

    W, H = 46, 26

    def __init__(self, parent, on=False, command=None, bg=None):
        super().__init__(parent, width=self.W, height=self.H, bg=bg or _bg_of(parent), highlightthickness=0, bd=0,
                         cursor="hand2")
        self.on, self.command = on, command
        self._pos = 1.0 if on else 0.0
        self._job = None
        self._draw()
        self.bind("<Button-1>", self._click)

    def _draw(self):
        self.delete("all")
        track = mix(mix(P.BORDER, P.CARD_HI, 0.5), P.ACCENT, self._pos)
        pill_shape(self, 0, 0, self.W - 1, self.H - 1, track)
        x = 3 + self._pos * (self.W - self.H)
        self.create_oval(x, 3, x + self.H - 7, self.H - 4, fill="#ffffff", outline="#ffffff")

    def _click(self, _e=None):
        self.on = not self.on
        self._animate(1.0 if self.on else 0.0)
        if self.command:
            self.command(self.on)

    def _animate(self, target):
        if self._job:
            self.after_cancel(self._job)
        step = 0.25 if target > self._pos else -0.25
        self._pos = max(0.0, min(1.0, self._pos + step))
        self._draw()
        if abs(self._pos - target) > 1e-6:
            self._job = self.after(16, self._animate, target)
        else:
            self._job = None


class Banner(tk.Canvas):
    """A rounded horizontal-gradient header with faint Wi-Fi arcs."""

    def __init__(self, parent, height=170, c1="#2c64ff", c2=None, radius=20):
        super().__init__(parent, height=height, bg=_bg_of(parent), highlightthickness=0, bd=0)
        self.c1, self.c2, self.radius = c1, c2 or P.PURPLE, radius
        self.bind("<Configure>", self._draw, add="+")

    def _draw(self, _e=None):
        self.delete("grad")
        w, h, r = self.winfo_width(), self.winfo_height(), self.radius
        if w < 4:
            return
        for x in range(0, w, 2):
            dx = min(x, w - 1 - x)
            dy = r - (r * r - (r - dx) ** 2) ** 0.5 if dx < r else 0
            self.create_line(x, dy, x, h - dy, fill=mix(self.c1, self.c2, x / max(1, w - 1)), width=2,
                             tags="grad")
        cx, cy = w - 120, h - 26
        for i, rad in enumerate((26, 54, 82)):
            self.create_arc(cx - rad, cy - rad, cx + rad, cy + rad, start=45, extent=90, style="arc",
                            outline=mix(self.c2, "#ffffff", 0.35 - i * 0.08), width=7, tags="grad")
        self.create_oval(cx - 7, cy - 7, cx + 7, cy + 7, fill=mix(self.c2, "#ffffff", 0.4), outline="",
                         tags="grad")
        self.tag_lower("grad")


def chip(parent, text, color, bg=None, size=8):
    bg = bg or _bg_of(parent)
    f = tkfont.Font(family=UI, size=size, weight="bold")
    w, h = f.measure(text) + 16, f.metrics("linespace") + 6
    c = tk.Canvas(parent, width=w, height=h, bg=bg, highlightthickness=0, bd=0)
    fill = mix(color, bg, 0.78)
    pill_shape(c, 0, 0, w - 1, h - 1, fill)
    c.create_text(w / 2, h / 2, text=text, font=f, fill=color)
    return c


def avatar(parent, glyph, color, size=42, bg=None):
    bg = bg or _bg_of(parent)
    c = tk.Canvas(parent, width=size, height=size, bg=bg, highlightthickness=0, bd=0)
    c.create_oval(1, 1, size - 1, size - 1, fill=mix(color, bg, 0.78), outline=mix(color, bg, 0.45), width=1)
    c.create_text(size / 2, size / 2 + 1, text=glyph, font=(EMOJI, int(size * 0.36)), fill=P.TEXT)
    return c


def dot(parent, color, size=10, bg=None):
    c = tk.Canvas(parent, width=size, height=size, bg=bg or _bg_of(parent), highlightthickness=0, bd=0)
    c.create_oval(1, 1, size - 1, size - 1, fill=color, outline="", tags="dot")
    return c


def meter(parent, frac, color=None, w=220, h=8, bg=None):
    """A rounded progress/level bar; frac is 0..1."""
    bg = bg or _bg_of(parent)
    color = color or P.ACCENT
    c = tk.Canvas(parent, width=w, height=h, bg=bg, highlightthickness=0, bd=0)
    pill_shape(c, 0, 0, w - 1, h - 1, mix(P.BORDER, bg, 0.3))
    fw = max(h, int(w * max(0.0, min(1.0, frac))))
    pill_shape(c, 0, 0, fw - 1, h - 1, color)
    return c


def bars(parent, values, color=None, w=240, h=56, bg=None):
    """A tiny bar chart (e.g. 24 hourly values, 0..1)."""
    bg = bg or _bg_of(parent)
    color = color or P.ACCENT
    c = tk.Canvas(parent, width=w, height=h, bg=bg, highlightthickness=0, bd=0)
    n = max(1, len(values))
    gap = 2
    bw = (w - (n - 1) * gap) / n
    for i, v in enumerate(values):
        x = i * (bw + gap)
        bh = max(2, v * (h - 2))
        c.create_rectangle(x, h - bh, x + bw, h, fill=mix(color, bg, 1 - (0.35 + 0.65 * v)), outline="")
    return c


class ScrollArea(tk.Frame):
    """A vertically scrolling frame; put content in `.inner`."""

    def __init__(self, parent, bg=None):
        bg = bg or P.BG
        super().__init__(parent, bg=bg)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self._win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self._win, width=e.width))
        self.canvas.bind_all("<MouseWheel>", self._wheel)

    def _wheel(self, event):
        try:
            if self.inner.winfo_reqheight() > self.canvas.winfo_height():
                self.canvas.yview_scroll(int(-event.delta / 120), "units")
        except tk.TclError:
            pass

    def recolor(self, bg):
        self.configure(bg=bg)
        self.canvas.configure(bg=bg)
        self.inner.configure(bg=bg)

    def to_top(self):
        try:
            self.canvas.yview_moveto(0)
        except tk.TclError:
            pass
