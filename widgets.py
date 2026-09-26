"""Custom widgets for the main window: icon glyphs, rounded cards, toggle
switches, status rings and sidebar nav items.

Tk canvas shapes aren't antialiased on Windows, so anything curved is drawn
with Pillow at 4x and downsampled, then cached as a PhotoImage.
"""
import tkinter as tk
from tkinter import font as tkfont

from PIL import Image, ImageDraw, ImageTk

from theme import ACCENT, BG, BORDER, CARD, CARD_HOVER, FONT, FONT_BOLD, PANEL, TEXT, TEXT_MUTED

SUPERSAMPLE = 4
_image_cache = {}

# Segoe Fluent Icons (Windows 11) / Segoe MDL2 Assets (Windows 10) codepoints.
ICONS = {
    "home": "",
    "scan": "",
    "shield": "",
    "lock": "",
    "history": "",
    "check": "",
    "warning": "",
    "folder": "",
    "download": "",
    "apps": "",
    "power": "",
    "refresh": "",
    "restore": "",
    "delete": "",
}
_icon_family = None


def icon_font(size: int):
    global _icon_family
    if _icon_family is None:
        families = set(tkfont.families())
        _icon_family = next(
            (f for f in ("Segoe Fluent Icons", "Segoe MDL2 Assets") if f in families), ""
        )
    return (_icon_family, size) if _icon_family else FONT


def icon_label(parent, name, size=14, fg=TEXT, bg=CARD, **kw):
    text = ICONS.get(name, "") if _icon_family != "" else ""
    return tk.Label(parent, text=text, font=icon_font(size), fg=fg, bg=bg, **kw)


def _cached(key, render):
    if key not in _image_cache:
        _image_cache[key] = ImageTk.PhotoImage(render())
    return _image_cache[key]


def _downsample(img: Image.Image, size) -> Image.Image:
    return img.resize(size, Image.LANCZOS)


# ------------------------------------------------------------------ recolor --
def recolor(widget, old: str, new: str, _root=True):
    """Swap background `old` -> `new` on a widget tree (used for hover states).
    Widgets with baked-in image backgrounds (switches) repaint via set_bg."""
    try:
        matches = str(widget.cget("bg")) == old
    except tk.TclError:
        matches = False
    if not _root and hasattr(widget, "set_bg"):
        if matches:
            widget.set_bg(new)
        return
    if matches:
        widget.configure(bg=new)
    for child in widget.winfo_children():
        recolor(child, old, new, _root=False)


# ------------------------------------------------------------- RoundedCard --
def _corner_images(radius: int, inner: str, outer: str):
    def render(quadrant):
        s = radius * SUPERSAMPLE
        big = Image.new("RGB", (s * 2, s * 2), outer)
        ImageDraw.Draw(big).ellipse((0, 0, s * 2 - 1, s * 2 - 1), fill=inner)
        small = _downsample(big, (radius * 2, radius * 2))
        x, y = quadrant
        return small.crop((x * radius, y * radius, (x + 1) * radius, (y + 1) * radius))

    return [
        _cached(("corner", radius, inner, outer, q), lambda q=q: render(q))
        for q in ((0, 0), (1, 0), (0, 1), (1, 1))
    ]


class RoundedCard(tk.Frame):
    """A card with antialiased rounded corners. Put content in `.body`.
    Padding must be at least the radius so content never sits under a corner."""

    def __init__(self, parent, bg=CARD, outer=BG, radius=12, padx=22, pady=20,
                 hover_bg=None, command=None, **kw):
        super().__init__(parent, bg=bg, **kw)
        self.bg, self.outer, self.radius = bg, outer, radius
        self.rest_bg = bg  # color when not hovered (e.g. a selected chip)
        self.body = tk.Frame(self, bg=bg)
        self.body.pack(fill="both", expand=True, padx=padx, pady=pady)
        self._corners = []
        for relx, rely, anchor in ((0, 0, "nw"), (1, 0, "ne"), (0, 1, "sw"), (1, 1, "se")):
            lbl = tk.Label(self, bd=0, bg=outer, highlightthickness=0)
            lbl.place(relx=relx, rely=rely, anchor=anchor)
            self._corners.append(lbl)
        self._paint_corners(bg)

        if command:
            self._make_clickable(command, hover_bg or CARD_HOVER)

    def _paint_corners(self, inner):
        for lbl, img in zip(self._corners, _corner_images(self.radius, inner, self.outer)):
            lbl.configure(image=img)

    def set_bg(self, new):
        recolor(self, self.bg, new)
        for lbl in self._corners:  # corner labels' own bg is the outer color
            lbl.configure(bg=self.outer)
        self._paint_corners(new)
        self.bg = new

    def set_rest(self, bg):
        self.rest_bg = bg
        self.set_bg(bg)

    def _make_clickable(self, command, hover_bg):
        base = self.bg

        def enter(_e):
            if self.rest_bg == base:  # a highlighted (selected) card keeps its color
                self.set_bg(hover_bg)

        def bind_all(widget):
            if getattr(widget, "_keeps_own_clicks", False):
                return
            widget.bind("<Button-1>", lambda e: command(), add="+")
            widget.bind("<Enter>", enter, add="+")
            widget.bind("<Leave>", lambda e: self._maybe_leave(), add="+")
            widget.configure(cursor="hand2")
            for child in widget.winfo_children():
                bind_all(child)

        # Bind after the caller has filled in the body.
        self.after_idle(lambda: bind_all(self))

    def _maybe_leave(self):
        x, y = self.winfo_pointerxy()
        inside = self.winfo_rootx() <= x < self.winfo_rootx() + self.winfo_width() and \
            self.winfo_rooty() <= y < self.winfo_rooty() + self.winfo_height()
        if not inside:
            self.set_bg(self.rest_bg)


# ------------------------------------------------------------ ToggleSwitch --
def _switch_image(on: bool, enabled: bool, bg: str, w=46, h=26):
    def render():
        s = SUPERSAMPLE
        img = Image.new("RGB", (w * s, h * s), bg)
        d = ImageDraw.Draw(img)
        track = (ACCENT if on else BORDER) if enabled else "#2a3142"
        d.rounded_rectangle((0, 0, w * s - 1, h * s - 1), radius=h * s // 2, fill=track)
        pad = 3 * s
        knob = h * s - 2 * pad
        x = (w * s - pad - knob) if on else pad
        d.ellipse((x, pad, x + knob, pad + knob), fill="#ffffff" if enabled else "#6b7385")
        return _downsample(img, (w, h))

    return _cached(("switch", on, enabled, bg, w, h), render)


class ToggleSwitch(tk.Label):
    _keeps_own_clicks = True  # a clickable card around it must not also react

    def __init__(self, parent, command=None, bg=CARD, on=False):
        super().__init__(parent, bd=0, bg=bg, cursor="hand2", highlightthickness=0)
        self.command, self.on, self.enabled, self._bg = command, on, True, bg
        self.bind("<Button-1>", self._click)
        self._draw()

    def _draw(self):
        self.configure(image=_switch_image(self.on, self.enabled, self._bg))

    def _click(self, _event=None):
        if self.enabled and self.command:
            self.command()
        return "break"

    def set(self, on: bool):
        self.on = on
        self._draw()

    def set_enabled(self, enabled: bool):
        self.enabled = enabled
        self.configure(cursor="hand2" if enabled else "arrow")
        self._draw()

    def set_bg(self, bg):
        self._bg = bg
        self.configure(bg=bg)
        self._draw()


# -------------------------------------------------------------------- Ring --
def _ring_image(size, bg, track, color, start=None, extent=None, width_frac=0.075):
    """Full ring in `color`, or a `track` ring with an arc of `color` on it."""

    def render():
        s = size * SUPERSAMPLE
        img = Image.new("RGB", (s, s), bg)
        d = ImageDraw.Draw(img)
        w = int(s * width_frac)
        box = (w // 2, w // 2, s - w // 2 - 1, s - w // 2 - 1)
        if start is None:
            d.ellipse(box, outline=color, width=w)
        else:
            d.ellipse(box, outline=track, width=w)
            d.arc(box, start=start, end=start + extent, fill=color, width=w)
        return _downsample(img, (size, size))

    return _cached(("ring", size, bg, track, color, start, extent, width_frac), render)


class Ring(tk.Canvas):
    """Status ring: static (colored ring + center image/glyph/text) or spinning."""

    def __init__(self, parent, size=150, bg=CARD):
        super().__init__(parent, width=size, height=size, bg=bg, highlightthickness=0)
        self.size, self._bg = size, bg
        self._ring = self.create_image(size // 2, size // 2)
        self._center_img = self.create_image(size // 2, size // 2)
        self._glyph = self.create_text(size // 2, size // 2 - 8, fill=TEXT, font=icon_font(30))
        self._text = self.create_text(size // 2, size // 2, fill=TEXT, font=("Segoe UI Semibold", 18))
        self._sub = self.create_text(size // 2, size // 2 + 22, fill=TEXT_MUTED, font=("Segoe UI", 9))
        self._spin_job = None
        self._angle = 0

    def show(self, color, image=None, glyph=None, text="", glyph_color=None):
        """Static ring in `color`, with a center image, or a glyph over a short label."""
        self.stop()
        c = self.size // 2
        self.itemconfigure(self._ring, image=_ring_image(self.size, self._bg, color, color))
        self.itemconfigure(self._center_img, image=image or "")
        glyph_text = ICONS.get(glyph, "") if glyph and _icon_family else ""
        self.itemconfigure(self._glyph, text=glyph_text, fill=glyph_color or color)
        self.coords(self._glyph, c, c - 14 if text else c)
        self.coords(self._text, c, c + 24)
        self.itemconfigure(self._text, text=text, font=("Segoe UI Semibold", 11))
        self.itemconfigure(self._sub, text="")

    def spin(self, text="", subtext=""):
        """Rotating arc with a big number and a caption (used while scanning)."""
        c = self.size // 2
        self.itemconfigure(self._center_img, image="")
        self.itemconfigure(self._glyph, text="")
        self.coords(self._text, c, c - 7)
        self.coords(self._sub, c, c + 17)
        self.itemconfigure(self._text, text=text, font=("Segoe UI Semibold", 18))
        self.itemconfigure(self._sub, text=subtext)
        if self._spin_job is None:
            self._tick()

    def set_text(self, text, subtext=None):
        self.itemconfigure(self._text, text=text)
        if subtext is not None:
            self.itemconfigure(self._sub, text=subtext)

    def _tick(self):
        self._angle = (self._angle + 12) % 360
        self.itemconfigure(self._ring, image=_ring_image(
            self.size, self._bg, BORDER, ACCENT, start=self._angle, extent=100))
        self._spin_job = self.after(33, self._tick)

    def stop(self):
        if self._spin_job is not None:
            self.after_cancel(self._spin_job)
            self._spin_job = None


# ----------------------------------------------------------------- NavItem --
class NavItem(tk.Frame):
    def __init__(self, parent, icon, label, command):
        super().__init__(parent, bg=PANEL, cursor="hand2")
        self.active = False
        self.bar = tk.Frame(self, bg=PANEL, width=3)
        self.bar.pack(side="left", fill="y")
        self.icon = icon_label(self, icon, 13, fg=TEXT_MUTED, bg=PANEL)
        self.icon.pack(side="left", padx=(17, 12), pady=11)
        self.text = tk.Label(self, text=label, font=FONT, fg=TEXT_MUTED, bg=PANEL, anchor="w")
        self.text.pack(side="left", fill="x", expand=True)
        for w in (self, self.bar, self.icon, self.text):
            w.bind("<Button-1>", lambda e: command())
            w.bind("<Enter>", lambda e: self._hover(True))
            w.bind("<Leave>", lambda e: self._hover(False))

    def _paint(self, bg, fg, bar, font):
        for w in (self, self.icon, self.text):
            w.configure(bg=bg)
        self.icon.configure(fg=fg if not self.active else ACCENT)
        self.text.configure(fg=fg, font=font)
        self.bar.configure(bg=bar)

    def set_active(self, active: bool):
        self.active = active
        if active:
            self._paint(CARD, TEXT, ACCENT, FONT_BOLD)
        else:
            self._paint(PANEL, TEXT_MUTED, PANEL, FONT)

    def _hover(self, inside: bool):
        if not self.active:
            self._paint(CARD if inside else PANEL, TEXT if inside else TEXT_MUTED, PANEL, FONT)


# -------------------------------------------------------------- EmptyState --
class EmptyState(tk.Frame):
    """Centered message shown over an empty table."""

    def __init__(self, parent, icon, title, message, bg=CARD):
        super().__init__(parent, bg=bg)
        icon_label(self, icon, 30, fg=TEXT_MUTED, bg=bg).pack()
        self.title = tk.Label(self, text=title, font=FONT_BOLD, fg=TEXT, bg=bg)
        self.title.pack(pady=(10, 2))
        self.message = tk.Label(self, text=message, font=FONT, fg=TEXT_MUTED, bg=bg,
                                wraplength=380, justify="center")
        self.message.pack()

    def show(self, title=None, message=None):
        if title is not None:
            self.title.configure(text=title)
        if message is not None:
            self.message.configure(text=message)
        self.place(relx=0.5, rely=0.5, anchor="center")
        self.lift()

    def hide(self):
        self.place_forget()
