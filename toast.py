"""Bottom-right popup notifications, drawn by the app just above the taskbar."""
import sys
import tkinter as tk
from tkinter import ttk

from core.i18n import t
import theme as C
from theme import FONT_BOLD, FONT_SMALL

WIDTH = 360
MARGIN = 16
GAP = 10


def _work_area(root: tk.Misc) -> tuple[int, int]:
    """Right/bottom edge of the usable screen area (excludes the taskbar)."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        rect = wintypes.RECT()
        SPI_GETWORKAREA = 0x0030
        if ctypes.windll.user32.SystemParametersInfoW(SPI_GETWORKAREA, 0, ctypes.byref(rect), 0):
            return rect.right, rect.bottom
    return root.winfo_screenwidth(), root.winfo_screenheight() - 48


class Toast(tk.Toplevel):
    def __init__(self, manager, title, filename, detail, location, accent, actions,
                 on_error=None, auto_close_ms=None):
        super().__init__(manager.root)
        self.manager = manager
        self.on_error = on_error
        self.buttons = {}
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.attributes("-alpha", 0.0)
        self.configure(bg=C.BORDER)

        body = tk.Frame(self, bg=C.CARD)
        body.pack(fill="both", expand=True, padx=1, pady=1)
        tk.Frame(body, bg=accent, width=4).pack(side="left", fill="y")

        content = tk.Frame(body, bg=C.CARD, padx=14, pady=12)
        content.pack(side="left", fill="both", expand=True)

        header = tk.Frame(content, bg=C.CARD)
        header.pack(fill="x")
        tk.Label(header, text=title, bg=C.CARD, fg=accent, font=FONT_BOLD).pack(side="left")
        close = tk.Label(header, text="✕", bg=C.CARD, fg=C.TEXT_MUTED, font=FONT_SMALL, cursor="hand2")
        close.pack(side="right")
        close.bind("<Button-1>", lambda e: self.dismiss())

        wrap = WIDTH - 50
        for text, color, font, pady in (
            (filename, C.TEXT, FONT_BOLD, (6, 0)),
            (detail, C.TEXT_MUTED, FONT_SMALL, (2, 0)),
            (location, C.TEXT_MUTED, FONT_SMALL, (0, 0)),
        ):
            if text:
                tk.Label(content, text=text, bg=C.CARD, fg=color, font=font, wraplength=wrap,
                         justify="left", anchor="w").pack(fill="x", pady=pady)

        self.button_row = tk.Frame(content, bg=C.CARD)
        if actions:
            self.button_row.pack(fill="x", pady=(12, 0))
        if auto_close_ms:
            self.after(auto_close_ms, self.dismiss)
        for label, style, callback in actions:
            btn = ttk.Button(self.button_row, text=label, style=style,
                             command=lambda cb=callback, lb=label: self._run_action(cb, lb))
            btn.pack(side="left", padx=(0, 8))
            self.buttons[label] = btn

        self.status = tk.Label(content, text="", bg=C.CARD, fg=C.TEXT, font=FONT_SMALL,
                               wraplength=wrap, justify="left", anchor="w")

    def _run_action(self, callback, label):
        """callback returns a status message to show, or None to just close."""
        try:
            message = callback()
        except Exception as e:
            if self.on_error:
                self.on_error(label, e)
            self._show_status(t("toast_failed", action=label, error=e), C.BAD, close_after_ms=8000)
            return
        if message is None:
            self.dismiss()
        else:
            self._show_status(message, C.TEXT, close_after_ms=2500)

    def _show_status(self, message, color, close_after_ms):
        self.button_row.pack_forget()
        self.status.configure(text=message, fg=color)
        self.status.pack(fill="x", pady=(12, 0))
        self.manager.reflow()
        self.after(close_after_ms, self.dismiss)

    def fade_in(self, alpha=0.0):
        alpha = min(alpha + 0.12, 1.0)
        self.attributes("-alpha", alpha)
        if alpha < 1.0:
            self.after(15, self.fade_in, alpha)

    def dismiss(self):
        if self.winfo_exists():
            self.manager.remove(self)
            self.destroy()


class ToastManager:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.toasts: list[Toast] = []

    def show(self, title, filename, detail, location, accent, actions=(),
             on_error=None, auto_close_ms=None) -> Toast:
        toast = Toast(self, title, filename, detail, location, accent, actions,
                      on_error, auto_close_ms)
        self.toasts.append(toast)
        self.reflow()
        toast.fade_in()
        return toast

    def remove(self, toast: Toast):
        if toast in self.toasts:
            self.toasts.remove(toast)
            self.reflow()

    def reflow(self):
        """Newest toast sits at the bottom; older ones stack upward."""
        right, bottom = _work_area(self.root)
        y = bottom - MARGIN
        for toast in reversed(self.toasts):
            toast.update_idletasks()
            height = toast.winfo_reqheight()
            y -= height
            toast.geometry(f"{WIDTH}x{height}+{right - WIDTH - MARGIN}+{y}")
            y -= GAP
