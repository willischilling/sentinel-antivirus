"""System tray icon. pystray runs its own loop on a background thread, so
callbacks must only hand work to the Tk thread (e.g. via a queue)."""
import threading

import pystray
from PIL import Image


class Tray:
    def __init__(self, icon_path, title, items):
        """items: (label, zero-arg callback, is_default) tuples. A label can be a
        callable taking the menu item, so it's re-read each time the menu opens
        (used for language changes)."""
        menu = pystray.Menu(*[
            pystray.MenuItem(label, callback, default=is_default)
            for label, callback, is_default in items
        ])
        self.icon = pystray.Icon("Sentinel", Image.open(icon_path), title, menu)

    def start(self):
        threading.Thread(target=self.icon.run, daemon=True).start()

    def stop(self):
        self.icon.stop()
