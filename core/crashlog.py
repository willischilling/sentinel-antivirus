"""Records unexpected errors in data/crash.log. The installed app has no console, so
without this an error in the window or a background thread vanishes without a trace."""
import faulthandler
import sys
import threading
import time
import traceback

from . import paths

LOG_PATH = paths.DATA_DIR / "crash.log"
MAX_SIZE = 256 * 1024
_fault_file = None


def write(where: str, exc_type, exc, tb):
    try:
        if LOG_PATH.exists() and LOG_PATH.stat().st_size > MAX_SIZE:
            LOG_PATH.replace(LOG_PATH.with_suffix(".old.log"))
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"--- {time.strftime('%Y-%m-%d %H:%M:%S')} {where}\n")
            f.write("".join(traceback.format_exception(exc_type, exc, tb)))
    except OSError:
        pass


def install(role: str):
    """role: "window" or "agent"."""
    global _fault_file
    sys.excepthook = lambda t, e, tb: write(role, t, e, tb)
    threading.excepthook = lambda a: write(f"{role} thread {a.thread.name if a.thread else '?'}",
                                           a.exc_type, a.exc_value, a.exc_traceback)
    try:
        _fault_file = open(LOG_PATH.with_name("crash_native.log"), "a", encoding="utf-8")
        faulthandler.enable(_fault_file)  # hard crashes inside native code (Tk, SQLite, YARA...)
    except OSError:
        pass
