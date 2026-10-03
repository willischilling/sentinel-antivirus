"""Home Network Manager — entry point.

Normal run:      python main.py           (opens the window)
Admin helper:    python main.py --elevated <result-file> <action> <args...>
                 (launched by the app itself through the Windows admin prompt;
                  not meant to be run by hand)

Because the built app runs with no console, any crash would otherwise vanish
silently. So unexpected errors are written to a crash log instead:
%LOCALAPPDATA%\\HomeNetManager\\crash.log
"""
import sys
import threading
import traceback

from homenet import elevate, settings


def _install_crash_logging():
    def hook(exc_type, exc, tb):
        settings.log_crash("uncaught", "".join(traceback.format_exception(exc_type, exc, tb)))
    sys.excepthook = hook

    def thread_hook(args):
        settings.log_crash("thread", "".join(
            traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)))
    try:
        threading.excepthook = thread_hook
    except Exception:
        pass


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == elevate.FLAG:
        return elevate.main(sys.argv[2:])
    _install_crash_logging()
    try:
        from homenet import ui
        ui.run()
    except Exception:
        settings.log_crash("startup", traceback.format_exc())
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
