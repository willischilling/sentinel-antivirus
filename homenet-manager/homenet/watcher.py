"""Background check that keeps the website blocks in place.

Every few minutes it reads the hosts file (no admin rights) and, if the block
has been removed or changed, puts it back. Re-applying needs the one Windows
admin prompt, so it is edge-triggered: it acts once when a change first
appears, not every tick, and won't ask again for the same list until it has
been restored or the list changes.
"""
import threading
import time

from . import control

CHECK_SECONDS = 300  # every 5 minutes


def start(on_reapplied=None, on_error=None) -> threading.Thread:
    """Start the check in a daemon thread. Callbacks run on that thread."""
    thread = threading.Thread(target=_loop, args=(on_reapplied, on_error), daemon=True)
    thread.start()
    return thread


def _loop(on_reapplied, on_error):
    time.sleep(20)
    acted_on = None
    while True:
        try:
            if control.enforce_on() and control.needs_reapply():
                want = tuple(sorted(control.active_blocklist()))
                if want != acted_on:
                    acted_on = want
                    control.reapply()  # one admin prompt; raises if declined
                    if on_reapplied:
                        on_reapplied(len(want))
            else:
                acted_on = None
        except Exception as e:
            if on_error:
                on_error(str(e))
        time.sleep(CHECK_SECONDS)
