"""Background keeper. Every ~20 seconds it:

1. Makes this PC's internet match what it should be — paused when a focus timer
   is running, during an off-hours schedule window, or when you paused it by
   hand; online otherwise.
2. Every few minutes, re-applies the website blocks if something changed them.

Changes to the firewall or hosts file need the one Windows admin prompt, so the
keeper is edge-triggered: it acts once when the desired state changes, not every
tick, and won't ask again for the same thing until it changes.
"""
import threading
import time

from . import control, firewall, hostsblock

PAUSE_EVERY = 20       # seconds between pause-state checks
BLOCK_EVERY = 300      # seconds between website-block checks


def start(on_event=None) -> threading.Thread:
    """Start the keeper in a daemon thread. on_event(text) runs on that thread."""
    thread = threading.Thread(target=_loop, args=(on_event,), daemon=True)
    thread.start()
    return thread


def _loop(on_event):
    time.sleep(10)
    last_pause_target = None   # the desired pause state we last tried to apply
    last_block_sig = None
    since_block = BLOCK_EVERY
    while True:
        # --- this PC's internet matches schedule / focus / manual ----------
        try:
            want = control.desired_pc_paused()
            if want != last_pause_target:
                actual = firewall.internet_paused()
                if actual != want:
                    control.enforce_this_pc(want)
                    reason = control.pause_reason() or ("manual" if want else "")
                    msg = ("Paused this PC" if want else "Resumed this PC") + (f" ({reason})" if reason and want
                                                                               else "")
                    control.log("auto", msg)
                    if on_event:
                        on_event(msg)
                last_pause_target = want
        except Exception:
            pass  # declined prompt or transient error; retry when the target changes

        # --- website blocks stay applied ----------------------------------
        since_block += PAUSE_EVERY
        if since_block >= BLOCK_EVERY:
            since_block = 0
            try:
                if control.enforce_on() and control.needs_reapply():
                    sig = tuple(sorted(control.active_blocklist()))
                    if sig != last_block_sig:
                        last_block_sig = sig
                        control.reapply()
                        control.log("auto", f"Put back {len(sig)} blocked site(s)")
                        if on_event:
                            on_event("Put back website blocks that were changed.")
                else:
                    last_block_sig = None
            except Exception:
                pass
        time.sleep(PAUSE_EVERY)
