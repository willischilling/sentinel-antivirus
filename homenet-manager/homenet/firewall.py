"""Pauses and resumes THIS PC's internet through the built-in Windows Firewall.

Pausing adds a block-all-outbound rule ("Home Network: Internet Paused") with
netsh, which cuts all outgoing traffic; resuming deletes it. For the rule to
take effect the Windows Firewall has to be on, so pausing turns it on first.

After pausing, it VERIFIES the internet is really cut (by trying to connect
out). If traffic still gets through — usually because another security product
has taken over the firewall — it says so instead of pretending it worked.

Every change goes through the one Windows admin prompt (elevate.py).
"""
import socket
import subprocess
import time

PAUSE_RULE = "Home Network: Internet Paused"
CREATE_NO_WINDOW = 0x08000000
PROBES = [("1.1.1.1", 443), ("8.8.8.8", 443), ("1.1.1.1", 53)]


def _netsh(*args, timeout=25) -> subprocess.CompletedProcess:
    return subprocess.run(["netsh", "advfirewall", *args], capture_output=True, text=True,
                          stdin=subprocess.DEVNULL, timeout=timeout, creationflags=CREATE_NO_WINDOW,
                          errors="replace")


def _can_reach(timeout=1.5) -> bool:
    """True if any outbound test connection succeeds right now."""
    for host, port in PROBES:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def pause_internet():
    from . import elevate
    elevate.run("firewall", "pause")


def resume_internet():
    from . import elevate
    elevate.run("firewall", "resume")


def internet_paused() -> bool:
    """Whether the pause rule is in place (reads state, no admin prompt).
    netsh exits 0 when the rule exists, non-zero when no rule matches —
    language-independent, unlike parsing the printed text."""
    return _netsh("firewall", "show", "rule", f"name={PAUSE_RULE}", "dir=out", timeout=15).returncode == 0


# ------------------------------------------------ admin side (one prompt) --
def _add_block_rule():
    return _netsh("firewall", "add", "rule", f"name={PAUSE_RULE}",
                  "dir=out", "action=block", "enable=yes", "profile=any",
                  "description=Internet paused by Home Network Manager")


def _delete_rule():
    # Deleting a non-existent rule returns non-zero; that's fine.
    _netsh("firewall", "delete", "rule", f"name={PAUSE_RULE}", timeout=15)


def elevated(action: str, args: list[str]):
    """Admin side: only pause or resume, with no free-form arguments."""
    if action == "resume":
        _delete_rule()
        return
    if action != "pause":
        raise RuntimeError(f"unknown firewall action {action!r}")

    could_reach = _can_reach()  # baseline: is the internet up at all?

    on = _netsh("set", "allprofiles", "state", "on")
    if on.returncode != 0:
        raise RuntimeError("Couldn't turn the Windows Firewall on. Its service may be stopped or managed by "
                           "another security program. " + (on.stderr or on.stdout).strip()[:200])
    _delete_rule()
    added = _add_block_rule()
    if added.returncode != 0:
        raise RuntimeError("Couldn't add the block rule. " + (added.stderr or added.stdout).strip()[:200])

    # Verify it actually cut traffic. If we had internet before and still do,
    # the firewall isn't enforcing our rule.
    if could_reach:
        time.sleep(1.2)
        if _can_reach():
            _delete_rule()  # don't leave a rule that does nothing
            raise RuntimeError("The block was added but the internet is still on, so the Windows Firewall isn't "
                               "enforcing it — usually because another antivirus/firewall has taken it over. "
                               "Pause can't work until Windows Firewall is the active firewall.")
