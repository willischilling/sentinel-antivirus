"""Starts/stops the background protection agent and opens the main window,
for both the installed exe and a dev run from source."""
import subprocess
import sys
import time
from pathlib import Path

import single_instance

DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200


def _command(*args: str) -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, *args]
    return [sys.executable, str(Path(__file__).resolve().parent / "gui.py"), *args]


def _spawn(*args: str):
    # Detached so it outlives whichever process launched it.
    subprocess.Popen(
        _command(*args),
        creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
        close_fds=True,
    )


def agent_running() -> bool:
    return single_instance.AGENT.is_running()


def start_agent():
    if not agent_running():
        _spawn("--agent")


def stop_agent(timeout: float = 6.0) -> bool:
    # Re-signal while waiting: an agent that's still starting up may not be
    # listening yet when the first signal goes out.
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not agent_running():
            return True
        single_instance.AGENT.signal()
        time.sleep(0.25)
    return not agent_running()


def open_ui():
    if single_instance.UI.is_running():
        single_instance.UI.signal()
    else:
        _spawn()
