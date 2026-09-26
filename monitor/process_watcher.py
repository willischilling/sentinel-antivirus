"""Real-time process monitoring: check running programs' files against the
fingerprint database and YARA rules."""
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path

import psutil

from core import database, signatures, yara_engine


@dataclass
class ProcessAlert:
    pid: int
    name: str
    exe_path: str
    signature_name: str


# (exe path, mtime, size) -> threat name or None. Re-reading every running
# program's file every few seconds is expensive, so each file is judged once
# until it changes or the threat data is updated.
_verdicts: dict[tuple, str | None] = {}
_verdicts_intel_version = None


def _judge(exe: Path, stat) -> str | None:
    match = database.lookup_signature(signatures.hash_file(exe))
    if match:
        return match
    strong = [h for h in yara_engine.match(exe, stat.st_size) if h.score >= yara_engine.THREAT_SCORE]
    return f"YARA: {strong[0].rule}" if strong else None


def _refresh_cache_if_intel_changed():
    global _verdicts_intel_version
    intel_version = database.get_meta("intel_updated")
    if intel_version != _verdicts_intel_version:
        _verdicts.clear()
        _verdicts_intel_version = intel_version


def _check(proc) -> ProcessAlert | None:
    exe = proc.exe()
    if not exe:
        return None
    stat = Path(exe).stat()
    key = (exe, stat.st_mtime_ns, stat.st_size)
    if key not in _verdicts:
        _verdicts[key] = _judge(Path(exe), stat)
    return ProcessAlert(proc.pid, proc.name(), exe, _verdicts[key]) if _verdicts[key] else None


def scan_running_processes(pids=None) -> list[ProcessAlert]:
    """Checks the given PIDs (default: every running process)."""
    _refresh_cache_if_intel_changed()
    alerts = []
    for pid in (psutil.pids() if pids is None else pids):
        try:
            alert = _check(psutil.Process(pid))
            if alert:
                alerts.append(alert)
        except (psutil.NoSuchProcess, psutil.AccessDenied, PermissionError, OSError):
            continue
    return alerts


def monitor_loop(interval_seconds: float, on_alert, stop_flag: list[bool],
                 full_sweep_seconds: float = 60.0, sweep_batch: int = 8):
    """Every `interval_seconds`: check newly started processes first, then a
    small batch of a background sweep over everything already running.

    New programs are never stuck behind the sweep, and the sweep's cost (reading
    each program file once to fill the cache) is spread out instead of spiking.
    The sweep restarts every `full_sweep_seconds` so programs that become
    known-bad after a threat database update are still caught.
    on_alert(ProcessAlert) is called once per matching process.
    """
    already_alerted = set()
    seen = set()
    sweep = deque()
    next_sweep = 0.0
    while not stop_flag[0]:
        current = set(psutil.pids())
        now = time.monotonic()
        new = current - seen if seen else set()
        seen = current
        if not sweep and now >= next_sweep:
            sweep.extend(current)
            next_sweep = now + full_sweep_seconds
        batch = [sweep.popleft() for _ in range(min(sweep_batch, len(sweep)))]
        already_alerted &= current  # forget processes that have exited
        for alert in scan_running_processes(list(new) + [p for p in batch if p not in new]):
            if alert.pid not in already_alerted:
                already_alerted.add(alert.pid)
                on_alert(alert)
        time.sleep(interval_seconds)


def kill_process(pid: int) -> bool:
    """True once the process is gone (including if it had already exited)."""
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        proc.wait(timeout=5)
        return True
    except psutil.NoSuchProcess:
        return True
    except (psutil.TimeoutExpired, psutil.AccessDenied):
        return False
