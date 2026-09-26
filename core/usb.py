"""Removable drives (USB sticks, SD cards) for USB scanning: which ones are
plugged in right now, with their names. The background agent polls this and
scans (or offers to scan) each newly inserted drive.
"""
import ctypes
from dataclasses import dataclass

import psutil

from . import settings

MODES = ("scan", "ask", "off")
DEFAULT_MODE = "scan"


@dataclass(frozen=True)
class Drive:
    root: str      # e.g. "E:\\"
    label: str     # volume name, e.g. "KINGSTON" (may be empty)

    @property
    def display(self) -> str:
        letter = self.root.rstrip("\\")
        return f"{self.label} ({letter})" if self.label else letter


def mode() -> str:
    value = settings.load().get("usb_mode", DEFAULT_MODE)
    return value if value in MODES else DEFAULT_MODE


def removable_drives() -> set[Drive]:
    drives = set()
    for part in psutil.disk_partitions(all=False):
        if "removable" in part.opts and "cdrom" not in part.opts:
            drives.add(Drive(part.mountpoint, _label(part.mountpoint)))
    return drives


def _label(root: str) -> str:
    buf = ctypes.create_unicode_buffer(261)
    try:
        ok = ctypes.windll.kernel32.GetVolumeInformationW(root, buf, 261, None, None, None, None, 0)
    except OSError:
        return ""
    return buf.value if ok else ""
