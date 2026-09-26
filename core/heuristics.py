"""Lightweight heuristic checks: suspicious strings, entropy, extension spoofing."""
import math
import re
from collections import Counter
from pathlib import Path

SUSPICIOUS_STRINGS = [
    rb"powershell -enc",
    rb"powershell.exe -windowstyle hidden",
    rb"cmd.exe /c del",
    rb"reg add.*\\Run",
    rb"vssadmin delete shadows",
    rb"bcdedit /set.*recoveryenabled no",
    rb"CreateRemoteThread",
    rb"VirtualAllocEx",
    rb"WriteProcessMemory",
    rb"base64 -d.*\|.*sh",
    rb"IEX\s*\(",
    rb"DownloadString",
]
SUSPICIOUS_RE = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_STRINGS]

# Extensions that are commonly disguised (double extension trick)
DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|bat|cmd|js|vbs|ps1)$", re.IGNORECASE
)

SCAN_CHUNK = 512 * 1024  # only scan first 512KB for strings (perf)
ENTROPY_SAMPLE = 128 * 1024  # entropy only needs a small sample to be meaningful


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    # Counter() does the byte-frequency count in C; only the final log2 sum
    # (at most 256 iterations) runs in pure Python, which keeps this from
    # blocking the GIL long enough to make a threaded GUI stutter.
    length = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# Entropy alone is a weak signal: nearly all legitimately compressed/packed
# executables (installers, self-extracting archives) score above 7.5 too.
# Script-like formats are rarely legitimately high-entropy, so it's a much
# stronger signal there than for compiled binaries.
ENTROPY_SCRIPT_EXTS = {".ps1", ".vbs", ".js", ".bat", ".cmd"}
ENTROPY_BINARY_EXTS = {".exe", ".dll", ".scr"}

# Suspicious text only matters in something that can run. A database, log or
# text file that merely contains "powershell -enc" (Sentinel's own scan
# history, security articles, source code) is harmless. "" = no extension.
RUNNABLE_EXTS = {
    "", ".exe", ".dll", ".scr", ".sys", ".com", ".pif", ".cpl", ".ocx", ".msi", ".msp",
    ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".hta", ".sct", ".lnk", ".jar", ".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".potm",
}


def check_file(path: Path) -> list[str]:
    try:
        with open(path, "rb") as f:
            data = f.read(SCAN_CHUNK)
    except (PermissionError, OSError):
        data = b""
    return check_bytes(path.name, data)


def check_bytes(name: str, data: bytes) -> list[str]:
    """Returns a list of human-readable heuristic flags (empty = clean).
    Works on in-memory content too, e.g. a file inside a ZIP.

    Only "hard" signals (suspicious strings, double extensions) trigger a
    flag on their own. Entropy is noisy for compiled binaries, so it is only
    surfaced as corroborating detail once a hard signal already fired.
    """
    hard_flags = []
    if DOUBLE_EXT_RE.search(name):
        hard_flags.append(f"Suspicious double extension: {name}")

    suffix = Path(name).suffix.lower()
    if suffix not in RUNNABLE_EXTS:
        return hard_flags

    data = data[:SCAN_CHUNK]
    for pattern in SUSPICIOUS_RE:
        if pattern.search(data):
            hard_flags.append(f"Suspicious pattern matched: {pattern.pattern.decode(errors='replace')}")

    if suffix in ENTROPY_SCRIPT_EXTS:
        entropy = shannon_entropy(data[:ENTROPY_SAMPLE])
        if entropy > 6.5:
            hard_flags.append(f"High entropy for a script file ({entropy:.2f}/8.0) — possible obfuscation")
    elif hard_flags and suffix in ENTROPY_BINARY_EXTS:
        entropy = shannon_entropy(data[:ENTROPY_SAMPLE])
        if entropy > 7.5:
            hard_flags.append(f"High entropy ({entropy:.2f}/8.0) — possible packing/obfuscation")

    return hard_flags
