"""YARA rule matching (rules from YARA Forge, compiled by core/threat_intel.py).

Rules are compiled once and cached on disk; each process loads the compiled
file and reloads it automatically when an update replaces it.
"""
import threading
from dataclasses import dataclass
from pathlib import Path

from . import paths

try:
    import yara
except ImportError:  # the app still works without YARA, just with less coverage
    yara = None

RULES_DIR = paths.DATA_DIR / "yara"
COMPILED_PATH = RULES_DIR / "core.yarc"

MAX_FILE_SIZE = 32 * 1024 * 1024
# Media rarely carries executable malware and is often huge; skipping it keeps scans fast.
SKIP_SUFFIXES = {".mp4", ".mkv", ".avi", ".mov", ".mp3", ".wav", ".flac", ".jpg", ".jpeg",
                 ".png", ".gif", ".webp", ".heic", ".iso", ".vhd", ".vhdx"}
THREAT_SCORE = 70  # YARA Forge scores rules 0-100; at/above this we treat a hit as a threat
DEFAULT_SCORE = 75

_lock = threading.Lock()
_rules = None
_loaded_mtime = None


@dataclass
class YaraHit:
    rule: str
    score: int
    description: str


def available() -> bool:
    return yara is not None and COMPILED_PATH.exists()


def _get_rules():
    global _rules, _loaded_mtime
    if yara is None:
        return None
    try:
        mtime = COMPILED_PATH.stat().st_mtime_ns
    except FileNotFoundError:
        return None
    with _lock:
        if _rules is None or mtime != _loaded_mtime:
            try:
                _rules = yara.load(str(COMPILED_PATH))
                _loaded_mtime = mtime
            except yara.Error:
                return _rules
        return _rules


def rule_count() -> int:
    rules = _get_rules()
    return sum(1 for _ in rules) if rules else 0


def match(path: Path, size: int | None = None) -> list[YaraHit]:
    if path.suffix.lower() in SKIP_SUFFIXES:
        return []
    if size is None:
        try:
            size = path.stat().st_size
        except OSError:
            return []
    if size > MAX_FILE_SIZE:
        return []
    return _run(lambda rules: rules.match(str(path), timeout=30))


def match_data(name: str, data: bytes) -> list[YaraHit]:
    """Same as match(), for in-memory content (e.g. a file inside a ZIP)."""
    if Path(name).suffix.lower() in SKIP_SUFFIXES or len(data) > MAX_FILE_SIZE:
        return []
    return _run(lambda rules: rules.match(data=data, timeout=30))


def _run(do_match) -> list[YaraHit]:
    rules = _get_rules()
    if rules is None:
        return []
    try:
        matches = do_match(rules)
    except yara.Error:
        return []
    hits = []
    for m in matches:
        try:
            score = int(m.meta.get("score", DEFAULT_SCORE))
        except (TypeError, ValueError):
            score = DEFAULT_SCORE
        hits.append(YaraHit(m.rule, score, str(m.meta.get("description", ""))))
    return sorted(hits, key=lambda h: -h.score)
