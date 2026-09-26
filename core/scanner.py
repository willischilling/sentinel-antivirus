"""File/directory scanner. Each file goes through these layers, strongest first:
exact fingerprint match (local list + MalwareBazaar), YARA rules, the files
inside ZIP archives, then heuristics. Weak signals (heuristics, low-score YARA)
are dropped for files with a valid publisher signature."""
from dataclasses import dataclass, field
from pathlib import Path

from . import archives, authenticode, database, heuristics, paths, signatures, yara_engine

SKIP_DIRS = {".git", "node_modules", "__pycache__", "$RECYCLE.BIN", "System Volume Information"}
MAX_FILE_SIZE = 500 * 1024 * 1024  # skip files over 500MB (perf)
# Sentinel's own data (threat database, compiled rules, logs) and the
# quarantine (known threats, already neutralised) must never be reported.
OWN_DIRS = tuple(p.resolve() for p in (paths.DATA_DIR, paths.QUARANTINE_DIR))


def is_own_file(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return False
    return any(resolved.is_relative_to(d) for d in OWN_DIRS)


@dataclass
class ScanResult:
    path: Path
    verdict: str  # "clean", "signature_match", "suspicious", "error"
    signature_name: str | None = None
    heuristic_flags: list[str] = field(default_factory=list)
    file_hash: str | None = None
    error: str | None = None
    publisher: str | None = None  # set when a valid signature cleared weak signals


# Large files only get the (slower) YARA pass if they could run or carry something that can:
# programs, scripts, archives, Office documents, PDFs. Big logs, game data, fonts and the like
# still get the fingerprint check, which catches known malware whatever its name.
YARA_SMALL = 2 * 1024 * 1024
RISKY_MAGIC = (b"MZ", b"\x7fELF", b"PK", b"Rar!", b"7z\xbc\xaf", b"\xd0\xcf\x11\xe0", b"%PDF", b"{\\rtf", b"#!",
               b"MSCF", b"\x1f\x8b")


def worth_yara(path: Path, size: int) -> bool:
    if size <= YARA_SMALL or path.suffix.lower() in heuristics.RUNNABLE_EXTS:
        return True
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return True
    return head.startswith(RISKY_MAGIC)


def scan_file(path: Path) -> ScanResult:
    if is_own_file(path):
        return ScanResult(path, "clean")
    try:
        size = path.stat().st_size
        if size > MAX_FILE_SIZE:
            return ScanResult(path, "clean", error="skipped: file too large")

        is_match, sig_name, file_hash = signatures.check_file(path)
        if is_match:
            result = ScanResult(path, "signature_match", signature_name=sig_name, file_hash=file_hash)
            database.log_scan(str(path), result.verdict, sig_name or "")
            return result

        yara_hits = yara_engine.match(path, size) if worth_yara(path, size) else []
        strong = [h for h in yara_hits if h.score >= yara_engine.THREAT_SCORE]
        if strong:
            name = f"YARA: {strong[0].rule}"
            result = ScanResult(path, "signature_match", signature_name=name, file_hash=file_hash)
            database.log_scan(str(path), result.verdict, name)
            return result

        archive_flags = []
        if archives.is_archive(path):
            report = archives.scan(path)
            if report.threats:
                name = f"Inside archive: {report.threats[0]}"
                if len(report.threats) > 1:
                    name += f" (+{len(report.threats) - 1} more)"
                result = ScanResult(path, "signature_match", signature_name=name, file_hash=file_hash)
                database.log_scan(str(path), result.verdict, name)
                return result
            archive_flags = [f"Inside archive: {s}" for s in report.suspicious]
            # Weak rules matched against the compressed bytes are noise; the contents were just checked.
            yara_hits = []

        flags = [f"YARA rule matched: {h.rule}" for h in yara_hits] + heuristics.check_file(path)
        publisher = None
        if flags:
            signature = authenticode.check(path)
            if signature.signed:  # e.g. Microsoft or Intel tools that legitimately use injection APIs
                flags, publisher = [], signature.publisher
        flags = archive_flags + flags
        verdict = "suspicious" if flags else "clean"
        result = ScanResult(path, verdict, heuristic_flags=flags, file_hash=file_hash, publisher=publisher)
        if verdict != "clean":
            database.log_scan(str(path), verdict, "; ".join(flags))
        return result

    except (PermissionError, OSError) as e:
        return ScanResult(path, "error", error=str(e))


def scan_directory(root: Path, recursive: bool = True):
    """Generator yielding ScanResult for each file under root."""
    if not root.exists():
        return

    if root.is_file():
        yield scan_file(root)
        return

    walker = root.rglob("*") if recursive else root.glob("*")
    for entry in walker:
        if entry.is_dir():
            continue
        if any(part in SKIP_DIRS for part in entry.parts) or is_own_file(entry):
            continue
        yield scan_file(entry)
