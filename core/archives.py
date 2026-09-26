"""Scans the files inside archives.

- ZIP-format (.zip, .jar): read in memory with Python's zipfile.
- 7-Zip, RAR, TAR, CAB and ISO disk images: listed and extracted with
  Windows' own tar.exe (Microsoft-signed libarchive), into a temporary folder
  that is deleted afterwards. Nothing extra has to be installed or bundled.

The listing is checked against limits before anything is extracted, so zip
bombs (tiny archives that expand to gigabytes) are caught without expanding
them. Archives inside archives are followed up to MAX_DEPTH levels, across
formats (a RAR inside a ZIP, and so on).
"""
import hashlib
import io
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import authenticode, database, heuristics, yara_engine

ZIP_SUFFIXES = {".zip", ".jar"}
LIBARCHIVE_SUFFIXES = {".7z", ".rar", ".tar", ".tgz", ".cab", ".iso"}
LIBARCHIVE_DOUBLE = (".tar.gz", ".tar.xz", ".tar.bz2", ".tar.zst")
MAX_MEMBERS = 2000
MAX_MEMBER_SIZE = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_RATIO = 250            # real files rarely compress past ~100:1; bombs go far beyond
MAX_DEPTH = 2              # archive inside archive inside archive
TOOL_TIMEOUT = 120
CREATE_NO_WINDOW = 0x08000000  # no console flash when run from the windowed app
SIGNABLE_SUFFIXES = {".exe", ".dll", ".sys", ".msi", ".scr", ".ocx"}
# Password-protected archives are a classic way to sneak programs past scanners.
RUNNABLE_SUFFIXES = SIGNABLE_SUFFIXES | {".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf",
                                         ".hta", ".lnk", ".com", ".pif", ".jar", ".iso"}
# bsdtar -tv line: mode links owner group size month day time|year name
LISTING_RE = re.compile(r"^(\S)\S*\s+\d+\s+\S+\s+\S+\s+(\d+)\s+\w{3}\s+\d+\s+(?:\d{1,2}:\d{2}|\d{4})\s(.+)$")


@dataclass
class ArchiveReport:
    threats: list[str] = field(default_factory=list)      # "member: threat name"
    suspicious: list[str] = field(default_factory=list)   # "member: reason"
    notes: list[str] = field(default_factory=list)        # things that couldn't be scanned


def _tar_exe() -> str | None:
    system_tar = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "tar.exe"
    return str(system_tar) if system_tar.exists() else shutil.which("tar")


def archive_kind(path: Path) -> str | None:
    name = path.name.lower()
    if path.suffix.lower() in ZIP_SUFFIXES:
        return "zip"
    if path.suffix.lower() in LIBARCHIVE_SUFFIXES or name.endswith(LIBARCHIVE_DOUBLE):
        return "libarchive" if _tar_exe() else None
    return None


def is_archive(path: Path) -> bool:
    kind = archive_kind(path)
    return kind == "libarchive" or (kind == "zip" and zipfile.is_zipfile(path))


def scan(path: Path) -> ArchiveReport:
    report = ArchiveReport()
    budget = [MAX_TOTAL_BYTES, MAX_MEMBERS]
    _scan_path(path, "", 0, report, budget)
    return report


def _scan_path(path: Path, prefix: str, depth: int, report: ArchiveReport, budget: list):
    kind = archive_kind(path)
    if kind == "zip":
        try:
            with zipfile.ZipFile(path) as zf:
                _scan_zip(zf, prefix, depth, report, budget)
        except (zipfile.BadZipFile, OSError, RuntimeError) as e:
            report.notes.append(f"{prefix}couldn't open archive: {e}")
    elif kind == "libarchive":
        _scan_libarchive(path, prefix, depth, report, budget)


# ------------------------------------------------------------------- ZIP --
def _scan_zip(zf: zipfile.ZipFile, prefix: str, depth: int, report: ArchiveReport, budget: list):
    batch = _Batch(report)
    for info in zf.infolist():
        if info.is_dir():
            continue
        name = prefix + info.filename
        if budget[1] <= 0:
            report.notes.append("Stopped early: too many files in archive")
            return
        budget[1] -= 1
        if info.flag_bits & 0x1:
            _encrypted_member(name, report)
            continue
        ratio = info.file_size / max(info.compress_size, 1)
        if info.file_size > 1024 * 1024 and ratio > MAX_RATIO:
            report.suspicious.append(f"{name}: possible zip bomb ({ratio:.0f}:1 compression)")
            continue
        if info.file_size > MAX_MEMBER_SIZE or info.file_size > budget[0]:
            report.notes.append(f"{name}: too large to scan inside the archive")
            continue
        try:
            with zf.open(info) as member:
                data = member.read(MAX_MEMBER_SIZE + 1)  # never trust the declared size
        except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError) as e:
            report.notes.append(f"{name}: couldn't be read ({e})")
            continue
        budget[0] -= len(data)
        batch.add(name, data)
        if depth < MAX_DEPTH:
            _scan_nested_bytes(info.filename, name, data, depth, report, budget)
    batch.flush()


def _scan_nested_bytes(filename: str, name: str, data: bytes, depth: int, report, budget):
    """An archive found inside an archive: scan its contents too."""
    kind = archive_kind(Path(filename))
    if kind == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as inner:
                _scan_zip(inner, name + " > ", depth + 1, report, budget)
        except zipfile.BadZipFile:
            pass
    elif kind == "libarchive":
        tmpdir = tempfile.mkdtemp(prefix="sentinel_nested_")
        try:
            inner = Path(tmpdir) / Path(filename).name
            inner.write_bytes(data)
            _scan_libarchive(inner, name + " > ", depth + 1, report, budget)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------- 7z / RAR / TAR / ISO --
def _run_tar(*args) -> subprocess.CompletedProcess:
    return subprocess.run([_tar_exe(), *args], capture_output=True, timeout=TOOL_TIMEOUT,
                          creationflags=CREATE_NO_WINDOW)


def _decode(raw: bytes) -> str:
    for encoding in ("utf-8", "mbcs"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1")


def _scan_libarchive(path: Path, prefix: str, depth: int, report: ArchiveReport, budget: list):
    label = prefix.rstrip(" >") or path.name
    try:
        listing = _run_tar("-tvf", str(path))
    except (OSError, subprocess.TimeoutExpired) as e:
        report.notes.append(f"{label}: couldn't list archive ({e})")
        return
    errors = _decode(listing.stderr)
    entries = []  # (name, size)
    for line in _decode(listing.stdout).splitlines():
        m = LISTING_RE.match(line)
        if m and m.group(1) != "d":
            entries.append((m.group(3), int(m.group(2))))
    if not entries:
        if "ncrypt" in errors:  # names themselves are encrypted: nothing can be checked
            report.suspicious.append(
                f"{label}: password-protected archive with hidden file names (contents can't be checked)")
        elif listing.returncode != 0:
            report.notes.append(f"{label}: unsupported or damaged archive")
        return

    total = sum(size for _, size in entries)
    packed = max(path.stat().st_size, 1)
    if total > 1024 * 1024 and total / packed > MAX_RATIO:
        report.suspicious.append(f"{label}: possible archive bomb ({total / packed:.0f}:1 compression)")
        return
    if len(entries) > budget[1] or total > budget[0]:
        report.notes.append(f"{label}: too large to scan inside ({total / 1e6:.0f} MB unpacked)")
        return

    tmpdir = tempfile.mkdtemp(prefix="sentinel_archive_")
    try:
        try:
            extracted = _run_tar("-xf", str(path), "-C", tmpdir)
        except (OSError, subprocess.TimeoutExpired) as e:
            report.notes.append(f"{label}: couldn't extract ({e})")
            return
        encrypted = set()
        for line in _decode(extracted.stderr).splitlines():
            if "ncrypt" in line and ": " in line:
                encrypted.add(line.split(": ", 1)[0].replace("\\", "/").strip())
        for name, _ in entries:
            if name in encrypted:
                _encrypted_member(prefix + name, report)

        batch = _Batch(report)
        for root, dirs, files in os.walk(tmpdir, followlinks=False):
            for file in files:
                full = Path(root) / file
                rel = full.relative_to(tmpdir).as_posix()
                if rel in encrypted or full.is_symlink():
                    continue
                if budget[1] <= 0:
                    report.notes.append("Stopped early: too many files in archive")
                    batch.flush()
                    return
                budget[1] -= 1
                try:
                    size = full.stat().st_size
                    if size > MAX_MEMBER_SIZE or size > budget[0]:
                        report.notes.append(f"{prefix}{rel}: too large to scan inside the archive")
                        continue
                    data = full.read_bytes()
                except OSError as e:  # e.g. Windows Defender grabbed it first
                    report.notes.append(f"{prefix}{rel}: couldn't be read ({e.strerror})")
                    continue
                budget[0] -= len(data)
                batch.add(prefix + rel, data)
                if depth < MAX_DEPTH:
                    _scan_nested_bytes(rel, prefix + rel, data, depth, report, budget)
        batch.flush()
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# --------------------------------------------------------------- members --
def _encrypted_member(name: str, report: ArchiveReport):
    if Path(name).suffix.lower() in RUNNABLE_SUFFIXES:
        report.suspicious.append(f"{name}: program hidden in a password-protected archive")
    else:
        report.notes.append(f"{name}: encrypted, couldn't be scanned")


# Files inside archives that get their own YARA pass. Everything else (Java classes,
# images, text, data...) is still checked, but in large combined chunks: a JAR can hold
# thousands of small files, and one YARA call per file made those take seconds each.
OWN_YARA_SUFFIXES = RUNNABLE_SUFFIXES | {".zip", ".7z", ".rar", ".iso", ".cab", ".tar", ".gz", ".lnk", ".hta",
                                         ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf", ".pdf", ""}
BATCH_FILES = 400
BATCH_BYTES = 16 * 1024 * 1024


class _Batch:
    """Collects files from an archive and checks them together: one database query for all
    their fingerprints, and combined YARA runs for the ordinary ones."""

    def __init__(self, report: ArchiveReport):
        self.report, self.items, self.size = report, [], 0

    def add(self, name: str, data: bytes):
        self.items.append((name, data))
        self.size += len(data)
        if len(self.items) >= BATCH_FILES or self.size >= BATCH_BYTES:
            self.flush()

    def flush(self):
        items, self.items, self.size = self.items, [], 0
        if not items:
            return
        report = self.report
        hashes = [hashlib.sha256(data).hexdigest() for _, data in items]
        known = database.lookup_signatures(hashes)
        combined, combined_names = [], []
        for (name, data), digest in zip(items, hashes):
            if digest in known:
                report.threats.append(f"{name}: {known[digest]}")
            elif Path(name).suffix.lower() in OWN_YARA_SUFFIXES:
                _scan_member(name, data, report, skip_hash=True)
            else:
                combined.append(data)
                combined_names.append(name)
                flags = heuristics.check_bytes(name, data)
                if flags and not _signed(name, data):
                    report.suspicious.extend(f"{name}: {flag}" for flag in flags)
        if combined:
            hits = yara_engine.match_data("combined.bin", b"\n".join(combined))
            strong = [h for h in hits if h.score >= yara_engine.THREAT_SCORE]
            where = combined_names[0] if len(combined_names) == 1 else f"{combined_names[0]} (+{len(combined_names) - 1})"
            if strong:
                report.threats.append(f"{where}: YARA {strong[0].rule}")
            report.suspicious.extend(f"{where}: YARA rule matched: {h.rule}" for h in hits if h not in strong)


def _scan_member(name: str, data: bytes, report: ArchiveReport, skip_hash: bool = False):
    if not skip_hash:
        known = database.lookup_signature(hashlib.sha256(data).hexdigest())
        if known:
            report.threats.append(f"{name}: {known}")
            return
    hits = yara_engine.match_data(name, data)
    strong = [h for h in hits if h.score >= yara_engine.THREAT_SCORE]
    if strong:
        report.threats.append(f"{name}: YARA {strong[0].rule}")
        return
    flags = [f"YARA rule matched: {h.rule}" for h in hits] + heuristics.check_bytes(name, data)
    if flags and _signed(name, data):
        return  # same rule as loose files: a valid publisher signature outweighs weak signals
    report.suspicious.extend(f"{name}: {flag}" for flag in flags)


def _signed(name: str, data: bytes) -> bool:
    """Signature checks need a real file, so write the member out briefly.
    Only happens for the rare member that tripped a weak signal."""
    suffix = Path(name).suffix.lower()
    if suffix not in SIGNABLE_SUFFIXES:
        return False
    fd, tmp = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return authenticode.check(Path(tmp)).signed
    finally:
        os.unlink(tmp)
