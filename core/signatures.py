"""Hash-based (signature) detection."""
import hashlib
from pathlib import Path

from . import database

HASH_CHUNK = 1024 * 1024  # 1 MB


def hash_file(path: Path, algo: str = "sha256") -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(HASH_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def check_file(path: Path) -> tuple[bool, str | None, str]:
    """Returns (is_match, signature_name, sha256_hash)."""
    file_hash = hash_file(path, "sha256")
    match = database.lookup_signature(file_hash)
    return (match is not None, match, file_hash)


def seed_default_signatures():
    """Seeds a small local blocklist. EICAR is the industry-standard
    harmless AV test string; add real hashes you source yourself as needed.
    """
    eicar_string = (
        r"X5O!P%@AP[4\PZX54(P^)7CC)7}$" r"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    eicar_hash = hashlib.sha256(eicar_string.encode()).hexdigest()
    database.add_signature(eicar_hash, "EICAR-Test-File")


def import_signature_list(path: Path):
    """Import a plain-text file of `<sha256>  <name>` lines into the DB."""
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            file_hash = parts[0]
            name = parts[1] if len(parts) > 1 else "Unnamed-Threat"
            database.add_signature(file_hash, name)
