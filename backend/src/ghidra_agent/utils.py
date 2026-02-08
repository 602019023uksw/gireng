import hashlib
import os
from pathlib import Path


def compute_sha256(file_path: Path) -> str:
    hasher = hashlib.sha256()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def normalize_address(address: str) -> str:
    trimmed = address.lower().strip()
    if not trimmed.startswith("0x"):
        trimmed = "0x" + trimmed
    return trimmed


def is_valid_hex(address: str) -> bool:
    if not address:
        return False
    try:
        int(normalize_address(address), 16)
    except ValueError:
        return False
    return True


def safe_basename(name: str) -> str:
    return os.path.basename(name).replace("..", "").replace("/", "_").replace("\\", "_")
