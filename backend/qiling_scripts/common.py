"""Shared helpers for Qiling analysis scripts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Tuple


def load_input(path: str) -> Dict[str, Any]:
    raw = Path(path).read_text(encoding="utf-8", errors="ignore")
    data = json.loads(raw) if raw.strip() else {}
    if not isinstance(data, dict):
        raise ValueError("Input JSON must be an object")
    return data


def write_output(path: str, payload: Dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def fail_payload(error: str, **extra: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {"ok": False, "success": False, "error": error}
    result.update(extra)
    return result


def detect_binary(binary_path: str) -> Dict[str, Any]:
    p = Path(binary_path)
    result: Dict[str, Any] = {
        "binary_format": "unknown",
        "os": "unknown",
        "arch": "unknown",
        "bits": 0,
    }
    if not p.exists():
        return result

    data = p.read_bytes()[:512]
    if len(data) < 4:
        return result

    # PE (MZ)
    if data[:2] == b"MZ":
        result["binary_format"] = "pe"
        result["os"] = "windows"
        try:
            pe_off = int.from_bytes(data[0x3C:0x40], "little")
            if pe_off + 0x18 + 2 <= len(data):
                magic = int.from_bytes(data[pe_off + 0x18: pe_off + 0x1A], "little")
                if magic == 0x20B:
                    result["bits"] = 64
                    result["arch"] = "x86_64"
                else:
                    result["bits"] = 32
                    result["arch"] = "x86"
        except Exception:
            pass
        return result

    # ELF
    if data[:4] == b"\x7fELF":
        result["binary_format"] = "elf"
        result["os"] = "linux"
        ei_class = data[4] if len(data) > 4 else 0
        ei_data = data[5] if len(data) > 5 else 1
        result["bits"] = 64 if ei_class == 2 else 32 if ei_class == 1 else 0
        endian = "little" if ei_data == 1 else "big"
        if len(data) >= 20:
            e_machine = int.from_bytes(data[18:20], endian)
            arch_map = {
                0x03: "x86",
                0x3E: "x86_64",
                0x28: "arm",
                0xB7: "arm64",
                0x08: "mips",
            }
            result["arch"] = arch_map.get(e_machine, "unknown")
        return result

    return result


def choose_rootfs(rootfs_base: str, os_name: str, arch: str) -> Tuple[str, str]:
    os_norm = (os_name or "").strip().lower()
    arch_norm = (arch or "").strip().lower()

    if os_norm == "linux":
        if arch_norm in {"x86_64", "amd64", "x8664"}:
            return str(Path(rootfs_base) / "x8664_linux"), "x8664_linux"
        if arch_norm in {"x86", "i386", "i686"}:
            return str(Path(rootfs_base) / "x86_linux"), "x86_linux"
    if os_norm == "windows":
        if arch_norm in {"x86_64", "amd64", "x8664"}:
            return str(Path(rootfs_base) / "x8664_windows"), "x8664_windows"
        if arch_norm in {"x86", "i386", "i686"}:
            return str(Path(rootfs_base) / "x86_windows"), "x86_windows"

    return "", ""

