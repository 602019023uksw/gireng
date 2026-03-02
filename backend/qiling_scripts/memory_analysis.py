"""Capture coarse-grained memory behavior during Qiling emulation."""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from common import choose_rootfs, detect_binary, fail_payload, load_input, write_output


# ---------------------------------------------------------------------------
# Capstone helpers for detecting unpacking jumps to freshly-written code
# ---------------------------------------------------------------------------

_ARCH_MAP: Dict[Tuple[str, int], Tuple[int, int]] = {}


def _populate_arch_map() -> None:
    if _ARCH_MAP:
        return
    try:
        from capstone import (
            CS_ARCH_ARM,
            CS_ARCH_ARM64,
            CS_ARCH_MIPS,
            CS_ARCH_X86,
            CS_MODE_32,
            CS_MODE_64,
            CS_MODE_ARM,
            CS_MODE_LITTLE_ENDIAN,
            CS_MODE_MIPS32,
        )
    except ImportError:
        return
    _ARCH_MAP.update(
        {
            ("x86", 32): (CS_ARCH_X86, CS_MODE_32),
            ("x86", 64): (CS_ARCH_X86, CS_MODE_64),
            ("x86_64", 64): (CS_ARCH_X86, CS_MODE_64),
            ("x86_64", 32): (CS_ARCH_X86, CS_MODE_32),
            ("arm", 32): (CS_ARCH_ARM, CS_MODE_ARM),
            ("arm64", 64): (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN),
            ("aarch64", 64): (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN),
            ("mips", 32): (CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN),
        }
    )


def _get_capstone_md(arch: str, bits: int):  # noqa: ANN205
    _populate_arch_map()
    key = (arch.lower(), bits)
    if key not in _ARCH_MAP:
        return None
    try:
        from capstone import Cs
        cs_arch, cs_mode = _ARCH_MAP[key]
        return Cs(cs_arch, cs_mode)
    except Exception:
        return None


def _run(binary_path: str, timeout_sec: int, rootfs_base: str) -> Dict[str, Any]:
    binary_meta = detect_binary(binary_path)
    rootfs, rootfs_name = choose_rootfs(rootfs_base, binary_meta.get("os", ""), binary_meta.get("arch", ""))

    result: Dict[str, Any] = {
        "ok": False,
        "success": False,
        "rootfs": rootfs_name,
        "memory_events": {"events": [], "indicators": {"self_modifying_code": False, "unpacking_detected": False, "shellcode_injection": False, "rwx_segments": 0}},
        "error": None,
    }

    if not Path(binary_path).exists():
        result["error"] = f"Binary not found: {binary_path}"
        return result
    if not rootfs or not Path(rootfs).exists():
        result["error"] = f"Rootfs not found for {binary_meta.get('os')}/{binary_meta.get('arch')}"
        return result

    try:
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
    except Exception as exc:
        result["error"] = f"Qiling import failed: {exc}"
        return result

    # Optional Capstone for OEP / transition detection
    md = _get_capstone_md(binary_meta.get("arch", ""), binary_meta.get("bits", 0))

    events: List[Dict[str, Any]] = []
    total_write_events = 0
    total_exec_write_events = 0
    permission_events: List[Dict[str, Any]] = []
    rwx_segment_count = 0

    # Enhanced unpacking tracking
    written_exec_pages: Set[int] = set()  # 4K page addresses that were written in exec regions
    oep_candidates: List[Dict[str, Any]] = []  # potential Original Entry Point transitions
    unpack_loops_detected = 0
    last_write_page: Optional[int] = None
    consecutive_same_page_writes = 0
    max_consecutive_same_page = 0

    def _perm_is_executable(perm: Any) -> bool:
        if isinstance(perm, str):
            return "x" in perm.lower()
        if isinstance(perm, int):
            # Linux PROT_EXEC bit
            return bool(perm & 0x4)
        return False

    def _iter_map_rows(ql_obj) -> List[Any]:  # noqa: ANN001
        # Qiling APIs differ across versions; try common accessors.
        for attr in ("map_info", "mapinfo"):
            candidate = getattr(ql_obj.mem, attr, None)
            if candidate is None:
                continue
            try:
                rows = candidate() if callable(candidate) else candidate
                if isinstance(rows, list):
                    return rows
            except Exception:
                continue
        return []

    def _is_exec_address(ql_obj, address: int) -> bool:  # noqa: ANN001
        try:
            for row in _iter_map_rows(ql_obj):
                start = end = None
                perm = ""
                if isinstance(row, dict):
                    start = row.get("start")
                    end = row.get("end")
                    perm = row.get("perm", "")
                elif isinstance(row, (list, tuple)) and len(row) >= 3:
                    start, end, perm = row[0], row[1], row[2]
                if isinstance(start, int) and isinstance(end, int):
                    if start <= address < end and _perm_is_executable(perm):
                        return True
        except Exception:
            pass
        return False

    try:
        ql = Qiling([binary_path], rootfs, verbose=QL_VERBOSE.OFF)

        def _mem_write(ql_obj, access, address, size, value):  # noqa: ANN001
            nonlocal total_write_events, total_exec_write_events
            nonlocal last_write_page, consecutive_same_page_writes, max_consecutive_same_page
            total_write_events += 1
            is_exec_target = isinstance(address, int) and _is_exec_address(ql_obj, address)
            if is_exec_target:
                total_exec_write_events += 1
                # Track 4K pages written in executable regions (unpacking indicator)
                page = (address >> 12) << 12
                written_exec_pages.add(page)
                # Detect tight unpack loops: many consecutive writes to the same page
                if page == last_write_page:
                    consecutive_same_page_writes += 1
                    if consecutive_same_page_writes > max_consecutive_same_page:
                        max_consecutive_same_page = consecutive_same_page_writes  # noqa: F841
                else:
                    consecutive_same_page_writes = 1
                last_write_page = page
            # B4 FIX: Removed duplicate `if is_exec_target: total_exec_write_events += 1`
            if len(events) >= 250:
                return
            entry = {
                "type": "write_to_exec" if is_exec_target else "memory_write",
                "target_address": hex(address) if isinstance(address, int) else str(address),
                "size": int(size) if isinstance(size, int) else 0,
                "description": (
                    "Write observed in executable memory region"
                    if is_exec_target
                    else "Memory write observed during emulation"
                ),
            }
            events.append(entry)

        def _mprotect_hook(ql_obj, *args, **kwargs):  # noqa: ANN001
            nonlocal rwx_segment_count
            if len(permission_events) >= 100:
                return None
            if len(args) < 3:
                return None
            addr = args[0] if isinstance(args[0], int) else 0
            size = args[1] if isinstance(args[1], int) else 0
            prot = args[2] if isinstance(args[2], int) else 0
            has_write = bool(prot & 0x2)
            has_exec = bool(prot & 0x4)
            if has_write and has_exec:
                rwx_segment_count += 1
            permission_events.append(
                {
                    "type": "permission_change",
                    "address": hex(addr),
                    "size": size,
                    "new_perms": prot,
                    "description": "mprotect called to update memory permissions",
                }
            )
            return None

        try:
            ql.hook_mem_write(_mem_write)
        except Exception:
            # Not all targets expose this uniformly; keep running without it.
            pass

        # Hook code execution to detect jumps into freshly written pages (OEP transition)
        _prev_in_written = False

        def _code_hook(ql_obj, address, size):  # noqa: ANN001
            nonlocal _prev_in_written, unpack_loops_detected
            page = (address >> 12) << 12
            in_written = page in written_exec_pages
            if in_written and not _prev_in_written and written_exec_pages:
                # Transition from non-written code into freshly-unpacked code
                entry: Dict[str, Any] = {
                    "address": hex(address),
                    "written_pages": len(written_exec_pages),
                }
                # Try to disassemble the first instruction at the OEP candidate
                if md is not None:
                    try:
                        code_bytes = ql_obj.mem.read(address, min(size, 15))
                        insns = list(md.disasm(bytes(code_bytes), address))
                        if insns:
                            entry["first_insn"] = f"{insns[0].mnemonic} {insns[0].op_str}".strip()
                    except Exception:
                        pass
                if len(oep_candidates) < 20:
                    oep_candidates.append(entry)
                unpack_loops_detected += 1
            _prev_in_written = in_written

        try:
            ql.hook_code(_code_hook)
        except Exception:
            pass

        try:
            from qiling.const import QL_INTERCEPT
            ql.os.set_syscall("mprotect", _mprotect_hook, QL_INTERCEPT.ENTER)
        except Exception:
            pass

        ql.run(timeout=timeout_sec * 1000)

        indicators = {
            # Flag SMC only when writes target executable pages.
            "self_modifying_code": total_exec_write_events > 0,
            # Unpacking heuristic: sustained writes to executable pages,
            # or detection of execution transitioning into written regions.
            "unpacking_detected": (
                total_exec_write_events >= 25
                or (total_write_events > 500 and total_exec_write_events > 0)
                or (rwx_segment_count > 0 and total_exec_write_events > 0)
                or unpack_loops_detected > 0
                or len(written_exec_pages) >= 5
            ),
            "shellcode_injection": total_exec_write_events > 0 and rwx_segment_count > 0,
            "rwx_segments": rwx_segment_count,
            "written_exec_pages": len(written_exec_pages),
            "oep_transitions": unpack_loops_detected,
            "oep_candidates": oep_candidates[:10],
        }

        result["ok"] = True
        result["success"] = True
        result["memory_events"] = {"events": events + permission_events, "indicators": indicators}
        return result
    except Exception as exc:
        result["memory_events"] = {
            "events": events + permission_events,
            "indicators": {
                "self_modifying_code": total_exec_write_events > 0,
                "unpacking_detected": (
                    unpack_loops_detected > 0
                    or len(written_exec_pages) >= 5
                    or (total_exec_write_events >= 25)
                ),
                "shellcode_injection": total_exec_write_events > 0 and rwx_segment_count > 0,
                "rwx_segments": rwx_segment_count,
                "written_exec_pages": len(written_exec_pages),
                "oep_transitions": unpack_loops_detected,
                "oep_candidates": oep_candidates[:10],
            },
        }
        result["error"] = str(exc)
        # Partial execution: always report ok since memory analysis is best-effort
        result["ok"] = True
        result["success"] = False
        return result


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: memory_analysis.py <input.json> <output.json>", file=sys.stderr)
        return 2

    input_path, output_path = sys.argv[1], sys.argv[2]
    try:
        payload = load_input(input_path)
        binary_path = str(payload.get("binary_path", "")).strip()
        timeout_sec = int(payload.get("timeout", 60))
        rootfs_base = str(payload.get("rootfs_base", "/opt/qiling/rootfs"))

        if not binary_path:
            write_output(output_path, fail_payload("binary_path missing in input", memory_events={"events": [], "indicators": {}}))
            return 0

        result = _run(binary_path, timeout_sec, rootfs_base)
        write_output(output_path, result)
        return 0
    except Exception as exc:
        write_output(output_path, fail_payload(f"memory_analysis.py failed: {exc}", memory_events={"events": [], "indicators": {}}))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
