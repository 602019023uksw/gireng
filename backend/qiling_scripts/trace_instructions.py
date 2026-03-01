"""Trace executed instructions during Qiling emulation using Capstone disassembly.

Captures address, mnemonic, and operands for every executed instruction.
Output is capped to avoid unbounded growth; a statistical summary is always
provided regardless of the cap.
"""

from __future__ import annotations

import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from common import choose_rootfs, detect_binary, fail_payload, load_input, write_output

# ---------------------------------------------------------------------------
# Capstone architecture mapping
# ---------------------------------------------------------------------------

_ARCH_MAP: Dict[Tuple[str, int], Tuple[int, int]] = {}


def _populate_arch_map() -> None:
    """Lazily fill the architecture mapping (Capstone must be importable)."""
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
            ("mips", 64): (CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN),
        }
    )


def _get_capstone_md(arch: str, bits: int):  # noqa: ANN205 – returns Optional[capstone.Cs]
    """Return a Capstone disassembler for the given architecture, or *None*."""
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


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

# Defaults — can be overridden via input JSON.
DEFAULT_MAX_INSTRUCTIONS = 100_000_000  # overall instruction cap
DEFAULT_MAX_TRACE = 50_000  # max instructions to store in trace output
DEFAULT_SAMPLE_RATE = 1  # store every Nth instruction (1 = store all up to cap)


def _run(
    binary_path: str,
    timeout_sec: int,
    rootfs_base: str,
    max_instructions: int,
    max_trace: int,
    sample_rate: int,
) -> Dict[str, Any]:
    binary_meta = detect_binary(binary_path)
    rootfs, rootfs_name = choose_rootfs(
        rootfs_base, binary_meta.get("os", ""), binary_meta.get("arch", "")
    )

    result: Dict[str, Any] = {
        "ok": False,
        "success": False,
        "rootfs": rootfs_name,
        "instruction_trace": {
            "instructions": [],
            "summary": {
                "total_executed": 0,
                "traced": 0,
                "unique_mnemonics": 0,
                "top_mnemonics": [],
                "address_range": {"low": None, "high": None},
                "disasm_errors": 0,
            },
        },
        "error": None,
    }

    if not Path(binary_path).exists():
        result["error"] = f"Binary not found: {binary_path}"
        return result
    if not rootfs or not Path(rootfs).exists():
        result["error"] = (
            f"Rootfs not found for {binary_meta.get('os')}/{binary_meta.get('arch')}"
        )
        return result

    try:
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
    except Exception as exc:
        result["error"] = f"Qiling import failed: {exc}"
        return result

    md = _get_capstone_md(binary_meta.get("arch", ""), binary_meta.get("bits", 0))
    if md is None:
        result["error"] = (
            f"Capstone: unsupported arch={binary_meta.get('arch')} bits={binary_meta.get('bits')}"
        )
        return result

    # ---- state shared with hook ----
    traced: List[Dict[str, Any]] = []
    mnemonic_counter: Counter = Counter()
    total_executed = 0
    disasm_errors = 0
    addr_low: Optional[int] = None
    addr_high: Optional[int] = None

    def _hook_code(ql_obj, address: int, size: int) -> None:  # noqa: ANN001
        nonlocal total_executed, disasm_errors, addr_low, addr_high

        total_executed += 1
        if total_executed >= max_instructions:
            ql_obj.emu_stop()
            return

        # Track address range
        if addr_low is None or address < addr_low:
            addr_low = address
        if addr_high is None or address > addr_high:
            addr_high = address

        # Disassemble the instruction bytes
        try:
            code_bytes = ql_obj.mem.read(address, size)
            insns = list(md.disasm(bytes(code_bytes), address))
            if insns:
                insn = insns[0]
                mnemonic = insn.mnemonic
                operands = insn.op_str
            else:
                mnemonic = "???"
                operands = ""
                disasm_errors += 1
        except Exception:
            mnemonic = "???"
            operands = ""
            disasm_errors += 1

        mnemonic_counter[mnemonic] += 1

        # Sampling: only store if within cap and matches sample rate
        if len(traced) < max_trace and (total_executed % sample_rate == 0):
            traced.append(
                {
                    "address": hex(address),
                    "mnemonic": mnemonic,
                    "operands": operands,
                    "size": size,
                }
            )

    started = time.perf_counter()
    ql = None

    try:
        ql = Qiling([binary_path], rootfs, verbose=QL_VERBOSE.OFF)
        ql.hook_code(_hook_code)
        ql.run(timeout=timeout_sec * 1000)

        result["ok"] = True
        result["success"] = True
    except Exception as exc:
        msg = str(exc)
        if total_executed > 0:
            result["ok"] = True
            result["success"] = False
        result["error"] = msg
    finally:
        elapsed_ms = (time.perf_counter() - started) * 1000.0

        # Build summary
        top_mnemonics = [
            {"mnemonic": m, "count": c}
            for m, c in mnemonic_counter.most_common(30)
        ]
        result["instruction_trace"] = {
            "instructions": traced,
            "summary": {
                "total_executed": total_executed,
                "traced": len(traced),
                "unique_mnemonics": len(mnemonic_counter),
                "top_mnemonics": top_mnemonics,
                "address_range": {
                    "low": hex(addr_low) if addr_low is not None else None,
                    "high": hex(addr_high) if addr_high is not None else None,
                },
                "disasm_errors": disasm_errors,
                "sample_rate": sample_rate,
                "duration_ms": round(elapsed_ms, 3),
            },
        }

    return result


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: trace_instructions.py <input.json> <output.json>", file=sys.stderr)
        return 2

    input_path, output_path = sys.argv[1], sys.argv[2]
    try:
        payload = load_input(input_path)
        binary_path = str(payload.get("binary_path", "")).strip()
        timeout_sec = int(payload.get("timeout", 60))
        rootfs_base = str(payload.get("rootfs_base", "/opt/qiling/rootfs"))
        max_instructions = int(payload.get("max_instructions", DEFAULT_MAX_INSTRUCTIONS))
        max_trace = int(payload.get("max_trace", DEFAULT_MAX_TRACE))
        sample_rate = max(1, int(payload.get("sample_rate", DEFAULT_SAMPLE_RATE)))

        if not binary_path:
            write_output(
                output_path,
                fail_payload(
                    "binary_path missing in input",
                    instruction_trace={"instructions": [], "summary": {}},
                ),
            )
            return 0

        result = _run(
            binary_path, timeout_sec, rootfs_base, max_instructions, max_trace, sample_rate
        )
        write_output(output_path, result)
        return 0
    except Exception as exc:
        write_output(
            output_path,
            fail_payload(
                f"trace_instructions.py failed: {exc}",
                instruction_trace={"instructions": [], "summary": {}},
            ),
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
