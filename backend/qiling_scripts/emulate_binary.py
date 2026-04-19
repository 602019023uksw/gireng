"""Run a basic Qiling emulation and return execution metadata."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any, Dict

from common import choose_rootfs, detect_binary, fail_payload, load_input, write_output


def _run_emulation(binary_path: str, timeout_sec: int, rootfs_base: str, max_instructions: int) -> Dict[str, Any]:
    binary_meta = detect_binary(binary_path)
    rootfs, rootfs_name = choose_rootfs(rootfs_base, binary_meta.get("os", ""), binary_meta.get("arch", ""))

    result: Dict[str, Any] = {
        "ok": False,
        "success": False,
        "binary_format": binary_meta.get("binary_format", "unknown"),
        "arch": binary_meta.get("arch", "unknown"),
        "os": binary_meta.get("os", "unknown"),
        "bits": binary_meta.get("bits", 0),
        "rootfs": rootfs_name,
        "entry_point": "",
        "instructions_executed": 0,
        "duration_ms": 0.0,
        "exit_reason": "error",
        "exit_code": None,
        "error": None,
    }

    if not Path(binary_path).exists():
        result["error"] = f"Binary not found: {binary_path}"
        return result

    if not rootfs:
        result["error"] = (
            f"No rootfs mapping for os={binary_meta.get('os')} arch={binary_meta.get('arch')} "
            f"(rootfs_base={rootfs_base})"
        )
        return result

    if not Path(rootfs).exists():
        result["error"] = f"Rootfs not found: {rootfs}"
        return result

    try:
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
    except Exception as exc:
        result["error"] = f"Qiling import failed: {exc}"
        return result

    instruction_count = 0
    started = time.perf_counter()
    ql = None

    try:
        ql = Qiling([binary_path], rootfs, verbose=QL_VERBOSE.OFF)

        def _count_instructions(ql_obj, address, size):  # noqa: ANN001
            nonlocal instruction_count
            instruction_count += 1
            if instruction_count >= max_instructions:
                ql_obj.emu_stop()

        ql.hook_code(_count_instructions)
        ql.run(timeout=timeout_sec * 1000)

        result["ok"] = True
        result["success"] = True
        result["exit_reason"] = "normal"
        result["exit_code"] = 0
    except Exception as exc:
        msg = str(exc)
        lowered = msg.lower()
        if "timeout" in lowered:
            result["exit_reason"] = "timeout"
        elif "directory_entry_import" in lowered:
            # Malformed/truncated PE files can miss import tables; treat as
            # unsupported for dynamic emulation instead of a hard pipeline failure.
            result["ok"] = True
            result["success"] = False
            result["exit_reason"] = "unsupported_pe"
            msg = "Unsupported PE for emulation: missing/corrupt import directory"
        elif "uc_err_read_unmapped" in lowered or "uc_err_write_unmapped" in lowered or "uc_err_fetch_unmapped" in lowered:
            # Unicorn memory-mapping errors are common with packed, encrypted,
            # or API-heavy binaries that rely on unemulated OS behaviour.
            # Treat as unsupported so the pipeline continues with static data.
            result["ok"] = True
            result["success"] = False
            result["exit_reason"] = "unsupported"
            msg = f"Binary unsupported for emulation: {msg}"
        elif instruction_count > 0:
            # Partial execution: binary ran some instructions before crashing.
            # Mark as ok so the pipeline continues with whatever data we have.
            result["ok"] = True
            result["success"] = False
            result["exit_reason"] = "partial"
        else:
            result["exit_reason"] = "error"
        result["error"] = msg
    finally:
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        result["duration_ms"] = round(elapsed_ms, 3)
        result["instructions_executed"] = instruction_count
        if ql is not None:
            try:
                arch_pc = getattr(getattr(ql.arch, "regs", None), "arch_pc", None)
                if isinstance(arch_pc, int):
                    result["entry_point"] = hex(arch_pc)
            except Exception:
                pass

    return result


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: emulate_binary.py <input.json> <output.json>", file=sys.stderr)
        return 2

    input_path, output_path = sys.argv[1], sys.argv[2]
    try:
        payload = load_input(input_path)
        binary_path = str(payload.get("binary_path", "")).strip()
        timeout_sec = int(payload.get("timeout", 60))
        rootfs_base = str(payload.get("rootfs_base", "/opt/qiling/rootfs"))
        max_instructions = int(payload.get("max_instructions", 100_000_000))

        if not binary_path:
            write_output(output_path, fail_payload("binary_path missing in input"))
            return 0

        result = _run_emulation(binary_path, timeout_sec, rootfs_base, max_instructions)
        write_output(output_path, result)
        return 0
    except Exception as exc:
        write_output(output_path, fail_payload(f"emulate_binary.py failed: {exc}"))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
