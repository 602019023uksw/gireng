"""Trace key syscalls during Qiling emulation."""

from __future__ import annotations

import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from common import choose_rootfs, detect_binary, fail_payload, load_input, write_output


SYSCALL_CATEGORIES: Dict[str, str] = {
    # file I/O
    "open": "file_io",
    "openat": "file_io",
    "read": "file_io",
    "write": "file_io",
    "close": "file_io",
    "unlink": "file_io",
    "stat": "file_io",
    "chmod": "file_io",
    # network
    "socket": "network",
    "connect": "network",
    "bind": "network",
    "listen": "network",
    "accept": "network",
    "send": "network",
    "recv": "network",
    "sendto": "network",
    "recvfrom": "network",
    # process
    "fork": "process",
    "clone": "process",
    "execve": "process",
    "ptrace": "process",
    "kill": "process",
    "wait4": "process",
    # memory
    "mmap": "memory",
    "mprotect": "memory",
    "munmap": "memory",
    "brk": "memory",
    # system
    "ioctl": "system",
    "uname": "system",
    "sysinfo": "system",
    "getuid": "system",
    "getpid": "system",
}


def _safe_arg(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, bytes):
        return value[:64].hex()
    try:
        return str(value)
    except Exception:
        return "<unprintable>"


def _build_summary(calls: List[Dict[str, Any]]) -> Dict[str, Any]:
    categories = Counter(call.get("category", "unknown") for call in calls)
    unique_syscalls = sorted({str(call.get("name", "")) for call in calls if call.get("name")})
    suspicious: List[Dict[str, Any]] = []

    for call in calls:
        name = str(call.get("name", "")).lower()
        args = " ".join(str(a) for a in call.get("args", []))
        if name == "execve" and ("/bin/sh" in args or "/bin/bash" in args):
            suspicious.append(
                {"name": call.get("name"), "reason": "Shell execution", "address": call.get("address"), "risk": "high"}
            )
        if name == "ptrace":
            suspicious.append(
                {"name": call.get("name"), "reason": "Debugger detection syscall", "address": call.get("address"), "risk": "high"}
            )
        if name == "connect":
            suspicious.append(
                {"name": call.get("name"), "reason": "Outbound network connection attempt", "address": call.get("address"), "risk": "medium"}
            )

    return {
        "total_calls": len(calls),
        "categories": dict(categories),
        "unique_syscalls": unique_syscalls,
        "suspicious_calls": suspicious,
    }


def _run(binary_path: str, timeout_sec: int, rootfs_base: str) -> Dict[str, Any]:
    binary_meta = detect_binary(binary_path)
    rootfs, rootfs_name = choose_rootfs(rootfs_base, binary_meta.get("os", ""), binary_meta.get("arch", ""))

    result: Dict[str, Any] = {
        "ok": False,
        "success": False,
        "rootfs": rootfs_name,
        "syscalls": [],
        "summary": {"total_calls": 0, "categories": {}, "unique_syscalls": [], "suspicious_calls": []},
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
        from qiling.const import QL_INTERCEPT, QL_VERBOSE
    except Exception as exc:
        result["error"] = f"Qiling import failed: {exc}"
        return result

    calls: List[Dict[str, Any]] = []
    started = time.perf_counter()

    try:
        ql = Qiling([binary_path], rootfs, verbose=QL_VERBOSE.OFF)

        for syscall_name, category in SYSCALL_CATEGORIES.items():
            def _make_cb(name: str, cat: str):
                def _cb(ql_obj, *args, **kwargs):  # noqa: ANN001
                    timestamp_ms = round((time.perf_counter() - started) * 1000.0, 3)
                    address = ""
                    try:
                        pc = getattr(getattr(ql_obj.arch, "regs", None), "arch_pc", None)
                        if isinstance(pc, int):
                            address = hex(pc)
                    except Exception:
                        pass
                    calls.append(
                        {
                            "name": name,
                            "args": [_safe_arg(a) for a in args[:6]],
                            "retval": kwargs.get("retval"),
                            "address": address,
                            "category": cat,
                            "timestamp_ms": timestamp_ms,
                        }
                    )
                    return None

                return _cb

            try:
                ql.os.set_syscall(syscall_name, _make_cb(syscall_name, category), QL_INTERCEPT.ENTER)
            except Exception:
                # Best-effort hooks: some targets won't expose all syscalls.
                continue

        ql.run(timeout=timeout_sec * 1000)

        result["ok"] = True
        result["success"] = True
        result["syscalls"] = calls
        result["summary"] = _build_summary(calls)
        return result
    except Exception as exc:
        result["error"] = str(exc)
        result["syscalls"] = calls
        result["summary"] = _build_summary(calls)
        # Partial execution: if any calls were intercepted, report ok
        if calls:
            result["ok"] = True
            result["success"] = False
        return result


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: trace_syscalls.py <input.json> <output.json>", file=sys.stderr)
        return 2

    input_path, output_path = sys.argv[1], sys.argv[2]
    try:
        payload = load_input(input_path)
        binary_path = str(payload.get("binary_path", "")).strip()
        timeout_sec = int(payload.get("timeout", 60))
        rootfs_base = str(payload.get("rootfs_base", "/opt/qiling/rootfs"))

        if not binary_path:
            write_output(output_path, fail_payload("binary_path missing in input", syscalls=[], summary={}))
            return 0

        result = _run(binary_path, timeout_sec, rootfs_base)
        write_output(output_path, result)
        return 0
    except Exception as exc:
        write_output(output_path, fail_payload(f"trace_syscalls.py failed: {exc}", syscalls=[], summary={}))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

