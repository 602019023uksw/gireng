"""Trace Windows API calls during Qiling PE emulation (best-effort)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

from common import choose_rootfs, detect_binary, fail_payload, load_input, write_output


API_HOOKS = {
    "CreateFileW": "kernel32.dll",
    "WriteFile": "kernel32.dll",
    "DeleteFileW": "kernel32.dll",
    "RegSetValueExW": "advapi32.dll",
    "CreateProcessW": "kernel32.dll",
    "VirtualAllocEx": "kernel32.dll",
    "WriteProcessMemory": "kernel32.dll",
    "CreateRemoteThread": "kernel32.dll",
    "connect": "ws2_32.dll",
    "send": "ws2_32.dll",
    "recv": "ws2_32.dll",
    "IsDebuggerPresent": "kernel32.dll",
}


def _run(binary_path: str, timeout_sec: int, rootfs_base: str) -> Dict[str, Any]:
    binary_meta = detect_binary(binary_path)
    if binary_meta.get("binary_format") != "pe":
        return {
            "ok": True,
            "success": True,
            "api_calls": [],
            "summary": {"total_calls": 0, "modules_used": [], "suspicious_apis": []},
            "note": "Non-PE binary; API tracing skipped.",
        }

    rootfs, rootfs_name = choose_rootfs(rootfs_base, "windows", binary_meta.get("arch", ""))
    result: Dict[str, Any] = {
        "ok": False,
        "success": False,
        "rootfs": rootfs_name,
        "api_calls": [],
        "summary": {"total_calls": 0, "modules_used": [], "suspicious_apis": []},
        "error": None,
    }

    if not Path(binary_path).exists():
        result["error"] = f"Binary not found: {binary_path}"
        return result
    if not rootfs or not Path(rootfs).exists():
        result["error"] = f"Windows rootfs not found for arch={binary_meta.get('arch')}"
        return result

    try:
        from qiling import Qiling
        from qiling.const import QL_VERBOSE
    except Exception as exc:
        result["error"] = f"Qiling import failed: {exc}"
        return result

    calls: List[Dict[str, Any]] = []

    try:
        ql = Qiling([binary_path], rootfs, verbose=QL_VERBOSE.OFF)

        for api_name, module_name in API_HOOKS.items():
            def _make_cb(name: str, module: str):
                def _cb(ql_obj, address, params):  # noqa: ANN001
                    if len(calls) >= 250:
                        return None
                    calls.append(
                        {
                            "name": name,
                            "module": module,
                            "args": params if isinstance(params, dict) else {},
                            "retval": None,
                            "address": hex(address) if isinstance(address, int) else str(address),
                        }
                    )
                    return None

                return _cb

            try:
                ql.os.set_api(api_name, _make_cb(api_name, module_name))
            except Exception:
                continue

        ql.run(timeout=timeout_sec * 1000)

        suspicious = []
        for call in calls:
            if call["name"] in {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}:
                suspicious.append(
                    {
                        "name": call["name"],
                        "reason": "Potential process injection primitive",
                        "risk": "critical",
                    }
                )
            elif call["name"] == "IsDebuggerPresent":
                suspicious.append(
                    {
                        "name": call["name"],
                        "reason": "Debugger detection behavior",
                        "risk": "high",
                    }
                )

        result["ok"] = True
        result["success"] = True
        result["api_calls"] = calls
        result["summary"] = {
            "total_calls": len(calls),
            "modules_used": sorted({c.get("module", "") for c in calls if c.get("module")}),
            "suspicious_apis": suspicious,
        }
        return result
    except Exception as exc:
        result["api_calls"] = calls
        result["summary"] = {
            "total_calls": len(calls),
            "modules_used": sorted({c.get("module", "") for c in calls if c.get("module")}),
            "suspicious_apis": [],
        }
        result["error"] = str(exc)
        return result


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: trace_api_calls.py <input.json> <output.json>", file=sys.stderr)
        return 2

    input_path, output_path = sys.argv[1], sys.argv[2]
    try:
        payload = load_input(input_path)
        binary_path = str(payload.get("binary_path", "")).strip()
        timeout_sec = int(payload.get("timeout", 60))
        rootfs_base = str(payload.get("rootfs_base", "/opt/qiling/rootfs"))

        if not binary_path:
            write_output(output_path, fail_payload("binary_path missing in input", api_calls=[], summary={}))
            return 0

        result = _run(binary_path, timeout_sec, rootfs_base)
        write_output(output_path, result)
        return 0
    except Exception as exc:
        write_output(output_path, fail_payload(f"trace_api_calls.py failed: {exc}", api_calls=[], summary={}))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

