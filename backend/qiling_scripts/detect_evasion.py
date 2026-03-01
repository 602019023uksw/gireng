"""Detect basic anti-analysis behavior during Qiling emulation."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

from common import choose_rootfs, detect_binary, fail_payload, load_input, write_output


EVASION_SYSCALLS = {
    "ptrace": ("Debugger Detection", "T1622", "Defense Evasion"),
    "prctl": ("Anti-analysis Configuration", "T1497", "Defense Evasion"),
    "clone": ("Process Forking Evasion", "T1497.001", "Defense Evasion"),
}


def _risk_level(count: int) -> str:
    if count >= 5:
        return "high"
    if count >= 2:
        return "medium"
    return "low"


def _run(binary_path: str, timeout_sec: int, rootfs_base: str) -> Dict[str, Any]:
    binary_meta = detect_binary(binary_path)
    rootfs, rootfs_name = choose_rootfs(rootfs_base, binary_meta.get("os", ""), binary_meta.get("arch", ""))

    result: Dict[str, Any] = {
        "ok": False,
        "success": False,
        "rootfs": rootfs_name,
        "evasion_techniques": {"techniques": [], "summary": {"total_techniques": 0, "risk_level": "low", "mitre_tactics": []}},
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

    techniques: List[Dict[str, Any]] = []

    try:
        ql = Qiling([binary_path], rootfs, verbose=QL_VERBOSE.OFF)

        for syscall_name, (technique, mitre_id, mitre_tactic) in EVASION_SYSCALLS.items():
            def _make_cb(name: str, t_name: str, t_id: str, t_tactic: str):
                def _cb(ql_obj, *args, **kwargs):  # noqa: ANN001
                    address = ""
                    try:
                        pc = getattr(getattr(ql_obj.arch, "regs", None), "arch_pc", None)
                        if isinstance(pc, int):
                            address = hex(pc)
                    except Exception:
                        pass

                    techniques.append(
                        {
                            "technique": t_name,
                            "method": name,
                            "address": address,
                            "mitre_id": t_id,
                            "mitre_tactic": t_tactic,
                            "description": f"Detected {name} syscall, often used for anti-analysis checks.",
                        }
                    )
                    return None

                return _cb

            try:
                ql.os.set_syscall(
                    syscall_name,
                    _make_cb(syscall_name, technique, mitre_id, mitre_tactic),
                    QL_INTERCEPT.ENTER,
                )
            except Exception:
                continue

        ql.run(timeout=timeout_sec * 1000)
        summary = {
            "total_techniques": len(techniques),
            "risk_level": _risk_level(len(techniques)),
            "mitre_tactics": sorted({t.get("mitre_tactic", "Defense Evasion") for t in techniques}),
        }
        result["ok"] = True
        result["success"] = True
        result["evasion_techniques"] = {"techniques": techniques, "summary": summary}
        return result
    except Exception as exc:
        result["error"] = str(exc)
        result["evasion_techniques"] = {
            "techniques": techniques,
            "summary": {
                "total_techniques": len(techniques),
                "risk_level": _risk_level(len(techniques)),
                "mitre_tactics": sorted({t.get("mitre_tactic", "Defense Evasion") for t in techniques}),
            },
        }
        # Partial execution: always report ok since evasion is best-effort
        result["ok"] = True
        result["success"] = False
        return result


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: detect_evasion.py <input.json> <output.json>", file=sys.stderr)
        return 2

    input_path, output_path = sys.argv[1], sys.argv[2]
    try:
        payload = load_input(input_path)
        binary_path = str(payload.get("binary_path", "")).strip()
        timeout_sec = int(payload.get("timeout", 60))
        rootfs_base = str(payload.get("rootfs_base", "/opt/qiling/rootfs"))

        if not binary_path:
            write_output(
                output_path,
                fail_payload(
                    "binary_path missing in input",
                    evasion_techniques={"techniques": [], "summary": {"total_techniques": 0, "risk_level": "low", "mitre_tactics": []}},
                ),
            )
            return 0

        result = _run(binary_path, timeout_sec, rootfs_base)
        write_output(output_path, result)
        return 0
    except Exception as exc:
        write_output(
            output_path,
            fail_payload(
                f"detect_evasion.py failed: {exc}",
                evasion_techniques={"techniques": [], "summary": {"total_techniques": 0, "risk_level": "low", "mitre_tactics": []}},
            ),
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

