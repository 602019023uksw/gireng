"""Trace network-centric syscalls during Qiling emulation."""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

from common import choose_rootfs, detect_binary, fail_payload, load_input, write_output

NETWORK_SYSCALLS = {"socket", "connect", "bind", "listen", "accept", "send", "recv", "sendto", "recvfrom"}
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b",
    re.IGNORECASE,
)


def _safe_arg(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, bytes):
        return value[:64].hex()
    return str(value)


def _extract_domains(args_safe: List[Any]) -> List[str]:
    domains: set[str] = set()
    for arg in args_safe:
        if not isinstance(arg, str):
            continue
        for match in DOMAIN_PATTERN.finditer(arg):
            candidate = match.group(0).strip(".").lower()
            if candidate and not candidate.replace(".", "").isdigit():
                domains.add(candidate)
    return sorted(domains)


def _has_dns_port(args_safe: List[Any]) -> bool:
    for arg in args_safe:
        if isinstance(arg, int) and arg == 53:
            return True
        if isinstance(arg, str):
            lowered = arg.lower()
            if ":53" in lowered or "port=53" in lowered or "port 53" in lowered:
                return True
    return False


def _run(binary_path: str, timeout_sec: int, rootfs_base: str) -> Dict[str, Any]:
    binary_meta = detect_binary(binary_path)
    rootfs, rootfs_name = choose_rootfs(rootfs_base, binary_meta.get("os", ""), binary_meta.get("arch", ""))

    result: Dict[str, Any] = {
        "ok": False,
        "success": False,
        "rootfs": rootfs_name,
        "network_activity": {
            "connections": [],
            "dns_queries": [],
            "data_sent": [],
            "indicators": {"c2_candidates": [], "dns_domains": [], "protocols_used": []},
        },
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

    connections: List[Dict[str, Any]] = []
    dns_queries: List[Dict[str, Any]] = []
    data_sent: List[Dict[str, Any]] = []
    protocols: set[str] = set()
    seen_dns_domains: set[str] = set()
    started = time.perf_counter()

    try:
        ql = Qiling([binary_path], rootfs, verbose=QL_VERBOSE.OFF)

        def _make_cb(name: str):
            def _cb(ql_obj, *args, **kwargs):  # noqa: ANN001
                timestamp_ms = round((time.perf_counter() - started) * 1000.0, 3)
                args_safe = [_safe_arg(a) for a in args[:6]]
                domains = _extract_domains(args_safe)
                dns_signal = _has_dns_port(args_safe) or bool(domains)

                if name == "connect":
                    protocols.add("tcp")
                    connections.append(
                        {
                            "type": "tcp_connect",
                            "address": "unknown",
                            "port": 0,
                            "timestamp_ms": timestamp_ms,
                            "args": args_safe,
                        }
                    )
                elif name in {"send", "sendto"}:
                    protocols.add("udp" if name == "sendto" else "tcp")
                    payload_size = 0
                    if len(args_safe) >= 3 and isinstance(args_safe[2], int):
                        payload_size = args_safe[2]
                    data_sent.append(
                        {
                            "destination": "unknown",
                            "size": payload_size,
                            "preview_hex": "",
                            "timestamp_ms": timestamp_ms,
                        }
                    )
                elif name in {"recv", "recvfrom", "bind", "listen", "accept"}:
                    protocols.add("udp" if name == "recvfrom" else "tcp")
                elif name == "socket" and len(args_safe) >= 2 and isinstance(args_safe[1], int):
                    # SOCK_DGRAM=2, SOCK_STREAM=1
                    if args_safe[1] == 2:
                        protocols.add("udp")
                    elif args_safe[1] == 1:
                        protocols.add("tcp")

                if dns_signal:
                    if domains:
                        for domain in domains:
                            if domain in seen_dns_domains:
                                continue
                            seen_dns_domains.add(domain)
                            dns_queries.append(
                                {
                                    "domain": domain,
                                    "type": "A",
                                    "timestamp_ms": timestamp_ms,
                                    "args": args_safe,
                                }
                            )
                    else:
                        dns_queries.append(
                            {
                                "domain": "unknown",
                                "type": "A",
                                "timestamp_ms": timestamp_ms,
                                "args": args_safe,
                            }
                        )

                return None

            return _cb

        for syscall_name in NETWORK_SYSCALLS:
            try:
                ql.os.set_syscall(syscall_name, _make_cb(syscall_name), QL_INTERCEPT.ENTER)
            except Exception:
                continue

        ql.run(timeout=timeout_sec * 1000)

        indicators = {
            "c2_candidates": sorted({f"{c.get('address')}:{c.get('port')}" for c in connections}),
            "dns_domains": sorted({str(q.get("domain")) for q in dns_queries if q.get("domain") and q.get("domain") != "unknown"}),
            "protocols_used": sorted(protocols),
        }

        result["ok"] = True
        result["success"] = True
        result["network_activity"] = {
            "connections": connections,
            "dns_queries": dns_queries,
            "data_sent": data_sent,
            "indicators": indicators,
        }
        return result
    except Exception as exc:
        result["error"] = str(exc)
        result["network_activity"] = {
            "connections": connections,
            "dns_queries": dns_queries,
            "data_sent": data_sent,
            "indicators": {"c2_candidates": [], "dns_domains": [], "protocols_used": sorted(protocols)},
        }
        # Partial execution: always report ok since network analysis is best-effort
        result["ok"] = True
        result["success"] = False
        return result


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: network_analysis.py <input.json> <output.json>", file=sys.stderr)
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
                    network_activity={"connections": [], "dns_queries": [], "data_sent": [], "indicators": {}},
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
                f"network_analysis.py failed: {exc}",
                network_activity={"connections": [], "dns_queries": [], "data_sent": [], "indicators": {}},
            ),
        )
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
