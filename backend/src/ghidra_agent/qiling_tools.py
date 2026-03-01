"""Qiling analysis tools — LangChain @tool wrappers around the Qiling runner."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from langchain.tools import tool

from ghidra_agent.qiling.runner import QilingRunner

_runner: Optional[QilingRunner] = None


def get_runner() -> QilingRunner:
    global _runner
    if _runner is None:
        _runner = QilingRunner()
    return _runner


async def verify_qiling_ready() -> Dict[str, Any]:
    runner = get_runner()
    ready = await runner.verify_container()
    return {
        "ready": ready,
        "container": runner.container,
    }


def _bin(binary_path: Optional[str]) -> Path:
    if not binary_path:
        raise ValueError("binary_path is required for Qiling analysis")
    return Path(binary_path)


async def _run_qiling_script(script_name: str, binary_path: Optional[str], payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    runner = get_runner()
    bp = _bin(binary_path)
    result = await runner.run_script(script_name, bp, payload=payload or None)
    if not result.ok:
        return {"ok": False, "error": result.error}
    payload_data = dict(result.payload or {})
    payload_data.setdefault("ok", bool(payload_data.get("success", payload_data.get("ok", True))))
    return payload_data


@tool
async def qiling_emulate_binary(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Emulate binary execution with Qiling and return high-level execution metadata."""
    return await _run_qiling_script("emulate_binary.py", binary_path)


@tool
async def qiling_trace_syscalls(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Trace system calls via Qiling and return categorized call summaries."""
    return await _run_qiling_script("trace_syscalls.py", binary_path)


@tool
async def qiling_trace_api_calls(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Trace Windows API calls for PE binaries (best-effort; no-op for non-Windows binaries)."""
    return await _run_qiling_script("trace_api_calls.py", binary_path)


@tool
async def qiling_memory_analysis(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Analyze runtime memory behavior (self-modifying code, RWX changes, unpacking signals)."""
    return await _run_qiling_script("memory_analysis.py", binary_path)


@tool
async def qiling_network_analysis(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Collect runtime network behavior (connections, DNS-like patterns, and payload previews)."""
    return await _run_qiling_script("network_analysis.py", binary_path)


@tool
async def qiling_detect_evasion(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Detect anti-analysis/evasion signals observed during emulation."""
    return await _run_qiling_script("detect_evasion.py", binary_path)


@tool
async def qiling_trace_instructions(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Trace executed instructions with Capstone disassembly (address, mnemonic, operands)."""
    return await _run_qiling_script("trace_instructions.py", binary_path)

