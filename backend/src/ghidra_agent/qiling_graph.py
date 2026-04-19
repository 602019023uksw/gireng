"""Qiling pipeline — dynamic analysis stages executed in parallel with static analyzers."""

from __future__ import annotations

import asyncio
from typing import Any, Dict

from ghidra_agent.logging import logger
from ghidra_agent.qiling_tools import (
    qiling_detect_evasion,
    qiling_emulate_binary,
    qiling_memory_analysis,
    qiling_network_analysis,
    qiling_trace_api_calls,
    qiling_trace_instructions,
    qiling_trace_syscalls,
)
from ghidra_agent.state import AgentState


def _ensure_analyzer_maps(state: AgentState) -> None:
    state.setdefault("analyzer_progress", {"ghidra": 0, "radare2": 0, "qiling": 0})
    state.setdefault("analyzer_status", {"ghidra": "pending", "radare2": "pending", "qiling": "pending"})
    state.setdefault("analyzer_step", {"ghidra": "", "radare2": "", "qiling": ""})


def _set_qiling_progress(state: AgentState, progress: int, step: str, status: str = "running") -> None:
    _ensure_analyzer_maps(state)
    safe_progress = max(0, min(100, int(progress)))
    state["analyzer_progress"]["qiling"] = safe_progress
    state["analyzer_step"]["qiling"] = step
    state["analyzer_status"]["qiling"] = status
    if status == "completed":
        state["analyzer_progress"]["qiling"] = 100


async def _emit_qiling_progress(state: AgentState, progress: int, step: str, status: str = "running") -> None:
    _set_qiling_progress(state, progress, step, status)
    callback = state.get("progress_callback")
    if callback is None:
        return
    try:
        global_progress = int(state.get("progress", 0))
    except (TypeError, ValueError):
        global_progress = 0
    try:
        maybe_coro = callback(step, global_progress)
        if asyncio.iscoroutine(maybe_coro):
            await maybe_coro
    except Exception as exc:
        logger.warning("qiling_progress_callback_failed", step=step, progress=progress, error=str(exc))


def _is_success(result: Dict[str, Any]) -> bool:
    if result.get("ok") is True:
        return True
    return bool(result.get("success"))


def _is_windows_binary(execution_trace: Dict[str, Any]) -> bool:
    os_name = str(execution_trace.get("os", "")).lower()
    binary_format = str(execution_trace.get("binary_format", "")).lower()
    return "windows" in os_name or binary_format == "pe"


def _is_unsupported_qiling_sample(execution_trace: Dict[str, Any]) -> bool:
    if not isinstance(execution_trace, dict):
        return False
    exit_reason = str(execution_trace.get("exit_reason", "")).lower()
    if exit_reason in ("unsupported_pe", "unsupported"):
        return True
    err = str(execution_trace.get("error", "")).lower()
    return "directory_entry_import" in err


def _normalize_nested_section(
    payload: Dict[str, Any],
    nested_key: str,
    defaults: Dict[str, Any],
) -> Dict[str, Any]:
    """Flatten payloads that wrap data under a duplicate top-level key."""
    normalized: Dict[str, Any] = {}

    nested = payload.get(nested_key)
    if isinstance(nested, dict):
        normalized.update(nested)

    for key, value in payload.items():
        if key == nested_key:
            continue
        normalized[key] = value

    for key, value in defaults.items():
        normalized.setdefault(key, value)

    return normalized


async def _safe_call(tool, tool_args: Dict[str, Any], error_key: str) -> Dict[str, Any]:
    try:
        return await tool.ainvoke(tool_args)
    except Exception as exc:
        logger.error(error_key, error=str(exc))
        return {"ok": False, "error": str(exc)}


async def run_qiling_pipeline(state: AgentState) -> AgentState:
    """Execute Qiling emulation + dynamic behavior extraction."""
    tool_args = {
        "session_id": state["session_id"],
        "program_hash": state["program_hash"],
        "binary_path": state.get("binary_path"),
    }

    state.setdefault("qiling_analysis_results", {})
    state.setdefault("qiling_execution_cache", {})
    await _emit_qiling_progress(state, progress=0, step="qiling_discovery_starting", status="running")

    results: Dict[str, Any] = {}
    errors: list[str] = []

    await _emit_qiling_progress(state, progress=15, step="qiling_emulate_binary", status="running")
    execution_trace = await _safe_call(qiling_emulate_binary, tool_args, "qiling_emulation_failed")
    results["execution_trace"] = execution_trace
    state["qiling_execution_cache"]["execution_trace"] = execution_trace

    logger.info(
        "qiling_emulation_result",
        ok=execution_trace.get("ok") if isinstance(execution_trace, dict) else None,
        instructions=execution_trace.get("instructions_executed") if isinstance(execution_trace, dict) else None,
        exit_reason=execution_trace.get("exit_reason") if isinstance(execution_trace, dict) else None,
        error=execution_trace.get("error") if isinstance(execution_trace, dict) else str(execution_trace),
    )

    # Only bail early if emulation produced zero useful data (no instructions at all).
    # When the binary ran partially (instructions_executed > 0), continue with the
    # parallel analysis scripts — they each do their own emulation and collect
    # whatever data is possible before the same crash/timeout.
    exec_instructions = 0
    if isinstance(execution_trace, dict):
        exec_instructions = int(execution_trace.get("instructions_executed", 0) or 0)

    if _is_unsupported_qiling_sample(execution_trace) and exec_instructions == 0:
        if execution_trace.get("error"):
            errors.append(str(execution_trace["error"]))
        results["errors"] = errors
        results["skipped"] = True
        results["skip_reason"] = "unsupported_pe_for_emulation"
        state["qiling_analysis_results"] = results
        state["qiling_trace"].append("qiling_discovery_completed")
        await _emit_qiling_progress(state, progress=100, step="qiling_emulation_skipped", status="completed")
        return state

    if not _is_success(execution_trace) and exec_instructions == 0:
        if execution_trace.get("error"):
            errors.append(str(execution_trace["error"]))
        results["errors"] = errors
        state["qiling_analysis_results"] = results
        state["qiling_trace"].append("qiling_discovery_completed")
        await _emit_qiling_progress(state, progress=100, step="qiling_emulation_failed", status="failed")
        return state

    if not _is_success(execution_trace) and execution_trace.get("error"):
        errors.append(str(execution_trace["error"]))

    await _emit_qiling_progress(state, progress=40, step="qiling_parallel_analysis", status="running")
    syscalls, memory_events_raw, network_activity_raw, evasion_techniques_raw, instruction_trace_raw = await asyncio.gather(
        _safe_call(qiling_trace_syscalls, tool_args, "qiling_syscall_trace_failed"),
        _safe_call(qiling_memory_analysis, tool_args, "qiling_memory_analysis_failed"),
        _safe_call(qiling_network_analysis, tool_args, "qiling_network_analysis_failed"),
        _safe_call(qiling_detect_evasion, tool_args, "qiling_evasion_detection_failed"),
        _safe_call(qiling_trace_instructions, tool_args, "qiling_instruction_trace_failed"),
    )

    memory_events = _normalize_nested_section(
        memory_events_raw,
        "memory_events",
        {"events": [], "indicators": {}},
    )
    network_activity = _normalize_nested_section(
        network_activity_raw,
        "network_activity",
        {"connections": [], "dns_queries": [], "data_sent": [], "indicators": {}},
    )
    evasion_techniques = _normalize_nested_section(
        evasion_techniques_raw,
        "evasion_techniques",
        {"techniques": [], "summary": {"total_techniques": 0, "risk_level": "low", "mitre_tactics": []}},
    )

    instruction_trace = _normalize_nested_section(
        instruction_trace_raw,
        "instruction_trace",
        {"instructions": [], "summary": {}},
    )

    # B9 FIX: Merge OEP candidates from memory_events into instruction_trace
    # so they are accessible via a single path for LLM context and reporting.
    mem_indicators = memory_events.get("indicators", {}) if isinstance(memory_events, dict) else {}
    oep_candidates = mem_indicators.get("oep_candidates", []) if isinstance(mem_indicators, dict) else []
    if isinstance(oep_candidates, list) and oep_candidates:
        existing_oep = instruction_trace.get("oep_candidates", [])
        if not isinstance(existing_oep, list):
            existing_oep = []
        instruction_trace["oep_candidates"] = existing_oep + oep_candidates

    results["syscalls"] = syscalls
    results["memory_events"] = memory_events
    results["network_activity"] = network_activity
    results["evasion_techniques"] = evasion_techniques
    results["instruction_trace"] = instruction_trace

    for key, payload in (
        ("syscalls", syscalls),
        ("memory_events", memory_events),
        ("network_activity", network_activity),
        ("evasion_techniques", evasion_techniques),
        ("instruction_trace", instruction_trace),
    ):
        state["qiling_execution_cache"][key] = payload
        if not _is_success(payload) and payload.get("error"):
            errors.append(f"{key}:{payload['error']}")

    if _is_windows_binary(execution_trace):
        await _emit_qiling_progress(state, progress=70, step="qiling_api_trace", status="running")
        api_calls = await _safe_call(qiling_trace_api_calls, tool_args, "qiling_api_trace_failed")
        results["api_calls"] = api_calls
        state["qiling_execution_cache"]["api_calls"] = api_calls
        if not _is_success(api_calls) and api_calls.get("error"):
            errors.append(f"api_calls:{api_calls['error']}")

    if errors:
        results["errors"] = errors

    state["qiling_analysis_results"] = results
    state["qiling_trace"].append("qiling_discovery_completed")

    # Determine final status: "completed" if ANY useful data was collected,
    # even when individual scripts errored after partial execution.
    has_useful_data = (
        exec_instructions > 0
        or len(syscalls.get("syscalls", []) if isinstance(syscalls, dict) else []) > 0
        or len(evasion_techniques.get("techniques", []) if isinstance(evasion_techniques, dict) else []) > 0
        or len(network_activity.get("connections", []) if isinstance(network_activity, dict) else []) > 0
    )
    final_status = "completed" if has_useful_data or not errors else "failed"
    await _emit_qiling_progress(state, progress=100, step="qiling_discovery_completed", status=final_status)
    return state
