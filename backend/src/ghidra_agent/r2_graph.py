"""Radare2 LangGraph pipeline — runs R2 analysis nodes in parallel with Ghidra."""

import asyncio
from typing import Any, Dict

from ghidra_agent.call_graph_analyzer import analyze_call_graph
from ghidra_agent.config import settings
from ghidra_agent.function_priority import apply_priority_to_result
from ghidra_agent.logging import logger
from ghidra_agent.r2_tools import (
    r2_analyze_binary,
    r2_build_call_graph,
    r2_decompile_function,
    r2_disassemble_at,
    r2_find_strings,
    r2_find_xrefs,
    r2_list_functions,
    r2_syscall_analysis,
)
from ghidra_agent.state import AgentState

R2_AUTO_DECOMPILE_PERCENT = 0.75  # Decompile 75% of meaningful (non-stub) functions
R2_AUTO_DECOMPILE_MIN = 10         # Floor: always decompile at least this many
R2_AUTO_DECOMPILE_MAX = 40         # Ceiling: cap decompilation to avoid runaway on large binaries


def _to_num(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return 0.0
    return 0.0


def _function_priority_key(func: Dict[str, Any]) -> tuple[float, float, float, str]:
    score = _to_num(func.get("priority_score"))
    if score <= 0.0:
        score = _to_num(func.get("xrefs")) * 100.0 + _to_num(func.get("size"))
    return (
        score,
        _to_num(func.get("xrefs")),
        _to_num(func.get("size")),
        str(func.get("name", "")),
    )


async def _emit_progress(state: AgentState, step: str, pct: int) -> None:
    """Emit monotonic progress updates for R2 stages."""
    safe_pct = max(0, min(100, int(pct)))
    try:
        current_pct = int(state.get("progress", 0))
    except (TypeError, ValueError):
        current_pct = 0

    if safe_pct < current_pct:
        return

    state["current_step"] = step
    state["progress"] = safe_pct

    callback = state.get("progress_callback")
    if callback is None:
        return

    try:
        maybe_coro = callback(step, safe_pct)
        if asyncio.iscoroutine(maybe_coro):
            await maybe_coro
    except Exception as exc:
        logger.warning("r2_progress_callback_failed", step=step, progress=safe_pct, error=str(exc))


async def _safe_call(tool, tool_args: Dict[str, Any], error_key: str) -> Dict[str, Any]:
    try:
        return await tool.ainvoke(tool_args)
    except Exception as exc:
        logger.error(error_key, error=str(exc))
        return {"ok": False, "error": str(exc)}


async def r2_discovery(state: AgentState) -> AgentState:
    """Run Radare2 discovery: binary info, functions, and strings."""
    tool_args = {
        "session_id": state["session_id"],
        "program_hash": state["program_hash"],
        "binary_path": state.get("binary_path"),
    }

    # Run binary analysis, function listing, and string extraction
    binary_info: Dict[str, Any] = {"ok": False, "error": "not run"}
    functions: Dict[str, Any] = {"ok": False, "error": "not run"}
    call_graph: Dict[str, Any] = {"ok": False, "error": "not run"}
    strings: Dict[str, Any] = {"ok": False, "error": "not run"}
    syscalls: Dict[str, Any] = {"ok": False, "error": "not run"}

    await _emit_progress(state, "r2_binary_analysis", 8)
    binary_info = await _safe_call(r2_analyze_binary, tool_args, "r2_discovery_binary_failed")

    await _emit_progress(state, "r2_listing_functions", 12)
    functions = await _safe_call(r2_list_functions, tool_args, "r2_discovery_functions_failed")
    if functions.get("ok"):
        functions = apply_priority_to_result(
            functions,
            alpha=settings.function_priority_alpha,
            beta=settings.function_priority_beta,
        )

    # These steps are independent once function listing has run.
    await _emit_progress(state, "r2_parallel_discovery", 16)
    call_graph, strings, syscalls = await asyncio.gather(
        _safe_call(r2_build_call_graph, tool_args, "r2_discovery_call_graph_failed"),
        _safe_call(r2_find_strings, tool_args, "r2_discovery_strings_failed"),
        _safe_call(r2_syscall_analysis, tool_args, "r2_discovery_syscalls_failed"),
    )

    state["r2_analysis_results"]["binary"] = binary_info
    state["r2_analysis_results"]["functions"] = functions
    state["r2_analysis_results"]["call_graph"] = call_graph
    state["r2_analysis_results"]["call_graph_analysis"] = analyze_call_graph(call_graph)
    state["r2_analysis_results"]["strings"] = strings
    state["r2_analysis_results"]["syscalls"] = syscalls

    # Auto-decompile top functions (mirroring Ghidra pipeline)
    await _emit_progress(state, "r2_decompiling", 28)
    await _r2_auto_decompile(state, binary_info, functions)
    await _emit_progress(state, "r2_decompile_completed", 50)

    if not binary_info.get("ok"):
        state["r2_analysis_results"].setdefault("errors", []).append("r2_binary_structure_failed")

    state["reasoning_trace"].append("r2_discovery_completed")
    return state


async def _r2_auto_decompile(
    state: AgentState,
    binary_info: Dict[str, Any],
    functions: Dict[str, Any],
) -> None:
    """Auto-decompile top R2-detected functions into r2_decompilation_cache."""
    if not functions.get("ok") or not functions.get("functions"):
        return

    func_list = functions["functions"]

    # Filter out trivial PLT/import stubs (size <= 6 bytes).
    meaningful_funcs = [f for f in func_list if f.get("size", 0) > 6]

    # Prefer composite priority score (xrefs + size), with legacy fallback.
    sorted_funcs = sorted(
        meaningful_funcs,
        key=_function_priority_key,
        reverse=True,
    )

    # Percentage-based limit: decompile 75% of meaningful functions, min 10, max 25
    decompile_target = min(
        R2_AUTO_DECOMPILE_MAX,
        max(
            R2_AUTO_DECOMPILE_MIN,
            int(len(meaningful_funcs) * R2_AUTO_DECOMPILE_PERCENT),
        ),
    )

    funcs_to_decompile = sorted_funcs[:decompile_target]

    sem = asyncio.Semaphore(5)
    total_funcs = len(funcs_to_decompile)

    async def _decompile_one(func: Dict[str, Any], idx: int) -> int:
        name = func.get("name", "")
        addr = func.get("address", "")
        if not name or name in state.get("r2_decompilation_cache", {}):
            return 0

        async with sem:
            pct = 28 + int(((idx + 1) / max(total_funcs, 1)) * 22)
            await _emit_progress(state, f"r2_decompiling {idx + 1}/{total_funcs}", pct)
            try:
                decomp = await r2_decompile_function.ainvoke({
                    "session_id": state["session_id"],
                    "program_hash": state["program_hash"],
                    "binary_path": state.get("binary_path"),
                    "function_name": name,
                    "address": addr,
                })
            except Exception as exc:
                logger.error("r2_auto_decompile_failed", function=name, error=str(exc))
                return 0

            if decomp.get("ok") and decomp.get("c"):
                state["r2_decompilation_cache"][name] = decomp["c"]
                return 1
        return 0

    decompiled = sum(await asyncio.gather(*[_decompile_one(func, idx) for idx, func in enumerate(funcs_to_decompile)]))

    if decompiled:
        state["reasoning_trace"].append(f"r2_auto_decompiled:{decompiled}_functions")


async def r2_focus_analysis(state: AgentState) -> AgentState:
    """Focus R2 analysis on a specific function or address."""
    target = state.get("current_function")
    addr = state.get("current_address")
    tool_args = {
        "session_id": state["session_id"],
        "program_hash": state["program_hash"],
        "binary_path": state.get("binary_path"),
    }

    if target:
        try:
            decomp = await r2_decompile_function.ainvoke({
                **tool_args,
                "function_name": target,
                "address": addr,
            })
        except Exception as exc:
            decomp = {"ok": False, "error": str(exc)}

        if not decomp.get("ok") and addr:
            try:
                decomp = await r2_disassemble_at.ainvoke({**tool_args, "address": addr})
            except Exception as exc:
                decomp = {"ok": False, "error": str(exc)}

        state["r2_analysis_results"]["focus"] = decomp
        if decomp.get("ok") and decomp.get("c"):
            state["r2_decompilation_cache"][target] = decomp["c"]

    elif addr:
        try:
            disasm = await r2_disassemble_at.ainvoke({**tool_args, "address": addr})
        except Exception as exc:
            disasm = {"ok": False, "error": str(exc)}
        state["r2_analysis_results"]["focus"] = disasm
    else:
        state["r2_analysis_results"]["focus"] = {"ok": False, "error": "No focus target"}

    state["reasoning_trace"].append("r2_focus_completed")
    return state


async def r2_cross_reference(state: AgentState) -> AgentState:
    """Cross-reference analysis using Radare2."""
    addr = state.get("current_address")
    if addr:
        try:
            xrefs = await r2_find_xrefs.ainvoke({
                "session_id": state["session_id"],
                "program_hash": state["program_hash"],
                "binary_path": state.get("binary_path"),
                "address": addr,
            })
        except Exception as exc:
            xrefs = {"ok": False, "error": str(exc)}
        state["r2_analysis_results"]["xrefs"] = xrefs

    state["reasoning_trace"].append("r2_xref_completed")
    return state


async def run_r2_pipeline(state: AgentState) -> AgentState:
    """Execute the full R2 analysis pipeline (called in parallel with Ghidra).

    This is NOT a LangGraph sub-graph — it's a simple sequential pipeline
    that mirrors the Ghidra discovery→focus→xref flow.
    """
    state = await r2_discovery(state)

    # Only run focus/xref if a specific target is set
    if state.get("current_function") or state.get("current_address"):
        state = await r2_focus_analysis(state)
        if state.get("current_address"):
            state = await r2_cross_reference(state)

    return state
