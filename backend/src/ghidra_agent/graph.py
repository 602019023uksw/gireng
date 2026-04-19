import asyncio
import json
import re
from typing import Any, Dict, List

from langgraph.graph import END, StateGraph

from ghidra_agent.call_graph_analyzer import analyze_call_graph
from ghidra_agent.config import settings
from ghidra_agent.context_builder import build_analysis_context, build_light_context
from ghidra_agent.decompile_planner import plan_decompilation
from ghidra_agent.function_priority import (
    apply_priority_to_result,
    build_interesting_callers_set,
    build_string_ref_functions,
)
from ghidra_agent.ioc_extractor import calculate_verdict, classify_malware_type, extract_iocs_from_state, format_iocs_for_report
from ghidra_agent.langfuse_tracing import get_trace_metadata
from ghidra_agent.llm import call_llm
from ghidra_agent.logging import logger
from ghidra_agent.memory import get_memory_manager
from ghidra_agent.prompts import PLANNER_PROMPT, SYSTEM_PROMPT
from ghidra_agent.ranking_utils import _function_priority_key
from ghidra_agent.state import AgentState
from ghidra_agent.tools import (
    analyze_binary_structure,
    build_call_graph,
    decompile_function,
    disassemble_at,
    find_strings,
    find_xrefs,
    get_function_graph,
    list_functions,
    search_bytes,
)

GHIDRA_AUTO_DECOMPILE_PERCENT = 0.75  # Decompile 75% of meaningful (non-stub) functions
GHIDRA_AUTO_DECOMPILE_MIN = 10       # Floor: always decompile at least this many
GHIDRA_AUTO_DECOMPILE_MAX = 25       # Ceiling: cap decompilation to avoid runaway on large binaries
LLM_STRING_LIMIT = 120                 # How many strings to send (up from 75)
MAX_INVESTIGATION_ITERATIONS = 10


def _ensure_analyzer_maps(state: AgentState) -> None:
    state.setdefault("analyzer_progress", {"ghidra": 0, "radare2": 0, "qiling": 0})
    state.setdefault("analyzer_status", {"ghidra": "pending", "radare2": "pending", "qiling": "pending"})
    state.setdefault("analyzer_step", {"ghidra": "", "radare2": "", "qiling": ""})


def _set_analyzer_progress(
    state: AgentState,
    analyzer: str,
    *,
    progress: int | None = None,
    status: str | None = None,
    step: str | None = None,
) -> None:
    _ensure_analyzer_maps(state)
    if progress is not None:
        safe_progress = max(0, min(100, int(progress)))
        state["analyzer_progress"][analyzer] = safe_progress
    if step is not None:
        state["analyzer_step"][analyzer] = step
    if status is not None:
        state["analyzer_status"][analyzer] = status
        if status == "completed":
            state["analyzer_progress"][analyzer] = 100


def _ghidra_progress_from_global(pct: int) -> int:
    if pct <= 5:
        return 0
    scaled = int(((pct - 5) / 45.0) * 100)
    return max(0, min(100, scaled))


def _extract_breakpoint_decision(text: str) -> Dict[str, Any]:
    """Extract the breakpoint decision JSON from LLM output."""
    text = text.strip()
    if "```" in text:
        match = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
        if match:
            text = match.group(1).strip()
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return {
                "action": data.get("action", "stop"),
                "step": data.get("step", {}),
                "rationale": data.get("rationale", ""),
            }
    except Exception:
        logger.warning("failed_to_parse_breakpoint_json", text=text[:500])
    return {"action": "stop", "step": {}, "rationale": "parse_error"}


BYTE_SIGNATURE_PATTERNS = [
    {"id": "x64_shellcode_prologue", "pattern": "FC 48 83 E4 F0 E8"},
    {"id": "x86_execve_binsh", "pattern": "31 C0 50 68 2F 2F 73 68"},
    {"id": "nop_sled_16", "pattern": "90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90"},
]


async def _emit_progress(state: AgentState, step: str, pct: int) -> None:
    """Emit monotonic progress updates to state and optional callback."""
    safe_pct = max(0, min(100, int(pct)))
    try:
        current_pct = int(state.get("progress", 0))
    except (TypeError, ValueError):
        current_pct = 0

    # Prevent regressions when parallel tasks emit out-of-order updates.
    if safe_pct < current_pct:
        return

    state["current_step"] = step
    state["progress"] = safe_pct
    if step.startswith("ghidra_"):
        analyzer_pct = _ghidra_progress_from_global(safe_pct)
        _set_analyzer_progress(
            state,
            "ghidra",
            progress=analyzer_pct,
            status="completed" if analyzer_pct >= 100 else "running",
            step=step,
        )

    callback = state.get("progress_callback")
    if callback is None:
        return

    try:
        maybe_coro = callback(step, safe_pct)
        if asyncio.iscoroutine(maybe_coro):
            await maybe_coro
    except Exception as exc:
        logger.warning("progress_callback_failed", step=step, progress=safe_pct, error=str(exc))


async def parse_intent(state: AgentState) -> AgentState:
    await _emit_progress(state, "parse_intent", 2)
    query = state.get("user_query", "")
    intent = "reconnaissance"
    if any(term in query.lower() for term in ["vuln", "overflow", "format", "strcpy", "sprintf"]):
        intent = "vulnerability"
    elif any(term in query.lower() for term in ["malware", "packer", "obfus", "api"]):
        intent = "malware"
    elif any(term in query.lower() for term in ["protocol", "message", "packet"]):
        intent = "protocol"
    state["intent"] = intent

    # B2 FIX: Extract function names (FUN_xxxxx or known names) from the query
    func_match = re.search(r'\b(FUN_[0-9a-fA-F]+|main|entry|_start)\b', query)
    if func_match:
        func_name = func_match.group(1)
        state["current_function"] = func_name
        state["ghidra_trace"].append(f"target_function:{func_name}")

        # B2 FIX: Also extract address from FUN_xxx name for fallback
        if func_name.startswith("FUN_"):
            addr_match = re.search(r'[0-9a-fA-F]+', func_name[4:])
            if addr_match:
                addr = "0x" + addr_match.group(0).lower()
                state["current_address"] = addr
                state["ghidra_trace"].append(f"target_address:{addr}")

    # Extract hex addresses (0x...) from the query (only if not already set from FUN_xxx)
    addr_match = re.search(r'\b(0x[0-9a-fA-F]+)\b', query)
    if addr_match and not state.get("current_address"):
        state["current_address"] = addr_match.group(1)
        state["ghidra_trace"].append(f"target_address:{addr_match.group(1)}")

    state["ghidra_trace"].append(f"intent:{intent}")
    return state


async def initialize_ghidra(state: AgentState) -> AgentState:
    # Skip re-initialization on follow-up queries
    if "ghidra_initialized" in state.get("ghidra_trace", []):
        logger.info("skipping_reinit", reason="already_initialized")
        await _emit_progress(state, "initialize_skipped", 5)
        return state

    await _emit_progress(state, "initializing_ghidra", 4)
    state["status"] = "initialized"
    state["ghidra_trace"].append("ghidra_initialized")
    _set_analyzer_progress(state, "ghidra", progress=0, status="running", step="initializing_ghidra")

    # Verify R2 container if enabled
    if settings.enable_r2:
        try:
            from ghidra_agent.radare.runner import Radare2Runner
            runner = Radare2Runner()
            if await runner.verify_container():
                state["r2_trace"].append("r2_initialized")
                _set_analyzer_progress(state, "radare2", progress=0, status="pending", step="waiting_discovery")
            else:
                state["r2_trace"].append("r2_unavailable")
                _set_analyzer_progress(state, "radare2", status="failed", step="unavailable")
        except Exception as exc:
            logger.warning("r2_init_check_failed", error=str(exc))
            state["r2_trace"].append("r2_unavailable")
            _set_analyzer_progress(state, "radare2", status="failed", step="init_failed")

    # Verify Qiling container if enabled
    if settings.enable_qiling:
        try:
            from ghidra_agent.qiling.runner import QilingRunner
            runner = QilingRunner()
            if await runner.verify_container():
                state["qiling_trace"].append("qiling_initialized")
                _set_analyzer_progress(state, "qiling", progress=0, status="pending", step="waiting_discovery")
            else:
                state["qiling_trace"].append("qiling_unavailable")
                _set_analyzer_progress(state, "qiling", status="failed", step="unavailable")
        except Exception as exc:
            logger.warning("qiling_init_check_failed", error=str(exc))
            state["qiling_trace"].append("qiling_unavailable")
            _set_analyzer_progress(state, "qiling", status="failed", step="init_failed")

    await _emit_progress(state, "initialization_completed", 5)
    return state


async def discovery(state: AgentState) -> AgentState:
    # Skip re-discovery on follow-up queries if results already exist
    if state.get("analysis_results", {}).get("binary", {}).get("ok"):
        logger.info("skipping_rediscovery", reason="results_already_exist")
        await _emit_progress(state, "discovery_skipped", 60)
        return state

    await _emit_progress(state, "discovery_starting", 5)
    _set_analyzer_progress(state, "ghidra", status="running", step="discovery_starting")

    # Run static and dynamic analyzers concurrently when available.
    tasks = [_ghidra_discovery(state)]
    if settings.enable_r2 and "r2_initialized" in state.get("r2_trace", []):
        _set_analyzer_progress(state, "radare2", status="running", step="r2_discovery_starting")
        tasks.append(_safe_r2_pipeline(state))
    if settings.enable_qiling and "qiling_initialized" in state.get("qiling_trace", []):
        _set_analyzer_progress(state, "qiling", status="running", step="qiling_discovery_starting")
        tasks.append(_safe_qiling_pipeline(state))

    await asyncio.gather(*tasks)

    # Extract and persist IOC data during pipeline (before LLM synthesis).
    _refresh_ioc_context(state)
    await _emit_progress(state, "discovery_completed", 60)
    if state.get("analysis_results", {}).get("binary", {}).get("ok"):
        _set_analyzer_progress(state, "ghidra", status="completed", step="ghidra_discovery_completed")

    state["ghidra_trace"].append("discovery_completed")
    return state


async def _ghidra_discovery(state: AgentState) -> None:
    """Core Ghidra discovery: binary info, functions, strings, auto-decompile."""
    tool_args = {
        "session_id": state["session_id"],
        "program_hash": state["program_hash"],
        "binary_path": state.get("binary_path"),
    }
    await _emit_progress(state, "ghidra_binary_analysis", 8)
    try:
        binary_info = await analyze_binary_structure.ainvoke(tool_args)
    except Exception as exc:
        logger.error("discovery_binary_failed", error=str(exc))
        binary_info = {"ok": False, "error": str(exc)}

    await _emit_progress(state, "ghidra_listing_functions", 12)
    try:
        functions = await list_functions.ainvoke(tool_args)
    except Exception as exc:
        logger.error("discovery_functions_failed", error=str(exc))
        functions = {"ok": False, "error": str(exc)}

    await _emit_progress(state, "ghidra_finding_strings", 16)
    try:
        strings = await find_strings.ainvoke(tool_args)
    except Exception as exc:
        logger.error("discovery_strings_failed", error=str(exc))
        strings = {"ok": False, "error": str(exc)}

    await _emit_progress(state, "ghidra_call_graph", 20)
    try:
        call_graph = await build_call_graph.ainvoke(tool_args)
    except Exception as exc:
        logger.error("discovery_call_graph_failed", error=str(exc))
        call_graph = {"ok": False, "error": str(exc)}

    # --- Behavioral prioritization: compute boost signals from call graph + strings ---
    cg_analysis = analyze_call_graph(call_graph)
    adjacency = cg_analysis.get("adjacency", []) if cg_analysis.get("ok") else []

    interesting_callers = build_interesting_callers_set(adjacency)
    strings_list = strings.get("strings", []) if strings.get("ok") else []
    func_list = functions.get("functions", []) if functions.get("ok") else []
    string_ref_funcs = build_string_ref_functions(func_list, strings_list)

    # Identify main / entry-adjacent functions for boosting
    main_functions: set[str] = set()
    for f in func_list:
        fname = (f.get("name") or "").lower()
        if fname in {"main", "_start", "entry0", "entry", "start"}:
            main_functions.add(f.get("name", ""))
    # Also check if call graph has main-like entry nodes
    for entry_name in cg_analysis.get("entries", []):
        norm = (entry_name or "").strip().lower()
        for prefix in ("sym.imp.", "imp.", "sym.", "fcn.", "__imp_"):
            if norm.startswith(prefix):
                norm = norm[len(prefix):]
        if norm in {"main", "_start", "entry0", "entry", "start"}:
            main_functions.add(entry_name)

    logger.info(
        "behavioral_priority_signals",
        interesting_callers=len(interesting_callers),
        string_ref_functions=len(string_ref_funcs),
        main_functions=len(main_functions),
    )

    # Apply enhanced prioritization with all signals
    if functions.get("ok"):
        functions = apply_priority_to_result(
            functions,
            alpha=settings.function_priority_alpha,
            beta=settings.function_priority_beta,
            interesting_callers=interesting_callers,
            string_ref_functions=string_ref_funcs,
            main_functions=main_functions,
        )

    state["analysis_results"]["binary"] = binary_info
    state["analysis_results"]["functions"] = functions
    state["analysis_results"]["strings"] = strings
    state["analysis_results"]["call_graph"] = call_graph
    state["analysis_results"]["call_graph_analysis"] = cg_analysis

    # Scan for high-signal byte patterns (shellcode-like signatures).
    await _emit_progress(state, "ghidra_byte_signatures", 24)
    await _run_byte_signature_scan(state, tool_args)

    # Auto-decompile entry point and top functions
    await _emit_progress(state, "ghidra_decompiling", 28)
    await _auto_decompile_key_functions(state, binary_info, functions)
    await _emit_progress(state, "ghidra_decompile_completed", 50)

    if not binary_info.get("ok"):
        state["analysis_results"].setdefault("errors", []).append("binary_structure_failed")
        _set_analyzer_progress(state, "ghidra", status="failed", step="ghidra_discovery_failed")
    else:
        _set_analyzer_progress(state, "ghidra", status="completed", step="ghidra_discovery_completed")


async def _safe_r2_pipeline(state: AgentState) -> None:
    """Run R2 pipeline safely — failures don't block Ghidra results."""
    try:
        from ghidra_agent.r2_graph import run_r2_pipeline
        await asyncio.wait_for(
            run_r2_pipeline(state),
            timeout=max(30, int(settings.r2_pipeline_timeout)),
        )
    except asyncio.TimeoutError:
        timeout = max(30, int(settings.r2_pipeline_timeout))
        logger.error("r2_pipeline_timeout", timeout_seconds=timeout)
        state["r2_trace"].append(f"r2_error:timeout_after_{timeout}s")
        _set_analyzer_progress(state, "radare2", status="failed", step="pipeline_timeout")
    except Exception as exc:
        logger.error("r2_pipeline_failed", error=str(exc))
        state["r2_trace"].append(f"r2_error:{exc}")
        _set_analyzer_progress(state, "radare2", status="failed", step="pipeline_error")


async def _safe_qiling_pipeline(state: AgentState) -> None:
    """Run Qiling pipeline safely — failures don't block static analysis results."""
    try:
        from ghidra_agent.qiling_graph import run_qiling_pipeline
        await run_qiling_pipeline(state)
    except Exception as exc:
        logger.error("qiling_pipeline_failed", error=str(exc))
        state["qiling_trace"].append(f"qiling_error:{exc}")
        _set_analyzer_progress(state, "qiling", status="failed", step="pipeline_error")


async def _run_byte_signature_scan(state: AgentState, tool_args: Dict[str, Any]) -> None:
    matches = []
    for signature in BYTE_SIGNATURE_PATTERNS:
        try:
            result = await search_bytes.ainvoke(
                {
                    **tool_args,
                    "pattern": signature["pattern"],
                }
            )
        except Exception as exc:
            logger.warning("byte_signature_scan_failed", signature=signature["id"], error=str(exc))
            result = {"ok": False, "error": str(exc), "matches": []}

        sig_matches = result.get("matches", []) if result.get("ok") else []
        matches.append(
            {
                "id": signature["id"],
                "pattern": signature["pattern"],
                "count": len(sig_matches),
                "addresses": sig_matches[:10],
                "ok": bool(result.get("ok")),
            }
        )

    state["analysis_results"]["byte_signatures"] = {"ok": True, "signatures": matches}
    hit_count = sum(1 for m in matches if m["count"] > 0)
    state["ghidra_trace"].append(f"byte_signature_hits:{hit_count}")


def _refresh_ioc_context(state: AgentState) -> None:
    iocs = extract_iocs_from_state(state)
    verdict, verdict_class, indicators, score = calculate_verdict(iocs, state)
    ioc_dict = iocs.to_dict()

    state["analysis_results"]["iocs"] = {
        "ok": not iocs.is_empty(),
        "data": ioc_dict,
        "summary": format_iocs_for_report(iocs),
    }
    state["analysis_results"]["ioc_assessment"] = {
        "verdict": verdict,
        "class": verdict_class,
        "score": score,
        "indicators": indicators,
    }
    total_ioc_items = sum(len(v) for v in ioc_dict.values())
    state["ghidra_trace"].append(f"iocs_extracted:{total_ioc_items}")


async def _auto_decompile_key_functions(state: AgentState, binary_info: Dict, functions: Dict) -> None:
    """B3 + I1: Auto-decompile entry point, main, interesting callers, and top ranked functions."""
    if not functions.get("ok") or not functions.get("functions"):
        return

    func_list = functions["functions"]
    if not func_list:
        return

    funcs_to_decompile, entry_func_name, entry_addr = plan_decompilation(
        func_list,
        binary_info=binary_info,
        min_funcs=GHIDRA_AUTO_DECOMPILE_MIN,
        max_funcs=GHIDRA_AUTO_DECOMPILE_MAX,
        percent=GHIDRA_AUTO_DECOMPILE_PERCENT,
        include_entry_point=True,
    )
    if entry_func_name and entry_addr:
        state["current_function"] = entry_func_name
        state["current_address"] = entry_addr

    logger.info(
        "auto_decompile_plan",
        total_functions=len(func_list),
        decompile_target=len(funcs_to_decompile),
    )

    # Decompile selected functions
    total_decompile = len(funcs_to_decompile)
    decompiled_count = 0
    for idx, func in enumerate(funcs_to_decompile):
        func_name = func.get("name")
        func_addr = func.get("address")
        if not func_name or func_name in state.get("decompilation_cache", {}):
            continue

        pct = 28 + int(((idx + 1) / max(total_decompile, 1)) * 22)
        await _emit_progress(state, f"ghidra_decompiling {idx + 1}/{total_decompile}", pct)

        try:
            decomp = await decompile_function.ainvoke(
                {
                    "session_id": state["session_id"],
                    "program_hash": state["program_hash"],
                    "binary_path": state.get("binary_path"),
                    "function_name": func_name,
                    "address": func_addr,
                }
            )
            if decomp.get("ok") and decomp.get("c"):
                state["decompilation_cache"][func_name] = decomp.get("c")
                decompiled_count += 1
        except Exception as exc:
            logger.error("auto_decompile_failed", function=func_name, error=str(exc))

    if decompiled_count > 0:
        state["ghidra_trace"].append(f"auto_decompiled:{decompiled_count}_functions")


async def focus_analysis(state: AgentState) -> AgentState:
    await _emit_progress(state, "focus_analysis", 62)
    target_function = state.get("current_function")
    if target_function:
        try:
            decomp = await decompile_function.ainvoke(
                {
                    "session_id": state["session_id"],
                    "program_hash": state["program_hash"],
                    "binary_path": state.get("binary_path"),
                    "function_name": target_function,
                }
            )
        except Exception as exc:
            logger.error("focus_decompile_failed", error=str(exc))
            decomp = {"ok": False, "error": str(exc)}
        if not decomp.get("ok") and state.get("current_address"):
            try:
                decomp = await disassemble_at.ainvoke(
                    {
                        "session_id": state["session_id"],
                        "program_hash": state["program_hash"],
                        "binary_path": state.get("binary_path"),
                        "address": state["current_address"],
                    }
                )
            except Exception as exc:
                logger.error("focus_disassemble_failed", error=str(exc))
                decomp = {"ok": False, "error": str(exc)}
        state["analysis_results"]["focus"] = decomp
        if decomp.get("ok") and decomp.get("c"):
            state["decompilation_cache"][target_function] = decomp.get("c")
    elif state.get("current_address"):
        try:
            disasm = await disassemble_at.ainvoke(
                {
                    "session_id": state["session_id"],
                    "program_hash": state["program_hash"],
                    "binary_path": state.get("binary_path"),
                    "address": state["current_address"],
                }
            )
        except Exception as exc:
            logger.error("focus_disassemble_at_failed", error=str(exc))
            disasm = {"ok": False, "error": str(exc)}
        state["analysis_results"]["focus"] = disasm
    else:
        state["analysis_results"]["focus"] = {"ok": False, "error": "No focus target set."}
    state["ghidra_trace"].append("focus_analysis_completed")
    await _emit_progress(state, "focus_analysis_completed", 66)
    return state


async def cross_reference(state: AgentState) -> AgentState:
    await _emit_progress(state, "cross_reference", 68)
    address = state.get("current_address")
    if address:
        try:
            xrefs = await find_xrefs.ainvoke(
                {
                    "session_id": state["session_id"],
                    "program_hash": state["program_hash"],
                    "binary_path": state.get("binary_path"),
                    "address": address,
                }
            )
        except Exception as exc:
            logger.error("xrefs_failed", error=str(exc))
            xrefs = {"ok": False, "error": str(exc)}
        state["analysis_results"]["xrefs"] = xrefs
    elif state.get("current_function"):
        try:
            graph_result = await get_function_graph.ainvoke(
                {
                    "session_id": state["session_id"],
                    "program_hash": state["program_hash"],
                    "binary_path": state.get("binary_path"),
                    "function_name": state["current_function"],
                }
            )
        except Exception as exc:
            logger.error("function_graph_failed", error=str(exc))
            graph_result = {"ok": False, "error": str(exc)}
        state["analysis_results"]["function_graph"] = graph_result
    state["ghidra_trace"].append("cross_reference_completed")
    await _emit_progress(state, "cross_reference_completed", 70)
    return state


def _build_fallback_summary(state: AgentState, error_msg: str) -> str:
    """Generate a structured summary from raw data when the LLM is unavailable."""
    results = state.get("analysis_results", {})
    r2_results = state.get("r2_analysis_results", {})
    parts: List[str] = []
    parts.append(f"> **Note**: {error_msg}  ")
    parts.append("> The following summary was auto-generated from raw analysis data.\n")

    # Binary info
    binary = results.get("binary", {})
    if binary.get("ok"):
        parts.append("## Binary Information")
        parts.append(f"- **Architecture**: {binary.get('architecture', 'N/A')}")
        parts.append(f"- **Image base**: {binary.get('image_base', 'N/A')}")
        if binary.get("entry_points"):
            parts.append(f"- **Entry points**: {', '.join(binary['entry_points'][:10])}")
        parts.append("")

    # Function summary
    funcs = results.get("functions", {})
    func_list = funcs.get("functions", []) if funcs.get("ok") else []
    r2_funcs = r2_results.get("functions", {})
    r2_func_list = r2_funcs.get("functions", []) if r2_funcs.get("ok") else []
    if func_list or r2_func_list:
        parts.append("## Functions")
        if func_list:
            top = sorted(func_list, key=_function_priority_key, reverse=True)[:15]
            names = [
                f"{f.get('name')} (score:{f.get('priority_score', 0)}, xrefs:{f.get('xrefs', 0)}, size:{f.get('size', 0)})"
                for f in top
            ]
            parts.append(f"- **Ghidra** ({len(func_list)} total): {', '.join(names)}")
        if r2_func_list:
            top = sorted(r2_func_list, key=_function_priority_key, reverse=True)[:15]
            names = [
                f"{f.get('name')} (score:{f.get('priority_score', 0)}, xrefs:{f.get('xrefs', 0)}, size:{f.get('size', 0)})"
                for f in top
            ]
            parts.append(f"- **Radare2** ({len(r2_func_list)} total): {', '.join(names)}")
        parts.append("")

    # Imports/Exports
    imports = binary.get("imports", [])
    exports = binary.get("exports", [])
    if imports or exports:
        parts.append("## Imports / Exports")
        if imports:
            parts.append(f"- **Imports** ({len(imports)}): {', '.join(imports[:30])}")
        if exports:
            parts.append(f"- **Exports** ({len(exports)}): {', '.join(exports[:30])}")
        parts.append("")

    # IOCs & Verdict
    from ghidra_agent.ioc_extractor import calculate_verdict, extract_iocs_from_state, format_iocs_for_report
    iocs = extract_iocs_from_state(state)
    verdict, _, indicators, score = calculate_verdict(iocs, state)
    parts.append("## Verdict")
    parts.append(f"- **Verdict**: {verdict} (score: {score})")
    if indicators:
        parts.append(f"- **Indicators**: {indicators}")
    if not iocs.is_empty():
        parts.append("\n### Extracted IOCs")
        parts.append(format_iocs_for_report(iocs))
    parts.append("")

    # Call graph / attack chains
    cga = results.get("call_graph_analysis", {})
    r2_cga = r2_results.get("call_graph_analysis", {})
    for label, analysis in [("Ghidra", cga), ("Radare2", r2_cga)]:
        if analysis.get("ok"):
            chains = analysis.get("chains", [])
            stats = analysis.get("stats", {})
            parts.append(f"## {label} Call Graph")
            parts.append(f"- Nodes: {stats.get('nodes', 0)}, Edges: {stats.get('edges', 0)}, Chains: {stats.get('chains', len(chains))}")
            if chains:
                parts.append("\n### Attack Chains")
                for ch in chains[:15]:
                    parts.append(f"- **[{ch.get('category', '?')}]** {' → '.join(ch.get('path', []))}")
            parts.append("")

    # Qiling dynamic results
    qiling_results = state.get("qiling_analysis_results", {})
    if qiling_results:
        parts.append("## Dynamic Analysis (Qiling)")
        execution = qiling_results.get("execution_trace", {})
        if execution:
            parts.append(
                "- Execution: "
                f"success={execution.get('success')}, os={execution.get('os', 'unknown')}, "
                f"arch={execution.get('arch', 'unknown')}, "
                f"instructions={execution.get('instructions_executed', 0)}, "
                f"exit={execution.get('exit_reason', 'unknown')}"
            )
        syscalls = qiling_results.get("syscalls", {})
        syscall_summary = syscalls.get("summary", {}) if isinstance(syscalls, dict) else {}
        if syscall_summary:
            parts.append(
                "- Syscalls: "
                f"{syscall_summary.get('total_calls', 0)} total, "
                f"categories={syscall_summary.get('categories', {})}"
            )
        network = qiling_results.get("network_activity", {})
        if isinstance(network, dict):
            indicators = network.get("indicators", {})
            c2 = indicators.get("c2_candidates", []) if isinstance(indicators, dict) else []
            if c2:
                parts.append(f"- Network C2 candidates: {', '.join(str(v) for v in c2[:10])}")
        evasion = qiling_results.get("evasion_techniques", {})
        if isinstance(evasion, dict):
            ev_summary = evasion.get("summary", {})
            if isinstance(ev_summary, dict) and ev_summary:
                parts.append(
                    "- Evasion techniques: "
                    f"{ev_summary.get('total_techniques', 0)} "
                    f"(risk={ev_summary.get('risk_level', 'low')})"
                )
        instruction_trace = qiling_results.get("instruction_trace", {})
        if isinstance(instruction_trace, dict) and instruction_trace:
            it_summary = instruction_trace.get("summary", {})
            if isinstance(it_summary, dict):
                parts.append(
                    "- Instruction Trace: "
                    f"{it_summary.get('total_executed', 0)} instructions, "
                    f"{it_summary.get('unique_mnemonics', 0)} unique"
                )
                freq = it_summary.get("top_mnemonics", [])
                if isinstance(freq, list) and freq:
                    top_strs = [f"{e.get('mnemonic', '?')}:{e.get('count', 0)}" for e in freq[:10] if isinstance(e, dict)]
                    parts.append(f"- Top Mnemonics: {', '.join(top_strs)}")
            oep = instruction_trace.get("oep_candidates", [])
            if isinstance(oep, list) and oep:
                oep_strs = [f"{o.get('address', '?')}({o.get('confidence', '?')})" for o in oep[:5] if isinstance(o, dict)]
                parts.append(f"- OEP Candidates: {', '.join(oep_strs)}")
        q_errors = qiling_results.get("errors", [])
        if q_errors:
            parts.append(f"- Qiling errors: {q_errors}")
        parts.append("")

    # Decompiled function names
    decomp = state.get("decompilation_cache", {})
    r2_decomp = state.get("r2_decompilation_cache", {})
    if decomp or r2_decomp:
        parts.append("## Decompiled Functions")
        if decomp:
            parts.append(f"- **Ghidra** ({len(decomp)}): {', '.join(list(decomp.keys())[:20])}")
        if r2_decomp:
            parts.append(f"- **Radare2** ({len(r2_decomp)}): {', '.join(list(r2_decomp.keys())[:20])}")
        parts.append("")

    parts.append("*Use `/query` to ask specific questions about the binary.*")
    return "\n".join(parts)


async def plan_analysis(state: AgentState) -> AgentState:
    await _emit_progress(state, "planning_investigation", 72)
    light_context = build_light_context(state)

    prev_results: List[str] = []
    for key, value in state.get("investigation_results", {}).items():
        ok = value.get("ok", False)
        status = "success" if ok else f"failed:{value.get('error', 'unknown')}"
        snippet = ""
        if ok and value.get("c"):
            snippet = value["c"][:600].replace("\n", " ")
        elif ok and value.get("instructions"):
            snippet = f"{len(value['instructions'])} instructions"
        elif ok and value.get("xrefs"):
            snippet = f"xrefs={value.get('xrefs')}"
        elif ok and value.get("nodes"):
            snippet = f"nodes={len(value.get('nodes', []))}"
        prev_results.append(f"- {key} -> {status}; {snippet}")

    prev_section = ""
    if prev_results:
        prev_section = "\n\nPrevious investigation results:\n" + "\n".join(prev_results)

    prompt = f"{PLANNER_PROMPT}\n\nAnalysis summary:\n{light_context}{prev_section}\n\nGenerate your breakpoint decision JSON now."

    iterations = state.get("investigation_iterations", 0)

    # Safety guardrail: force stop after max iterations
    if iterations >= MAX_INVESTIGATION_ITERATIONS:
        logger.info("planner_hit_max_iterations_guard", iterations=iterations)
        state["analysis_plan"] = []
        state["investigation_iterations"] = iterations + 1
        state["investigation_trace"] = f"Investigation halted by safety guardrail after {iterations} iterations (max {MAX_INVESTIGATION_ITERATIONS})."
        state["ghidra_trace"].append("plan_analysis_guard_stop")
        await _emit_progress(state, "planning_stop_guard", 74)
        return state

    try:
        lf_meta = get_trace_metadata(generation_name="plan_analysis")
        result = await call_llm(prompt, metadata=lf_meta or None, model=state.get("llm_model"), timeout=300)
        decision = _extract_breakpoint_decision(result.get("content", ""))
        action = decision.get("action", "stop")
        step = decision.get("step", {})

        if action == "investigate" and isinstance(step, dict) and step.get("tool") and step.get("target"):
            state["analysis_plan"] = [step]
            state["investigation_iterations"] = iterations + 1
            logger.info(
                "planner_breakpoint_continue",
                tool=step.get("tool"),
                target=step.get("target"),
                rationale=decision.get("rationale"),
            )
        else:
            state["analysis_plan"] = []
            state["investigation_iterations"] = iterations + 1
            rationale = decision.get("rationale", "")
            state["investigation_trace"] = rationale
            logger.info("planner_breakpoint_stop", rationale=rationale)
    except Exception as exc:
        logger.error("plan_analysis_failed", error=str(exc))
        state["analysis_plan"] = []

    state["ghidra_trace"].append("plan_analysis_completed")
    await _emit_progress(state, "planning_completed", 74)
    return state


async def investigate(state: AgentState) -> AgentState:
    await _emit_progress(state, "investigating", 76)
    steps = state.get("analysis_plan", [])
    if not steps:
        await _emit_progress(state, "investigation_skipped", 80)
        return state

    tool_args_base = {
        "session_id": state["session_id"],
        "program_hash": state["program_hash"],
        "binary_path": state.get("binary_path"),
    }

    for idx, step in enumerate(steps):
        tool = step.get("tool", "")
        target = step.get("target", "")
        reason = step.get("reason", "")
        if not tool or not target:
            continue

        key = f"{tool}:{target}"
        if key in state.get("investigation_results", {}):
            continue

        await _emit_progress(state, f"investigating {tool} {target}", 76 + int((idx / max(len(steps), 1)) * 8))
        logger.info("investigation_step", tool=tool, target=target, reason=reason)

        result: Dict[str, Any] = {"ok": False, "error": "unsupported tool"}
        try:
            if tool == "decompile":
                result = await decompile_function.ainvoke({**tool_args_base, "function_name": target})
            elif tool == "disassemble":
                result = await disassemble_at.ainvoke({**tool_args_base, "address": target})
            elif tool == "find_xrefs":
                result = await find_xrefs.ainvoke({**tool_args_base, "address": target})
            elif tool == "function_graph":
                result = await get_function_graph.ainvoke({**tool_args_base, "function_name": target})
            else:
                result = {"ok": False, "error": f"unsupported tool: {tool}"}
        except Exception as exc:
            logger.error("investigation_step_failed", tool=tool, target=target, error=str(exc))
            result = {"ok": False, "error": str(exc)}

        state["investigation_results"][key] = result

    state["analysis_plan"] = []
    state["ghidra_trace"].append("investigation_completed")
    await _emit_progress(state, "investigation_completed", 84)
    return state


async def synthesize(state: AgentState) -> AgentState:
    await _emit_progress(state, "synthesizing_report", 85)
    user_query = state.get("user_query", "")
    results = state.get("analysis_results", {})

    context = build_analysis_context(
        state,
        include_focus=True,
        include_xrefs=True,
        string_limit=100,
        func_limit=50,
        ghidra_decomp_limit=20,
        r2_decomp_limit=20,
        decomp_chars=2000,
        decomp_chars_high=10000,
    )
    if len(context) > 80_000:
        logger.warning("synthesize_context_oversized", chars=len(context))
        context = build_analysis_context(
            state,
            include_focus=True,
            include_xrefs=True,
            string_limit=60,
            func_limit=30,
            ghidra_decomp_limit=12,
            r2_decomp_limit=12,
            decomp_chars=1500,
            decomp_chars_high=6000,
        )


    if user_query:
        prompt = f"""{SYSTEM_PROMPT}

Binary hash: {state.get('program_hash', 'unknown')}

Analysis data:
{context}

User question: {user_query}

Answer based ONLY on the data provided. Be specific with addresses and evidence."""
    else:
        prompt = f"""{SYSTEM_PROMPT}

Binary hash: {state.get('program_hash', 'unknown')}

Analysis data:
{context}

Generate a complete structured malware analysis report with ALL sections listed in your instructions.
Use ONLY the data provided above - do not invent or assume information.
If the malware family is unknown, state "Unknown".
Cite actual addresses (0xXXXXXXXX) and actual strings from the analysis data."""

    logger.info("synthesize_llm_start", prompt_len=len(prompt), model=state.get("llm_model"))
    try:
        lf_meta = get_trace_metadata(generation_name="synthesize")
        # Synthesize can take up to 20 minutes for large binaries with deep thinking.
        result = await call_llm(prompt, metadata=lf_meta or None, model=state.get("llm_model"), timeout=1200)
        summary = result.get("content", "")
        reasoning = result.get("reasoning_content", "")
        # Store reasoning in state for later reference
        if reasoning:
            state.setdefault("synthesis_reasoning", reasoning)
    except Exception as exc:
        logger.error("synthesize_llm_failed", error=str(exc))
        summary = f"[LLM error: {exc}]"

    # Graceful fallback: if the LLM failed or timed out, generate a
    # structured summary from the raw data so results are never blank.
    if summary.startswith("[LLM error:"):
        logger.info("synthesize_fallback_summary")
        summary = _build_fallback_summary(state, summary)

    state["summary"] = summary
    state["status"] = "completed"
    # Merge per-analyzer traces into the global reasoning trace to eliminate
    # race conditions from concurrent appends during parallel analysis.
    state["reasoning_trace"] = (
        state.get("ghidra_trace", [])
        + state.get("r2_trace", [])
        + state.get("qiling_trace", [])
        + ["synthesized"]
    )
    await _emit_progress(state, "analysis_completed", 100)

    # Record analysis in episodic memory for future reference
    try:
        memory = get_memory_manager()
        # Extract capabilities and techniques from the analysis
        _, mtype, mcaps = classify_malware_type(state)
        capabilities = mcaps if mcaps else []

        # Extract IOCs and verdict for memory recording
        iocs = extract_iocs_from_state(state)
        verdict, _, _, _ = calculate_verdict(iocs, state)

        # Extract techniques from IOCs and analysis results
        techniques = []
        if iocs:
            if iocs.domains:
                techniques.append("C2 Communication")
            if iocs.ips:
                techniques.append("External Network Connection")
            if iocs.file_system_operations:
                techniques.append("File System Manipulation")
            if iocs.registry_operations:
                techniques.append("Registry Persistence")
            if iocs.process_operations:
                techniques.append("Process Manipulation")

        # Add techniques from Qiling analysis
        qiling_results = state.get("qiling_analysis_results", {})
        if qiling_results:
            evasion = qiling_results.get("evasion_techniques", {})
            if isinstance(evasion, dict) and evasion.get("techniques"):
                techniques.extend([f"Evasion: {t}" for t in evasion.get("techniques", [])])

        # Count IOCs
        iocs_count = (
            len(iocs.domains or []) +
            len(iocs.ips or []) +
            len(iocs.urls or []) +
            len(iocs.file_system_operations or []) +
            len(iocs.registry_operations or []) +
            len(iocs.process_operations or []) +
            len(iocs.suspicious_strings or [])
        ) if iocs else 0

        # Create a brief summary from the full report
        brief_summary = summary[:1000] if len(summary) > 1000 else summary
        # Extract key findings (first 500 chars or first section)
        if "Executive Summary" in summary:
            parts = summary.split("##")
            for part in parts:
                if "Executive Summary" in part:
                    brief_summary = part[:500]
                    break

        memory.record_analysis(
            program_hash=state.get("program_hash", ""),
            verdict=verdict,
            capabilities=list(set(capabilities + [mtype])) if mtype != "Unknown" else capabilities,
            iocs_count=iocs_count,
            techniques=list(set(techniques)),
            summary=brief_summary,
            session_id=state.get("session_id"),
        )
        logger.info("analysis_recorded_in_memory", program_hash=state.get("program_hash"), verdict=verdict)
    except Exception as exc:
        logger.warning("memory_recording_failed", error=str(exc))

    return state


def _needs_discovery(state: AgentState) -> str:
    results = state["analysis_results"]
    if results.get("binary") or results.get("functions"):
        return "focus_analysis"
    return "discovery"


def _discovery_next(state: AgentState) -> str:
    if state.get("current_function") or state.get("current_address"):
        return "focus_analysis"
    return "plan_analysis"


def _focus_next(state: AgentState) -> str:
    if state.get("current_address"):
        return "cross_reference"
    return "plan_analysis"


def _cross_next(state: AgentState) -> str:
    return "plan_analysis"


def _plan_next(state: AgentState) -> str:
    if state.get("analysis_plan"):
        return "investigate"
    return "synthesize"


def build_graph() -> StateGraph:
    graph = StateGraph(AgentState)
    graph.add_node("parse_intent", parse_intent)
    graph.add_node("initialize_ghidra", initialize_ghidra)
    graph.add_node("discovery", discovery)
    graph.add_node("focus_analysis", focus_analysis)
    graph.add_node("cross_reference", cross_reference)
    graph.add_node("plan_analysis", plan_analysis)
    graph.add_node("investigate", investigate)
    graph.add_node("synthesize", synthesize)

    graph.set_entry_point("parse_intent")
    graph.add_edge("parse_intent", "initialize_ghidra")
    graph.add_conditional_edges("initialize_ghidra", _needs_discovery)
    graph.add_conditional_edges("discovery", _discovery_next)
    graph.add_conditional_edges("focus_analysis", _focus_next)
    graph.add_conditional_edges("cross_reference", _cross_next)
    graph.add_conditional_edges("plan_analysis", _plan_next)
    graph.add_edge("investigate", "plan_analysis")
    graph.add_edge("synthesize", END)
    return graph


graph = build_graph().compile()
