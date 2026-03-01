import asyncio
import re
from typing import Any, Dict, List

from langgraph.graph import END, StateGraph

from ghidra_agent.call_graph_analyzer import analyze_call_graph
from ghidra_agent.config import settings
from ghidra_agent.function_priority import (
    apply_priority_to_result,
    build_interesting_callers_set,
    build_string_ref_functions,
)
from ghidra_agent.ioc_extractor import calculate_verdict, extract_iocs_from_state, format_iocs_for_report
from ghidra_agent.langfuse_tracing import get_trace_metadata
from ghidra_agent.llm import call_llm
from ghidra_agent.logging import logger
from ghidra_agent.prompts import SYSTEM_PROMPT
from ghidra_agent.state import AgentState
from ghidra_agent.tools import (
    add_comment,
    analyze_binary_structure,
    build_call_graph,
    decompile_function,
    disassemble_at,
    find_strings,
    find_xrefs,
    get_function_graph,
    list_functions,
    rename_symbol,
    search_bytes,
)

GHIDRA_AUTO_DECOMPILE_PERCENT = 0.75  # Decompile 75% of meaningful (non-stub) functions
GHIDRA_AUTO_DECOMPILE_MIN = 10       # Floor: always decompile at least this many
GHIDRA_AUTO_DECOMPILE_MAX = 40       # Ceiling: cap decompilation to avoid runaway on large binaries
LLM_GHIDRA_DECOMP_LIMIT = 25
LLM_R2_DECOMP_LIMIT = 25
LLM_DECOMP_SNIPPET_CHARS = 4000
LLM_DECOMP_SNIPPET_CHARS_HIGH = 10000  # Larger budget for top-priority functions
LLM_HIGH_PRIORITY_COUNT = 5            # How many top functions get the larger budget
LLM_STRING_LIMIT = 120                 # How many strings to send (up from 75)


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


def _smart_truncate(code: str, limit: int = LLM_DECOMP_SNIPPET_CHARS) -> str:
    """Truncate decompiled code keeping 100% head.

    Keeps from the beginning of the function up to the character limit so
    the LLM sees the full setup, declarations, and as much logic as fits.
    """
    if len(code) <= limit:
        return code
    marker = "\n/* ... [truncated at %d chars] ... */" % limit
    return code[:limit] + marker


BYTE_SIGNATURE_PATTERNS = [
    {"id": "x64_shellcode_prologue", "pattern": "FC 48 83 E4 F0 E8"},
    {"id": "x86_execve_binsh", "pattern": "31 C0 50 68 2F 2F 73 68"},
    {"id": "nop_sled_16", "pattern": "90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90"},
]



def _to_num(value: Any) -> float:
    """Best-effort numeric conversion for ranking metadata fields."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return 0.0
    return 0.0


def _function_priority_key(func: Dict[str, Any]) -> tuple[float, float, float, str]:
    """Sort by composite score first, with deterministic tie-breakers."""
    score = _to_num(func.get("priority_score"))
    if score <= 0.0:
        # Backward compatible fallback when score isn't present.
        score = _to_num(func.get("xrefs")) * 100.0 + _to_num(func.get("size"))
    return (
        score,
        _to_num(func.get("xrefs")),
        _to_num(func.get("size")),
        str(func.get("name", "")),
    )


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
        state["reasoning_trace"].append(f"target_function:{func_name}")

        # B2 FIX: Also extract address from FUN_xxx name for fallback
        if func_name.startswith("FUN_"):
            addr_match = re.search(r'[0-9a-fA-F]+', func_name[4:])
            if addr_match:
                addr = "0x" + addr_match.group(0).lower()
                state["current_address"] = addr
                state["reasoning_trace"].append(f"target_address:{addr}")

    # Extract hex addresses (0x...) from the query (only if not already set from FUN_xxx)
    addr_match = re.search(r'\b(0x[0-9a-fA-F]+)\b', query)
    if addr_match and not state.get("current_address"):
        state["current_address"] = addr_match.group(1)
        state["reasoning_trace"].append(f"target_address:{addr_match.group(1)}")

    state["reasoning_trace"].append(f"intent:{intent}")
    return state


async def initialize_ghidra(state: AgentState) -> AgentState:
    # Skip re-initialization on follow-up queries
    if "ghidra_initialized" in state.get("reasoning_trace", []):
        logger.info("skipping_reinit", reason="already_initialized")
        await _emit_progress(state, "initialize_skipped", 5)
        return state

    await _emit_progress(state, "initializing_ghidra", 4)
    state["status"] = "initialized"
    state["reasoning_trace"].append("ghidra_initialized")
    _set_analyzer_progress(state, "ghidra", progress=0, status="running", step="initializing_ghidra")

    # Verify R2 container if enabled
    if settings.enable_r2:
        try:
            from ghidra_agent.radare.runner import Radare2Runner
            runner = Radare2Runner()
            if await runner.verify_container():
                state["reasoning_trace"].append("r2_initialized")
                _set_analyzer_progress(state, "radare2", progress=0, status="pending", step="waiting_discovery")
            else:
                state["reasoning_trace"].append("r2_unavailable")
                _set_analyzer_progress(state, "radare2", status="failed", step="unavailable")
        except Exception as exc:
            logger.warning("r2_init_check_failed", error=str(exc))
            state["reasoning_trace"].append("r2_unavailable")
            _set_analyzer_progress(state, "radare2", status="failed", step="init_failed")

    # Verify Qiling container if enabled
    if settings.enable_qiling:
        try:
            from ghidra_agent.qiling.runner import QilingRunner
            runner = QilingRunner()
            if await runner.verify_container():
                state["reasoning_trace"].append("qiling_initialized")
                _set_analyzer_progress(state, "qiling", progress=0, status="pending", step="waiting_discovery")
            else:
                state["reasoning_trace"].append("qiling_unavailable")
                _set_analyzer_progress(state, "qiling", status="failed", step="unavailable")
        except Exception as exc:
            logger.warning("qiling_init_check_failed", error=str(exc))
            state["reasoning_trace"].append("qiling_unavailable")
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
    if settings.enable_r2 and "r2_initialized" in state.get("reasoning_trace", []):
        _set_analyzer_progress(state, "radare2", status="running", step="r2_discovery_starting")
        tasks.append(_safe_r2_pipeline(state))
    if settings.enable_qiling and "qiling_initialized" in state.get("reasoning_trace", []):
        _set_analyzer_progress(state, "qiling", status="running", step="qiling_discovery_starting")
        tasks.append(_safe_qiling_pipeline(state))

    await asyncio.gather(*tasks)

    # Extract and persist IOC data during pipeline (before LLM synthesis).
    _refresh_ioc_context(state)
    await _emit_progress(state, "discovery_completed", 60)
    if state.get("analysis_results", {}).get("binary", {}).get("ok"):
        _set_analyzer_progress(state, "ghidra", status="completed", step="ghidra_discovery_completed")

    state["reasoning_trace"].append("discovery_completed")
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
        await run_r2_pipeline(state)
    except Exception as exc:
        logger.error("r2_pipeline_failed", error=str(exc))
        state["reasoning_trace"].append(f"r2_error:{exc}")
        _set_analyzer_progress(state, "radare2", status="failed", step="pipeline_error")


async def _safe_qiling_pipeline(state: AgentState) -> None:
    """Run Qiling pipeline safely — failures don't block static analysis results."""
    try:
        from ghidra_agent.qiling_graph import run_qiling_pipeline
        await run_qiling_pipeline(state)
    except Exception as exc:
        logger.error("qiling_pipeline_failed", error=str(exc))
        state["reasoning_trace"].append(f"qiling_error:{exc}")
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
    state["reasoning_trace"].append(f"byte_signature_hits:{hit_count}")


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
    state["reasoning_trace"].append(f"iocs_extracted:{total_ioc_items}")


async def _auto_decompile_key_functions(state: AgentState, binary_info: Dict, functions: Dict) -> None:
    """B3 + I1: Auto-decompile entry point, main, interesting callers, and top ranked functions."""
    if not functions.get("ok") or not functions.get("functions"):
        return

    func_list = functions["functions"]
    if not func_list:
        return

    # Filter out trivial PLT/GOT stubs (size <= 6 bytes) — they decompile to
    # a single indirect-jump and waste decompilation slots.
    meaningful_funcs = [f for f in func_list if f.get("size", 0) > 6]

    # Prefer composite priority score (xrefs + size + behavioral boosts), with legacy fallback.
    sorted_funcs = sorted(
        meaningful_funcs,
        key=_function_priority_key,
        reverse=True,
    )

    # Percentage-based limit: decompile 75% of meaningful functions, min 10, max 40
    decompile_target = min(
        GHIDRA_AUTO_DECOMPILE_MAX,
        max(
            GHIDRA_AUTO_DECOMPILE_MIN,
            int(len(meaningful_funcs) * GHIDRA_AUTO_DECOMPILE_PERCENT),
        ),
    )

    logger.info(
        "auto_decompile_plan",
        total_functions=len(func_list),
        meaningful_functions=len(meaningful_funcs),
        decompile_target=decompile_target,
    )

    # Select functions to decompile: entry point first, then must-haves, then top ranked
    funcs_to_decompile: list[Dict] = []
    seen_names: set[str] = set()
    entry_point = None

    # Try to find entry point from binary info
    if binary_info.get("ok") and binary_info.get("entry_points"):
        entry_points = binary_info.get("entry_points", [])
        if entry_points:
            entry_point = entry_points[0]

    # Add entry point function first (B3 fix)
    if entry_point:
        for f in func_list:
            if f.get("address") == entry_point:
                funcs_to_decompile.append(f)
                seen_names.add(f.get("name", ""))
                state["current_function"] = f.get("name")
                state["current_address"] = entry_point
                break

    # Collect must-decompile functions: main, interesting callers, string-ref functions
    must_have: list[Dict] = []
    for f in meaningful_funcs:
        fname = f.get("name", "")
        if fname in seen_names:
            continue
        # Always include main-like functions
        if (fname or "").lower() in {"main", "_start", "entry0"}:
            must_have.append(f)
            seen_names.add(fname)
            continue
        # Always include functions that call security-relevant APIs
        if f.get("is_interesting_caller"):
            must_have.append(f)
            seen_names.add(fname)
            continue
        # Always include functions that reference suspicious strings
        if f.get("has_suspicious_strings"):
            must_have.append(f)
            seen_names.add(fname)
            continue

    funcs_to_decompile.extend(must_have)

    # Add top ranked functions to reach the percentage-based target.
    remaining_slots = max(0, decompile_target - len(funcs_to_decompile))
    top_funcs = [f for f in sorted_funcs if f.get("name", "") not in seen_names][:remaining_slots]
    funcs_to_decompile.extend(top_funcs)

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
        state["reasoning_trace"].append(f"auto_decompiled:{decompiled_count}_functions")


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
    state["reasoning_trace"].append("focus_analysis_completed")
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
    state["reasoning_trace"].append("cross_reference_completed")
    await _emit_progress(state, "cross_reference_completed", 70)
    return state


def _prioritize_strings(strings_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """I4: Sort strings by relevance - IOCs, C2 indicators, and suspicious patterns first."""
    def relevance_score(s: Dict[str, Any]) -> int:
        val = s.get("value", "")
        score = 0
        # ---- C2 / protocol-specific boosts ----
        # Google Sheets / Docs / Drive API (C2 over cloud services)
        if re.search(r'googleapis\.com|sheets\.google|docs\.google|drive\.google', val, re.IGNORECASE):
            score += 110
        # OAuth2 / JWT / auth tokens
        if re.search(r'oauth|bearer|refresh.?token|client.?secret|client.?id|jwt|authorization', val, re.IGNORECASE):
            score += 105
        # Spreadsheet cell references (A1, V1, B2 etc.) used in C2 polling
        if re.search(r'\b[A-Z][1-9]\b|values/|!A1|!V1', val):
            score += 100
        # Command syntax delimiters and patterns
        if re.search(r'-\d+-|C-C|C-U|C-D|S-\d|split.*-|strchr.*-', val, re.IGNORECASE):
            score += 100
        # Base64 / encoding patterns
        if re.search(r'base64|b64|url.?safe|ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef|\+/=', val, re.IGNORECASE):
            score += 95
        # Sleep / timer / jitter patterns
        if re.search(r'sleep|usleep|nanosleep|timer|interval|jitter|poll|idle', val, re.IGNORECASE):
            score += 90
        # ---- General malware indicators ----
        # High priority: file paths in /proc, /dev, /bin, /etc
        if re.search(r'/proc/|/dev/|/bin/|/etc/|/tmp/|/var/', val):
            score += 100
        # High priority: IP addresses
        if re.search(r'\d+\.\d+\.\d+\.\d+', val):
            score += 90
        # High priority: URLs/domains
        if re.search(r'https?://|\.com|\.net|\.org|\.io', val):
            score += 80
        # Medium priority: crypto-related
        if re.search(r'crypt|aes|rsa|md5|sha|encrypt|decrypt', val, re.IGNORECASE):
            score += 70
        # Medium priority: network-related
        if re.search(r'socket|connect|bind|listen|recv|send|http', val, re.IGNORECASE):
            score += 60
        # Medium priority: interesting API calls
        if re.search(r'exec|system|popen|fork|clone|mmap', val, re.IGNORECASE):
            score += 50
        # Medium priority: file operations
        if re.search(r'fopen|fwrite|fread|unlink|rename|chmod', val, re.IGNORECASE):
            score += 45
        # Low priority: section names
        if val.startswith('.') and len(val) < 10:
            score -= 50
        # Penalty: very short strings (likely noise)
        if len(val) < 4:
            score -= 30
        return score

    return sorted(strings_list, key=relevance_score, reverse=True)


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
                    f"{it_summary.get('total_instructions', 0)} instructions, "
                    f"{it_summary.get('unique_instructions', 0)} unique"
                )
                freq = it_summary.get("mnemonic_frequency", {})
                if isinstance(freq, dict) and freq:
                    top = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:10]
                    parts.append(f"- Top Mnemonics: {', '.join(f'{m}:{c}' for m, c in top)}")
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


def _safe_sequence(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return []


def _summarize_qiling_network(network: Dict[str, Any]) -> str:
    indicators = network.get("indicators", {}) if isinstance(network, dict) else {}
    c2 = _safe_sequence(indicators.get("c2_candidates", [])) if isinstance(indicators, dict) else []
    dns_domains = _safe_sequence(indicators.get("dns_domains", [])) if isinstance(indicators, dict) else []
    protocols = _safe_sequence(indicators.get("protocols_used", [])) if isinstance(indicators, dict) else []
    return (
        "Qiling Network: "
        f"connections={len(_safe_sequence(network.get('connections', [])))}, "
        f"dns_queries={len(_safe_sequence(network.get('dns_queries', [])))}, "
        f"c2_candidates={c2[:10]}, "
        f"dns_domains={dns_domains[:10]}, "
        f"protocols={protocols[:10]}"
    )


def _summarize_qiling_evasion(evasion: Dict[str, Any]) -> str:
    summary = evasion.get("summary", {}) if isinstance(evasion, dict) else {}
    techniques = _safe_sequence(evasion.get("techniques", [])) if isinstance(evasion, dict) else []
    sample = [
        f"{t.get('method', 'unknown')}:{t.get('mitre_id', 'N/A')}"
        for t in techniques[:10]
        if isinstance(t, dict)
    ]
    return (
        "Qiling Evasion: "
        f"total={summary.get('total_techniques', len(techniques)) if isinstance(summary, dict) else len(techniques)}, "
        f"risk={summary.get('risk_level', 'low') if isinstance(summary, dict) else 'low'}, "
        f"sample={sample}"
    )


def _summarize_qiling_api_calls(api_calls: Dict[str, Any]) -> str:
    calls = _safe_sequence(api_calls.get("api_calls", [])) if isinstance(api_calls, dict) else []
    summary = api_calls.get("summary", {}) if isinstance(api_calls, dict) else {}
    modules = _safe_sequence(summary.get("modules_used", [])) if isinstance(summary, dict) else []
    suspicious = _safe_sequence(summary.get("suspicious_apis", [])) if isinstance(summary, dict) else []
    suspicious_names = [
        s.get("name", "unknown")
        for s in suspicious[:10]
        if isinstance(s, dict)
    ]
    return (
        "Qiling API Calls: "
        f"total={summary.get('total_calls', len(calls)) if isinstance(summary, dict) else len(calls)}, "
        f"modules={modules[:10]}, "
        f"suspicious={suspicious_names}"
    )


def _summarize_qiling_instruction_trace(instruction_trace: Dict[str, Any]) -> str:
    """Summarize Qiling instruction trace (Capstone disassembly) for LLM context."""
    if not isinstance(instruction_trace, dict):
        return ""
    summary = instruction_trace.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    total = summary.get("total_instructions", 0)
    unique = summary.get("unique_instructions", 0)

    # Top mnemonics
    freq = summary.get("mnemonic_frequency", {})
    top_mnemonics = []
    if isinstance(freq, dict):
        sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:15]
        top_mnemonics = [f"{m}:{c}" for m, c in sorted_freq]

    # OEP candidates from memory analysis integration
    oep_candidates = instruction_trace.get("oep_candidates", [])
    oep_info = ""
    if isinstance(oep_candidates, list) and oep_candidates:
        oep_entries = []
        for oep in oep_candidates[:5]:
            if isinstance(oep, dict):
                oep_entries.append(
                    f"addr={oep.get('address', '?')}"
                    f"(confidence={oep.get('confidence', '?')},"
                    f"reason={oep.get('reason', '?')})"
                )
        if oep_entries:
            oep_info = f", oep_candidates=[{'; '.join(oep_entries)}]"

    # Instruction regions / segments
    regions = instruction_trace.get("regions", [])
    region_info = ""
    if isinstance(regions, list) and regions:
        region_summaries = []
        for r in regions[:5]:
            if isinstance(r, dict):
                region_summaries.append(
                    f"{r.get('name', '?')}({r.get('instruction_count', 0)} insns)"
                )
        if region_summaries:
            region_info = f", regions=[{', '.join(region_summaries)}]"

    # Sample instructions (first few + last few for entry/exit patterns)
    instructions = instruction_trace.get("instructions", [])
    sample_info = ""
    if isinstance(instructions, list) and instructions:
        sample_lines = []
        for insn in instructions[:10]:
            if isinstance(insn, dict):
                sample_lines.append(
                    f"  {insn.get('address', '?')}: {insn.get('mnemonic', '?')} {insn.get('operands', '')}"
                )
        if len(instructions) > 20:
            sample_lines.append(f"  ... ({len(instructions) - 20} more instructions) ...")
            for insn in instructions[-10:]:
                if isinstance(insn, dict):
                    sample_lines.append(
                        f"  {insn.get('address', '?')}: {insn.get('mnemonic', '?')} {insn.get('operands', '')}"
                    )
        if sample_lines:
            sample_info = "\n" + "\n".join(sample_lines)

    return (
        f"Qiling Instruction Trace: total={total}, unique={unique}, "
        f"top_mnemonics=[{', '.join(top_mnemonics)}]"
        f"{oep_info}{region_info}"
        f"{sample_info}"
    )


async def synthesize(state: AgentState) -> AgentState:
    await _emit_progress(state, "synthesizing_report", 85)
    user_query = state.get("user_query", "")
    results = state.get("analysis_results", {})

    # B4 + I5 FIX: Build enhanced context for the LLM
    context_parts = []
    binary = results.get("binary", {})
    if binary.get("ok"):
        context_parts.append(f"Architecture: {binary.get('architecture')}, Image base: {binary.get('image_base')}")
        context_parts.append(f"Segments: {', '.join(binary.get('segments', []))}")
        # Include entry point info
        if binary.get("entry_points"):
            context_parts.append(f"Entry points: {', '.join(binary.get('entry_points', []))}")
        if binary.get("imports"):
            context_parts.append(f"Ghidra Imports: {', '.join(binary.get('imports', []))}")
        if binary.get("exports"):
            context_parts.append(f"Ghidra Exports: {', '.join(binary.get('exports', []))}")

    # Rank functions by composite score (xrefs + size), include top 100.
    funcs = results.get("functions", {})
    if funcs.get("ok") and funcs.get("functions"):
        sorted_funcs = sorted(funcs["functions"], key=_function_priority_key, reverse=True)
        top_funcs = sorted_funcs[:100]
        func_descriptions = [
            f"{f.get('name')}(score:{f.get('priority_score', 0)},xrefs:{f.get('xrefs', 0)},size:{f.get('size', 0)})"
            for f in top_funcs
        ]
        context_parts.append(
            f"Top functions by composite priority ({len(funcs['functions'])} total): {', '.join(func_descriptions)}"
        )

    # I4 FIX: Sort strings by relevance (IOCs first), not alphabetically
    strings_data = results.get("strings", {})
    if strings_data.get("ok") and strings_data.get("strings"):
        sorted_strings = _prioritize_strings(strings_data["strings"])
        str_vals = [s.get("value") for s in sorted_strings[:LLM_STRING_LIMIT]]
        context_parts.append(f"Strings ({len(strings_data['strings'])} total): {', '.join(str_vals)}")

    # Include byte-signature findings collected in discovery.
    byte_sigs = results.get("byte_signatures", {})
    if byte_sigs.get("ok"):
        sig_hits = [s for s in byte_sigs.get("signatures", []) if s.get("count", 0) > 0]
        if sig_hits:
            context_parts.append("\n=== BYTE SIGNATURE HITS ===")
            for sig in sig_hits:
                context_parts.append(
                    f"{sig.get('id')} matched {sig.get('count')} time(s) at {', '.join(sig.get('addresses', [])[:5])}"
                )

    # Include extracted IOCs and verdict scoring explicitly.
    iocs = extract_iocs_from_state(state)
    verdict, _, indicators, score = calculate_verdict(iocs, state)
    context_parts.append(f"\nIOC Assessment: verdict={verdict}, score={score}, indicators={indicators}")
    if not iocs.is_empty():
        context_parts.append("\n=== EXTRACTED IOCS ===")
        context_parts.append(format_iocs_for_report(iocs))

    # B5 + I2 + I3 FIX: Include decompilation_cache contents (the actual C code!)
    # Give top-priority functions a larger character budget so the LLM can see
    # deep logic like command-parsing loops, C2 protocol handlers, etc.
    decomp_cache = state.get("decompilation_cache", {})
    if decomp_cache:
        context_parts.append(f"\n=== DECOMPILED CODE ({len(decomp_cache)} functions) ===")
        context_parts.append("YOU MUST ANALYZE EACH FUNCTION BELOW IN DETAIL:")
        for i, (func_name, c_code) in enumerate(list(decomp_cache.items())[:LLM_GHIDRA_DECOMP_LIMIT], 1):
            char_limit = LLM_DECOMP_SNIPPET_CHARS_HIGH if i <= LLM_HIGH_PRIORITY_COUNT else LLM_DECOMP_SNIPPET_CHARS
            context_parts.append(f"\n--- Function {i}: {func_name} ---")
            context_parts.append(_smart_truncate(c_code, limit=char_limit))

        if len(decomp_cache) > LLM_GHIDRA_DECOMP_LIMIT:
            context_parts.append(
                f"\n... and {len(decomp_cache) - LLM_GHIDRA_DECOMP_LIMIT} more decompiled functions in cache"
            )

    # Include focused analysis result if available
    focus = results.get("focus", {})
    if focus.get("ok"):
        if focus.get("c"):
            focused_code = focus['c'][:4000]
            if len(focus['c']) > 4000:
                focused_code += "\n/* ... [truncated at 4000 chars] ... */"
            context_parts.append(f"\n=== FOCUSED DECOMPILE ===\n{focused_code}")
        elif focus.get("instructions"):
            instr_str = "\n".join(
                f"  {i.get('address')}: {i.get('mnemonic')} {i.get('operands', '')}"
                for i in focus["instructions"][:40]
            )
            context_parts.append(f"\n=== FOCUSED DISASSEMBLY ===\n{instr_str}")

    xrefs = results.get("xrefs", {})
    if xrefs.get("ok"):
        context_parts.append(f"\nXRefs to: {xrefs.get('to', [])}, from: {xrefs.get('from', [])}")

    # Include call-graph summary + detected attack chains for data-driven flow analysis.
    call_graph = results.get("call_graph", {})
    call_graph_analysis = results.get("call_graph_analysis", {})
    if call_graph.get("ok"):
        context_parts.append(
            f"\nGhidra Call Graph: nodes={len(call_graph.get('nodes', []))}, edges={len(call_graph.get('edges', []))}"
        )
    if call_graph_analysis.get("ok"):
        context_parts.append("\n=== GHIDRA ATTACK CHAINS ===")
        entries = call_graph_analysis.get("entries", [])
        if entries:
            context_parts.append(f"Entry functions: {', '.join(entries)}")
        for chain in call_graph_analysis.get("chains", [])[:20]:
            path = " -> ".join(chain.get("path", []))
            context_parts.append(f"[{chain.get('category', 'Unknown')}] {path}")
        cycles = call_graph_analysis.get("cycles", [])
        if cycles:
            cycle_preview = [" -> ".join(c) for c in cycles[:5]]
            context_parts.append(f"Detected recursive/cyclic paths: {', '.join(cycle_preview)}")

    # Include Radare2 results if available
    r2_results = state.get("r2_analysis_results", {})
    r2_decomp = state.get("r2_decompilation_cache", {})
    if r2_results:
        context_parts.append("\n=== RADARE2 ANALYSIS ===")
        r2_binary = r2_results.get("binary", {})
        if r2_binary.get("ok"):
            context_parts.append(f"R2 Binary: arch={r2_binary.get('architecture')}, bits={r2_binary.get('bits')}, os={r2_binary.get('os')}")
            if r2_binary.get("imports"):
                context_parts.append(f"R2 Imports: {', '.join(r2_binary['imports'])}")
            if r2_binary.get("exports"):
                context_parts.append(f"R2 Exports: {', '.join(r2_binary['exports'])}")
        r2_funcs = r2_results.get("functions", {})
        if r2_funcs.get("ok") and r2_funcs.get("functions"):
            r2_sorted = sorted(r2_funcs["functions"], key=_function_priority_key, reverse=True)
            r2_desc = [
                f"{f.get('name')}(score:{f.get('priority_score', 0)},xrefs:{f.get('xrefs', 0)},size:{f.get('size', 0)})"
                for f in r2_sorted[:40]
            ]
            context_parts.append(f"R2 Functions by priority ({len(r2_funcs['functions'])} total): {', '.join(r2_desc)}")
        # Include R2 strings (may find different strings than Ghidra)
        r2_strings = r2_results.get("strings", {})
        if r2_strings.get("ok") and r2_strings.get("strings"):
            r2_sorted_strings = _prioritize_strings(r2_strings["strings"])
            r2_str_vals = [s.get("value") for s in r2_sorted_strings[:LLM_STRING_LIMIT]]
            context_parts.append(f"R2 Strings ({len(r2_strings['strings'])} total): {', '.join(r2_str_vals)}")
        r2_call_graph = r2_results.get("call_graph", {})
        if r2_call_graph.get("ok"):
            context_parts.append(
                f"R2 Call Graph: nodes={len(r2_call_graph.get('nodes', []))}, edges={len(r2_call_graph.get('edges', []))}"
            )
        r2_call_graph_analysis = r2_results.get("call_graph_analysis", {})
        if r2_call_graph_analysis.get("ok"):
            context_parts.append("\n=== R2 ATTACK CHAINS ===")
            for chain in r2_call_graph_analysis.get("chains", [])[:20]:
                path = " -> ".join(chain.get("path", []))
                context_parts.append(f"[{chain.get('category', 'Unknown')}] {path}")
        r2_syscalls = r2_results.get("syscalls", {})
        if r2_syscalls.get("ok") and r2_syscalls.get("syscalls"):
            sys_desc = [f"{s.get('name')}#{s.get('number')}" for s in r2_syscalls.get("syscalls", [])[:40]]
            context_parts.append(f"R2 Syscalls ({len(r2_syscalls.get('syscalls', []))} total): {', '.join(sys_desc)}")
    if r2_decomp:
        context_parts.append(f"\n=== R2 DECOMPILED CODE ({len(r2_decomp)} functions) ===")
        for i, (func_name, c_code) in enumerate(list(r2_decomp.items())[:LLM_R2_DECOMP_LIMIT], 1):
            char_limit = LLM_DECOMP_SNIPPET_CHARS_HIGH if i <= LLM_HIGH_PRIORITY_COUNT else LLM_DECOMP_SNIPPET_CHARS
            context_parts.append(f"\n--- R2 Function: {func_name} ---")
            context_parts.append(_smart_truncate(c_code, limit=char_limit))

    # Include Qiling dynamic analysis when available.
    qiling_results = state.get("qiling_analysis_results", {})
    if qiling_results:
        context_parts.append("\n=== QILING DYNAMIC ANALYSIS ===")
        execution = qiling_results.get("execution_trace", {})
        if isinstance(execution, dict) and execution:
            context_parts.append(
                "Execution Trace: "
                f"success={execution.get('success')}, "
                f"os={execution.get('os', 'unknown')}, "
                f"arch={execution.get('arch', 'unknown')}, "
                f"instructions={execution.get('instructions_executed', 0)}, "
                f"duration_ms={execution.get('duration_ms', 0)}, "
                f"exit_reason={execution.get('exit_reason', 'unknown')}"
            )
        syscalls = qiling_results.get("syscalls", {})
        if isinstance(syscalls, dict) and syscalls:
            summary = syscalls.get("summary", {})
            if isinstance(summary, dict):
                context_parts.append(
                    "Qiling Syscalls: "
                    f"total={summary.get('total_calls', 0)}, "
                    f"categories={summary.get('categories', {})}, "
                    f"suspicious={summary.get('suspicious_calls', [])[:20]}"
                )
        memory_events = qiling_results.get("memory_events", {})
        if isinstance(memory_events, dict) and memory_events:
            indicators = memory_events.get("indicators", {})
            context_parts.append(
                "Qiling Memory Indicators: "
                f"{indicators if isinstance(indicators, dict) else {}}"
            )
        network = qiling_results.get("network_activity", {})
        if isinstance(network, dict) and network:
            context_parts.append(_summarize_qiling_network(network))
        evasion = qiling_results.get("evasion_techniques", {})
        if isinstance(evasion, dict) and evasion:
            context_parts.append(_summarize_qiling_evasion(evasion))
        api_calls = qiling_results.get("api_calls", {})
        if isinstance(api_calls, dict) and api_calls:
            context_parts.append(_summarize_qiling_api_calls(api_calls))
        instruction_trace = qiling_results.get("instruction_trace", {})
        if isinstance(instruction_trace, dict) and instruction_trace:
            context_parts.append(_summarize_qiling_instruction_trace(instruction_trace))
        if qiling_results.get("errors"):
            context_parts.append(f"Qiling Errors: {qiling_results.get('errors')}")

    context = "\n".join(context_parts) if context_parts else "No analysis data available."

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

    try:
        lf_meta = get_trace_metadata(generation_name="synthesize")
        summary = await call_llm(prompt, metadata=lf_meta or None)
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
    state["reasoning_trace"].append("synthesized")
    await _emit_progress(state, "analysis_completed", 100)
    return state


async def human_review(state: AgentState) -> AgentState:
    state["status"] = "awaiting_review"
    return state


async def action_execution(state: AgentState) -> AgentState:
    if not state.get("write_mode_enabled"):
        state["status"] = "write_actions_skipped"
        state["reasoning_trace"].append("write_actions_skipped")
        return state
    for action in state.get("pending_actions", []):
        try:
            if action.get("type") == "rename_symbol":
                await rename_symbol.ainvoke(
                    {
                        "session_id": state["session_id"],
                        "program_hash": state["program_hash"],
                        "binary_path": state.get("binary_path"),
                        "address": action["address"],
                        "new_name": action["new_name"],
                    }
                )
            elif action.get("type") == "add_comment":
                await add_comment.ainvoke(
                    {
                        "session_id": state["session_id"],
                        "program_hash": state["program_hash"],
                        "binary_path": state.get("binary_path"),
                        "address": action["address"],
                        "comment": action["comment"],
                    }
                )
        except Exception as exc:
            logger.error("action_execution_failed", action_type=action.get("type"), error=str(exc))
    state["pending_actions"] = []
    state["status"] = "write_actions_completed"
    state["reasoning_trace"].append("write_actions_done")
    return state


def _needs_discovery(state: AgentState) -> str:
    results = state["analysis_results"]
    if results.get("binary") or results.get("functions"):
        return "focus_analysis"
    return "discovery"


def _discovery_next(state: AgentState) -> str:
    if state.get("current_function") or state.get("current_address"):
        return "focus_analysis"
    return "synthesize"


def _focus_next(state: AgentState) -> str:
    if state.get("current_address"):
        return "cross_reference"
    if state.get("write_mode_enabled") and state.get("pending_actions"):
        return "human_review"
    return "synthesize"


def _cross_next(state: AgentState) -> str:
    # Always proceed to synthesize after cross-reference to avoid infinite loops.
    # (focus_analysis and cross_reference would loop if current_function is set)
    return "synthesize"


def _review_next(state: AgentState) -> str:
    if state.get("pending_actions") and state.get("review_approved"):
        return "action_execution"
    return "synthesize"


def build_graph() -> StateGraph:
    graph = StateGraph(AgentState)
    graph.add_node("parse_intent", parse_intent)
    graph.add_node("initialize_ghidra", initialize_ghidra)
    graph.add_node("discovery", discovery)
    graph.add_node("focus_analysis", focus_analysis)
    graph.add_node("cross_reference", cross_reference)
    graph.add_node("synthesize", synthesize)
    graph.add_node("human_review", human_review)
    graph.add_node("action_execution", action_execution)

    graph.set_entry_point("parse_intent")
    graph.add_edge("parse_intent", "initialize_ghidra")
    graph.add_conditional_edges("initialize_ghidra", _needs_discovery)
    graph.add_conditional_edges("discovery", _discovery_next)
    graph.add_conditional_edges("focus_analysis", _focus_next)
    graph.add_conditional_edges("cross_reference", _cross_next)
    graph.add_conditional_edges("human_review", _review_next)
    graph.add_edge("action_execution", "synthesize")
    graph.add_edge("synthesize", END)
    return graph


graph = build_graph().compile()
