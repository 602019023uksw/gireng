import asyncio
import json
import re
from typing import Dict, List, Any
from langgraph.graph import StateGraph, END

from ghidra_agent.config import settings
from ghidra_agent.llm import call_llm
from ghidra_agent.logging import logger
from ghidra_agent.prompts import SYSTEM_PROMPT
from ghidra_agent.state import AgentState
from ghidra_agent.call_graph_analyzer import analyze_call_graph
from ghidra_agent.function_priority import apply_priority_to_result
from ghidra_agent.ioc_extractor import extract_iocs_from_state, format_iocs_for_report, calculate_verdict
from ghidra_agent.tools import (
    ToolContext,
    analyze_binary_structure,
    list_functions,
    build_call_graph,
    decompile_function,
    find_strings,
    search_bytes,
    find_xrefs,
    get_function_graph,
    disassemble_at,
    rename_symbol,
    add_comment,
)

GHIDRA_AUTO_DECOMPILE_PERCENT = 0.75  # Decompile 75% of meaningful (non-stub) functions
GHIDRA_AUTO_DECOMPILE_MIN = 10       # Floor: always decompile at least this many
GHIDRA_AUTO_DECOMPILE_MAX = 40       # Ceiling: cap decompilation to avoid runaway on large binaries
LLM_GHIDRA_DECOMP_LIMIT = 25
LLM_R2_DECOMP_LIMIT = 25
LLM_DECOMP_SNIPPET_CHARS = 4000


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


async def parse_intent(state: AgentState) -> AgentState:
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
        return state

    state["status"] = "initialized"
    state["reasoning_trace"].append("ghidra_initialized")

    # Verify R2 container if enabled
    if settings.enable_r2:
        try:
            from ghidra_agent.radare.runner import Radare2Runner
            runner = Radare2Runner()
            if await runner.verify_container():
                state["reasoning_trace"].append("r2_initialized")
            else:
                state["reasoning_trace"].append("r2_unavailable")
        except Exception as exc:
            logger.warning("r2_init_check_failed", error=str(exc))
            state["reasoning_trace"].append("r2_unavailable")

    return state


async def discovery(state: AgentState) -> AgentState:
    # Skip re-discovery on follow-up queries if results already exist
    if state.get("analysis_results", {}).get("binary", {}).get("ok"):
        logger.info("skipping_rediscovery", reason="results_already_exist")
        return state

    # Run Ghidra discovery
    await _ghidra_discovery(state)

    # Run R2 in parallel if available
    if settings.enable_r2 and "r2_initialized" in state.get("reasoning_trace", []):
        try:
            await _safe_r2_pipeline(state)
        except Exception as exc:
            logger.error("r2_parallel_failed", error=str(exc))

    # Extract and persist IOC data during pipeline (before LLM synthesis).
    _refresh_ioc_context(state)

    state["reasoning_trace"].append("discovery_completed")
    return state


async def _ghidra_discovery(state: AgentState) -> None:
    """Core Ghidra discovery: binary info, functions, strings, auto-decompile."""
    tool_args = {
        "session_id": state["session_id"],
        "program_hash": state["program_hash"],
        "binary_path": state.get("binary_path"),
    }
    try:
        binary_info = await analyze_binary_structure.ainvoke(tool_args)
    except Exception as exc:
        logger.error("discovery_binary_failed", error=str(exc))
        binary_info = {"ok": False, "error": str(exc)}
    try:
        functions = await list_functions.ainvoke(tool_args)
    except Exception as exc:
        logger.error("discovery_functions_failed", error=str(exc))
        functions = {"ok": False, "error": str(exc)}
    if functions.get("ok"):
        functions = apply_priority_to_result(
            functions,
            alpha=settings.function_priority_alpha,
            beta=settings.function_priority_beta,
        )
    try:
        strings = await find_strings.ainvoke(tool_args)
    except Exception as exc:
        logger.error("discovery_strings_failed", error=str(exc))
        strings = {"ok": False, "error": str(exc)}
    try:
        call_graph = await build_call_graph.ainvoke(tool_args)
    except Exception as exc:
        logger.error("discovery_call_graph_failed", error=str(exc))
        call_graph = {"ok": False, "error": str(exc)}

    state["analysis_results"]["binary"] = binary_info
    state["analysis_results"]["functions"] = functions
    state["analysis_results"]["strings"] = strings
    state["analysis_results"]["call_graph"] = call_graph
    state["analysis_results"]["call_graph_analysis"] = analyze_call_graph(call_graph)

    # Scan for high-signal byte patterns (shellcode-like signatures).
    await _run_byte_signature_scan(state, tool_args)

    # Auto-decompile entry point and top functions
    await _auto_decompile_key_functions(state, binary_info, functions)

    if not binary_info.get("ok"):
        state["analysis_results"].setdefault("errors", []).append("binary_structure_failed")


async def _safe_r2_pipeline(state: AgentState) -> None:
    """Run R2 pipeline safely — failures don't block Ghidra results."""
    try:
        from ghidra_agent.r2_graph import run_r2_pipeline
        await run_r2_pipeline(state)
    except Exception as exc:
        logger.error("r2_pipeline_failed", error=str(exc))
        state["reasoning_trace"].append(f"r2_error:{exc}")


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
    """B3 + I1: Auto-decompile entry point and top xref'd functions during discovery."""
    if not functions.get("ok") or not functions.get("functions"):
        return
    
    func_list = functions["functions"]
    if not func_list:
        return
    
    # Filter out trivial PLT/GOT stubs (size <= 6 bytes) — they decompile to
    # a single indirect-jump and waste decompilation slots.
    meaningful_funcs = [f for f in func_list if f.get("size", 0) > 6]

    # Prefer composite priority score (xrefs + size), with legacy fallback.
    sorted_funcs = sorted(
        meaningful_funcs,
        key=_function_priority_key,
        reverse=True,
    )

    # Percentage-based limit: decompile 75% of meaningful functions, min 10, max 25
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

    # Select functions to decompile: entry point first, then top ranked
    funcs_to_decompile = []
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
                state["current_function"] = f.get("name")
                state["current_address"] = entry_point
                break
    
    # Add top ranked functions to reach the percentage-based target.
    remaining_slots = max(0, decompile_target - len(funcs_to_decompile))
    top_funcs = [f for f in sorted_funcs if f not in funcs_to_decompile][:remaining_slots]
    funcs_to_decompile.extend(top_funcs)
    
    # Decompile selected functions
    decompiled_count = 0
    for func in funcs_to_decompile:
        func_name = func.get("name")
        func_addr = func.get("address")
        if not func_name or func_name in state.get("decompilation_cache", {}):
            continue
        
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
    return state


async def cross_reference(state: AgentState) -> AgentState:
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
    return state


def _prioritize_strings(strings_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """I4: Sort strings by relevance - IOCs and suspicious patterns first."""
    def relevance_score(s: Dict[str, Any]) -> int:
        val = s.get("value", "")
        score = 0
        # High priority: file paths in /proc, /dev, /bin, /etc
        if re.search(r'/proc/|/dev/|/bin/|/etc/|/tmp/|/var/', val):
            score += 100
        # High priority: IP addresses
        if re.search(r'\d+\.\d+\.\d+\.\d+', val):
            score += 90
        # High priority: URLs/domains
        if re.search(r'https?://|\.com|\.net|\.org|\.io', val):
            score += 80
        # High priority: crypto-related
        if re.search(r'crypt|aes|rsa|md5|sha|encrypt|decrypt', val, re.IGNORECASE):
            score += 70
        # High priority: network-related
        if re.search(r'socket|connect|bind|listen|recv|send|http', val, re.IGNORECASE):
            score += 60
        # Medium priority: interesting API calls
        if re.search(r'exec|system|popen|fork|clone|mmap', val, re.IGNORECASE):
            score += 50
        # Low priority: section names
        if val.startswith('.') and len(val) < 10:
            score -= 50
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
    from ghidra_agent.ioc_extractor import extract_iocs_from_state, calculate_verdict, format_iocs_for_report
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


async def synthesize(state: AgentState) -> AgentState:
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
        str_vals = [s.get("value") for s in sorted_strings[:75]]  # Increased from 30 to 75
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
    decomp_cache = state.get("decompilation_cache", {})
    if decomp_cache:
        context_parts.append(f"\n=== DECOMPILED CODE ({len(decomp_cache)} functions) ===")
        context_parts.append("YOU MUST ANALYZE EACH FUNCTION BELOW IN DETAIL:")
        for i, (func_name, c_code) in enumerate(list(decomp_cache.items())[:LLM_GHIDRA_DECOMP_LIMIT], 1):
            context_parts.append(f"\n--- Function {i}: {func_name} ---")
            context_parts.append(_smart_truncate(c_code))
        
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
        for func_name, c_code in list(r2_decomp.items())[:LLM_R2_DECOMP_LIMIT]:
            context_parts.append(f"\n--- R2 Function: {func_name} ---")
            context_parts.append(_smart_truncate(c_code))

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
        summary = await call_llm(prompt)
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
