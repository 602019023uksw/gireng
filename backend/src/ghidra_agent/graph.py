import json
import re
from typing import Dict, List, Any
from langgraph.graph import StateGraph, END

from ghidra_agent.llm import call_llm
from ghidra_agent.logging import logger
from ghidra_agent.prompts import SYSTEM_PROMPT
from ghidra_agent.state import AgentState
from ghidra_agent.tools import (
    ToolContext,
    analyze_binary_structure,
    list_functions,
    decompile_function,
    find_strings,
    find_xrefs,
    get_function_graph,
    disassemble_at,
    rename_symbol,
    add_comment,
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
    state["status"] = "initialized"
    state["reasoning_trace"].append("ghidra_initialized")
    return state


async def discovery(state: AgentState) -> AgentState:
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
    try:
        strings = await find_strings.ainvoke(tool_args)
    except Exception as exc:
        logger.error("discovery_strings_failed", error=str(exc))
        strings = {"ok": False, "error": str(exc)}
    
    state["analysis_results"]["binary"] = binary_info
    state["analysis_results"]["functions"] = functions
    state["analysis_results"]["strings"] = strings
    
    # B3 FIX + I1: Auto-decompile entry point and top functions on initial upload
    await _auto_decompile_key_functions(state, binary_info, functions)
    
    if not binary_info.get("ok"):
        state["analysis_results"].setdefault("errors", []).append("binary_structure_failed")
    state["reasoning_trace"].append("discovery_completed")
    return state


async def _auto_decompile_key_functions(state: AgentState, binary_info: Dict, functions: Dict) -> None:
    """B3 + I1: Auto-decompile entry point and top xref'd functions during discovery."""
    if not functions.get("ok") or not functions.get("functions"):
        return
    
    func_list = functions["functions"]
    if not func_list:
        return
    
    # Sort by xref count descending (I5 improvement)
    sorted_funcs = sorted(func_list, key=lambda f: f.get("xrefs", 0), reverse=True)
    
    # Select functions to decompile: entry point + top 3 by xrefs
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
    
    # Add top 15 most referenced functions (I1 improvement - increased from 3)
    top_funcs = [f for f in sorted_funcs[:20] if f not in funcs_to_decompile][:15]
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

    # B4 + I5 FIX: Sort functions by xref count, include top 50
    funcs = results.get("functions", {})
    if funcs.get("ok") and funcs.get("functions"):
        # Sort by xref count descending
        sorted_funcs = sorted(funcs["functions"], key=lambda f: f.get("xrefs", 0), reverse=True)
        
        # Include top 100 most referenced functions with their xrefs
        top_funcs = sorted_funcs[:100]
        func_descriptions = [f"{f.get('name')}(xrefs:{f.get('xrefs', 0)})" for f in top_funcs]
        context_parts.append(f"Top functions by references ({len(funcs['functions'])} total): {', '.join(func_descriptions)}")

    # I4 FIX: Sort strings by relevance (IOCs first), not alphabetically
    strings_data = results.get("strings", {})
    if strings_data.get("ok") and strings_data.get("strings"):
        sorted_strings = _prioritize_strings(strings_data["strings"])
        str_vals = [s.get("value") for s in sorted_strings[:75]]  # Increased from 30 to 75
        context_parts.append(f"Strings ({len(strings_data['strings'])} total): {', '.join(str_vals)}")

    # B5 + I2 + I3 FIX: Include decompilation_cache contents (the actual C code!)
    decomp_cache = state.get("decompilation_cache", {})
    if decomp_cache:
        context_parts.append(f"\n=== DECOMPILED CODE ({len(decomp_cache)} functions) ===")
        context_parts.append("YOU MUST ANALYZE EACH FUNCTION BELOW IN DETAIL:")
        for i, (func_name, c_code) in enumerate(list(decomp_cache.items())[:10], 1):
            context_parts.append(f"\n--- Function {i}: {func_name} ---")
            context_parts.append(c_code[:5000])  # First 5000 chars per function
        
        if len(decomp_cache) > 10:
            context_parts.append(f"\n... and {len(decomp_cache) - 5} more decompiled functions in cache")

    # Include focused analysis result if available
    focus = results.get("focus", {})
    if focus.get("ok"):
        if focus.get("c"):
            context_parts.append(f"\n=== FOCUSED DECOMPILE ===\n{focus['c'][:3000]}")
        elif focus.get("instructions"):
            instr_str = "\n".join(
                f"  {i.get('address')}: {i.get('mnemonic')} {i.get('operands', '')}"
                for i in focus["instructions"][:20]
            )
            context_parts.append(f"\n=== FOCUSED DISASSEMBLY ===\n{instr_str}")

    xrefs = results.get("xrefs", {})
    if xrefs.get("ok"):
        context_parts.append(f"\nXRefs to: {xrefs.get('to', [])}, from: {xrefs.get('from', [])}")

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
        summary = f"Analysis completed. {len(results.get('functions', {}).get('functions', []))} functions found. Use /query to ask specific questions."

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
