import json
from typing import Dict
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
    import re
    query = state.get("user_query", "")
    intent = "reconnaissance"
    if any(term in query.lower() for term in ["vuln", "overflow", "format", "strcpy", "sprintf"]):
        intent = "vulnerability"
    elif any(term in query.lower() for term in ["malware", "packer", "obfus", "api"]):
        intent = "malware"
    elif any(term in query.lower() for term in ["protocol", "message", "packet"]):
        intent = "protocol"
    state["intent"] = intent

    # Extract function names (FUN_xxxxx or known names) from the query
    func_match = re.search(r'\b(FUN_[0-9a-fA-F]+|main|entry|_start)\b', query)
    if func_match:
        state["current_function"] = func_match.group(1)
        state["reasoning_trace"].append(f"target_function:{func_match.group(1)}")

    # Extract hex addresses (0x...) from the query
    addr_match = re.search(r'\b(0x[0-9a-fA-F]+)\b', query)
    if addr_match and not state.get("current_function"):
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
    if not binary_info.get("ok"):
        state["analysis_results"].setdefault("errors", []).append("binary_structure_failed")
    state["reasoning_trace"].append("discovery_completed")
    return state


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


async def synthesize(state: AgentState) -> AgentState:
    user_query = state.get("user_query", "")
    results = state.get("analysis_results", {})

    # Build a concise context for the LLM
    context_parts = []
    binary = results.get("binary", {})
    if binary.get("ok"):
        context_parts.append(f"Architecture: {binary.get('architecture')}, Image base: {binary.get('image_base')}")
        context_parts.append(f"Segments: {', '.join(binary.get('segments', []))}")

    funcs = results.get("functions", {})
    if funcs.get("ok") and funcs.get("functions"):
        func_names = [f.get("name") for f in funcs["functions"][:30]]
        context_parts.append(f"Functions ({len(funcs['functions'])} total): {', '.join(func_names)}")

    strings_data = results.get("strings", {})
    if strings_data.get("ok") and strings_data.get("strings"):
        str_vals = [s.get("value") for s in strings_data["strings"][:20]]
        context_parts.append(f"Strings ({len(strings_data['strings'])} total): {', '.join(str_vals)}")

    focus = results.get("focus", {})
    if focus.get("ok"):
        if focus.get("c"):
            context_parts.append(f"Decompiled function:\n{focus['c'][:2000]}")
        elif focus.get("instructions"):
            instr_str = "\n".join(
                f"  {i.get('address')}: {i.get('mnemonic')} {i.get('operands', '')}"
                for i in focus["instructions"][:20]
            )
            context_parts.append(f"Disassembly:\n{instr_str}")

    xrefs = results.get("xrefs", {})
    if xrefs.get("ok"):
        context_parts.append(f"XRefs to: {xrefs.get('to', [])}, from: {xrefs.get('from', [])}")

    context = "\n".join(context_parts) if context_parts else "No analysis data available."

    if user_query:
        prompt = f"""{SYSTEM_PROMPT}

Binary hash: {state.get('program_hash', 'unknown')}
Intent: {state.get('intent', 'reconnaissance')}

Analysis data:
{context}

User question: {user_query}

Provide a clear, structured answer based on the analysis data above. If the data is insufficient to fully answer, say so and suggest what additional analysis could help."""
    else:
        prompt = f"""{SYSTEM_PROMPT}

Binary hash: {state.get('program_hash', 'unknown')}

Analysis data:
{context}

Provide a brief executive summary of this binary based on the analysis data above. Include: architecture, notable functions, suspicious indicators (if any), and recommended next steps."""

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
    if state.get("current_function"):
        return "focus_analysis"
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
