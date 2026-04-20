"""Unified LLM context builder for analysis data.

Consolidates the ~200 lines of duplicated context-building logic between
`graph.py` (synthesize node) and `api/main.py` (/query endpoint).
"""

import re
from typing import Any, Dict, List

from ghidra_agent.ioc_extractor import (
    calculate_verdict,
    classify_malware_type,
    extract_iocs_from_state,
    format_iocs_for_report,
)
from ghidra_agent.ranking_utils import _function_priority_key

LLM_STRING_LIMIT = 100
LLM_GHIDRA_DECOMP_LIMIT = 20
LLM_R2_DECOMP_LIMIT = 20
LLM_DECOMP_SNIPPET_CHARS = 2000
LLM_DECOMP_SNIPPET_CHARS_HIGH = 10000
LLM_HIGH_PRIORITY_COUNT = 5


def _safe_sequence(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return []


def _smart_truncate(code: str, limit: int = LLM_DECOMP_SNIPPET_CHARS) -> str:
    """Truncate decompiled code keeping 100% head."""
    if len(code) <= limit:
        return code
    marker = "\n/* ... [truncated at %d chars] ... */" % limit
    return code[:limit] + marker


def _prioritize_strings(strings_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sort strings by relevance - IOCs, C2 indicators, and suspicious patterns first."""
    def relevance_score(s: Dict[str, Any]) -> int:
        val = s.get("value", "")
        score = 0
        xrefs = s.get("xrefs", [])
        if isinstance(xrefs, list) and xrefs:
            score += min(len(xrefs), 10) * 15
        if re.search(r'googleapis\.com|sheets\.google|docs\.google|drive\.google', val, re.IGNORECASE):
            score += 110
        if re.search(r'oauth|bearer|refresh.?token|client.?secret|client.?id|jwt|authorization', val, re.IGNORECASE):
            score += 105
        if re.search(r'\b[A-Z][1-9]\b|values/|!A1|!V1', val):
            score += 100
        if re.search(r'-\d+-|C-C|C-U|C-D|S-\d|split.*-|strchr.*-', val, re.IGNORECASE):
            score += 100
        if re.search(r'base64|b64|url.?safe|ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef|\+/=', val, re.IGNORECASE):
            score += 90
        if re.search(r'powershell|cmd\.exe|/c\s|/k\s|wscript|cscript|mshta|regsvr32|rundll32', val, re.IGNORECASE):
            score += 85
        if re.search(r'crypt|aes|rsa|des|blowfish|chacha|rc4|key|encrypt|decrypt', val, re.IGNORECASE):
            score += 80
        if re.search(r'http|https|tcp|udp|socket|connect|recv|send|ws://|wss://', val, re.IGNORECASE):
            score += 70
        if re.search(r'download|upload|url|curl|wget|fetch|request|post|get\s+http', val, re.IGNORECASE):
            score += 65
        if re.search(r'\\[a-zA-Z]:\\|appdata|programdata|temp\\|tmp\\|startup', val, re.IGNORECASE):
            score += 60
        if re.search(r'registry|regedit|reg\s+add|run\\|shell\\|userinit', val, re.IGNORECASE):
            score += 55
        if re.search(r'vmware|virtualbox|vbox|xen|qemu|hyper-v|sandbox|debugger', val, re.IGNORECASE):
            score += 50
        if re.search(r'kernel32|ntdll|advapi32|user32|ws2_32|wininet|urlmon|crypt32', val, re.IGNORECASE):
            score += 40
        if re.search(r'MZ|PE|ELF|\.exe|\.dll|\.sys|\.scr|\.bat|\.cmd|\.ps1', val, re.IGNORECASE):
            score += 30
        if len(val) >= 50:
            score += 10
        return score

    return sorted(strings_list, key=relevance_score, reverse=True)


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
    dynamic_imports = _safe_sequence(api_calls.get("dynamic_imports", [])) if isinstance(api_calls, dict) else []
    dynamic_sample = [
        item.get("name", "unknown")
        for item in dynamic_imports[:10]
        if isinstance(item, dict)
    ]
    suspicious_names = [
        s.get("name", "unknown")
        for s in suspicious[:10]
        if isinstance(s, dict)
    ]
    return (
        "Qiling API Calls: "
        f"total={summary.get('total_calls', len(calls)) if isinstance(summary, dict) else len(calls)}, "
        f"modules={modules[:10]}, "
        f"suspicious={suspicious_names}, "
        f"dynamic_imports={dynamic_sample}"
    )


def _summarize_qiling_instruction_trace(instruction_trace: Dict[str, Any]) -> str:
    if not isinstance(instruction_trace, dict):
        return ""
    summary = instruction_trace.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}
    total = summary.get("total_executed", 0)
    unique = summary.get("unique_mnemonics", 0)
    freq = summary.get("top_mnemonics", [])
    top_mnemonics = []
    for item in freq[:10]:
        if isinstance(item, dict):
            top_mnemonics.append(f"{item.get('mnemonic', '?')}:{item.get('count', 0)}")
        elif isinstance(item, tuple) and len(item) == 2:
            top_mnemonics.append(f"{item[0]}:{item[1]}")
    return (
        "Qiling Instructions: "
        f"total={total}, unique={unique}, "
        f"range={summary.get('address_range', 'unknown')}, "
        f"top=[{', '.join(top_mnemonics)}]"
    )


def build_light_context(state: Dict[str, Any]) -> str:
    """Build a minimal high-level context for the planner agent.

    Includes only binary metadata, top functions/strings, IOCs, attack chains,
    and Qiling summaries — no decompiled code to keep the prompt small.
    """
    context_parts: List[str] = []
    results = state.get("analysis_results", {})
    binary = results.get("binary", {})

    if binary.get("ok"):
        context_parts.append(f"Architecture: {binary.get('architecture')}, Image base: {binary.get('image_base')}")
        if binary.get("entry_points"):
            context_parts.append(f"Entry points: {', '.join(binary.get('entry_points', []))}")
        if binary.get("imports"):
            context_parts.append(f"Imports ({len(binary['imports'])}): {', '.join(str(i) for i in binary['imports'][:30])}")
        if binary.get("exports"):
            context_parts.append(f"Exports ({len(binary['exports'])}): {', '.join(str(e) for e in binary['exports'][:30])}")

    funcs = results.get("functions", {})
    if funcs.get("ok") and funcs.get("functions"):
        sorted_funcs = sorted(funcs["functions"], key=_function_priority_key, reverse=True)
        top_funcs = sorted_funcs[:20]
        func_descriptions = [
            f"{f.get('name')}@{f.get('address')}(score:{f.get('priority_score', 0)},xrefs:{f.get('xrefs', 0)},size:{f.get('size', 0)})"
            for f in top_funcs
        ]
        context_parts.append(
            f"Top functions ({len(funcs['functions'])} total): {', '.join(func_descriptions)}"
        )

    strings_data = results.get("strings", {})
    if strings_data.get("ok") and strings_data.get("strings"):
        sorted_strings = _prioritize_strings(strings_data["strings"])
        str_entries = []
        for s in sorted_strings[:30]:
            val = s.get("value", "")
            xrefs = s.get("xrefs", [])
            if isinstance(xrefs, list) and xrefs:
                str_entries.append(f"{val} [xrefs: {', '.join(str(x) for x in xrefs[:3])}]")
            else:
                str_entries.append(val)
        context_parts.append(f"Top strings ({len(strings_data['strings'])} total): {', '.join(str_entries)}")

    byte_sigs = results.get("byte_signatures", {})
    if byte_sigs.get("ok"):
        sig_hits = [s for s in byte_sigs.get("signatures", []) if s.get("count", 0) > 0]
        if sig_hits:
            context_parts.append("Byte signature hits:")
            for sig in sig_hits:
                context_parts.append(
                    f"  {sig.get('id')} matched {sig.get('count')} time(s) at {', '.join(sig.get('addresses', [])[:5])}"
                )

    iocs = extract_iocs_from_state(state)
    verdict, _, indicators, score = calculate_verdict(iocs, state)
    context_parts.append(f"IOC Assessment: verdict={verdict}, score={score}, indicators={indicators}")
    if not iocs.is_empty():
        context_parts.append(format_iocs_for_report(iocs))

    mtype, mconf, mcaps = classify_malware_type(state)
    if mtype != "Unknown":
        context_parts.append(
            f"Heuristic Malware Type: {mtype} (confidence: {mconf}, capabilities: {', '.join(mcaps)})"
        )

    call_graph_analysis = results.get("call_graph_analysis", {})
    if call_graph_analysis.get("ok"):
        context_parts.append("Attack chains:")
        entries = call_graph_analysis.get("entries", [])
        if entries:
            context_parts.append(f"  Entries: {', '.join(entries)}")
        for chain in call_graph_analysis.get("chains", [])[:10]:
            path = " -> ".join(chain.get("path", []))
            context_parts.append(f"  [{chain.get('category', 'Unknown')}] {path}")

    r2_results = state.get("r2_analysis_results", {})
    if r2_results:
        r2_binary = r2_results.get("binary", {})
        if r2_binary.get("ok"):
            context_parts.append(
                f"R2 Binary: arch={r2_binary.get('architecture')}, bits={r2_binary.get('bits')}, os={r2_binary.get('os')}"
            )
        r2_funcs = r2_results.get("functions", {})
        if r2_funcs.get("ok") and r2_funcs.get("functions"):
            r2_sorted = sorted(r2_funcs["functions"], key=_function_priority_key, reverse=True)
            r2_desc = [
                f"{f.get('name')}@{f.get('address')}(score:{f.get('priority_score', 0)})"
                for f in r2_sorted[:15]
            ]
            context_parts.append(f"R2 Top functions ({len(r2_funcs['functions'])} total): {', '.join(r2_desc)}")
        r2_call_graph_analysis = r2_results.get("call_graph_analysis", {})
        if r2_call_graph_analysis.get("ok"):
            context_parts.append("R2 Attack chains:")
            for chain in r2_call_graph_analysis.get("chains", [])[:10]:
                path = " -> ".join(chain.get("path", []))
                context_parts.append(f"  [{chain.get('category', 'Unknown')}] {path}")

    qiling_results = state.get("qiling_analysis_results", {})
    if qiling_results:
        context_parts.append("Qiling Dynamic Summary:")
        execution = qiling_results.get("execution_trace", {})
        if isinstance(execution, dict) and execution:
            context_parts.append(
                f"  Execution: success={execution.get('success')}, "
                f"instructions={execution.get('instructions_executed', 0)}, "
                f"exit={execution.get('exit_reason', 'unknown')}"
            )
        syscalls = qiling_results.get("syscalls", {})
        if isinstance(syscalls, dict) and syscalls:
            summary = syscalls.get("summary", {})
            if isinstance(summary, dict):
                context_parts.append(
                    f"  Syscalls: total={summary.get('total_calls', 0)}, "
                    f"categories={summary.get('categories', {})}"
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

    return "\n".join(context_parts) if context_parts else "No analysis data available."


def build_analysis_context(
    state: Dict[str, Any],
    *,
    include_focus: bool = False,
    include_xrefs: bool = False,
    string_limit: int = LLM_STRING_LIMIT,
    func_limit: int = 100,
    ghidra_decomp_limit: int = LLM_GHIDRA_DECOMP_LIMIT,
    r2_decomp_limit: int = LLM_R2_DECOMP_LIMIT,
    decomp_chars: int = LLM_DECOMP_SNIPPET_CHARS,
    decomp_chars_high: int = LLM_DECOMP_SNIPPET_CHARS_HIGH,
    high_priority_count: int = LLM_HIGH_PRIORITY_COUNT,
    truncate_decomp: bool = True,
    include_investigation: bool = True,
) -> str:
    """Build a unified LLM context string from analysis state.

    Parameters mirror the limits used by both the synthesize node and the
    /query endpoint so each caller can tune the context size independently.
    """
    context_parts: List[str] = []
    results = state.get("analysis_results", {})
    binary = results.get("binary", {})

    if binary.get("ok"):
        context_parts.append(f"Architecture: {binary.get('architecture')}, Image base: {binary.get('image_base')}")
        if binary.get("entry_points"):
            context_parts.append(f"Entry points: {', '.join(binary.get('entry_points', []))}")
        if binary.get("imports"):
            context_parts.append(f"Ghidra Imports: {', '.join(str(i) for i in binary.get('imports', []))}")
        if binary.get("exports"):
            context_parts.append(f"Ghidra Exports: {', '.join(str(e) for e in binary.get('exports', []))}")

    funcs = results.get("functions", {})
    if funcs.get("ok") and funcs.get("functions"):
        sorted_funcs = sorted(funcs["functions"], key=_function_priority_key, reverse=True)
        top_funcs = sorted_funcs[:func_limit]
        func_descriptions = [
            f"{f.get('name')}(score:{f.get('priority_score', 0)},xrefs:{f.get('xrefs', 0)},size:{f.get('size', 0)})"
            for f in top_funcs
        ]
        context_parts.append(
            f"Top functions by composite priority ({len(funcs['functions'])} total): {', '.join(func_descriptions)}"
        )
        # Function index (names only) so the LLM can reference any function.
        # Cap at 200 to avoid blowing up the context on large binaries.
        _MAX_FUNC_INDEX = 200
        all_func_names = [f"{f.get('name')}@{f.get('address')}" for f in sorted_funcs[:_MAX_FUNC_INDEX]]
        if all_func_names:
            suffix = f" ... ({len(sorted_funcs) - _MAX_FUNC_INDEX} more truncated)" if len(sorted_funcs) > _MAX_FUNC_INDEX else ""
            context_parts.append(f"Function index: {', '.join(all_func_names)}{suffix}")

    strings_data = results.get("strings", {})
    if strings_data.get("ok") and strings_data.get("strings"):
        sorted_strings = _prioritize_strings(strings_data["strings"])
        str_entries = []
        for s in sorted_strings[:string_limit]:
            val = s.get("value", "")
            xrefs = s.get("xrefs", [])
            if isinstance(xrefs, list) and xrefs:
                str_entries.append(f"{val} [xrefs: {', '.join(str(x) for x in xrefs[:3])}]")
            else:
                str_entries.append(val)
        context_parts.append(f"Strings ({len(strings_data['strings'])} total): {', '.join(str_entries)}")

    byte_sigs = results.get("byte_signatures", {})
    if byte_sigs.get("ok"):
        sig_hits = [s for s in byte_sigs.get("signatures", []) if s.get("count", 0) > 0]
        if sig_hits:
            context_parts.append("\n=== BYTE SIGNATURE HITS ===")
            for sig in sig_hits:
                context_parts.append(
                    f"{sig.get('id')} matched {sig.get('count')} time(s) at {', '.join(sig.get('addresses', [])[:5])}"
                )

    iocs = extract_iocs_from_state(state)
    verdict, _, indicators, score = calculate_verdict(iocs, state)
    context_parts.append(f"\nIOC Assessment: verdict={verdict}, score={score}, indicators={indicators}")

    mtype, mconf, mcaps = classify_malware_type(state)
    if mtype != "Unknown":
        context_parts.append(
            f"\nHeuristic Malware Type Classification: {mtype} (confidence: {mconf}, capabilities: {', '.join(mcaps)})"
        )
        context_parts.append(
            "NOTE: This is a heuristic hint. Refine or override based on your deep code analysis. "
            "You MUST output **Malware Type: <type>** in your conclusion."
        )
    else:
        context_parts.append(
            "\nHeuristic Malware Type: could not be determined automatically. "
            "Analyze the decompiled code to determine the type (RAT, Backdoor, Ransomware, etc.) "
            "and output **Malware Type: <type>** in your conclusion."
        )

    if not iocs.is_empty():
        context_parts.append("\n=== EXTRACTED IOCS ===")
        context_parts.append(format_iocs_for_report(iocs))

    decomp_cache = state.get("decompilation_cache", {})
    if decomp_cache:
        context_parts.append(f"\n=== DECOMPILED CODE ({len(decomp_cache)} functions) ===")
        if truncate_decomp:
            context_parts.append(
                "Analyze the TOP 5 functions in deepest detail. "
                "For functions 6-15, examine structure and key logic. "
                "For remaining functions, refer to the Function Index above."
            )
        decomp_items = list(decomp_cache.items())
        for i, (func_name, c_code) in enumerate(decomp_items[:ghidra_decomp_limit], 1):
            if i <= high_priority_count:
                char_limit = decomp_chars_high
            elif i <= high_priority_count + 10:
                char_limit = decomp_chars
            else:
                char_limit = decomp_chars // 2
            context_parts.append(f"\n--- Function {i}: {func_name} ---")
            snippet = _smart_truncate(c_code, limit=char_limit) if truncate_decomp else c_code[:char_limit]
            context_parts.append(snippet)
        if len(decomp_cache) > ghidra_decomp_limit:
            context_parts.append(f"\n... and {len(decomp_cache) - ghidra_decomp_limit} more decompiled functions in cache")

    if include_focus:
        focus = results.get("focus", {})
        if focus.get("ok"):
            if focus.get("c"):
                focused_code = focus["c"][:4000]
                if len(focus["c"]) > 4000:
                    focused_code += "\n/* ... [truncated at 4000 chars] ... */"
                context_parts.append(f"\n=== FOCUSED DECOMPILE ===\n{focused_code}")
            elif focus.get("instructions"):
                instr_str = "\n".join(
                    f"  {i.get('address')}: {i.get('mnemonic')} {i.get('operands', '')}"
                    for i in focus["instructions"][:40]
                )
                context_parts.append(f"\n=== FOCUSED DISASSEMBLY ===\n{instr_str}")

    if include_xrefs:
        xrefs = results.get("xrefs", {})
        if xrefs.get("ok"):
            context_parts.append(f"\nXRefs to: {xrefs.get('to', [])}, from: {xrefs.get('from', [])}")

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

    r2_results = state.get("r2_analysis_results", {})
    r2_decomp = state.get("r2_decompilation_cache", {})
    if r2_results:
        context_parts.append("\n=== RADARE2 ANALYSIS ===")
        r2_binary = r2_results.get("binary", {})
        if r2_binary.get("ok"):
            context_parts.append(
                f"R2 Binary: arch={r2_binary.get('architecture')}, bits={r2_binary.get('bits')}, os={r2_binary.get('os')}"
            )
            if r2_binary.get("imports"):
                context_parts.append(f"R2 Imports: {', '.join(str(i) for i in r2_binary['imports'])}")
            if r2_binary.get("exports"):
                context_parts.append(f"R2 Exports: {', '.join(str(e) for e in r2_binary['exports'])}")
        r2_funcs = r2_results.get("functions", {})
        if r2_funcs.get("ok") and r2_funcs.get("functions"):
            r2_sorted = sorted(r2_funcs["functions"], key=_function_priority_key, reverse=True)
            r2_desc = [
                f"{f.get('name')}(score:{f.get('priority_score', 0)},xrefs:{f.get('xrefs', 0)},size:{f.get('size', 0)})"
                for f in r2_sorted[:40]
            ]
            context_parts.append(f"R2 Functions by priority ({len(r2_funcs['functions'])} total): {', '.join(r2_desc)}")
            r2_all_names = [f"{f.get('name')}@{f.get('address')}" for f in r2_sorted[:_MAX_FUNC_INDEX]]
            if r2_all_names:
                suffix = f" ... ({len(r2_sorted) - _MAX_FUNC_INDEX} more truncated)" if len(r2_sorted) > _MAX_FUNC_INDEX else ""
                context_parts.append(f"R2 Function index: {', '.join(r2_all_names)}{suffix}")
        r2_strings = r2_results.get("strings", {})
        if r2_strings.get("ok") and r2_strings.get("strings"):
            r2_sorted_strings = _prioritize_strings(r2_strings["strings"])
            r2_str_vals = [s.get("value") for s in r2_sorted_strings[:string_limit]]
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
        r2_decomp_items = list(r2_decomp.items())
        for i, (func_name, c_code) in enumerate(r2_decomp_items[:r2_decomp_limit], 1):
            if i <= high_priority_count:
                char_limit = decomp_chars_high
            elif i <= high_priority_count + 10:
                char_limit = decomp_chars
            else:
                char_limit = decomp_chars // 2
            context_parts.append(f"\n--- R2 Function: {func_name} ---")
            snippet = _smart_truncate(c_code, limit=char_limit) if truncate_decomp else c_code[:char_limit]
            context_parts.append(snippet)

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

    if include_investigation:
        investigation = state.get("investigation_results", {})
        if investigation:
            context_parts.append("\n=== TARGETED INVESTIGATION RESULTS ===")
            for key, value in investigation.items():
                context_parts.append(f"\n--- Investigation: {key} ---")
                if isinstance(value, dict):
                    if value.get("ok"):
                        if value.get("c"):
                            snippet = _smart_truncate(value["c"], limit=decomp_chars_high)
                            context_parts.append(snippet)
                        elif value.get("instructions"):
                            instr_str = "\n".join(
                                f"  {i.get('address')}: {i.get('mnemonic')} {i.get('operands', '')}"
                                for i in value["instructions"][:60]
                            )
                            context_parts.append(instr_str)
                        elif "from" in value or "to" in value:
                            context_parts.append(f"xrefs from: {value.get('from', [])}")
                            context_parts.append(f"xrefs to: {value.get('to', [])}")
                        elif value.get("nodes"):
                            context_parts.append(
                                f"function graph nodes={len(value.get('nodes', []))}, "
                                f"edges={len(value.get('edges', []))}"
                            )
                        else:
                            context_parts.append(str(value)[:2000])
                    else:
                        context_parts.append(f"Error: {value.get('error', 'unknown error')}")
                else:
                    context_parts.append(str(value)[:2000])

    return "\n".join(context_parts) if context_parts else "No analysis data available."
