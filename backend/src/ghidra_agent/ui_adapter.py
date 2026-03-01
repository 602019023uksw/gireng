import json
from typing import Any, Dict

from ghidra_agent.ioc_extractor import calculate_verdict, extract_iocs_from_state, format_iocs_for_report
from ghidra_agent.state import AgentState


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


def _analyzer_details(state: AgentState) -> Dict[str, Any]:
    findings = state.get("analysis_results", {})
    logs = state.get("reasoning_trace", [])

    # I6: Extract IOCs for the API response
    iocs = extract_iocs_from_state(state)
    iocs_text = format_iocs_for_report(iocs) if not iocs.is_empty() else "No IOCs extracted."

    # Build better static analysis
    static_parts = []
    binary = findings.get("binary", {})
    if binary.get("ok"):
        static_parts.append(f"Architecture: {binary.get('architecture', 'unknown')}")
        static_parts.append(f"Compiler: {binary.get('compiler', 'unknown')}")
        static_parts.append(f"Image Base: {binary.get('image_base', 'unknown')}")
        static_parts.append(f"Entry Points: {', '.join(binary.get('entry_points', []))}")
        static_parts.append(f"Segments: {', '.join(binary.get('segments', []))}")
        if binary.get("imports"):
            static_parts.append(f"Imports ({len(binary['imports'])}): {', '.join(binary['imports'][:30])}")
        if binary.get("exports"):
            static_parts.append(f"Exports ({len(binary['exports'])}): {', '.join(binary['exports'][:30])}")

    funcs = findings.get("functions", {})
    if funcs.get("ok") and funcs.get("functions"):
        sorted_funcs = sorted(funcs["functions"], key=_function_priority_key, reverse=True)
        static_parts.append(f"\nFunctions ({len(funcs['functions'])} total):")
        for f in sorted_funcs[:20]:
            static_parts.append(
                "  - "
                f"{f.get('name')} @ {f.get('address')} "
                f"(score: {f.get('priority_score', 0)}, xrefs: {f.get('xrefs', 0)}, size: {f.get('size', 0)})"
            )

    call_graph_analysis = findings.get("call_graph_analysis", {})
    if call_graph_analysis.get("ok"):
        static_parts.append("\nCall Graph:")
        stats = call_graph_analysis.get("stats", {})
        static_parts.append(
            f"  - Nodes: {stats.get('nodes', 0)}, Edges: {stats.get('edges', 0)}, Chains: {stats.get('chains', 0)}"
        )
        entries = call_graph_analysis.get("entries", [])
        if entries:
            static_parts.append(f"  - Entry Points: {', '.join(entries[:10])}")
        chains = call_graph_analysis.get("chains", [])
        for chain in chains[:10]:
            path = " -> ".join(chain.get("path", []))
            static_parts.append(f"  - [{chain.get('category', 'Unknown')}] {path}")

    # Build behavioral analysis
    strings_data = findings.get("strings", {})
    behavioral = []
    if strings_data.get("ok"):
        strings_vals = " ".join([s.get("value", "").lower() for s in strings_data.get("strings", [])])

        capabilities = []
        if any(x in strings_vals for x in ["socket", "connect", "recv", "send"]):
            capabilities.append("Network Communication")
        if any(x in strings_vals for x in ["exec", "system", "popen"]):
            capabilities.append("Command Execution")
        if any(x in strings_vals for x in ["encrypt", "aes", "rsa"]):
            capabilities.append("Cryptography")
        if any(x in strings_vals for x in ["registry", "startup", "cron"]):
            capabilities.append("Persistence")
        if any(x in strings_vals for x in ["debugger", "vmware", "sandbox"]):
            capabilities.append("Anti-Analysis")

        if capabilities:
            behavioral.append(f"Detected Capabilities: {', '.join(capabilities)}")

    # Determine verdict using shared function
    verdict, _, _, _ = calculate_verdict(iocs, state)

    return {
        "executiveSummary": state.get("summary", "Ghidra analysis completed."),
        "staticAnalysis": "\n".join(static_parts) if static_parts else json.dumps(findings, indent=2),
        "behavioralAnalysis": "\n".join(behavioral) if behavioral else "Headless static analysis only.",
        "iocs": iocs_text,
        "conclusion": f"Analysis verdict: {verdict}. Review findings for indicators.",
        "executionLogs": logs,
    }


def build_analyzer_response(state: AgentState, analyzer_id: str = "ghidra") -> Dict[str, Any]:
    """Build response for a specific analyzer (ghidra, radare2, or qiling)."""
    iocs = extract_iocs_from_state(state)
    verdict, _, _, _ = calculate_verdict(iocs, state)

    if analyzer_id == "qiling":
        return {
            "id": "qiling",
            "name": "Qiling Dynamic Analysis Agent",
            "source": "gireng",
            "sourceUrl": "https://github.com/danilchristianto/gireng",
            "verdict": verdict,
            "details": _qiling_analyzer_details(state),
        }

    if analyzer_id == "radare2":
        return {
            "id": "radare2",
            "name": "Radare2 Reverse Engineer Agent",
            "source": "gireng",
            "sourceUrl": "https://github.com/danilchristianto/gireng",
            "verdict": verdict,
            "details": _r2_analyzer_details(state),
        }

    return {
        "id": "ghidra",
        "name": "Ghidra Reverse Engineer Agent",
        "source": "gireng",
        "sourceUrl": "https://github.com/danilchristianto/gireng",
        "verdict": verdict,
        "details": _analyzer_details(state),
    }


def _r2_analyzer_details(state: AgentState) -> Dict[str, Any]:
    """Build details payload from Radare2 analysis results."""
    findings = state.get("r2_analysis_results", {})
    logs = [l for l in state.get("reasoning_trace", []) if "r2" in l.lower()]

    iocs = extract_iocs_from_state(state)
    iocs_text = format_iocs_for_report(iocs) if not iocs.is_empty() else "No IOCs extracted."

    static_parts = []
    binary = findings.get("binary", {})
    if binary.get("ok"):
        static_parts.append(f"Architecture: {binary.get('architecture', 'unknown')}")
        static_parts.append(f"Bits: {binary.get('bits', 'unknown')}")
        static_parts.append(f"OS: {binary.get('os', 'unknown')}")
        static_parts.append(f"Endian: {binary.get('endian', 'unknown')}")
        static_parts.append(f"Stripped: {binary.get('stripped', 'unknown')}")
        if binary.get("imports"):
            static_parts.append(f"Imports ({len(binary['imports'])}): {', '.join(binary['imports'][:30])}")
        if binary.get("exports"):
            static_parts.append(f"Exports ({len(binary['exports'])}): {', '.join(binary['exports'][:30])}")

    funcs = findings.get("functions", {})
    if funcs.get("ok") and funcs.get("functions"):
        sorted_funcs = sorted(funcs["functions"], key=_function_priority_key, reverse=True)
        static_parts.append(f"\nFunctions ({len(funcs['functions'])} total):")
        for f in sorted_funcs[:20]:
            static_parts.append(
                "  - "
                f"{f.get('name')} @ {f.get('address')} "
                f"(score: {f.get('priority_score', 0)}, xrefs: {f.get('xrefs', 0)}, size: {f.get('size', 0)})"
            )

    call_graph_analysis = findings.get("call_graph_analysis", {})
    if call_graph_analysis.get("ok"):
        static_parts.append("\nCall Graph:")
        stats = call_graph_analysis.get("stats", {})
        static_parts.append(
            f"  - Nodes: {stats.get('nodes', 0)}, Edges: {stats.get('edges', 0)}, Chains: {stats.get('chains', 0)}"
        )
        entries = call_graph_analysis.get("entries", [])
        if entries:
            static_parts.append(f"  - Entry Points: {', '.join(entries[:10])}")
        chains = call_graph_analysis.get("chains", [])
        for chain in chains[:10]:
            path = " -> ".join(chain.get("path", []))
            static_parts.append(f"  - [{chain.get('category', 'Unknown')}] {path}")

    syscalls = findings.get("syscalls", {})
    if syscalls.get("ok") and syscalls.get("syscalls"):
        static_parts.append(f"\nSyscalls ({len(syscalls['syscalls'])} total):")
        for sc in syscalls.get("syscalls", [])[:20]:
            static_parts.append(f"  - {sc.get('name')} (#{sc.get('number')}) @ {sc.get('address', 'N/A')}")

    # Behavioral analysis from R2 strings
    strings_data = findings.get("strings", {})
    behavioral = []
    if strings_data.get("ok"):
        strings_vals = " ".join([s.get("value", "").lower() for s in strings_data.get("strings", [])])
        capabilities = []
        if any(x in strings_vals for x in ["socket", "connect", "recv", "send"]):
            capabilities.append("Network Communication")
        if any(x in strings_vals for x in ["exec", "system", "popen"]):
            capabilities.append("Command Execution")
        if any(x in strings_vals for x in ["encrypt", "aes", "rsa"]):
            capabilities.append("Cryptography")
        if capabilities:
            behavioral.append(f"Detected Capabilities: {', '.join(capabilities)}")

    verdict, _, _, _ = calculate_verdict(iocs, state)

    return {
        "executiveSummary": state.get("summary", "Radare2 analysis completed."),
        "staticAnalysis": "\n".join(static_parts) if static_parts else json.dumps(findings, indent=2),
        "behavioralAnalysis": "\n".join(behavioral) if behavioral else "Static analysis only.",
        "iocs": iocs_text,
        "conclusion": f"Analysis verdict: {verdict}. Review findings for indicators.",
        "executionLogs": logs,
    }


def _qiling_analyzer_details(state: AgentState) -> Dict[str, Any]:
    """Build details payload from Qiling dynamic analysis results."""
    findings = state.get("qiling_analysis_results", {})
    logs = [l for l in state.get("reasoning_trace", []) if "qiling" in l.lower()]

    iocs = extract_iocs_from_state(state)
    iocs_text = format_iocs_for_report(iocs) if not iocs.is_empty() else "No IOCs extracted."

    static_parts = []
    execution = findings.get("execution_trace", {})
    if isinstance(execution, dict) and execution:
        static_parts.append(f"Execution success: {execution.get('success')}")
        static_parts.append(f"Architecture: {execution.get('arch', 'unknown')}")
        static_parts.append(f"OS: {execution.get('os', 'unknown')}")
        static_parts.append(f"Instructions executed: {execution.get('instructions_executed', 0)}")
        static_parts.append(f"Duration (ms): {execution.get('duration_ms', 0)}")
        static_parts.append(f"Exit reason: {execution.get('exit_reason', 'unknown')}")

    syscalls = findings.get("syscalls", {})
    if isinstance(syscalls, dict) and syscalls:
        summary = syscalls.get("summary", {})
        if isinstance(summary, dict):
            static_parts.append(f"Syscalls total: {summary.get('total_calls', 0)}")
            static_parts.append(f"Syscall categories: {summary.get('categories', {})}")
            suspicious = summary.get("suspicious_calls", [])
            if suspicious:
                static_parts.append(f"Suspicious syscalls: {suspicious[:20]}")

    network = findings.get("network_activity", {})
    behavioral = []
    if isinstance(network, dict) and network:
        indicators = network.get("indicators", {})
        if isinstance(indicators, dict):
            c2 = indicators.get("c2_candidates", [])
            if c2:
                behavioral.append(f"C2 candidates: {', '.join(str(v) for v in c2[:20])}")
            protocols = indicators.get("protocols_used", [])
            if protocols:
                behavioral.append(f"Protocols used: {', '.join(str(v) for v in protocols)}")

    evasion = findings.get("evasion_techniques", {})
    if isinstance(evasion, dict) and evasion:
        ev_summary = evasion.get("summary", {})
        if isinstance(ev_summary, dict):
            behavioral.append(
                f"Evasion techniques: {ev_summary.get('total_techniques', 0)} "
                f"(risk: {ev_summary.get('risk_level', 'low')})"
            )

    memory_events = findings.get("memory_events", {})
    if isinstance(memory_events, dict) and memory_events:
        indicators = memory_events.get("indicators", {})
        if indicators:
            behavioral.append(f"Memory indicators: {indicators}")

    verdict, _, _, _ = calculate_verdict(iocs, state)

    return {
        "executiveSummary": state.get("summary", "Qiling dynamic analysis completed."),
        "staticAnalysis": "\n".join(static_parts) if static_parts else json.dumps(findings, indent=2),
        "behavioralAnalysis": "\n".join(behavioral) if behavioral else "No dynamic behavior detected.",
        "iocs": iocs_text,
        "conclusion": f"Analysis verdict: {verdict}. Review dynamic findings for runtime behavior.",
        "executionLogs": logs,
    }


def build_file_tree(state: AgentState) -> Dict[str, Any]:
    children = []
    for func_name in state.get("decompilation_cache", {}).keys():
        children.append({"id": func_name, "name": f"{func_name}.c", "type": "code"})
    return {"id": "root", "name": state.get("program_hash", ""), "type": "folder", "children": children}


def build_code_file(state: AgentState, file_id: str) -> Dict[str, Any]:
    content = state.get("decompilation_cache", {}).get(file_id, "")
    return {"id": file_id, "name": f"{file_id}.c", "language": "c", "content": content}


def build_reports(state: AgentState) -> list[Dict[str, Any]]:
    reports = [{"id": "summary", "name": "Analysis Report", "timestamp": 0}]
    if state.get("r2_analysis_results"):
        reports.append({"id": "r2_summary", "name": "Radare2 Report", "timestamp": 0})
    if state.get("qiling_analysis_results"):
        reports.append({"id": "qiling_summary", "name": "Qiling Dynamic Report", "timestamp": 0})
    return reports


def build_report_content(state: AgentState, report_id: str) -> Dict[str, Any]:
    """Return report as markdown content for the UI viewer."""
    if report_id == "r2_summary":
        content = _build_r2_report_markdown(state)
        return {"id": report_id, "name": "Radare2 Report", "timestamp": 0, "content": content}
    if report_id == "qiling_summary":
        content = _build_qiling_report_markdown(state)
        return {"id": report_id, "name": "Qiling Dynamic Report", "timestamp": 0, "content": content}
    summary = state.get("summary", "No summary available.")
    call_graph_sections = []
    gh_call_graph = _build_call_graph_markdown(
        "Ghidra",
        state.get("analysis_results", {}).get("call_graph_analysis", {}),
    )
    r2_call_graph = _build_call_graph_markdown(
        "Radare2",
        state.get("r2_analysis_results", {}).get("call_graph_analysis", {}),
    )
    if gh_call_graph:
        call_graph_sections.append(gh_call_graph)
    if r2_call_graph:
        call_graph_sections.append(r2_call_graph)
    qiling_overview = _build_qiling_overview_markdown(state.get("qiling_analysis_results", {}))
    if qiling_overview:
        call_graph_sections.append(qiling_overview)
    if call_graph_sections:
        summary = summary.rstrip() + "\n\n" + "\n\n".join(call_graph_sections)
    return {"id": report_id, "name": "Analysis Report", "timestamp": 0, "content": summary}


def _build_call_graph_markdown(source: str, analysis: Dict[str, Any]) -> str:
    if not analysis or not analysis.get("ok"):
        return ""
    stats = analysis.get("stats", {})
    entries = analysis.get("entries", []) or []
    chains = analysis.get("chains", []) or []
    adjacency = analysis.get("adjacency", []) or []
    lines = [f"## {source} Call Graph & Attack Chains", ""]
    lines.append(
        f"- **Nodes:** {stats.get('nodes', 0)} | **Edges:** {stats.get('edges', 0)} | **Chains:** {stats.get('chains', len(chains))}"
    )
    if entries:
        lines.append(f"- **Entry Points:** {', '.join(entries[:10])}")
    if chains:
        lines.append("")
        lines.append("### Attack Chains")
        for chain in chains[:15]:
            path = " -> ".join(chain.get("path", []))
            lines.append(f"- **[{chain.get('category', 'Unknown')}]** {path}")
    if adjacency:
        lines.append("")
        lines.append("### Adjacency (Who Calls Whom)")
        for row in adjacency[:20]:
            fn = row.get("function", "")
            calls = row.get("calls", []) or []
            calls_text = ", ".join(calls[:10]) if calls else "-"
            lines.append(f"- `{fn}` -> {calls_text}")
    return "\n".join(lines)


def _build_qiling_overview_markdown(qiling: Dict[str, Any]) -> str:
    if not isinstance(qiling, dict) or not qiling:
        return ""

    lines: list[str] = ["## Qiling Dynamic Highlights", ""]

    execution = qiling.get("execution_trace", {})
    if isinstance(execution, dict) and execution:
        lines.append(
            "- **Execution:** "
            f"success={execution.get('success')}, "
            f"os={execution.get('os', 'unknown')}, "
            f"arch={execution.get('arch', 'unknown')}, "
            f"instructions={execution.get('instructions_executed', 0)}, "
            f"duration_ms={execution.get('duration_ms', 0)}, "
            f"exit_reason={execution.get('exit_reason', 'unknown')}"
        )

    syscalls = qiling.get("syscalls", {})
    if isinstance(syscalls, dict) and syscalls:
        summary = syscalls.get("summary", {})
        if isinstance(summary, dict):
            lines.append(f"- **Syscalls:** {summary.get('total_calls', 0)} total")
            lines.append(f"- **Syscall Categories:** {summary.get('categories', {})}")
            suspicious = summary.get("suspicious_calls", [])
            if isinstance(suspicious, list) and suspicious:
                suspicious_names = [
                    item.get("name", "unknown") if isinstance(item, dict) else str(item)
                    for item in suspicious[:10]
                ]
                lines.append(f"- **Suspicious Syscalls:** {', '.join(suspicious_names)}")

    network = qiling.get("network_activity", {})
    if isinstance(network, dict) and network:
        indicators = network.get("indicators", {})
        if isinstance(indicators, dict):
            c2 = indicators.get("c2_candidates", [])
            protocols = indicators.get("protocols_used", [])
            if c2:
                lines.append(f"- **C2 Candidates:** {', '.join(str(v) for v in c2[:20])}")
            if protocols:
                lines.append(f"- **Protocols:** {', '.join(str(v) for v in protocols[:20])}")
        connections = network.get("connections", [])
        if isinstance(connections, list):
            lines.append(f"- **Connections Observed:** {len(connections)}")

    memory = qiling.get("memory_events", {})
    if isinstance(memory, dict):
        indicators = memory.get("indicators", {})
        if indicators:
            lines.append(f"- **Memory Indicators:** {indicators}")

    evasion = qiling.get("evasion_techniques", {})
    if isinstance(evasion, dict) and evasion:
        summary = evasion.get("summary", {})
        if isinstance(summary, dict):
            lines.append(
                "- **Evasion:** "
                f"{summary.get('total_techniques', 0)} techniques "
                f"(risk={summary.get('risk_level', 'low')})"
            )

    errors = qiling.get("errors", [])
    if isinstance(errors, list) and errors:
        lines.append(f"- **Qiling Errors:** {', '.join(str(e) for e in errors[:10])}")

    if len(lines) <= 2:
        lines.append("- Qiling ran but returned no dynamic telemetry.")

    return "\n".join(lines)


def _build_r2_report_markdown(state: AgentState) -> str:
    """Build a distinct Radare2 report from R2-specific analysis data."""
    r2 = state.get("r2_analysis_results", {})
    parts: list[str] = ["# Radare2 Analysis Report\n"]

    # Binary info
    binary = r2.get("binary", {})
    if binary.get("ok"):
        parts.append("## Binary Information")
        parts.append(f"- **Architecture:** {binary.get('architecture', 'N/A')}")
        parts.append(f"- **Image Base:** {binary.get('image_base', 'N/A')}")
        entries = binary.get("entry_points", [])
        if entries:
            parts.append(f"- **Entry Points:** {', '.join(entries)}")
        imports = binary.get("imports", [])
        if imports:
            parts.append(f"- **Imports:** {', '.join(imports[:30])}")
        exports = binary.get("exports", [])
        if exports:
            parts.append(f"- **Exports:** {', '.join(exports[:30])}")
        parts.append("")

    # Functions
    funcs = r2.get("functions", {})
    func_list = funcs if isinstance(funcs, list) else funcs.get("functions", [])
    if func_list:
        ranked_funcs = sorted(func_list, key=_function_priority_key, reverse=True)
        parts.append(f"## Functions Discovered ({len(func_list)})")
        for f in ranked_funcs[:30]:
            name = f.get("name", "unknown")
            raw_addr = f.get("address", f.get("addr", f.get("offset", "")))
            if isinstance(raw_addr, int):
                addr = hex(raw_addr)
            else:
                addr = str(raw_addr) if raw_addr else "N/A"
            size = f.get("size", "?")
            parts.append(
                f"- `{name}` at `{addr}` "
                f"(score: {f.get('priority_score', 0)}, xrefs: {f.get('xrefs', 0)}, size: {size})"
            )
        if len(func_list) > 30:
            parts.append(f"- ... and {len(func_list) - 30} more functions")
        parts.append("")

    # Strings
    strings = r2.get("strings", {})
    str_list = strings.get("strings", []) if isinstance(strings, dict) else []
    if str_list:
        parts.append(f"## Strings Extracted ({len(str_list)})")
        for s in str_list[:40]:
            val = s.get("value", "")
            parts.append(f"- `{val}`")
        if len(str_list) > 40:
            parts.append(f"- ... and {len(str_list) - 40} more strings")
        parts.append("")

    # Decompiled code
    r2_cache = state.get("r2_decompilation_cache", {})
    if r2_cache:
        parts.append(f"## Decompiled Functions ({len(r2_cache)})")
        for fname, code in list(r2_cache.items())[:10]:
            parts.append(f"### {fname}")
            parts.append(f"```c\n{code}\n```")
            parts.append("")

    # Cross-references
    xrefs = r2.get("xrefs", {})
    if xrefs and xrefs.get("ok"):
        xref_list = xrefs.get("xrefs", [])
        if xref_list:
            parts.append(f"## Cross-References ({len(xref_list)})")
            for x in xref_list[:20]:
                parts.append(f"- `{x.get('from', '?')}` -> `{x.get('to', '?')}` ({x.get('type', '?')})")
            parts.append("")

    # Syscalls
    syscalls = r2.get("syscalls", {})
    if syscalls.get("ok") and syscalls.get("syscalls"):
        sc_list = syscalls.get("syscalls", [])
        parts.append(f"## Syscalls Detected ({len(sc_list)})")
        for sc in sc_list[:30]:
            parts.append(f"- `{sc.get('name', 'unknown')}` (#{sc.get('number', '?')}) at `{sc.get('address', 'N/A')}`")
        parts.append("")

    call_graph_section = _build_call_graph_markdown("Radare2", r2.get("call_graph_analysis", {}))
    if call_graph_section:
        parts.append(call_graph_section)
        parts.append("")

    if len(parts) <= 1:
        parts.append("No Radare2 analysis data available for this session.")

    return "\n".join(parts)


def _build_qiling_report_markdown(state: AgentState) -> str:
    """Build a Qiling-focused dynamic analysis report."""
    ql = state.get("qiling_analysis_results", {})
    parts: list[str] = ["# Qiling Dynamic Analysis Report\n"]

    execution = ql.get("execution_trace", {})
    if isinstance(execution, dict) and execution:
        parts.append("## Execution Trace")
        parts.append(f"- **Success:** {execution.get('success')}")
        parts.append(f"- **Architecture:** {execution.get('arch', 'unknown')}")
        parts.append(f"- **OS:** {execution.get('os', 'unknown')}")
        parts.append(f"- **Instructions:** {execution.get('instructions_executed', 0)}")
        parts.append(f"- **Duration (ms):** {execution.get('duration_ms', 0)}")
        parts.append(f"- **Exit Reason:** {execution.get('exit_reason', 'unknown')}")
        if execution.get("error"):
            parts.append(f"- **Error:** {execution.get('error')}")
        parts.append("")

    syscalls = ql.get("syscalls", {})
    if isinstance(syscalls, dict) and syscalls:
        summary = syscalls.get("summary", {})
        calls = syscalls.get("syscalls", [])
        parts.append("## Syscall Trace")
        parts.append(f"- **Total Calls:** {summary.get('total_calls', 0) if isinstance(summary, dict) else len(calls)}")
        if isinstance(summary, dict):
            parts.append(f"- **Categories:** {summary.get('categories', {})}")
            suspicious = summary.get("suspicious_calls", [])
            if suspicious:
                parts.append("### Suspicious Calls")
                for item in suspicious[:20]:
                    parts.append(f"- `{item.get('name', 'unknown')}`: {item.get('reason', '')}")
        if isinstance(calls, list) and calls:
            parts.append("### Sample Syscalls")
            for call in calls[:30]:
                parts.append(
                    f"- `{call.get('name', 'unknown')}` @ `{call.get('address', 'N/A')}` "
                    f"(category: {call.get('category', 'unknown')})"
                )
        parts.append("")

    network = ql.get("network_activity", {})
    if isinstance(network, dict) and network:
        parts.append("## Network Activity")
        indicators = network.get("indicators", {})
        parts.append(f"- **C2 Candidates:** {indicators.get('c2_candidates', []) if isinstance(indicators, dict) else []}")
        parts.append(f"- **Protocols Used:** {indicators.get('protocols_used', []) if isinstance(indicators, dict) else []}")
        connections = network.get("connections", [])
        if isinstance(connections, list) and connections:
            parts.append("### Connections")
            for conn in connections[:20]:
                parts.append(
                    f"- `{conn.get('type', 'unknown')}` -> `{conn.get('address', 'unknown')}:{conn.get('port', 0)}` "
                    f"(t={conn.get('timestamp_ms', 0)}ms)"
                )
        parts.append("")

    memory_events = ql.get("memory_events", {})
    if isinstance(memory_events, dict) and memory_events:
        parts.append("## Memory Behavior")
        indicators = memory_events.get("indicators", {})
        parts.append(f"- **Indicators:** {indicators}")
        events = memory_events.get("events", [])
        if isinstance(events, list) and events:
            parts.append("### Memory Events")
            for event in events[:20]:
                parts.append(
                    f"- `{event.get('type', 'event')}` at `{event.get('target_address', event.get('address', 'N/A'))}` "
                    f"(size: {event.get('size', 0)})"
                )
        parts.append("")

    evasion = ql.get("evasion_techniques", {})
    if isinstance(evasion, dict) and evasion:
        parts.append("## Evasion Techniques")
        summary = evasion.get("summary", {})
        parts.append(f"- **Summary:** {summary}")
        techniques = evasion.get("techniques", [])
        if isinstance(techniques, list):
            for tech in techniques[:20]:
                parts.append(
                    f"- `{tech.get('technique', 'unknown')}` via `{tech.get('method', 'unknown')}` "
                    f"({tech.get('mitre_id', 'N/A')})"
                )
        parts.append("")

    if ql.get("errors"):
        parts.append("## Errors")
        for err in ql.get("errors", []):
            parts.append(f"- {err}")
        parts.append("")

    if len(parts) <= 1:
        parts.append("No Qiling analysis data available for this session.")

    return "\n".join(parts)


def build_similar_files(state: AgentState) -> list[Dict[str, Any]]:
    return []


def build_model_list() -> list[Dict[str, Any]]:
    return [
        {"id": "glm-4.7", "name": "GLM 4.7", "icon": "circle", "type": "other", "isSelected": True},
    ]
