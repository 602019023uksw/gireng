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


def _md_cell(value: Any, limit: int = 120) -> str:
    text = "N/A" if value is None or value == "" else str(value)
    text = text.replace("\n", " ").replace("|", "\\|").strip()
    if len(text) > limit:
        return text[: limit - 1].rstrip() + "…"
    return text


def _md_table(headers: list[str], rows: list[list[Any]]) -> str:
    if not rows:
        return ""
    lines = [
        "| " + " | ".join(_md_cell(header, 80) for header in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        padded = row + [""] * (len(headers) - len(row))
        lines.append("| " + " | ".join(_md_cell(value) for value in padded[: len(headers)]) + " |")
    return "\n".join(lines)


def _compact_list(values: Any, limit: int = 8) -> str:
    if not isinstance(values, list) or not values:
        return "None"
    visible = [str(v) for v in values[:limit]]
    if len(values) > limit:
        visible.append(f"+{len(values) - limit} more")
    return ", ".join(visible)


def _format_addr(item: Dict[str, Any]) -> str:
    raw_addr = item.get("address", item.get("addr", item.get("offset", "")))
    if isinstance(raw_addr, int):
        return hex(raw_addr)
    return str(raw_addr) if raw_addr else "N/A"


def _format_kv_map(value: Any, limit: int = 8) -> str:
    if not isinstance(value, dict) or not value:
        return "None"
    items = list(value.items())[:limit]
    text = ", ".join(f"{key}: {val}" for key, val in items)
    if len(value) > limit:
        text += f", +{len(value) - limit} more"
    return text


def _strings_list(strings: Any) -> list[Dict[str, Any]]:
    if isinstance(strings, dict):
        values = strings.get("strings", [])
        return values if isinstance(values, list) else []
    return strings if isinstance(strings, list) else []


def _functions_list(functions: Any) -> list[Dict[str, Any]]:
    if isinstance(functions, dict):
        values = functions.get("functions", [])
        return values if isinstance(values, list) else []
    return functions if isinstance(functions, list) else []


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
    logs = [l for l in state.get("r2_trace", []) if "r2" in l.lower()]

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
    logs = [l for l in state.get("qiling_trace", []) if "qiling" in l.lower()]

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
    if state.get("analysis_results"):
        reports.append({"id": "ghidra_summary", "name": "Ghidra Report", "timestamp": 0})
    if state.get("r2_analysis_results"):
        reports.append({"id": "r2_summary", "name": "Radare2 Report", "timestamp": 0})
    if state.get("qiling_analysis_results"):
        reports.append({"id": "qiling_summary", "name": "Qiling Dynamic Report", "timestamp": 0})
    return reports


def build_report_content(state: AgentState, report_id: str) -> Dict[str, Any]:
    """Return report as markdown content for the UI viewer."""
    if report_id == "ghidra_summary":
        content = _build_ghidra_report_markdown(state)
        return {"id": report_id, "name": "Ghidra Report", "timestamp": 0, "content": content}
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
    result: Dict[str, Any] = {"id": report_id, "name": "Analysis Report", "timestamp": 0, "content": summary}
    # Include HTML view URL so the UI can render the styled report
    program_hash = state.get("program_hash", "")
    if program_hash:
        result["html_url"] = f"/api/analysis/{program_hash}/view/html"
    return result


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


def _build_ghidra_report_markdown(state: AgentState) -> str:
    """Build a Ghidra-focused static/decompiler report."""
    ghidra = state.get("analysis_results", {})
    parts: list[str] = ["# Ghidra Analysis Report", ""]

    binary = ghidra.get("binary", {})
    functions = _functions_list(ghidra.get("functions", {}))
    strings = _strings_list(ghidra.get("strings", {}))
    decomp_cache = state.get("decompilation_cache", {})
    call_graph = ghidra.get("call_graph_analysis", {})

    parts.append("## Summary")
    parts.append(
        _md_table(
            ["Metric", "Value"],
            [
                ["Architecture", binary.get("architecture", "unknown")],
                ["Image Base", binary.get("image_base", "unknown")],
                ["Entry Points", _compact_list(binary.get("entry_points", []), 6)],
                ["Segments", _compact_list(binary.get("segments", []), 8)],
                ["Compiler", binary.get("compiler", "unknown")],
                ["Functions", len(functions)],
                ["Decompiled Functions", len(decomp_cache)],
                ["Strings", len(strings)],
            ],
        )
    )
    parts.append("")

    if functions:
        ranked_funcs = sorted(functions, key=_function_priority_key, reverse=True)
        parts.append(f"## High-Priority Functions ({len(functions)} discovered)")
        parts.append(
            _md_table(
                ["Function", "Address", "XRefs", "Size", "Priority"],
                [
                    [
                        f"`{func.get('name', 'unknown')}`",
                        f"`{_format_addr(func)}`",
                        func.get("xrefs", 0),
                        func.get("size", "?"),
                        func.get("priority_score", 0),
                    ]
                    for func in ranked_funcs[:25]
                ],
            )
        )
        address_summary = "; ".join(
            f"`{func.get('name', 'unknown')}` at `{_format_addr(func)}`" for func in ranked_funcs[:5]
        )
        if address_summary:
            parts.append(f"\n> Address summary: {address_summary}")
        if len(functions) > 25:
            parts.append(f"\n> Showing top 25 functions. {len(functions) - 25} additional functions are available in raw results.")
        parts.append("")

    if strings:
        parts.append(f"## Strings & Indicators ({len(strings)} extracted)")
        parts.append(
            _md_table(
                ["Address", "String"],
                [[f"`{item.get('address', 'N/A')}`", f"`{item.get('value', item.get('string', ''))}`"] for item in strings[:25]],
            )
        )
        if len(strings) > 25:
            parts.append(f"\n> Showing top 25 strings. {len(strings) - 25} additional strings are available in raw results.")
        parts.append("")

    if decomp_cache:
        parts.append(f"## Decompiled Evidence ({len(decomp_cache)} functions)")
        for fname, code in list(decomp_cache.items())[:5]:
            parts.append(f"### `{fname}`")
            parts.append(f"```c\n{code}\n```")
            parts.append("")
        if len(decomp_cache) > 5:
            parts.append(f"> Showing first 5 decompiled functions. {len(decomp_cache) - 5} additional functions are available in code view.")
            parts.append("")

    call_graph_section = _build_call_graph_markdown("Ghidra", call_graph)
    if call_graph_section:
        parts.append(call_graph_section)
        parts.append("")

    if len(parts) <= 3:
        parts.append("No Ghidra analysis data available for this session.")

    return "\n".join(parts)


def _build_r2_report_markdown(state: AgentState) -> str:
    """Build a distinct Radare2 report from R2-specific analysis data."""
    r2 = state.get("r2_analysis_results", {})
    parts: list[str] = ["# Radare2 Analysis Report", ""]

    binary = r2.get("binary", {})
    funcs = r2.get("functions", {})
    func_list = _functions_list(funcs)
    strings = r2.get("strings", {})
    str_list = _strings_list(strings)
    r2_cache = state.get("r2_decompilation_cache", {})
    syscalls = r2.get("syscalls", {})
    sc_list = syscalls.get("syscalls", []) if isinstance(syscalls, dict) else []

    parts.append("## Summary")
    parts.append(
        _md_table(
            ["Metric", "Value"],
            [
                ["Architecture", binary.get("architecture", "unknown")],
                ["Binary Type", binary.get("binary_type", "unknown")],
                ["Image Base", binary.get("image_base", "unknown")],
                ["Entry Points", _compact_list(binary.get("entry_points", []), 6)],
                ["Imports", _compact_list(binary.get("imports", []), 10)],
                ["Exports", _compact_list(binary.get("exports", []), 10)],
                ["Functions", len(func_list)],
                ["Decompiled Functions", len(r2_cache)],
                ["Strings", len(str_list)],
                ["Syscalls", len(sc_list)],
            ],
        )
    )
    parts.append("")

    if func_list:
        ranked_funcs = sorted(func_list, key=_function_priority_key, reverse=True)
        parts.append(f"## Functions Discovered ({len(func_list)})")
        parts.append(
            _md_table(
                ["Function", "Address", "XRefs", "Size", "Priority"],
                [
                    [
                        f"`{func.get('name', 'unknown')}`",
                        f"`{_format_addr(func)}`",
                        func.get("xrefs", 0),
                        func.get("size", "?"),
                        func.get("priority_score", 0),
                    ]
                    for func in ranked_funcs[:30]
                ],
            )
        )
        address_summary = "; ".join(
            f"`{func.get('name', 'unknown')}` at `{_format_addr(func)}`" for func in ranked_funcs[:5]
        )
        if address_summary:
            parts.append(f"\n> Address summary: {address_summary}")
        if len(func_list) > 30:
            parts.append(f"\n> Showing top 30 functions. {len(func_list) - 30} additional functions are available in raw results.")
        parts.append("")

    if str_list:
        parts.append(f"## Strings Extracted ({len(str_list)})")
        parts.append(
            _md_table(
                ["Address", "Type", "String"],
                [
                    [
                        f"`{item.get('address', item.get('vaddr', 'N/A'))}`",
                        item.get("type", "ascii"),
                        f"`{item.get('value', item.get('string', ''))}`",
                    ]
                    for item in str_list[:30]
                ],
            )
        )
        if len(str_list) > 30:
            parts.append(f"\n> Showing top 30 strings. {len(str_list) - 30} additional strings are available in raw results.")
        parts.append("")

    if r2_cache:
        parts.append(f"## Decompiled Functions ({len(r2_cache)})")
        for fname, code in list(r2_cache.items())[:5]:
            parts.append(f"### `{fname}`")
            parts.append(f"```c\n{code}\n```")
            parts.append("")
        if len(r2_cache) > 5:
            parts.append(f"> Showing first 5 decompiled functions. {len(r2_cache) - 5} additional functions are available in code view.")
            parts.append("")

    xrefs = r2.get("xrefs", {})
    if xrefs and xrefs.get("ok"):
        xref_list = xrefs.get("xrefs", [])
        if xref_list:
            parts.append(f"## Cross-References ({len(xref_list)})")
            parts.append(
                _md_table(
                    ["From", "To", "Type"],
                    [[f"`{x.get('from', '?')}`", f"`{x.get('to', '?')}`", x.get("type", "?")] for x in xref_list[:20]],
                )
            )
            parts.append("")

    if isinstance(syscalls, dict) and syscalls.get("ok") and sc_list:
        parts.append(f"## Syscalls Detected ({len(sc_list)})")
        parts.append(
            _md_table(
                ["Name", "Number", "Address"],
                [[f"`{sc.get('name', 'unknown')}`", sc.get("number", "?"), f"`{sc.get('address', 'N/A')}`"] for sc in sc_list[:30]],
            )
        )
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
    parts: list[str] = ["# Qiling Dynamic Analysis Report", ""]

    execution = ql.get("execution_trace", {})
    syscalls = ql.get("syscalls", {})
    summary = syscalls.get("summary", {}) if isinstance(syscalls, dict) else {}
    calls = syscalls.get("syscalls", []) if isinstance(syscalls, dict) else []
    network = ql.get("network_activity", {})
    memory_events = ql.get("memory_events", {})
    evasion = ql.get("evasion_techniques", {})

    parts.append("## Summary")
    parts.append(
        _md_table(
            ["Metric", "Value"],
            [
                ["Execution Success", execution.get("success", "unknown") if isinstance(execution, dict) else "unknown"],
                ["Architecture", execution.get("arch", "unknown") if isinstance(execution, dict) else "unknown"],
                ["OS", execution.get("os", "unknown") if isinstance(execution, dict) else "unknown"],
                [
                    "Instructions",
                    execution.get("instructions_executed", 0) if isinstance(execution, dict) else 0,
                ],
                ["Duration", f"{execution.get('duration_ms', 0)} ms" if isinstance(execution, dict) else "0 ms"],
                ["Exit Reason", execution.get("exit_reason", "unknown") if isinstance(execution, dict) else "unknown"],
                [
                    "Syscalls",
                    summary.get("total_calls", len(calls)) if isinstance(summary, dict) else len(calls),
                ],
                [
                    "Network Indicators",
                    _compact_list(
                        network.get("indicators", {}).get("c2_candidates", [])
                        if isinstance(network, dict) and isinstance(network.get("indicators", {}), dict)
                        else [],
                        6,
                    ),
                ],
                [
                    "Memory Events",
                    len(memory_events.get("events", []))
                    if isinstance(memory_events, dict) and isinstance(memory_events.get("events", []), list)
                    else 0,
                ],
                [
                    "Evasion Risk",
                    evasion.get("summary", {}).get("risk_level", "low")
                    if isinstance(evasion, dict) and isinstance(evasion.get("summary", {}), dict)
                    else "low",
                ],
            ],
        )
    )
    parts.append("")

    if isinstance(execution, dict) and execution:
        parts.append("## Execution Trace")
        rows = [
            ["Success", execution.get("success")],
            ["Binary Format", execution.get("binary_format", "unknown")],
            ["Architecture", execution.get("arch", "unknown")],
            ["OS", execution.get("os", "unknown")],
            ["Bits", execution.get("bits", "unknown")],
            ["Instructions", execution.get("instructions_executed", 0)],
            ["Duration", f"{execution.get('duration_ms', 0)} ms"],
            ["Exit Reason", execution.get("exit_reason", "unknown")],
        ]
        if execution.get("error"):
            rows.append(["Error", execution.get("error")])
        parts.append(_md_table(["Property", "Value"], rows))
        parts.append("")

    if isinstance(syscalls, dict) and syscalls:
        parts.append("## Syscall Trace")
        if isinstance(summary, dict):
            parts.append(
                _md_table(
                    ["Metric", "Value"],
                    [
                        ["Total Calls", summary.get("total_calls", len(calls))],
                        ["Categories", _format_kv_map(summary.get("categories", {}))],
                        ["Unique Syscalls", _compact_list(summary.get("unique_syscalls", []), 12)],
                    ],
                )
            )
            suspicious = summary.get("suspicious_calls", [])
            if suspicious:
                parts.append("### Suspicious Calls")
                parts.append(
                    _md_table(
                        ["Name", "Risk", "Reason"],
                        [[f"`{item.get('name', 'unknown')}`", item.get("risk", "unknown"), item.get("reason", "")] for item in suspicious[:20]],
                    )
                )
        if isinstance(calls, list) and calls:
            parts.append("### Sample Syscalls")
            parts.append(
                _md_table(
                    ["Name", "Address", "Category", "Arguments"],
                    [
                        [
                            f"`{call.get('name', 'unknown')}`",
                            f"`{call.get('address', 'N/A')}`",
                            call.get("category", "unknown"),
                            _compact_list(call.get("args", []), 5),
                        ]
                        for call in calls[:25]
                    ],
                )
            )
            if len(calls) > 25:
                parts.append(f"\n> Showing first 25 syscalls. {len(calls) - 25} additional calls are available in raw results.")
        parts.append("")

    if isinstance(network, dict) and network:
        parts.append("## Network Activity")
        indicators = network.get("indicators", {})
        parts.append(
            _md_table(
                ["Indicator", "Value"],
                [
                    ["C2 Candidates", _compact_list(indicators.get("c2_candidates", []), 10) if isinstance(indicators, dict) else "None"],
                    ["DNS Domains", _compact_list(indicators.get("dns_domains", []), 10) if isinstance(indicators, dict) else "None"],
                    ["Protocols Used", _compact_list(indicators.get("protocols_used", []), 10) if isinstance(indicators, dict) else "None"],
                ],
            )
        )
        connections = network.get("connections", [])
        if isinstance(connections, list) and connections:
            parts.append("### Connections")
            parts.append(
                _md_table(
                    ["Type", "Destination", "Time"],
                    [
                        [
                            f"`{conn.get('type', 'unknown')}`",
                            f"`{conn.get('address', 'unknown')}:{conn.get('port', 0)}`",
                            f"{conn.get('timestamp_ms', 0)} ms",
                        ]
                        for conn in connections[:20]
                    ],
                )
            )
        parts.append("")

    if isinstance(memory_events, dict) and memory_events:
        parts.append("## Memory Behavior")
        indicators = memory_events.get("indicators", {})
        parts.append(
            _md_table(
                ["Indicator", "Value"],
                [[key, val] for key, val in indicators.items()] if isinstance(indicators, dict) else [["Indicators", indicators]],
            )
        )
        events = memory_events.get("events", [])
        if isinstance(events, list) and events:
            parts.append("### Sample Memory Events")
            parts.append(
                _md_table(
                    ["Type", "Address", "Size"],
                    [
                        [
                            f"`{event.get('type', 'event')}`",
                            f"`{event.get('target_address', event.get('address', 'N/A'))}`",
                            event.get("size", 0),
                        ]
                        for event in events[:20]
                    ],
                )
            )
            if len(events) > 20:
                parts.append(f"\n> Showing first 20 memory events. {len(events) - 20} additional events are available in raw results.")
        parts.append("")

    if isinstance(evasion, dict) and evasion:
        parts.append("## Evasion Techniques")
        summary = evasion.get("summary", {})
        if isinstance(summary, dict):
            parts.append(
                _md_table(
                    ["Metric", "Value"],
                    [
                        ["Total Techniques", summary.get("total_techniques", 0)],
                        ["Risk Level", summary.get("risk_level", "low")],
                        ["MITRE Tactics", _compact_list(summary.get("mitre_tactics", []), 8)],
                    ],
                )
            )
        techniques = evasion.get("techniques", [])
        if isinstance(techniques, list):
            parts.append(
                _md_table(
                    ["Technique", "Method", "MITRE"],
                    [
                        [
                            f"`{tech.get('technique', 'unknown')}`",
                            tech.get("method", "unknown"),
                            tech.get("mitre_id", "N/A"),
                        ]
                        for tech in techniques[:20]
                    ],
                )
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


async def build_similar_files(state: AgentState) -> list[Dict[str, Any]]:
    program_hash = state.get("program_hash", "")
    if not program_hash:
        return []
    from ghidra_agent import database as db
    from ghidra_agent.ioc_extractor import calculate_verdict, extract_iocs_from_state
    iocs = extract_iocs_from_state(state)
    verdict, _, _, _ = calculate_verdict(iocs, state)
    if not verdict:
        return []
    rows = await db.find_similar_analyses(program_hash, verdict, limit=10)
    return [
        {
            "hash": r.get("program_hash", ""),
            "labels": [r.get("verdict", "Unknown")]
            + ([f"score:{r.get('threat_score')}"] if r.get("threat_score") is not None else []),
        }
        for r in rows
    ]


def build_model_list() -> list[Dict[str, Any]]:
    return [
        {"id": "deepseek-v4-pro", "name": "DeepSeek V4 Pro", "icon": "circle", "type": "other", "isSelected": True},
        {"id": "deepseek-v4-flash", "name": "DeepSeek V4 Flash", "icon": "circle", "type": "other", "isSelected": False},
    ]
