import json
from typing import Any, Dict
from ghidra_agent.reporting import build_report_html
from ghidra_agent.state import AgentState
from ghidra_agent.ioc_extractor import extract_iocs_from_state, format_iocs_for_report, calculate_verdict


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
    
    funcs = findings.get("functions", {})
    if funcs.get("ok") and funcs.get("functions"):
        sorted_funcs = sorted(funcs["functions"], key=lambda f: f.get("xrefs", 0), reverse=True)
        static_parts.append(f"\nFunctions ({len(funcs['functions'])} total):")
        for f in sorted_funcs[:20]:
            static_parts.append(f"  - {f.get('name')} @ {f.get('address')} (xrefs: {f.get('xrefs', 0)})")
    
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
    """Build response for a specific analyzer (ghidra or radare2)."""
    iocs = extract_iocs_from_state(state)
    verdict, _, _, _ = calculate_verdict(iocs, state)

    if analyzer_id == "radare2":
        return {
            "id": "radare2",
            "name": "Radare2 Reverse Engineer Agent",
            "source": "Ireng",
            "sourceUrl": "https://irengsec.ai",
            "verdict": verdict,
            "details": _r2_analyzer_details(state),
        }

    return {
        "id": "ghidra",
        "name": "Ghidra Reverse Engineer Agent",
        "source": "Ireng",
        "sourceUrl": "https://irengsec.ai",
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

    funcs = findings.get("functions", {})
    if funcs.get("ok") and funcs.get("functions"):
        sorted_funcs = sorted(funcs["functions"], key=lambda f: f.get("size", 0), reverse=True)
        static_parts.append(f"\nFunctions ({len(funcs['functions'])} total):")
        for f in sorted_funcs[:20]:
            static_parts.append(f"  - {f.get('name')} @ {f.get('address')} (size: {f.get('size', 0)})")

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
    return reports


def build_report_content(state: AgentState, report_id: str) -> Dict[str, Any]:
    """Return report as markdown content for the UI viewer."""
    if report_id == "r2_summary":
        content = _build_r2_report_markdown(state)
        return {"id": report_id, "name": "Radare2 Report", "timestamp": 0, "content": content}
    summary = state.get("summary", "No summary available.")
    return {"id": report_id, "name": "Analysis Report", "timestamp": 0, "content": summary}


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
        parts.append("")

    # Functions
    funcs = r2.get("functions", {})
    func_list = funcs if isinstance(funcs, list) else funcs.get("functions", [])
    if func_list:
        parts.append(f"## Functions Discovered ({len(func_list)})")
        for f in func_list[:30]:
            name = f.get("name", "unknown")
            raw_addr = f.get("address", f.get("addr", f.get("offset", "")))
            if isinstance(raw_addr, int):
                addr = hex(raw_addr)
            else:
                addr = str(raw_addr) if raw_addr else "N/A"
            size = f.get("size", "?")
            parts.append(f"- `{name}` at `{addr}` (size: {size})")
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

    if len(parts) <= 1:
        parts.append("No Radare2 analysis data available for this session.")

    return "\n".join(parts)


def build_similar_files(state: AgentState) -> list[Dict[str, Any]]:
    return []


def build_model_list() -> list[Dict[str, Any]]:
    return [
        {"id": "glm-4.7", "name": "GLM 4.7", "icon": "circle", "type": "other", "isSelected": True},
    ]
