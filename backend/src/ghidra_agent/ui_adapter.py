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


def build_analyzer_response(state: AgentState) -> Dict[str, Any]:
    # Calculate dynamic verdict using shared function
    iocs = extract_iocs_from_state(state)
    verdict, _, _, _ = calculate_verdict(iocs, state)
    
    return {
        "id": "ghidra",
        "name": "Ghidra Reverse Engineer Agent",
        "source": "Ireng",
        "sourceUrl": "https://irengsec.ai",
        "verdict": verdict,
        "details": _analyzer_details(state),
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
    return [{"id": "summary", "name": "Ghidra Summary", "timestamp": 0}]


def build_report_content(state: AgentState, report_id: str) -> Dict[str, Any]:
    content = build_report_html(state)
    return {"id": report_id, "name": "Ghidra Summary", "timestamp": 0, "content": content}


def build_similar_files(state: AgentState) -> list[Dict[str, Any]]:
    return []


def build_model_list() -> list[Dict[str, Any]]:
    return [
        {"id": "glm-4.7", "name": "GLM 4.7", "icon": "circle", "type": "other", "isSelected": True},
    ]
