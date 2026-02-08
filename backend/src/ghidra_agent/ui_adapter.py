import json
from typing import Any, Dict
from ghidra_agent.reporting import build_report_html
from ghidra_agent.state import AgentState


def _analyzer_details(state: AgentState) -> Dict[str, Any]:
    findings = state.get("analysis_results", {})
    logs = state.get("reasoning_trace", [])
    return {
        "executiveSummary": "Ghidra analysis completed.",
        "staticAnalysis": json.dumps(findings, indent=2),
        "behavioralAnalysis": "Headless static analysis only.",
        "iocs": "",
        "conclusion": "Review findings for indicators.",
        "executionLogs": logs,
    }


def build_analyzer_response(state: AgentState) -> Dict[str, Any]:
    return {
        "id": "ghidra",
        "name": "Ghidra Reverse Engineer Agent",
        "source": "Ireng",
        "sourceUrl": "https://irengsec.ai",
        "verdict": "Suspicious",
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
