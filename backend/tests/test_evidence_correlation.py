from copy import deepcopy

from ghidra_agent.context_builder import build_analysis_context
from ghidra_agent.evidence_correlator import build_evidence_correlation, format_evidence_correlation
from ghidra_agent.ioc_extractor import extract_iocs_from_state, extract_iocs_from_strings
from ghidra_agent.reporting import build_report_html, build_report_text
from ghidra_agent.state import DEFAULT_STATE
from tests.sample_data import (
    SAMPLE_BINARY_INFO_GHIDRA,
    SAMPLE_BINARY_INFO_R2,
    SAMPLE_CALL_GRAPH,
    SAMPLE_CALL_GRAPH_ANALYSIS,
    SAMPLE_DECOMPILE_R2,
    SAMPLE_FUNCTIONS_GHIDRA,
    SAMPLE_FUNCTIONS_R2,
    SAMPLE_QILING_RESULTS,
    SAMPLE_STRINGS_GHIDRA,
    SAMPLE_STRINGS_R2,
)


def _state():
    state = deepcopy(DEFAULT_STATE)
    state["program_hash"] = "abcd1234" * 8
    state["binary_path"] = "/tmp/sample"
    state["summary"] = "## Executive Summary\nSample analysis.\n\n## Conclusion\nSuspicious."
    state["analysis_results"] = {
        "binary": deepcopy(SAMPLE_BINARY_INFO_GHIDRA),
        "functions": deepcopy(SAMPLE_FUNCTIONS_GHIDRA),
        "strings": deepcopy(SAMPLE_STRINGS_GHIDRA),
        "call_graph": deepcopy(SAMPLE_CALL_GRAPH),
        "call_graph_analysis": deepcopy(SAMPLE_CALL_GRAPH_ANALYSIS),
    }
    state["r2_analysis_results"] = {
        "binary": deepcopy(SAMPLE_BINARY_INFO_R2),
        "functions": deepcopy(SAMPLE_FUNCTIONS_R2),
        "strings": deepcopy(SAMPLE_STRINGS_R2),
        "call_graph": deepcopy(SAMPLE_CALL_GRAPH),
        "call_graph_analysis": deepcopy(SAMPLE_CALL_GRAPH_ANALYSIS),
    }
    state["decompilation_cache"] = {"main": "char *c2 = \"http://evil.com/c2\"; connect(sock, addr, 16);"}
    state["r2_decompilation_cache"] = {"main": SAMPLE_DECOMPILE_R2["c"]}
    state["qiling_analysis_results"] = deepcopy(SAMPLE_QILING_RESULTS)
    return state


def test_decoded_ioc_extraction_finds_obfuscated_indicators():
    iocs = extract_iocs_from_strings(
        [
            {"value": "aHR0cDovL2V2aWwuZXhhbXBsZS5jb20vYzI="},
            {"value": "http%3A%2F%2Fevil.example.org%2Fx"},
            {"value": "687474703a2f2f6576696c2e746573742f70617468"},
        ]
    )

    assert "http://evil.example.com/c2" in iocs.urls
    assert "http://evil.example.org/x" in iocs.urls
    assert "http://evil.test/path" in iocs.urls
    assert any(item.startswith("base64 decoded: http://evil.example.com/c2") for item in iocs.decoded_strings)
    assert any(item.startswith("url decoded: http://evil.example.org/x") for item in iocs.decoded_strings)
    assert any(item.startswith("hex decoded: http://evil.test/path") for item in iocs.decoded_strings)


def test_evidence_correlation_links_static_dynamic_and_decompile_evidence():
    state = _state()
    iocs = extract_iocs_from_state(state)
    correlation = build_evidence_correlation(state, iocs)

    assert correlation["ok"] is True
    assert correlation["summary"]["total_findings"] >= 4
    assert {"ghidra", "radare2", "qiling"}.issubset(set(correlation["summary"]["engines"]))
    assert any(f["source"] == "string" and "http://evil.com/c2" in f["iocs"] for f in correlation["findings"])
    assert any(f["engine"] == "qiling" and "1.2.3.4:443" in f["iocs"] for f in correlation["findings"])
    assert any(f["source"] == "decompiled_code" and f["functions"] for f in correlation["findings"])

    formatted = format_evidence_correlation(correlation)
    assert "Cross-Engine Evidence Correlation" in formatted
    assert "http://evil.com/c2" in formatted


def test_analysis_context_and_reports_include_correlation_section():
    state = _state()

    context = build_analysis_context(state, ghidra_decomp_limit=2, r2_decomp_limit=2)
    assert "CROSS-ENGINE EVIDENCE CORRELATION" in context
    assert "http://evil.com/c2" in context

    text_report = build_report_text(state)
    assert "CROSS-ENGINE EVIDENCE CORRELATION" in text_report

    html_report = build_report_html(state)
    assert "Cross-Engine Evidence Correlation" in html_report
