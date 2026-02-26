"""End-to-end integration test using the chargen binary.

Tests the full pipeline from binary upload through analysis to report generation,
validating all components work together correctly:
  - Sessions (create, lookup, state management)
  - Graph pipeline (parse_intent → initialize → discovery → synthesize)
  - API endpoints (upload, status, analyzers, export)
  - IOC extraction
  - Reporting (HTML + text)
  - R2 pipeline integration
  - UI adapter (analyzer responses, file tree, code files)
"""

import sys
from copy import deepcopy
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Ensure the backend package is importable
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ghidra_agent.state import DEFAULT_STATE
from ghidra_agent.utils import compute_sha256

# ---- Path to the real chargen binary ----
CHARGEN_PATH = Path(__file__).parent.parent.parent / "sample-binary" / "chargen"


# ---------------------------------------------------------------------------
# Mock data derived from a realistic chargen-like binary
# ---------------------------------------------------------------------------

CHARGEN_BINARY_INFO_GHIDRA = {
    "ok": True,
    "architecture": "x86:LE:64:default",
    "image_base": "0x00400000",
    "entry_points": ["0x00401080"],
    "segments": [".text", ".data", ".bss", ".rodata", ".init", ".fini"],
    "compiler": "gcc (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0",
}

CHARGEN_FUNCTIONS_GHIDRA = {
    "ok": True,
    "functions": [
        {"name": "main", "address": "0x00401190", "size": 512, "xrefs": 1},
        {"name": "generate_chars", "address": "0x00401300", "size": 256, "xrefs": 5},
        {"name": "handle_client", "address": "0x00401400", "size": 384, "xrefs": 3},
        {"name": "setup_socket", "address": "0x00401600", "size": 192, "xrefs": 2},
        {"name": "FUN_00401080", "address": "0x00401080", "size": 47, "xrefs": 0},
        {"name": "_start", "address": "0x00401080", "size": 47, "xrefs": 0},
        {"name": "daemonize", "address": "0x00401700", "size": 128, "xrefs": 1},
    ],
}

CHARGEN_CALL_GRAPH = {
    "ok": True,
    "nodes": [
        {"name": "main", "address": "0x00401190", "size": 512},
        {"name": "setup_socket", "address": "0x00401600", "size": 192},
        {"name": "handle_client", "address": "0x00401400", "size": 384},
        {"name": "sym.imp.accept", "address": "0x00403010", "size": 0},
        {"name": "sym.imp.send", "address": "0x00403020", "size": 0},
    ],
    "edges": [
        {"from": "0x00401190", "to": "0x00401600", "from_name": "main", "to_name": "setup_socket", "type": "CALL"},
        {"from": "0x00401190", "to": "0x00401400", "from_name": "main", "to_name": "handle_client", "type": "CALL"},
        {"from": "0x00401400", "to": "0x00403010", "from_name": "handle_client", "to_name": "sym.imp.accept", "type": "CALL"},
        {"from": "0x00401400", "to": "0x00403020", "from_name": "handle_client", "to_name": "sym.imp.send", "type": "CALL"},
    ],
    "entry_points": ["0x00401190"],
}

CHARGEN_STRINGS_GHIDRA = {
    "ok": True,
    "strings": [
        {"value": "chargen service ready", "address": "0x00402000"},
        {"value": "0.0.0.0", "address": "0x00402020"},
        {"value": "socket", "address": "0x00402030"},
        {"value": "bind", "address": "0x00402038"},
        {"value": "listen", "address": "0x00402040"},
        {"value": "accept", "address": "0x00402048"},
        {"value": "Usage: chargen [port]", "address": "0x00402050"},
        {"value": "/var/log/chargen.log", "address": "0x00402070"},
        {"value": "Connection from %s:%d", "address": "0x00402090"},
        {"value": "send failed", "address": "0x004020b0"},
    ],
}

CHARGEN_DECOMPILE_MAIN = {
    "ok": True,
    "c": """int main(int argc, char **argv) {
    int port = 19;
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    int sockfd = setup_socket(port);
    if (sockfd < 0) {
        perror("setup_socket");
        return 1;
    }
    printf("chargen service ready on port %d\\n", port);
    while (1) {
        struct sockaddr_in client;
        socklen_t len = sizeof(client);
        int client_fd = accept(sockfd, (struct sockaddr *)&client, &len);
        if (client_fd < 0) continue;
        handle_client(client_fd);
        close(client_fd);
    }
    return 0;
}""",
}

CHARGEN_BINARY_INFO_R2 = {
    "ok": True,
    "architecture": "x86",
    "bits": 64,
    "os": "linux",
    "binary_type": "elf",
    "compiler": "gcc",
    "image_base": "0x400000",
    "entry_points": ["0x401080"],
    "sections": [".text", ".data", ".bss", ".rodata", ".init", ".fini", ".plt"],
    "imports": ["printf", "socket", "bind", "listen", "accept", "send", "close", "fork", "perror", "atoi"],
    "endian": "little",
    "stripped": False,
    "static": False,
}

CHARGEN_FUNCTIONS_R2 = {
    "ok": True,
    "functions": [
        {"name": "main", "address": "0x401190", "size": 512, "xrefs": 1, "calltype": "amd64"},
        {"name": "sym.generate_chars", "address": "0x401300", "size": 256, "xrefs": 5, "calltype": "amd64"},
        {"name": "sym.handle_client", "address": "0x401400", "size": 384, "xrefs": 3, "calltype": "amd64"},
        {"name": "sym.setup_socket", "address": "0x401600", "size": 192, "xrefs": 2, "calltype": "amd64"},
        {"name": "entry0", "address": "0x401080", "size": 47, "xrefs": 0, "calltype": "amd64"},
    ],
}

CHARGEN_STRINGS_R2 = {
    "ok": True,
    "strings": [
        {"value": "chargen service ready", "address": "0x402000", "length": 21, "section": ".rodata", "type": "ascii"},
        {"value": "0.0.0.0", "address": "0x402020", "length": 7, "section": ".rodata", "type": "ascii"},
        {"value": "socket", "address": "0x402030", "length": 6, "section": ".rodata", "type": "ascii"},
        {"value": "Usage: chargen [port]", "address": "0x402050", "length": 21, "section": ".rodata", "type": "ascii"},
        {"value": "/var/log/chargen.log", "address": "0x402070", "length": 20, "section": ".rodata", "type": "ascii"},
        {"value": "send failed", "address": "0x4020b0", "length": 11, "section": ".rodata", "type": "ascii"},
    ],
}

CHARGEN_DECOMPILE_R2 = {
    "ok": True,
    "c": "int main(int argc, char **argv) { int port = 19; sockfd = setup_socket(port); while(1) { accept(); handle_client(); } }",
    "function": "main",
    "decompiler": "pdg",
}

CHARGEN_XREFS = {
    "ok": True,
    "to": [
        {"from": "0x401090", "type": "CALL", "opcode": "call main"},
    ],
    "from": [],
}

CHARGEN_DISASM = {
    "ok": True,
    "instructions": [
        {"address": "0x401190", "mnemonic": "push", "operands": "rbp", "bytes": "55", "size": 1},
        {"address": "0x401191", "mnemonic": "mov", "operands": "rbp, rsp", "bytes": "4889e5", "size": 3},
        {"address": "0x401194", "mnemonic": "sub", "operands": "rsp, 0x30", "bytes": "4883ec30", "size": 4},
    ],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_r2_runner(container_alive=True):
    runner = MagicMock()
    runner.verify_container = AsyncMock(return_value=container_alive)
    runner.detect_decompilers = AsyncMock(return_value=["pdg", "pdd", "pdf"])
    return runner


def _ghidra_tool_mocks():
    return {
        "ghidra_agent.graph.analyze_binary_structure": AsyncMock(
            ainvoke=AsyncMock(return_value=CHARGEN_BINARY_INFO_GHIDRA)),
        "ghidra_agent.graph.list_functions": AsyncMock(
            ainvoke=AsyncMock(return_value=CHARGEN_FUNCTIONS_GHIDRA)),
        "ghidra_agent.graph.build_call_graph": AsyncMock(
            ainvoke=AsyncMock(return_value=CHARGEN_CALL_GRAPH)),
        "ghidra_agent.graph.find_strings": AsyncMock(
            ainvoke=AsyncMock(return_value=CHARGEN_STRINGS_GHIDRA)),
        "ghidra_agent.graph.decompile_function": AsyncMock(
            ainvoke=AsyncMock(return_value=CHARGEN_DECOMPILE_MAIN)),
        "ghidra_agent.graph.find_xrefs": AsyncMock(
            ainvoke=AsyncMock(return_value=CHARGEN_XREFS)),
        "ghidra_agent.graph.get_function_graph": AsyncMock(
            ainvoke=AsyncMock(return_value={"ok": True, "graph": {}})),
        "ghidra_agent.graph.disassemble_at": AsyncMock(
            ainvoke=AsyncMock(return_value=CHARGEN_DISASM)),
        "ghidra_agent.graph.search_bytes": AsyncMock(
            ainvoke=AsyncMock(return_value={"ok": True, "matches": []})),
    }


def _r2_tool_mocks():
    return {
        "ghidra_agent.r2_graph.r2_analyze_binary": AsyncMock(
            ainvoke=AsyncMock(return_value=CHARGEN_BINARY_INFO_R2)),
        "ghidra_agent.r2_graph.r2_list_functions": AsyncMock(
            ainvoke=AsyncMock(return_value=CHARGEN_FUNCTIONS_R2)),
        "ghidra_agent.r2_graph.r2_build_call_graph": AsyncMock(
            ainvoke=AsyncMock(return_value=CHARGEN_CALL_GRAPH)),
        "ghidra_agent.r2_graph.r2_find_strings": AsyncMock(
            ainvoke=AsyncMock(return_value=CHARGEN_STRINGS_R2)),
        "ghidra_agent.r2_graph.r2_decompile_function": AsyncMock(
            ainvoke=AsyncMock(return_value=CHARGEN_DECOMPILE_R2)),
        "ghidra_agent.r2_graph.r2_find_xrefs": AsyncMock(
            ainvoke=AsyncMock(return_value=CHARGEN_XREFS)),
        "ghidra_agent.r2_graph.r2_disassemble_at": AsyncMock(
            ainvoke=AsyncMock(return_value=CHARGEN_DISASM)),
        "ghidra_agent.r2_graph.r2_syscall_analysis": AsyncMock(
            ainvoke=AsyncMock(return_value={"ok": True, "syscalls": []})),
    }


import unittest.mock
from contextlib import contextmanager


@contextmanager
def _multi_patch(patches: dict):
    active = []
    try:
        for target, mock_obj in patches.items():
            p = unittest.mock.patch(target, mock_obj)
            p.start()
            active.append(p)
        yield
    finally:
        for p in reversed(active):
            p.stop()


# ---------------------------------------------------------------------------
# Tests: Full pipeline with chargen binary
# ---------------------------------------------------------------------------

class TestChargenBinaryExists:
    """Validate the chargen test binary exists and can be hashed."""

    def test_binary_file_exists(self):
        assert CHARGEN_PATH.exists(), f"chargen binary not found at {CHARGEN_PATH}"

    def test_can_compute_hash(self):
        h = compute_sha256(CHARGEN_PATH)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_binary_is_not_empty(self):
        assert CHARGEN_PATH.stat().st_size > 0


class TestChargenPipelineFlow:
    """Full graph pipeline test with chargen binary data."""

    @pytest.mark.asyncio
    async def test_full_discovery_and_synthesize(self):
        """Simulate a full upload → discovery → synthesize flow."""
        state = deepcopy(DEFAULT_STATE)
        state["session_id"] = "chargen-test"
        state["program_hash"] = compute_sha256(CHARGEN_PATH)
        state["binary_path"] = str(CHARGEN_PATH)
        state["user_query"] = ""

        all_mocks = {**_ghidra_tool_mocks(), **_r2_tool_mocks()}

        with _multi_patch(all_mocks):
            with patch("ghidra_agent.graph.call_llm", new_callable=AsyncMock) as mock_llm, \
                 patch("ghidra_agent.r2_tools.get_runner", return_value=_mock_r2_runner()), \
                 patch("ghidra_agent.radare.runner.Radare2Runner", return_value=_mock_r2_runner()):
                mock_llm.return_value = (
                    "## 1. Executive Summary\n"
                    "The binary is a chargen (Character Generator) network service.\n\n"
                    "## 2. Malware Capabilities\n"
                    "- **Network Communication**: Uses socket/bind/listen/accept for TCP connections\n\n"
                    "## 3. Binary Information\n"
                    "| Property | Value |\n|---|---|\n| Architecture | x86-64 |\n\n"
                    "## 11. Conclusion\nThis is a legitimate chargen service implementation."
                )

                from ghidra_agent.graph import discovery, initialize_ghidra, parse_intent, synthesize

                # Step 1: Parse intent (no query = reconnaissance)
                state = await parse_intent(state)
                assert state["intent"] == "reconnaissance"
                assert "intent:reconnaissance" in state["reasoning_trace"]

                # Step 2: Initialize
                state = await initialize_ghidra(state)
                assert state["status"] == "initialized"
                assert "ghidra_initialized" in state["reasoning_trace"]
                assert "r2_initialized" in state["reasoning_trace"]
                assert isinstance(state["r2_analysis_results"], dict)
                assert isinstance(state["r2_decompilation_cache"], dict)

                # Step 3: Discovery (both Ghidra and R2)
                state = await discovery(state)

                # Verify Ghidra results populated
                assert state["analysis_results"]["binary"]["ok"] is True
                assert state["analysis_results"]["binary"]["architecture"] == "x86:LE:64:default"
                assert state["analysis_results"]["functions"]["ok"] is True
                assert len(state["analysis_results"]["functions"]["functions"]) == 7
                assert state["analysis_results"]["strings"]["ok"] is True
                assert state["analysis_results"]["call_graph"]["ok"] is True
                assert state["analysis_results"]["call_graph_analysis"]["ok"] is True

                # Verify R2 results populated
                assert state["r2_analysis_results"]["binary"]["ok"] is True
                assert state["r2_analysis_results"]["binary"]["architecture"] == "x86"
                assert state["r2_analysis_results"]["functions"]["ok"] is True
                assert state["r2_analysis_results"]["strings"]["ok"] is True
                assert state["r2_analysis_results"]["call_graph"]["ok"] is True
                assert state["r2_analysis_results"]["call_graph_analysis"]["ok"] is True

                # Verify dual discovery trace
                assert "discovery_completed" in state["reasoning_trace"]
                assert "r2_discovery_completed" in state["reasoning_trace"]

                # Verify auto-decompilation happened
                assert len(state["decompilation_cache"]) > 0

                # Step 4: Synthesize (LLM call)
                state = await synthesize(state)
                assert state["status"] == "completed"
                assert state["summary"] != ""
                assert "synthesized" in state["reasoning_trace"]
                assert "chargen" in state["summary"].lower()

                # Verify LLM was called with correct context
                call_args = mock_llm.call_args[0][0]
                assert "x86:LE:64:default" in call_args  # Ghidra arch
                assert "R2" in call_args or "RADARE2" in call_args  # R2 section
                assert "chargen service ready" in call_args  # Strings included

    @pytest.mark.asyncio
    async def test_malware_query_with_chargen(self):
        """User query about network analysis on chargen."""
        state = deepcopy(DEFAULT_STATE)
        state["session_id"] = "chargen-query"
        state["program_hash"] = compute_sha256(CHARGEN_PATH)
        state["binary_path"] = str(CHARGEN_PATH)
        state["user_query"] = "analyze the protocol and network communication"

        all_mocks = {**_ghidra_tool_mocks(), **_r2_tool_mocks()}

        with _multi_patch(all_mocks):
            with patch("ghidra_agent.graph.call_llm", new_callable=AsyncMock) as mock_llm, \
                 patch("ghidra_agent.r2_tools.get_runner", return_value=_mock_r2_runner()), \
                 patch("ghidra_agent.radare.runner.Radare2Runner", return_value=_mock_r2_runner()):
                mock_llm.return_value = "Network analysis of chargen service."

                from ghidra_agent.graph import discovery, initialize_ghidra, parse_intent, synthesize

                state = await parse_intent(state)
                assert state["intent"] == "protocol"  # "protocol" keyword in query

                state = await initialize_ghidra(state)
                state = await discovery(state)
                state = await synthesize(state)
                assert state["status"] == "completed"

    @pytest.mark.asyncio
    async def test_r2_down_ghidra_still_works(self):
        """If R2 container is down, Ghidra analysis completes alone."""
        state = deepcopy(DEFAULT_STATE)
        state["session_id"] = "chargen-no-r2"
        state["program_hash"] = compute_sha256(CHARGEN_PATH)
        state["binary_path"] = str(CHARGEN_PATH)

        ghidra_mocks = _ghidra_tool_mocks()

        with _multi_patch(ghidra_mocks):
            with patch("ghidra_agent.graph.call_llm", new_callable=AsyncMock) as mock_llm, \
                 patch("ghidra_agent.r2_tools.get_runner", return_value=_mock_r2_runner(container_alive=False)), \
                 patch("ghidra_agent.radare.runner.Radare2Runner", return_value=_mock_r2_runner(container_alive=False)):
                mock_llm.return_value = "Chargen analysis (Ghidra only)."

                from ghidra_agent.graph import discovery, initialize_ghidra, parse_intent, synthesize

                state = await parse_intent(state)
                state = await initialize_ghidra(state)
                state = await discovery(state)

                # Ghidra should succeed
                assert state["analysis_results"]["binary"]["ok"] is True
                assert state["analysis_results"]["functions"]["ok"] is True

                # R2 should indicate it was skipped
                assert "r2_unavailable" in state["reasoning_trace"]

                state = await synthesize(state)
                assert state["status"] == "completed"


class TestChargenIOCExtraction:
    """Test IOC extraction from chargen analysis data."""

    def test_extracts_ip_from_strings(self):
        from ghidra_agent.ioc_extractor import extract_iocs_from_strings
        iocs = extract_iocs_from_strings(CHARGEN_STRINGS_GHIDRA["strings"])
        # 0.0.0.0 should be extracted as an IP
        assert any("0.0.0.0" in ip for ip in iocs.ips)

    def test_extracts_file_paths(self):
        from ghidra_agent.ioc_extractor import extract_iocs_from_strings
        iocs = extract_iocs_from_strings(CHARGEN_STRINGS_GHIDRA["strings"])
        assert any("/var/log/chargen.log" in p for p in iocs.file_paths)

    def test_full_state_extraction(self):
        from ghidra_agent.ioc_extractor import extract_iocs_from_state
        state = deepcopy(DEFAULT_STATE)
        state["analysis_results"] = {
            "strings": CHARGEN_STRINGS_GHIDRA,
        }
        state["r2_analysis_results"] = {
            "strings": CHARGEN_STRINGS_R2,
        }
        iocs = extract_iocs_from_state(state)
        assert not iocs.is_empty()

    def test_verdict_calculation(self):
        from ghidra_agent.ioc_extractor import calculate_verdict, extract_iocs_from_state
        state = deepcopy(DEFAULT_STATE)
        state["analysis_results"] = {"strings": CHARGEN_STRINGS_GHIDRA}
        state["r2_analysis_results"] = {"strings": CHARGEN_STRINGS_R2}
        iocs = extract_iocs_from_state(state)
        verdict_name, verdict_class, indicators, score = calculate_verdict(iocs, state)
        assert verdict_class in ("malicious", "suspicious", "clean", "unknown")
        assert isinstance(indicators, list)
        assert isinstance(score, (int, float))


class TestChargenUIAdapter:
    """Test UI adapter produces correct responses for chargen analysis."""

    def _make_state(self):
        state = deepcopy(DEFAULT_STATE)
        state["session_id"] = "chargen-ui"
        state["program_hash"] = "abc123"
        state["binary_path"] = str(CHARGEN_PATH)
        state["status"] = "completed"
        state["summary"] = "Chargen service analysis complete."
        state["analysis_results"] = {
            "binary": deepcopy(CHARGEN_BINARY_INFO_GHIDRA),
            "functions": deepcopy(CHARGEN_FUNCTIONS_GHIDRA),
            "strings": deepcopy(CHARGEN_STRINGS_GHIDRA),
        }
        state["decompilation_cache"] = {"main": CHARGEN_DECOMPILE_MAIN["c"]}
        state["r2_analysis_results"] = {
            "binary": deepcopy(CHARGEN_BINARY_INFO_R2),
            "functions": deepcopy(CHARGEN_FUNCTIONS_R2),
            "strings": deepcopy(CHARGEN_STRINGS_R2),
        }
        state["r2_decompilation_cache"] = {"main": CHARGEN_DECOMPILE_R2["c"]}
        return state

    def test_ghidra_analyzer_response(self):
        from ghidra_agent.ui_adapter import build_analyzer_response
        state = self._make_state()
        resp = build_analyzer_response(state, "ghidra")
        assert resp["id"] == "ghidra"
        assert resp["name"] == "Ghidra Reverse Engineer Agent"
        assert "details" in resp
        assert "executiveSummary" in resp["details"]
        assert "staticAnalysis" in resp["details"]
        assert resp["details"]["executiveSummary"] == "Chargen service analysis complete."

    def test_radare2_analyzer_response(self):
        from ghidra_agent.ui_adapter import build_analyzer_response
        state = self._make_state()
        resp = build_analyzer_response(state, "radare2")
        assert resp["id"] == "radare2"
        assert resp["name"] == "Radare2 Reverse Engineer Agent"
        assert "details" in resp
        assert "staticAnalysis" in resp["details"]
        # R2 static analysis should mention architecture
        assert "x86" in resp["details"]["staticAnalysis"]

    def test_file_tree(self):
        from ghidra_agent.ui_adapter import build_file_tree
        state = self._make_state()
        tree = build_file_tree(state)
        assert tree["id"] == "root"
        assert tree["type"] == "folder"
        children = tree.get("children", [])
        assert len(children) >= 1
        child_names = [c["name"] for c in children]
        assert "main.c" in child_names

    def test_code_file(self):
        from ghidra_agent.ui_adapter import build_code_file
        state = self._make_state()
        code = build_code_file(state, "main")
        assert code["id"] == "main"
        assert code["language"] == "c"
        assert "main" in code["content"]
        assert "setup_socket" in code["content"]

    def test_reports_list(self):
        from ghidra_agent.ui_adapter import build_reports
        state = self._make_state()
        reports = build_reports(state)
        assert len(reports) >= 1
        assert reports[0]["id"] == "summary"


class TestChargenReporting:
    """Test report generation with chargen data."""

    def _make_state(self):
        state = deepcopy(DEFAULT_STATE)
        state["session_id"] = "chargen-report"
        state["program_hash"] = compute_sha256(CHARGEN_PATH)
        state["binary_path"] = str(CHARGEN_PATH)
        state["status"] = "completed"
        state["summary"] = (
            "## 1. Executive Summary\nChargen network service.\n\n"
            "## 2. Malware Capabilities\n- Network Communication\n\n"
            "## 11. Conclusion\nLegitimate chargen service."
        )
        state["analysis_results"] = {
            "binary": deepcopy(CHARGEN_BINARY_INFO_GHIDRA),
            "functions": deepcopy(CHARGEN_FUNCTIONS_GHIDRA),
            "strings": deepcopy(CHARGEN_STRINGS_GHIDRA),
        }
        state["decompilation_cache"] = {"main": CHARGEN_DECOMPILE_MAIN["c"]}
        state["r2_analysis_results"] = {
            "binary": deepcopy(CHARGEN_BINARY_INFO_R2),
            "functions": deepcopy(CHARGEN_FUNCTIONS_R2),
            "strings": deepcopy(CHARGEN_STRINGS_R2),
        }
        state["r2_decompilation_cache"] = {"main": CHARGEN_DECOMPILE_R2["c"]}
        return state

    def test_html_report_generation(self):
        from ghidra_agent.reporting import build_report_html
        state = self._make_state()
        html = build_report_html(state)
        assert "<!DOCTYPE html>" in html or "<html" in html
        assert "Executive Summary" in html
        assert "chargen" in html.lower() or "Chargen" in html

    def test_text_report_generation(self):
        from ghidra_agent.reporting import build_report_text
        state = self._make_state()
        text = build_report_text(state)
        assert len(text) > 0
        assert "chargen" in text.lower() or "Chargen" in text


class TestChargenAPI:
    """Test API endpoints with chargen analysis data."""

    def _populated_state(self):
        state = deepcopy(DEFAULT_STATE)
        state["session_id"] = "chargen-api"
        state["program_hash"] = compute_sha256(CHARGEN_PATH)
        state["binary_path"] = str(CHARGEN_PATH)
        state["status"] = "completed"
        state["summary"] = "Chargen service analysis."
        state["analysis_results"] = {
            "binary": deepcopy(CHARGEN_BINARY_INFO_GHIDRA),
            "functions": deepcopy(CHARGEN_FUNCTIONS_GHIDRA),
            "strings": deepcopy(CHARGEN_STRINGS_GHIDRA),
        }
        state["decompilation_cache"] = {"main": CHARGEN_DECOMPILE_MAIN["c"]}
        state["r2_analysis_results"] = {
            "binary": deepcopy(CHARGEN_BINARY_INFO_R2),
            "functions": deepcopy(CHARGEN_FUNCTIONS_R2),
            "strings": deepcopy(CHARGEN_STRINGS_R2),
        }
        state["r2_decompilation_cache"] = {"main": CHARGEN_DECOMPILE_R2["c"]}
        return state

    @pytest.fixture
    def mock_store(self):
        state = self._populated_state()
        with patch("ghidra_agent.api.main.store") as mock_s:
            mock_s.sessions = {"chargen-api": state}
            mock_s.get_session = MagicMock(return_value=state)
            yield mock_s

    @pytest_asyncio.fixture
    async def client(self, mock_store):
        from ghidra_agent.api.main import app
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c

    @pytest.mark.asyncio
    async def test_status_endpoint(self, client):
        resp = await client.get("/status/chargen-api")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["session_id"] == "chargen-api"

    @pytest.mark.asyncio
    async def test_analyzers_returns_both(self, client):
        program_hash = compute_sha256(CHARGEN_PATH)
        resp = await client.get(f"/api/analysis/{program_hash}/analyzers")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        ids = [a["id"] for a in data]
        assert "ghidra" in ids
        assert "radare2" in ids

    @pytest.mark.asyncio
    async def test_analyzer_detail_ghidra(self, client):
        program_hash = compute_sha256(CHARGEN_PATH)
        resp = await client.get(f"/api/analysis/{program_hash}/analyzers/ghidra")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "ghidra"
        assert "details" in data

    @pytest.mark.asyncio
    async def test_analyzer_detail_radare2(self, client):
        program_hash = compute_sha256(CHARGEN_PATH)
        resp = await client.get(f"/api/analysis/{program_hash}/analyzers/radare2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "radare2"

    @pytest.mark.asyncio
    async def test_files_endpoint(self, client):
        program_hash = compute_sha256(CHARGEN_PATH)
        resp = await client.get(f"/api/analysis/{program_hash}/files")
        assert resp.status_code == 200
        data = resp.json()
        assert data["type"] == "folder"
        assert any(c["name"] == "main.c" for c in data.get("children", []))

    @pytest.mark.asyncio
    async def test_file_content_endpoint(self, client):
        program_hash = compute_sha256(CHARGEN_PATH)
        resp = await client.get(f"/api/analysis/{program_hash}/files/main")
        assert resp.status_code == 200
        data = resp.json()
        assert data["language"] == "c"
        assert "main" in data["content"]

    @pytest.mark.asyncio
    async def test_reports_endpoint(self, client):
        program_hash = compute_sha256(CHARGEN_PATH)
        resp = await client.get(f"/api/analysis/{program_hash}/reports")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    @pytest.mark.asyncio
    async def test_export_html(self, client):
        program_hash = compute_sha256(CHARGEN_PATH)
        resp = await client.get(f"/api/analysis/{program_hash}/export/html")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    @pytest.mark.asyncio
    async def test_export_text(self, client):
        program_hash = compute_sha256(CHARGEN_PATH)
        resp = await client.get(f"/api/analysis/{program_hash}/export/text")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]

    @pytest.mark.asyncio
    async def test_models_endpoint(self, client):
        resp = await client.get("/api/models")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert any(m["id"] == "glm-4.7" for m in data)

    @pytest.mark.asyncio
    async def test_analysis_status(self, client):
        program_hash = compute_sha256(CHARGEN_PATH)
        resp = await client.get(f"/api/analysis/{program_hash}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"


class TestChargenSessionStore:
    """Test session management with the real chargen binary."""

    def test_create_session_with_real_binary(self, tmp_path):
        """Create a session using the actual chargen binary file."""
        from ghidra_agent.sessions import SessionStore

        with patch("ghidra_agent.sessions.settings") as mock_settings:
            mock_settings.ghidra_shared_root = str(tmp_path)
            store = SessionStore()
            state = store.create_session(str(CHARGEN_PATH))

            assert state["session_id"] != ""
            assert state["program_hash"] == compute_sha256(CHARGEN_PATH)
            assert state["binary_path"] != ""
            assert state["status"] == "initialized"
            assert isinstance(state["analysis_results"], dict)
            assert isinstance(state["reasoning_trace"], list)

    def test_get_session(self, tmp_path):
        from ghidra_agent.sessions import SessionStore

        with patch("ghidra_agent.sessions.settings") as mock_settings:
            mock_settings.ghidra_shared_root = str(tmp_path)
            store = SessionStore()
            state = store.create_session(str(CHARGEN_PATH))
            session_id = state["session_id"]

            retrieved = store.get_session(session_id)
            assert retrieved is state  # same object

    def test_get_missing_session_raises(self):
        from ghidra_agent.sessions import SessionStore
        store = SessionStore()
        with pytest.raises(KeyError):
            store.get_session("nonexistent")


class TestChargenStateIntegrity:
    """Validate state integrity throughout the pipeline."""

    def test_default_state_has_all_fields(self):
        required_fields = [
            "binary_path", "program_hash", "current_address", "current_function",
            "analysis_results", "decompilation_cache", "r2_analysis_results",
            "r2_decompilation_cache", "user_query", "reasoning_trace",
            "pending_actions", "write_mode_enabled", "session_id", "intent",
            "status", "review_approved", "summary",
        ]
        for field in required_fields:
            assert field in DEFAULT_STATE, f"Missing field in DEFAULT_STATE: {field}"

    def test_agent_state_model_has_summary(self):
        from ghidra_agent.state import AgentStateModel
        m = AgentStateModel(
            binary_path="/test",
            program_hash="abc",
            session_id="s1",
        )
        assert hasattr(m, "summary")
        assert m.summary == ""

    def test_agent_state_model_has_r2_fields(self):
        from ghidra_agent.state import AgentStateModel
        m = AgentStateModel(
            binary_path="/test",
            program_hash="abc",
            session_id="s1",
        )
        assert hasattr(m, "r2_analysis_results")
        assert hasattr(m, "r2_decompilation_cache")
        assert m.r2_analysis_results == {}
        assert m.r2_decompilation_cache == {}


class TestChargenConfig:
    """Validate configuration for dual-agent setup."""

    def test_r2_settings_exist(self):
        from ghidra_agent.config import Settings
        s = Settings()
        assert hasattr(s, "r2_container_name")
        assert hasattr(s, "r2_shared_root")
        assert hasattr(s, "r2_timeout")
        assert hasattr(s, "enable_r2")
        assert s.r2_container_name == "radare2"
        assert s.r2_timeout == 90
        assert s.enable_r2 is True

    def test_llm_provider_setting(self):
        from ghidra_agent.config import Settings
        s = Settings()
        assert hasattr(s, "llm_provider")
        # Default should be anthropic
        assert s.llm_provider == "anthropic"

    def test_model_config_uses_configdict(self):
        from ghidra_agent.config import Settings
        assert hasattr(Settings, "model_config")
        assert Settings.model_config.get("populate_by_name") is True


class TestChargenPrompts:
    """Validate prompts reference both analysis tools."""

    def test_prompt_mentions_ghidra(self):
        from ghidra_agent.prompts import SYSTEM_PROMPT
        assert "Ghidra" in SYSTEM_PROMPT or "ghidra" in SYSTEM_PROMPT

    def test_prompt_mentions_radare2(self):
        from ghidra_agent.prompts import SYSTEM_PROMPT
        assert "Radare2" in SYSTEM_PROMPT or "radare2" in SYSTEM_PROMPT

    def test_prompt_mentions_cross_reference(self):
        from ghidra_agent.prompts import SYSTEM_PROMPT
        assert "cross-reference" in SYSTEM_PROMPT.lower() or "cross reference" in SYSTEM_PROMPT.lower()


# ── Reporting helpers: entry-point cap, compiler sanitization, code evidence ──


class TestReportingHelpers:
    """Test _sanitize_compiler, _format_entry_points, _is_library_content."""

    def test_sanitize_compiler_strips_java_tostring(self):
        from ghidra_agent.reporting import _sanitize_compiler
        result = _sanitize_compiler("ghidra.program.database.ProgramCompilerSpec@33c6625c")
        assert result == "ProgramCompilerSpec"
        assert "@" not in result

    def test_sanitize_compiler_preserves_normal_string(self):
        from ghidra_agent.reporting import _sanitize_compiler
        assert _sanitize_compiler("GCC (Ubuntu 9.4.0)") == "GCC (Ubuntu 9.4.0)"

    def test_sanitize_compiler_unknown(self):
        from ghidra_agent.reporting import _sanitize_compiler
        assert _sanitize_compiler("unknown") == "unknown"

    def test_format_entry_points_caps_at_limit(self):
        from ghidra_agent.reporting import _format_entry_points
        entries = [f"0x{i:04x}" for i in range(300)]
        result = _format_entry_points(entries)
        # Should only show 5 entries
        assert result.count("0x") == 5
        assert "+295 more" in result

    def test_format_entry_points_small_list(self):
        from ghidra_agent.reporting import _format_entry_points
        result = _format_entry_points(["0x401000", "0x401010"])
        assert result == "0x401000, 0x401010"
        assert "more" not in result

    def test_format_entry_points_empty(self):
        from ghidra_agent.reporting import _format_entry_points
        assert _format_entry_points([]) == "unknown"

    def test_is_library_content_openssl(self):
        from ghidra_agent.reporting import _is_library_content
        code = "void fcn() { OPENSSL_ia32cap_P = 0; }"
        assert _is_library_content("fcn.0043a460", code, ["memset"]) is True

    def test_is_library_content_dtls(self):
        from ghidra_agent.reporting import _is_library_content
        code = "void fcn() { dtls1_retransmit_message(); }"
        assert _is_library_content("fcn.004325a0", code, ["send"]) is True

    def test_is_library_content_generic_only_apis(self):
        from ghidra_agent.reporting import _is_library_content
        code = "void fcn() { memcpy(dst, src, len); memset(buf, 0, 100); }"
        assert _is_library_content("fcn.00454ff0", code, ["memcpy", "memset"]) is True

    def test_is_library_content_real_app_function(self):
        from ghidra_agent.reporting import _is_library_content
        code = "void my_func() { system(\"/bin/sh\"); }"
        assert _is_library_content("my_func", code, ["system"]) is False

    def test_is_library_content_fcn_with_real_apis(self):
        from ghidra_agent.reporting import _is_library_content
        code = "void fcn() { socket(AF_INET, SOCK_STREAM, 0); connect(fd, &addr, sizeof(addr)); }"
        assert _is_library_content("fcn.00401000", code, ["socket", "connect"]) is False


class TestCamelCaseAlphanumeric:
    """Test broadened _is_camelcase_identifier for alphanumeric crypto names."""

    def test_ripemd160WithRSA_detected(self):
        from ghidra_agent.ioc_extractor import _is_camelcase_identifier
        assert _is_camelcase_identifier("ripemd160WithRSA") is True

    def test_sha256WithRSAEncryption_detected(self):
        from ghidra_agent.ioc_extractor import _is_camelcase_identifier
        assert _is_camelcase_identifier("sha256WithRSAEncryption") is True

    def test_pure_alpha_camelcase_still_works(self):
        from ghidra_agent.ioc_extractor import _is_camelcase_identifier
        assert _is_camelcase_identifier("subjectKeyIdentifier") is True

    def test_hex_string_not_camelcase(self):
        from ghidra_agent.ioc_extractor import _is_camelcase_identifier
        assert _is_camelcase_identifier("33c6625cabcd") is False

    def test_plain_word_not_camelcase(self):
        from ghidra_agent.ioc_extractor import _is_camelcase_identifier
        assert _is_camelcase_identifier("malware") is False

    def test_ripemd_in_pki_substrings(self):
        """ripemd160WithRSA should be caught by _PKI_SUBSTRINGS too."""
        from ghidra_agent.ioc_extractor import _PKI_SUBSTRINGS
        assert _PKI_SUBSTRINGS.search("ripemd160WithRSA") is not None
