"""End-to-end integration test — simulates a full dual-agent analysis flow.

Mocks Docker/subprocess calls but exercises the real pipeline logic:
  parse_intent → initialize → discovery (Ghidra ∥ R2) → focus → xref → synthesize
"""

from copy import deepcopy
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from ghidra_agent.state import AgentState, DEFAULT_STATE
import ghidra_agent.graph  # ensure module is loaded for mock.patch
import ghidra_agent.r2_graph  # ensure module is loaded for mock.patch

from tests.sample_data import (
    SAMPLE_HASH,
    SAMPLE_BINARY_INFO_GHIDRA,
    SAMPLE_BINARY_INFO_R2,
    SAMPLE_CALL_GRAPH,
    SAMPLE_FUNCTIONS_GHIDRA,
    SAMPLE_FUNCTIONS_R2,
    SAMPLE_STRINGS_GHIDRA,
    SAMPLE_STRINGS_R2,
    SAMPLE_DECOMPILE_R2,
    SAMPLE_XREFS_R2,
    SAMPLE_DISASM_R2,
)


def _mock_r2_runner(container_alive=True, decompilers=None):
    """Create a mock R2 runner that passes the pre-flight container check."""
    runner = MagicMock()
    runner.verify_container = AsyncMock(return_value=container_alive)
    runner.detect_decompilers = AsyncMock(return_value=decompilers or ["pdg", "pdd", "pdf"])
    return runner


def _fresh_state() -> AgentState:
    state = deepcopy(DEFAULT_STATE)
    state["session_id"] = "e2e-session"
    state["program_hash"] = SAMPLE_HASH
    state["binary_path"] = "/data/shared/test_binary"
    state["user_query"] = ""
    return state


# ---------------------------------------------------------------------------
# Ghidra tool mocks
# ---------------------------------------------------------------------------

def _ghidra_tool_mocks():
    """Return a dict of patchers for Ghidra tools used in graph.py."""
    return {
        "ghidra_agent.graph.analyze_binary_structure": AsyncMock(
            ainvoke=AsyncMock(return_value=SAMPLE_BINARY_INFO_GHIDRA)),
        "ghidra_agent.graph.list_functions": AsyncMock(
            ainvoke=AsyncMock(return_value=SAMPLE_FUNCTIONS_GHIDRA)),
        "ghidra_agent.graph.build_call_graph": AsyncMock(
            ainvoke=AsyncMock(return_value=SAMPLE_CALL_GRAPH)),
        "ghidra_agent.graph.find_strings": AsyncMock(
            ainvoke=AsyncMock(return_value=SAMPLE_STRINGS_GHIDRA)),
        "ghidra_agent.graph.decompile_function": AsyncMock(
            ainvoke=AsyncMock(return_value={"ok": True, "c": "int main(){return 0;}"})),
        "ghidra_agent.graph.find_xrefs": AsyncMock(
            ainvoke=AsyncMock(return_value=SAMPLE_XREFS_R2)),
        "ghidra_agent.graph.get_function_graph": AsyncMock(
            ainvoke=AsyncMock(return_value={"ok": True, "graph": {}})),
        "ghidra_agent.graph.disassemble_at": AsyncMock(
            ainvoke=AsyncMock(return_value=SAMPLE_DISASM_R2)),
        "ghidra_agent.graph.search_bytes": AsyncMock(
            ainvoke=AsyncMock(return_value={"ok": True, "matches": []})),
    }


# ---------------------------------------------------------------------------
# R2 tool mocks
# ---------------------------------------------------------------------------

def _r2_tool_mocks():
    """Return a dict of patchers for R2 tools used in r2_graph.py."""
    return {
        "ghidra_agent.r2_graph.r2_analyze_binary": AsyncMock(
            ainvoke=AsyncMock(return_value=SAMPLE_BINARY_INFO_R2)),
        "ghidra_agent.r2_graph.r2_list_functions": AsyncMock(
            ainvoke=AsyncMock(return_value=SAMPLE_FUNCTIONS_R2)),
        "ghidra_agent.r2_graph.r2_build_call_graph": AsyncMock(
            ainvoke=AsyncMock(return_value=SAMPLE_CALL_GRAPH)),
        "ghidra_agent.r2_graph.r2_find_strings": AsyncMock(
            ainvoke=AsyncMock(return_value=SAMPLE_STRINGS_R2)),
        "ghidra_agent.r2_graph.r2_decompile_function": AsyncMock(
            ainvoke=AsyncMock(return_value=SAMPLE_DECOMPILE_R2)),
        "ghidra_agent.r2_graph.r2_find_xrefs": AsyncMock(
            ainvoke=AsyncMock(return_value=SAMPLE_XREFS_R2)),
        "ghidra_agent.r2_graph.r2_disassemble_at": AsyncMock(
            ainvoke=AsyncMock(return_value=SAMPLE_DISASM_R2)),
        "ghidra_agent.r2_graph.r2_syscall_analysis": AsyncMock(
            ainvoke=AsyncMock(return_value={"ok": True, "syscalls": []})),
    }


class TestE2EDualAgentFlow:
    """Exercises the full graph from parse_intent through synthesize,
    with both Ghidra and R2 running in parallel during discovery."""

    @pytest.mark.asyncio
    async def test_full_analysis_no_query(self):
        """Initial upload flow — no user query, full discovery + synthesize."""
        state = _fresh_state()

        ghidra_mocks = _ghidra_tool_mocks()
        r2_mocks = _r2_tool_mocks()
        all_mocks = {**ghidra_mocks, **r2_mocks}

        with patch.multiple("", **{k: v for k, v in all_mocks.items()}, create=True) if False else \
             _multi_patch(all_mocks):

            # Also mock the LLM
            with patch("ghidra_agent.graph.call_llm", new_callable=AsyncMock) as mock_llm, \
                 patch("ghidra_agent.r2_tools.get_runner", return_value=_mock_r2_runner()), \
                 patch("ghidra_agent.radare.runner.Radare2Runner", return_value=_mock_r2_runner()):
                mock_llm.return_value = "## 1. Executive Summary\nThis is a test malware.\n## 2. Malware Capabilities\n- Network"

                from ghidra_agent.graph import (
                    parse_intent, initialize_ghidra, discovery, synthesize
                )

                state = await parse_intent(state)
                assert state["intent"] == "reconnaissance"

                state = await initialize_ghidra(state)
                assert "ghidra_initialized" in state["reasoning_trace"]
                assert "r2_initialized" in state["reasoning_trace"]

                state = await discovery(state)

                # Verify Ghidra results
                assert state["analysis_results"]["binary"]["ok"] is True
                assert state["analysis_results"]["functions"]["ok"] is True
                assert state["analysis_results"]["strings"]["ok"] is True
                assert state["analysis_results"]["call_graph"]["ok"] is True
                assert state["analysis_results"]["call_graph_analysis"]["ok"] is True
                assert state["analysis_results"]["iocs"]["ok"] is True

                # Verify R2 results
                assert state["r2_analysis_results"]["binary"]["ok"] is True
                assert state["r2_analysis_results"]["functions"]["ok"] is True
                assert state["r2_analysis_results"]["strings"]["ok"] is True
                assert state["r2_analysis_results"]["call_graph"]["ok"] is True
                assert state["r2_analysis_results"]["call_graph_analysis"]["ok"] is True
                assert state["r2_analysis_results"]["syscalls"]["ok"] is True
                assert "discovery_completed" in state["reasoning_trace"]

                # Both should have decompiled functions
                assert len(state["decompilation_cache"]) > 0
                assert len(state["r2_decompilation_cache"]) > 0

                state = await synthesize(state)

                assert state["status"] == "completed"
                assert state["summary"] != ""
                assert "synthesized" in state["reasoning_trace"]

                # LLM should have been called with R2 context
                call_args = mock_llm.call_args[0][0]
                assert "RADARE2" in call_args or "R2" in call_args

    @pytest.mark.asyncio
    async def test_malware_query_flow(self):
        """User query triggers malware intent."""
        state = _fresh_state()
        state["user_query"] = "analyze this malware sample"

        ghidra_mocks = _ghidra_tool_mocks()
        r2_mocks = _r2_tool_mocks()
        all_mocks = {**ghidra_mocks, **r2_mocks}

        with _multi_patch(all_mocks):
            with patch("ghidra_agent.graph.call_llm", new_callable=AsyncMock) as mock_llm, \
                 patch("ghidra_agent.r2_tools.get_runner", return_value=_mock_r2_runner()), \
                 patch("ghidra_agent.radare.runner.Radare2Runner", return_value=_mock_r2_runner()):
                mock_llm.return_value = "This is malware analysis."

                from ghidra_agent.graph import parse_intent, initialize_ghidra, discovery, synthesize

                state = await parse_intent(state)
                assert state["intent"] == "malware"

                state = await initialize_ghidra(state)
                state = await discovery(state)
                state = await synthesize(state)

                assert state["status"] == "completed"

    @pytest.mark.asyncio
    async def test_r2_failure_does_not_block_ghidra(self):
        """If R2 container is down, Ghidra analysis still completes."""
        state = _fresh_state()

        ghidra_mocks = _ghidra_tool_mocks()
        r2_mocks = {
            "ghidra_agent.r2_graph.r2_analyze_binary": AsyncMock(
                ainvoke=AsyncMock(side_effect=Exception("container not running"))),
            "ghidra_agent.r2_graph.r2_list_functions": AsyncMock(
                ainvoke=AsyncMock(side_effect=Exception("container not running"))),
            "ghidra_agent.r2_graph.r2_build_call_graph": AsyncMock(
                ainvoke=AsyncMock(side_effect=Exception("container not running"))),
            "ghidra_agent.r2_graph.r2_find_strings": AsyncMock(
                ainvoke=AsyncMock(side_effect=Exception("container not running"))),
            "ghidra_agent.r2_graph.r2_decompile_function": AsyncMock(
                ainvoke=AsyncMock(side_effect=Exception("container not running"))),
            "ghidra_agent.r2_graph.r2_find_xrefs": AsyncMock(
                ainvoke=AsyncMock(return_value=SAMPLE_XREFS_R2)),
            "ghidra_agent.r2_graph.r2_disassemble_at": AsyncMock(
                ainvoke=AsyncMock(return_value=SAMPLE_DISASM_R2)),
        }
        all_mocks = {**ghidra_mocks, **r2_mocks}

        with _multi_patch(all_mocks):
            with patch("ghidra_agent.graph.call_llm", new_callable=AsyncMock) as mock_llm, \
                 patch("ghidra_agent.r2_tools.get_runner", return_value=_mock_r2_runner(container_alive=False)), \
                 patch("ghidra_agent.radare.runner.Radare2Runner", return_value=_mock_r2_runner(container_alive=False)):
                mock_llm.return_value = "Analysis with Ghidra only."

                from ghidra_agent.graph import parse_intent, initialize_ghidra, discovery, synthesize

                state = await parse_intent(state)
                state = await initialize_ghidra(state)
                state = await discovery(state)

                # Ghidra should still have succeeded
                assert state["analysis_results"]["binary"]["ok"] is True
                assert state["analysis_results"]["functions"]["ok"] is True

                # R2 should have failed gracefully — container was down so skipped
                assert "r2_unavailable" in state["reasoning_trace"]
                # R2 pipeline was skipped, so r2_analysis_results stays empty
                assert state["r2_analysis_results"] == {} or \
                       "error" in state["r2_analysis_results"] or \
                       state["r2_analysis_results"].get("binary", {}).get("ok") is False

                state = await synthesize(state)
                assert state["status"] == "completed"

    @pytest.mark.asyncio
    async def test_focus_function_flow(self):
        """Query targeting a specific function goes through focus + xref."""
        state = _fresh_state()
        state["user_query"] = "analyze FUN_00401200"

        ghidra_mocks = _ghidra_tool_mocks()
        r2_mocks = _r2_tool_mocks()
        all_mocks = {**ghidra_mocks, **r2_mocks}

        with _multi_patch(all_mocks):
            with patch("ghidra_agent.graph.call_llm", new_callable=AsyncMock) as mock_llm, \
                 patch("ghidra_agent.r2_tools.get_runner", return_value=_mock_r2_runner()), \
                 patch("ghidra_agent.radare.runner.Radare2Runner", return_value=_mock_r2_runner()):
                mock_llm.return_value = "Function FUN_00401200 analysis."

                from ghidra_agent.graph import (
                    parse_intent, initialize_ghidra, discovery,
                    focus_analysis, cross_reference, synthesize
                )

                state = await parse_intent(state)
                assert state["current_function"] == "FUN_00401200"
                assert state["current_address"] == "0x00401200"

                state = await initialize_ghidra(state)
                state = await discovery(state)
                state = await focus_analysis(state)
                assert "focus_analysis_completed" in state["reasoning_trace"]

                state = await cross_reference(state)
                assert "cross_reference_completed" in state["reasoning_trace"]

                state = await synthesize(state)
                assert state["status"] == "completed"


class TestUiAdapterDualAgent:
    """Tests that ui_adapter produces correct responses for both analyzers."""

    def test_ghidra_response(self, populated_state):
        from ghidra_agent.ui_adapter import build_analyzer_response
        resp = build_analyzer_response(populated_state, "ghidra")
        assert resp["id"] == "ghidra"
        assert resp["name"] == "Ghidra Reverse Engineer Agent"
        assert "details" in resp
        assert "executiveSummary" in resp["details"]

    def test_radare2_response(self, populated_state):
        from ghidra_agent.ui_adapter import build_analyzer_response
        resp = build_analyzer_response(populated_state, "radare2")
        assert resp["id"] == "radare2"
        assert resp["name"] == "Radare2 Reverse Engineer Agent"
        assert "details" in resp
        assert "staticAnalysis" in resp["details"]

    def test_default_is_ghidra(self, populated_state):
        from ghidra_agent.ui_adapter import build_analyzer_response
        resp = build_analyzer_response(populated_state)
        assert resp["id"] == "ghidra"


class TestStateIntegrity:
    """Verify R2 fields in AgentState and DEFAULT_STATE."""

    def test_default_state_has_r2_fields(self):
        assert "r2_analysis_results" in DEFAULT_STATE
        assert "r2_decompilation_cache" in DEFAULT_STATE
        assert isinstance(DEFAULT_STATE["r2_analysis_results"], dict)
        assert isinstance(DEFAULT_STATE["r2_decompilation_cache"], dict)

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


class TestPromptsDualAgent:
    """Verify the system prompt references both Ghidra and Radare2."""

    def test_prompt_mentions_both_tools(self):
        from ghidra_agent.prompts import SYSTEM_PROMPT
        assert "Ghidra" in SYSTEM_PROMPT or "GHIDRA" in SYSTEM_PROMPT
        assert "Radare2" in SYSTEM_PROMPT or "RADARE2" in SYSTEM_PROMPT
        assert "Cross-reference" in SYSTEM_PROMPT or "cross-reference" in SYSTEM_PROMPT


class TestConfigR2Settings:
    """Verify R2 settings are available in config."""

    def test_r2_settings_exist(self):
        from ghidra_agent.config import Settings
        s = Settings()
        assert hasattr(s, "r2_container_name")
        assert hasattr(s, "r2_shared_root")
        assert hasattr(s, "r2_timeout")
        assert s.r2_container_name == "radare2"
        assert s.r2_timeout == 60


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

from contextlib import contextmanager

@contextmanager
def _multi_patch(patches: dict):
    """Apply multiple patches at once from a dict of {target: mock}."""
    import unittest.mock
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
