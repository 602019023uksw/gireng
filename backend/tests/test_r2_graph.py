"""Tests for the Radare2 LangGraph pipeline (r2_graph.py)."""

from unittest.mock import AsyncMock, patch

import pytest

from ghidra_agent.state import AgentState
from tests.sample_data import (
    SAMPLE_BINARY_INFO_R2,
    SAMPLE_CALL_GRAPH,
    SAMPLE_DECOMPILE_R2,
    SAMPLE_DISASM_R2,
    SAMPLE_FUNCTIONS_R2,
    SAMPLE_STRINGS_R2,
    SAMPLE_XREFS_R2,
)


def _mock_ainvoke(return_value):
    """Build an AsyncMock suitable for tool.ainvoke()."""
    m = AsyncMock(return_value=return_value)
    return m


class TestR2Discovery:
    @pytest.mark.asyncio
    async def test_populates_r2_results(self, base_state: AgentState):
        with patch("ghidra_agent.r2_graph.r2_analyze_binary") as m_bin, \
             patch("ghidra_agent.r2_graph.r2_list_functions") as m_fn, \
             patch("ghidra_agent.r2_graph.r2_build_call_graph") as m_cg, \
             patch("ghidra_agent.r2_graph.r2_find_strings") as m_str, \
             patch("ghidra_agent.r2_graph.r2_syscall_analysis") as m_sys, \
             patch("ghidra_agent.r2_graph.r2_decompile_function") as m_dec:

            m_bin.ainvoke = _mock_ainvoke(SAMPLE_BINARY_INFO_R2)
            m_fn.ainvoke = _mock_ainvoke(SAMPLE_FUNCTIONS_R2)
            m_cg.ainvoke = _mock_ainvoke(SAMPLE_CALL_GRAPH)
            m_str.ainvoke = _mock_ainvoke(SAMPLE_STRINGS_R2)
            m_sys.ainvoke = _mock_ainvoke({"ok": True, "syscalls": []})
            m_dec.ainvoke = _mock_ainvoke(SAMPLE_DECOMPILE_R2)

            from ghidra_agent.r2_graph import r2_discovery
            result = await r2_discovery(base_state)

        assert result["r2_analysis_results"]["binary"]["ok"] is True
        assert result["r2_analysis_results"]["functions"]["ok"] is True
        assert "priority_weights" in result["r2_analysis_results"]["functions"]
        assert all(
            "priority_score" in f
            for f in result["r2_analysis_results"]["functions"]["functions"]
        )
        assert result["r2_analysis_results"]["call_graph"]["ok"] is True
        assert result["r2_analysis_results"]["call_graph_analysis"]["ok"] is True
        assert result["r2_analysis_results"]["strings"]["ok"] is True
        assert result["r2_analysis_results"]["syscalls"]["ok"] is True
        assert "r2_discovery_completed" in result["reasoning_trace"]

    @pytest.mark.asyncio
    async def test_handles_binary_failure(self, base_state: AgentState):
        with patch("ghidra_agent.r2_graph.r2_analyze_binary") as m_bin, \
             patch("ghidra_agent.r2_graph.r2_list_functions") as m_fn, \
             patch("ghidra_agent.r2_graph.r2_build_call_graph") as m_cg, \
             patch("ghidra_agent.r2_graph.r2_find_strings") as m_str, \
             patch("ghidra_agent.r2_graph.r2_syscall_analysis") as m_sys, \
             patch("ghidra_agent.r2_graph.r2_decompile_function") as m_dec:

            m_bin.ainvoke = _mock_ainvoke({"ok": False, "error": "container down"})
            m_fn.ainvoke = _mock_ainvoke(SAMPLE_FUNCTIONS_R2)
            m_cg.ainvoke = _mock_ainvoke(SAMPLE_CALL_GRAPH)
            m_str.ainvoke = _mock_ainvoke(SAMPLE_STRINGS_R2)
            m_sys.ainvoke = _mock_ainvoke({"ok": True, "syscalls": []})
            m_dec.ainvoke = _mock_ainvoke(SAMPLE_DECOMPILE_R2)

            from ghidra_agent.r2_graph import r2_discovery
            result = await r2_discovery(base_state)

        assert result["r2_analysis_results"]["binary"]["ok"] is False
        assert "r2_binary_structure_failed" in result["r2_analysis_results"].get("errors", [])

    @pytest.mark.asyncio
    async def test_auto_decompiles_top_functions(self, base_state: AgentState):
        with patch("ghidra_agent.r2_graph.r2_analyze_binary") as m_bin, \
             patch("ghidra_agent.r2_graph.r2_list_functions") as m_fn, \
             patch("ghidra_agent.r2_graph.r2_build_call_graph") as m_cg, \
             patch("ghidra_agent.r2_graph.r2_find_strings") as m_str, \
             patch("ghidra_agent.r2_graph.r2_syscall_analysis") as m_sys, \
             patch("ghidra_agent.r2_graph.r2_decompile_function") as m_dec:

            m_bin.ainvoke = _mock_ainvoke(SAMPLE_BINARY_INFO_R2)
            m_fn.ainvoke = _mock_ainvoke(SAMPLE_FUNCTIONS_R2)
            m_cg.ainvoke = _mock_ainvoke(SAMPLE_CALL_GRAPH)
            m_str.ainvoke = _mock_ainvoke(SAMPLE_STRINGS_R2)
            m_sys.ainvoke = _mock_ainvoke({"ok": True, "syscalls": []})
            m_dec.ainvoke = _mock_ainvoke(SAMPLE_DECOMPILE_R2)

            from ghidra_agent.r2_graph import r2_discovery
            result = await r2_discovery(base_state)

        # Should have decompiled at least some functions
        assert len(result["r2_decompilation_cache"]) > 0
        assert any("r2_auto_decompiled" in t for t in result["reasoning_trace"])


class TestR2FocusAnalysis:
    @pytest.mark.asyncio
    async def test_decompiles_target(self, base_state: AgentState):
        base_state["current_function"] = "main"

        with patch("ghidra_agent.r2_graph.r2_decompile_function") as m_dec, \
             patch("ghidra_agent.r2_graph.r2_disassemble_at") as m_dis:
            m_dec.ainvoke = _mock_ainvoke(SAMPLE_DECOMPILE_R2)
            m_dis.ainvoke = _mock_ainvoke(SAMPLE_DISASM_R2)

            from ghidra_agent.r2_graph import r2_focus_analysis
            result = await r2_focus_analysis(base_state)

        assert result["r2_analysis_results"]["focus"]["ok"] is True
        assert "main" in result["r2_decompilation_cache"]

    @pytest.mark.asyncio
    async def test_falls_back_to_disasm(self, base_state: AgentState):
        base_state["current_function"] = "missing_func"
        base_state["current_address"] = "0x401000"

        with patch("ghidra_agent.r2_graph.r2_decompile_function") as m_dec, \
             patch("ghidra_agent.r2_graph.r2_disassemble_at") as m_dis:
            m_dec.ainvoke = _mock_ainvoke({"ok": False, "error": "not found"})
            m_dis.ainvoke = _mock_ainvoke(SAMPLE_DISASM_R2)

            from ghidra_agent.r2_graph import r2_focus_analysis
            result = await r2_focus_analysis(base_state)

        assert result["r2_analysis_results"]["focus"]["ok"] is True

    @pytest.mark.asyncio
    async def test_no_target(self, base_state: AgentState):
        with patch("ghidra_agent.r2_graph.r2_decompile_function"), \
             patch("ghidra_agent.r2_graph.r2_disassemble_at"):
            from ghidra_agent.r2_graph import r2_focus_analysis
            result = await r2_focus_analysis(base_state)

        assert result["r2_analysis_results"]["focus"]["ok"] is False


class TestR2CrossReference:
    @pytest.mark.asyncio
    async def test_with_address(self, base_state: AgentState):
        base_state["current_address"] = "0x401000"

        with patch("ghidra_agent.r2_graph.r2_find_xrefs") as m_xref:
            m_xref.ainvoke = _mock_ainvoke(SAMPLE_XREFS_R2)

            from ghidra_agent.r2_graph import r2_cross_reference
            result = await r2_cross_reference(base_state)

        assert result["r2_analysis_results"]["xrefs"]["ok"] is True

    @pytest.mark.asyncio
    async def test_no_address(self, base_state: AgentState):
        with patch("ghidra_agent.r2_graph.r2_find_xrefs"):
            from ghidra_agent.r2_graph import r2_cross_reference
            result = await r2_cross_reference(base_state)

        assert "xrefs" not in result["r2_analysis_results"]
        assert "r2_xref_completed" in result["reasoning_trace"]


class TestRunR2Pipeline:
    @pytest.mark.asyncio
    async def test_full_pipeline_no_focus(self, base_state: AgentState):
        """Pipeline without a focus target runs only discovery."""
        with patch("ghidra_agent.r2_graph.r2_analyze_binary") as m_bin, \
             patch("ghidra_agent.r2_graph.r2_list_functions") as m_fn, \
             patch("ghidra_agent.r2_graph.r2_build_call_graph") as m_cg, \
             patch("ghidra_agent.r2_graph.r2_find_strings") as m_str, \
             patch("ghidra_agent.r2_graph.r2_syscall_analysis") as m_sys, \
             patch("ghidra_agent.r2_graph.r2_decompile_function") as m_dec:

            m_bin.ainvoke = _mock_ainvoke(SAMPLE_BINARY_INFO_R2)
            m_fn.ainvoke = _mock_ainvoke(SAMPLE_FUNCTIONS_R2)
            m_cg.ainvoke = _mock_ainvoke(SAMPLE_CALL_GRAPH)
            m_str.ainvoke = _mock_ainvoke(SAMPLE_STRINGS_R2)
            m_sys.ainvoke = _mock_ainvoke({"ok": True, "syscalls": []})
            m_dec.ainvoke = _mock_ainvoke(SAMPLE_DECOMPILE_R2)

            from ghidra_agent.r2_graph import run_r2_pipeline
            result = await run_r2_pipeline(base_state)

        assert "r2_discovery_completed" in result["reasoning_trace"]
        # No focus — so no r2_focus_completed
        assert "r2_focus_completed" not in result["reasoning_trace"]

    @pytest.mark.asyncio
    async def test_full_pipeline_with_focus(self, base_state: AgentState):
        base_state["current_function"] = "main"
        base_state["current_address"] = "0x401000"

        with patch("ghidra_agent.r2_graph.r2_analyze_binary") as m_bin, \
             patch("ghidra_agent.r2_graph.r2_list_functions") as m_fn, \
             patch("ghidra_agent.r2_graph.r2_build_call_graph") as m_cg, \
             patch("ghidra_agent.r2_graph.r2_find_strings") as m_str, \
             patch("ghidra_agent.r2_graph.r2_syscall_analysis") as m_sys, \
             patch("ghidra_agent.r2_graph.r2_decompile_function") as m_dec, \
             patch("ghidra_agent.r2_graph.r2_find_xrefs") as m_xref, \
             patch("ghidra_agent.r2_graph.r2_disassemble_at") as m_dis:

            m_bin.ainvoke = _mock_ainvoke(SAMPLE_BINARY_INFO_R2)
            m_fn.ainvoke = _mock_ainvoke(SAMPLE_FUNCTIONS_R2)
            m_cg.ainvoke = _mock_ainvoke(SAMPLE_CALL_GRAPH)
            m_str.ainvoke = _mock_ainvoke(SAMPLE_STRINGS_R2)
            m_sys.ainvoke = _mock_ainvoke({"ok": True, "syscalls": []})
            m_dec.ainvoke = _mock_ainvoke(SAMPLE_DECOMPILE_R2)
            m_xref.ainvoke = _mock_ainvoke(SAMPLE_XREFS_R2)
            m_dis.ainvoke = _mock_ainvoke(SAMPLE_DISASM_R2)

            from ghidra_agent.r2_graph import run_r2_pipeline
            result = await run_r2_pipeline(base_state)

        assert "r2_discovery_completed" in result["reasoning_trace"]
        assert "r2_focus_completed" in result["reasoning_trace"]
        assert "r2_xref_completed" in result["reasoning_trace"]
