"""Tests for the Qiling dynamic analysis pipeline (qiling_graph.py)."""

from unittest.mock import AsyncMock, patch

import pytest

from ghidra_agent.state import AgentState
from tests.sample_data import SAMPLE_QILING_EXECUTION, SAMPLE_QILING_SYSCALLS


def _mock_ainvoke(return_value):
    return AsyncMock(return_value=return_value)


class TestQilingPipeline:
    @pytest.mark.asyncio
    async def test_populates_qiling_results(self, base_state: AgentState):
        execution = dict(SAMPLE_QILING_EXECUTION)
        execution["ok"] = True
        execution["success"] = True

        with patch("ghidra_agent.qiling_graph.qiling_emulate_binary") as m_exec, \
             patch("ghidra_agent.qiling_graph.qiling_trace_syscalls") as m_sys, \
             patch("ghidra_agent.qiling_graph.qiling_memory_analysis") as m_mem, \
             patch("ghidra_agent.qiling_graph.qiling_network_analysis") as m_net, \
             patch("ghidra_agent.qiling_graph.qiling_detect_evasion") as m_eva:
            m_exec.ainvoke = _mock_ainvoke(execution)
            m_sys.ainvoke = _mock_ainvoke(SAMPLE_QILING_SYSCALLS)
            m_mem.ainvoke = _mock_ainvoke({"ok": True, "success": True, "memory_events": {"events": []}})
            m_net.ainvoke = _mock_ainvoke({"ok": True, "success": True, "network_activity": {"connections": []}})
            m_eva.ainvoke = _mock_ainvoke({"ok": True, "success": True, "evasion_techniques": {"techniques": []}})

            from ghidra_agent.qiling_graph import run_qiling_pipeline
            result = await run_qiling_pipeline(base_state)

        assert result["qiling_analysis_results"]["execution_trace"]["success"] is True
        assert result["qiling_analysis_results"]["syscalls"]["ok"] is True
        assert "events" in result["qiling_analysis_results"]["memory_events"]
        assert "memory_events" not in result["qiling_analysis_results"]["memory_events"]
        assert "techniques" in result["qiling_analysis_results"]["evasion_techniques"]
        assert "evasion_techniques" not in result["qiling_analysis_results"]["evasion_techniques"]
        assert "qiling_discovery_completed" in result["reasoning_trace"]

    @pytest.mark.asyncio
    async def test_emulation_failure_short_circuits(self, base_state: AgentState):
        with patch("ghidra_agent.qiling_graph.qiling_emulate_binary") as m_exec:
            m_exec.ainvoke = _mock_ainvoke({"ok": False, "success": False, "error": "rootfs missing"})

            from ghidra_agent.qiling_graph import run_qiling_pipeline
            result = await run_qiling_pipeline(base_state)

        ql = result["qiling_analysis_results"]
        assert ql["execution_trace"]["ok"] is False
        assert "errors" in ql
        assert "rootfs missing" in ql["errors"][0]

    @pytest.mark.asyncio
    async def test_windows_binary_runs_api_trace(self, base_state: AgentState):
        with patch("ghidra_agent.qiling_graph.qiling_emulate_binary") as m_exec, \
             patch("ghidra_agent.qiling_graph.qiling_trace_syscalls") as m_sys, \
             patch("ghidra_agent.qiling_graph.qiling_memory_analysis") as m_mem, \
             patch("ghidra_agent.qiling_graph.qiling_network_analysis") as m_net, \
             patch("ghidra_agent.qiling_graph.qiling_detect_evasion") as m_eva, \
             patch("ghidra_agent.qiling_graph.qiling_trace_api_calls") as m_api:
            m_exec.ainvoke = _mock_ainvoke(
                {"ok": True, "success": True, "os": "windows", "binary_format": "pe", "arch": "x86"}
            )
            m_sys.ainvoke = _mock_ainvoke({"ok": True, "success": True, "summary": {}})
            m_mem.ainvoke = _mock_ainvoke({"ok": True, "success": True})
            m_net.ainvoke = _mock_ainvoke({"ok": True, "success": True})
            m_eva.ainvoke = _mock_ainvoke({"ok": True, "success": True})
            m_api.ainvoke = _mock_ainvoke({"ok": True, "success": True, "api_calls": []})

            from ghidra_agent.qiling_graph import run_qiling_pipeline
            result = await run_qiling_pipeline(base_state)

        assert "api_calls" in result["qiling_analysis_results"]
        assert result["qiling_analysis_results"]["api_calls"]["ok"] is True
        assert "events" in result["qiling_analysis_results"]["memory_events"]
        assert "indicators" in result["qiling_analysis_results"]["memory_events"]
