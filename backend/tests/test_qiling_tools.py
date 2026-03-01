"""Tests for Qiling @tool functions (qiling_tools.py)."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ghidra_agent.qiling.runner import QilingTaskResult


def _ok(payload):
    return QilingTaskResult(ok=True, payload=payload)


def _err(msg: str = "fail"):
    return QilingTaskResult(ok=False, payload={}, error=msg)


TOOL_ARGS = {
    "session_id": "sess-1",
    "program_hash": "abc123",
    "binary_path": "/data/shared/test_bin",
}


class TestQilingTools:
    @pytest.fixture(autouse=True)
    def _patch_path_exists(self):
        with patch.object(Path, "exists", return_value=True):
            yield

    @pytest.mark.asyncio
    async def test_emulate_binary_success(self):
        from ghidra_agent.qiling_tools import qiling_emulate_binary

        mock_runner = MagicMock()
        mock_runner.run_script = AsyncMock(return_value=_ok({"ok": True, "success": True, "arch": "x86_64"}))
        with patch("ghidra_agent.qiling_tools.get_runner", return_value=mock_runner):
            result = await qiling_emulate_binary.ainvoke(TOOL_ARGS)

        assert result["ok"] is True
        assert result["arch"] == "x86_64"

    @pytest.mark.asyncio
    async def test_trace_syscalls_success(self):
        from ghidra_agent.qiling_tools import qiling_trace_syscalls

        payload = {
            "ok": True,
            "success": True,
            "syscalls": [{"name": "open"}],
            "summary": {"total_calls": 1},
        }
        mock_runner = MagicMock()
        mock_runner.run_script = AsyncMock(return_value=_ok(payload))
        with patch("ghidra_agent.qiling_tools.get_runner", return_value=mock_runner):
            result = await qiling_trace_syscalls.ainvoke(TOOL_ARGS)

        assert result["ok"] is True
        assert result["summary"]["total_calls"] == 1

    @pytest.mark.asyncio
    async def test_handles_runner_error(self):
        from ghidra_agent.qiling_tools import qiling_network_analysis

        mock_runner = MagicMock()
        mock_runner.run_script = AsyncMock(return_value=_err("container down"))
        with patch("ghidra_agent.qiling_tools.get_runner", return_value=mock_runner):
            result = await qiling_network_analysis.ainvoke(TOOL_ARGS)

        assert result["ok"] is False
        assert "container down" in result["error"]

    @pytest.mark.asyncio
    async def test_verify_qiling_ready(self):
        from ghidra_agent.qiling_tools import verify_qiling_ready

        mock_runner = MagicMock()
        mock_runner.container = "qiling_emulator"
        mock_runner.verify_container = AsyncMock(return_value=True)
        with patch("ghidra_agent.qiling_tools.get_runner", return_value=mock_runner):
            status = await verify_qiling_ready()

        assert status["ready"] is True
        assert status["container"] == "qiling_emulator"

