"""Tests for QilingRunner — the Docker exec wrapper for Qiling scripts."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from ghidra_agent.qiling.runner import QilingRunner, QilingTaskResult


class TestQilingRunner:
    @pytest.fixture(autouse=True)
    def _patch_settings(self, tmp_path: Path):
        with patch("ghidra_agent.qiling.runner.settings") as mock_s:
            mock_s.qiling_container_name = "qiling_emulator"
            mock_s.qiling_shared_root = str(tmp_path)
            mock_s.qiling_scripts_root = "/opt/qiling/scripts"
            mock_s.qiling_rootfs_base = "/opt/qiling/rootfs"
            mock_s.qiling_timeout = 30
            mock_s.docker_cli_path = "/usr/bin/docker"
            self.tmp_path = tmp_path
            self.runner = QilingRunner()
            yield

    @pytest.mark.asyncio
    async def test_verify_container_success(self):
        with patch.object(
            self.runner,
            "_docker_exec",
            AsyncMock(return_value=QilingTaskResult(ok=True, payload={"raw": "1.4.7"})),
        ):
            ok = await self.runner.verify_container()
        assert ok is True

    @pytest.mark.asyncio
    async def test_verify_container_failure(self):
        with patch.object(
            self.runner,
            "_docker_exec",
            AsyncMock(return_value=QilingTaskResult(ok=False, payload={}, error="down")),
        ):
            ok = await self.runner.verify_container()
        assert ok is False

    @pytest.mark.asyncio
    async def test_run_script_success(self):
        binary = self.tmp_path / "sample.bin"
        binary.write_bytes(b"\x7fELF\x02\x01\x01")

        async def _exec_side_effect(command, timeout):
            if command and command[0] == "python3":
                output_container = command[-1]
                output_host = self.tmp_path / Path(output_container).name
                output_host.write_text(json.dumps({"ok": True, "success": True, "value": 123}), encoding="utf-8")
            return QilingTaskResult(ok=True, payload={"raw": ""})

        with patch.object(self.runner, "_docker_exec", AsyncMock(side_effect=_exec_side_effect)):
            result = await self.runner.run_script("emulate_binary.py", binary)

        assert result.ok is True
        assert result.payload["ok"] is True
        assert result.payload["value"] == 123

    @pytest.mark.asyncio
    async def test_run_script_failure(self):
        binary = self.tmp_path / "sample.bin"
        binary.write_bytes(b"\x7fELF\x02\x01\x01")

        with patch.object(
            self.runner,
            "_docker_exec",
            AsyncMock(return_value=QilingTaskResult(ok=False, payload={}, error="exec failed")),
        ):
            result = await self.runner.run_script("emulate_binary.py", binary)

        assert result.ok is False
        assert "exec failed" in (result.error or "")

