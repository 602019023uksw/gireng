"""Tests for Radare2Runner — the Docker exec wrapper."""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from ghidra_agent.radare.runner import R2TaskResult, Radare2Runner

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_process(stdout: str = "", stderr: str = "", returncode: int = 0):
    """Build a mock asyncio.subprocess result."""
    proc = AsyncMock()
    proc.communicate = AsyncMock(return_value=(
        stdout.encode(),
        stderr.encode(),
    ))
    proc.returncode = returncode
    return proc


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestR2TaskResult:
    def test_ok_result(self):
        r = R2TaskResult(ok=True, payload={"raw": "hello"})
        assert r.ok is True
        assert r.error is None
        assert r.payload["raw"] == "hello"

    def test_error_result(self):
        r = R2TaskResult(ok=False, payload={}, error="boom")
        assert r.ok is False
        assert r.error == "boom"


class TestRadare2Runner:
    @pytest.fixture(autouse=True)
    def _patch_settings(self):
        with patch("ghidra_agent.radare.runner.settings") as mock_s:
            mock_s.r2_container_name = "radare2"
            mock_s.r2_shared_root = "/data/shared"
            mock_s.r2_timeout = 30
            mock_s.docker_cli_path = "/usr/bin/docker"
            self.runner = Radare2Runner()
            yield

    @pytest.mark.asyncio
    async def test_run_command_success(self):
        proc = _make_process(stdout="OK output")
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await self.runner.run_command(Path("/data/shared/bin"), "aaa;iIj")
        assert result.ok is True
        assert result.payload["raw"] == "OK output"

    @pytest.mark.asyncio
    async def test_run_command_nonzero_exit(self):
        proc = _make_process(stdout="partial", stderr="error msg", returncode=1)
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await self.runner.run_command(Path("/data/shared/bin"), "bad_cmd")
        assert result.ok is False
        assert "exited with code 1" in result.error

    @pytest.mark.asyncio
    async def test_run_command_timeout(self):
        async def _hang(*a, **kw):
            proc = AsyncMock()
            proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
            proc.returncode = -1
            return proc

        with patch("asyncio.create_subprocess_exec", side_effect=_hang):
            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError):
                result = await self.runner.run_command(Path("/data/shared/bin"), "aaa", timeout=1)
        assert result.ok is False
        assert "timeout" in result.error.lower()

    @pytest.mark.asyncio
    async def test_run_command_exception(self):
        with patch("asyncio.create_subprocess_exec", side_effect=OSError("docker not found")):
            result = await self.runner.run_command(Path("/data/shared/bin"), "aaa")
        assert result.ok is False
        assert "docker not found" in result.error

    @pytest.mark.asyncio
    async def test_run_json_command_parses_json(self):
        sample_json = json.dumps([{"name": "main", "offset": 0x401000}])
        proc = _make_process(stdout=sample_json)
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await self.runner.run_json_command(Path("/data/shared/bin"), "aflj")
        assert result.ok is True
        assert "json" in result.payload
        assert result.payload["json"][0]["name"] == "main"

    @pytest.mark.asyncio
    async def test_run_json_command_with_prefix_noise(self):
        """R2 sometimes prints warnings before JSON."""
        noisy_output = "WARNING: something\n" + json.dumps({"arch": "x86"})
        proc = _make_process(stdout=noisy_output)
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await self.runner.run_json_command(Path("/data/shared/bin"), "iIj")
        assert result.ok is True
        assert result.payload["json"]["arch"] == "x86"

    @pytest.mark.asyncio
    async def test_run_json_command_unparseable(self):
        """If output is not JSON at all, return raw text."""
        proc = _make_process(stdout="not json at all")
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await self.runner.run_json_command(Path("/data/shared/bin"), "pd 10")
        assert result.ok is True
        assert "json" not in result.payload
        assert result.payload["raw"] == "not json at all"

    @pytest.mark.asyncio
    async def test_run_json_command_propagates_error(self):
        """If underlying run_command fails, run_json_command returns the error."""
        proc = _make_process(returncode=1, stderr="fail")
        with patch("asyncio.create_subprocess_exec", return_value=proc):
            result = await self.runner.run_json_command(Path("/data/shared/bin"), "bad")
        assert result.ok is False

    def test_binary_path_in_container(self):
        out = self.runner._binary_path_in_container(Path("/data/shared/my_binary"))
        assert out == "/data/shared/my_binary"

    def test_binary_path_in_container_nested(self):
        out = self.runner._binary_path_in_container(Path("/some/other/path/sample.exe"))
        assert out == "/data/shared/sample.exe"
