"""Tests for Radare2 @tool functions (r2_tools.py)."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ghidra_agent.radare.runner import R2TaskResult

# We'll import tools after patching settings
_SETTINGS_PATCH = {
    "r2_container_name": "radare2",
    "r2_shared_root": "/data/shared",
    "r2_timeout": 30,
    "docker_cli_path": "/usr/bin/docker",
}


def _ok_json(data) -> R2TaskResult:
    return R2TaskResult(ok=True, payload={"json": data, "raw": json.dumps(data)})


def _ok_raw(text: str) -> R2TaskResult:
    return R2TaskResult(ok=True, payload={"raw": text})


def _err(msg: str = "fail") -> R2TaskResult:
    return R2TaskResult(ok=False, payload={}, error=msg)


def _make_mock_runner():
    """Create a mock runner with default detect_decompilers returning the full chain."""
    m = MagicMock()
    m.run_command = AsyncMock()
    m.run_json_command = AsyncMock()
    m.detect_decompilers = AsyncMock(return_value=["pdg", "pdd", "pdf"])
    m.verify_container = AsyncMock(return_value=True)
    return m


@pytest.fixture(autouse=True)
def _patch_settings():
    """Patch settings before r2_tools is imported."""
    with patch("ghidra_agent.radare.runner.settings") as mock_s:
        for k, v in _SETTINGS_PATCH.items():
            setattr(mock_s, k, v)
        with patch("ghidra_agent.r2_tools.settings", mock_s, create=True):
            yield


TOOL_ARGS = {
    "session_id": "sess-1",
    "program_hash": "abc123",
    "binary_path": "/data/shared/test_bin",
}


class TestR2AnalyzeBinary:
    @pytest.mark.asyncio
    async def test_success(self):
        from ghidra_agent.r2_tools import r2_analyze_binary

        binary_info = {"arch": "x86", "bits": 64, "os": "linux", "bintype": "elf",
                       "compiler": "gcc", "baddr": 0x400000, "endian": "little",
                       "stripped": False, "static": False}
        sections = [{"name": ".text"}, {"name": ".data"}]
        entries = [{"vaddr": 0x401000}]
        imports = [{"name": "printf"}, {"name": "malloc"}]
        exports = [{"name": "main"}, {"name": "handler"}]

        mock_runner = _make_mock_runner()
        mock_runner.run_json_command = AsyncMock(side_effect=[
            _ok_json(binary_info),  # aaa;iIj
            _ok_json(sections),     # iSj
            _ok_json(entries),      # iej
            _ok_json(imports),      # iij
            _ok_json(exports),      # iEj
        ])
        with patch("ghidra_agent.r2_tools.get_runner", return_value=mock_runner):
            result = await r2_analyze_binary.ainvoke(TOOL_ARGS)

        assert result["ok"] is True
        assert result["architecture"] == "x86"
        assert result["bits"] == 64
        assert ".text" in result["sections"]
        assert "0x401000" in result["entry_points"]
        assert "printf" in result["imports"]
        assert "main" in result["exports"]

    @pytest.mark.asyncio
    async def test_failure(self):
        from ghidra_agent.r2_tools import r2_analyze_binary

        mock_runner = _make_mock_runner()
        mock_runner.run_json_command = AsyncMock(return_value=_err("container down"))
        with patch("ghidra_agent.r2_tools.get_runner", return_value=mock_runner):
            result = await r2_analyze_binary.ainvoke(TOOL_ARGS)

        assert result["ok"] is False
        assert "container down" in result["error"]


class TestR2ListFunctions:
    @pytest.mark.asyncio
    async def test_success(self):
        from ghidra_agent.r2_tools import r2_list_functions

        funcs = [
            {"name": "main", "offset": 0x401000, "size": 256, "nrefsTo": 3, "nrefsFrom": 2, "calltype": "amd64"},
            {"name": "sym.helper", "offset": 0x401200, "size": 64, "nrefsTo": 1, "nrefsFrom": 0, "calltype": "amd64"},
        ]
        mock_runner = _make_mock_runner()
        mock_runner.run_json_command = AsyncMock(return_value=_ok_json(funcs))
        with patch("ghidra_agent.r2_tools.get_runner", return_value=mock_runner):
            result = await r2_list_functions.ainvoke(TOOL_ARGS)

        assert result["ok"] is True
        assert len(result["functions"]) == 2
        assert result["functions"][0]["name"] == "main"
        assert result["functions"][0]["xrefs"] == 3  # nrefsTo only (B6 fix)

    @pytest.mark.asyncio
    async def test_not_a_list(self):
        from ghidra_agent.r2_tools import r2_list_functions

        mock_runner = _make_mock_runner()
        mock_runner.run_json_command = AsyncMock(return_value=_ok_json({"unexpected": True}))
        with patch("ghidra_agent.r2_tools.get_runner", return_value=mock_runner):
            result = await r2_list_functions.ainvoke(TOOL_ARGS)

        assert result["ok"] is False


class TestR2DecompileFunction:
    @pytest.mark.asyncio
    async def test_pdg_success(self):
        from ghidra_agent.r2_tools import r2_decompile_function

        mock_runner = _make_mock_runner()
        mock_runner.run_command = AsyncMock(return_value=_ok_raw("int main() { return 0; }"))
        with patch("ghidra_agent.r2_tools.get_runner", return_value=mock_runner):
            result = await r2_decompile_function.ainvoke({
                **TOOL_ARGS, "function_name": "main",
            })

        assert result["ok"] is True
        assert "main" in result["c"]
        assert result["decompiler"] == "pdg"

    @pytest.mark.asyncio
    async def test_fallback_to_pdd(self):
        from ghidra_agent.r2_tools import r2_decompile_function

        mock_runner = _make_mock_runner()
        mock_runner.run_command = AsyncMock(side_effect=[
            _ok_raw(""),                # pdg returns empty
            _ok_raw("void func() {}"),  # pdd returns code
        ])
        with patch("ghidra_agent.r2_tools.get_runner", return_value=mock_runner):
            result = await r2_decompile_function.ainvoke({
                **TOOL_ARGS, "function_name": "func",
            })

        assert result["ok"] is True
        assert result["decompiler"] == "pdd"

    @pytest.mark.asyncio
    async def test_all_fail(self):
        from ghidra_agent.r2_tools import r2_decompile_function

        mock_runner = _make_mock_runner()
        mock_runner.run_command = AsyncMock(return_value=_ok_raw(""))
        with patch("ghidra_agent.r2_tools.get_runner", return_value=mock_runner):
            result = await r2_decompile_function.ainvoke({
                **TOOL_ARGS, "function_name": "missing",
            })

        assert result["ok"] is False


class TestR2FindStrings:
    @pytest.mark.asyncio
    async def test_success(self):
        from ghidra_agent.r2_tools import r2_find_strings

        raw_strings = [
            {"string": "hello world", "vaddr": 0x402000, "length": 11, "section": ".rodata", "type": "ascii"},
            {"string": "ab", "vaddr": 0x402020, "length": 2, "section": ".rodata", "type": "ascii"},  # too short
        ]
        mock_runner = _make_mock_runner()
        mock_runner.run_json_command = AsyncMock(return_value=_ok_json(raw_strings))
        with patch("ghidra_agent.r2_tools.get_runner", return_value=mock_runner):
            result = await r2_find_strings.ainvoke(TOOL_ARGS)

        assert result["ok"] is True
        assert len(result["strings"]) == 1  # "ab" filtered out (< 4 chars)
        assert result["strings"][0]["value"] == "hello world"

    @pytest.mark.asyncio
    async def test_query_filter(self):
        from ghidra_agent.r2_tools import r2_find_strings

        raw_strings = [
            {"string": "http://evil.com", "vaddr": 0x402000, "length": 15, "section": ".rodata", "type": "ascii"},
            {"string": "/etc/passwd", "vaddr": 0x402020, "length": 11, "section": ".rodata", "type": "ascii"},
        ]
        mock_runner = _make_mock_runner()
        mock_runner.run_json_command = AsyncMock(return_value=_ok_json(raw_strings))
        with patch("ghidra_agent.r2_tools.get_runner", return_value=mock_runner):
            result = await r2_find_strings.ainvoke({**TOOL_ARGS, "query": "http"})

        assert result["ok"] is True
        assert len(result["strings"]) == 1
        assert "http" in result["strings"][0]["value"]


class TestR2FindXrefs:
    @pytest.mark.asyncio
    async def test_success(self):
        from ghidra_agent.r2_tools import r2_find_xrefs

        xrefs = [
            {"from": 0x401050, "type": "CALL", "opcode": "call 0x401000"},
        ]
        mock_runner = _make_mock_runner()
        mock_runner.run_json_command = AsyncMock(return_value=_ok_json(xrefs))
        with patch("ghidra_agent.r2_tools.get_runner", return_value=mock_runner):
            result = await r2_find_xrefs.ainvoke({**TOOL_ARGS, "address": "0x401000"})

        assert result["ok"] is True
        assert len(result["to"]) == 1
        assert result["to"][0]["type"] == "CALL"


class TestR2DisassembleAt:
    @pytest.mark.asyncio
    async def test_success(self):
        from ghidra_agent.r2_tools import r2_disassemble_at

        instrs = [
            {"offset": 0x401000, "mnemonic": "push", "opcode": "push rbp", "bytes": "55", "size": 1},
            {"offset": 0x401001, "mnemonic": "mov", "opcode": "mov rbp, rsp", "bytes": "4889e5", "size": 3},
        ]
        mock_runner = _make_mock_runner()
        mock_runner.run_json_command = AsyncMock(return_value=_ok_json(instrs))
        with patch("ghidra_agent.r2_tools.get_runner", return_value=mock_runner):
            result = await r2_disassemble_at.ainvoke({**TOOL_ARGS, "address": "0x401000", "count": 10})

        assert result["ok"] is True
        assert len(result["instructions"]) == 2
        assert result["instructions"][0]["mnemonic"] == "push"


class TestR2SyscallAnalysis:
    @pytest.mark.asyncio
    async def test_success(self):
        from ghidra_agent.r2_tools import r2_syscall_analysis

        raw = [
            {"name": "read", "sysnum": 0, "addr": 0x401050},
            {"name": "write", "sysnum": 1, "addr": 0x401060},
        ]
        mock_runner = _make_mock_runner()
        mock_runner.run_json_command = AsyncMock(return_value=_ok_json(raw))
        with patch("ghidra_agent.r2_tools.get_runner", return_value=mock_runner):
            result = await r2_syscall_analysis.ainvoke(TOOL_ARGS)

        assert result["ok"] is True
        assert len(result["syscalls"]) == 2
        assert result["syscalls"][0]["name"] == "read"


class TestR2BuildCallGraph:
    @pytest.mark.asyncio
    async def test_success(self):
        from ghidra_agent.r2_tools import r2_build_call_graph

        # agCj returns nodes with imports arrays (callees)
        agcj_data = [
            {"name": "main", "offset": 0x401000, "size": 256, "imports": ["sym.worker", "sym.imp.connect"]},
            {"name": "sym.worker", "offset": 0x401100, "size": 128, "imports": ["sym.imp.send"]},
        ]
        mock_runner = _make_mock_runner()
        mock_runner.run_json_command = AsyncMock(
            side_effect=[
                _ok_json(agcj_data),                 # aaa;agCj
                _ok_json([{"vaddr": 0x401000}]),     # iej
            ]
        )
        with patch("ghidra_agent.r2_tools.get_runner", return_value=mock_runner):
            result = await r2_build_call_graph.ainvoke(TOOL_ARGS)

        assert result["ok"] is True
        assert len(result["nodes"]) >= 4  # main, worker, connect, send
        assert any(e["from_name"] == "main" and e["to_name"] == "sym.worker" for e in result["edges"])
        assert any("sym.imp.connect" in e["to_name"] for e in result["edges"])
        assert any("sym.imp.send" in e["to_name"] for e in result["edges"])
        assert "0x401000" in result["entry_points"]

    @pytest.mark.asyncio
    async def test_failure(self):
        from ghidra_agent.r2_tools import r2_build_call_graph

        mock_runner = _make_mock_runner()
        mock_runner.run_json_command = AsyncMock(return_value=_err("agCj failed"))
        with patch("ghidra_agent.r2_tools.get_runner", return_value=mock_runner):
            result = await r2_build_call_graph.ainvoke(TOOL_ARGS)

        assert result["ok"] is False
        assert "agCj failed" in result["error"]
