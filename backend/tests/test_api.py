"""Tests for API endpoints — focuses on dual-analyzer (Ghidra + R2) responses."""

from copy import deepcopy
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from ghidra_agent.state import DEFAULT_STATE
import ghidra_agent.api.main  # ensure module is loaded for mock.patch

from tests.sample_data import (
    SAMPLE_HASH,
    SAMPLE_BINARY_INFO_GHIDRA,
    SAMPLE_BINARY_INFO_R2,
    SAMPLE_FUNCTIONS_GHIDRA,
    SAMPLE_FUNCTIONS_R2,
    SAMPLE_STRINGS_GHIDRA,
    SAMPLE_STRINGS_R2,
    SAMPLE_DECOMPILE_R2,
)


def _populated_state():
    state = deepcopy(DEFAULT_STATE)
    state["session_id"] = "test-session"
    state["program_hash"] = SAMPLE_HASH
    state["binary_path"] = "/data/shared/test_binary"
    state["status"] = "completed"
    state["summary"] = "Test summary"
    state["analysis_results"] = {
        "binary": deepcopy(SAMPLE_BINARY_INFO_GHIDRA),
        "functions": deepcopy(SAMPLE_FUNCTIONS_GHIDRA),
        "strings": deepcopy(SAMPLE_STRINGS_GHIDRA),
    }
    state["decompilation_cache"] = {"main": "int main() { return 0; }"}
    state["r2_analysis_results"] = {
        "binary": deepcopy(SAMPLE_BINARY_INFO_R2),
        "functions": deepcopy(SAMPLE_FUNCTIONS_R2),
        "strings": deepcopy(SAMPLE_STRINGS_R2),
    }
    state["r2_decompilation_cache"] = {"main": SAMPLE_DECOMPILE_R2["c"]}
    return state


@pytest.fixture
def mock_store():
    """Patch the session store with a pre-populated session."""
    state = _populated_state()
    with patch("ghidra_agent.api.main.store") as mock_s:
        mock_s.sessions = {"test-session": state}
        mock_s.get_session = MagicMock(return_value=state)
        yield mock_s


@pytest_asyncio.fixture
async def client(mock_store):
    from ghidra_agent.api.main import app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestAnalyzersEndpoint:
    @pytest.mark.asyncio
    async def test_returns_both_analyzers(self, client: AsyncClient):
        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}/analyzers")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        ids = [a["id"] for a in data]
        assert "ghidra" in ids
        assert "radare2" in ids

    @pytest.mark.asyncio
    async def test_ghidra_only_when_no_r2(self, client: AsyncClient, mock_store):
        # Remove R2 results
        state = mock_store.sessions["test-session"]
        state["r2_analysis_results"] = {}
        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}/analyzers")
        data = resp.json()
        ids = [a["id"] for a in data]
        assert "ghidra" in ids
        assert "radare2" not in ids

    @pytest.mark.asyncio
    async def test_analyzer_detail_ghidra(self, client: AsyncClient):
        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}/analyzers/ghidra")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "ghidra"
        assert data["name"] == "Ghidra Reverse Engineer Agent"
        assert "details" in data

    @pytest.mark.asyncio
    async def test_analyzer_detail_radare2(self, client: AsyncClient):
        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}/analyzers/radare2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "radare2"
        assert data["name"] == "Radare2 Reverse Engineer Agent"

    @pytest.mark.asyncio
    async def test_analyzer_detail_unknown(self, client: AsyncClient):
        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}/analyzers/unknown")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_not_found_hash(self, client: AsyncClient):
        resp = await client.get("/api/analysis/nonexistent/analyzers")
        assert resp.status_code == 404


class TestStatusEndpoint:
    @pytest.mark.asyncio
    async def test_status(self, client: AsyncClient):
        resp = await client.get("/status/test-session")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"


class TestExportEndpoints:
    @pytest.mark.asyncio
    async def test_export_html(self, client: AsyncClient):
        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}/export/html")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "<!DOCTYPE html>" in resp.text or "<html" in resp.text

    @pytest.mark.asyncio
    async def test_export_text(self, client: AsyncClient):
        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}/export/text")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]


class TestReportsEndpoint:
    @pytest.mark.asyncio
    async def test_r2_report_contains_function_addresses(self, client: AsyncClient):
        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}/reports/r2_summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "r2_summary"
        content = data["content"]
        assert "## Functions Discovered" in content
        assert "`main` at `0x401000`" in content
        assert "`sym.send_data` at `0x401200`" in content
        assert "`0x0`" not in content

    @pytest.mark.asyncio
    async def test_r2_report_falls_back_to_addr_or_offset(self, client: AsyncClient, mock_store):
        state = mock_store.sessions["test-session"]
        state["r2_analysis_results"]["functions"]["functions"] = [
            {"name": "main", "addr": 0x401000, "size": 256},
            {"name": "sym.send_data", "offset": 0x401200, "size": 128},
        ]

        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}/reports/r2_summary")
        assert resp.status_code == 200
        content = resp.json()["content"]
        assert "`main` at `0x401000`" in content
        assert "`sym.send_data` at `0x401200`" in content
