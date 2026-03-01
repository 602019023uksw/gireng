"""Tests for API endpoints — focuses on dual-analyzer (Ghidra + R2) responses."""

import asyncio
from copy import deepcopy
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from ghidra_agent.state import DEFAULT_STATE
from tests.sample_data import (
    SAMPLE_BINARY_INFO_GHIDRA,
    SAMPLE_BINARY_INFO_R2,
    SAMPLE_CALL_GRAPH,
    SAMPLE_CALL_GRAPH_ANALYSIS,
    SAMPLE_DECOMPILE_R2,
    SAMPLE_FUNCTIONS_GHIDRA,
    SAMPLE_FUNCTIONS_R2,
    SAMPLE_HASH,
    SAMPLE_QILING_RESULTS,
    SAMPLE_STRINGS_GHIDRA,
    SAMPLE_STRINGS_R2,
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
        "call_graph": deepcopy(SAMPLE_CALL_GRAPH),
        "call_graph_analysis": deepcopy(SAMPLE_CALL_GRAPH_ANALYSIS),
    }
    state["decompilation_cache"] = {"main": "int main() { return 0; }"}
    state["r2_analysis_results"] = {
        "binary": deepcopy(SAMPLE_BINARY_INFO_R2),
        "functions": deepcopy(SAMPLE_FUNCTIONS_R2),
        "strings": deepcopy(SAMPLE_STRINGS_R2),
        "call_graph": deepcopy(SAMPLE_CALL_GRAPH),
        "call_graph_analysis": deepcopy(SAMPLE_CALL_GRAPH_ANALYSIS),
    }
    state["r2_decompilation_cache"] = {"main": SAMPLE_DECOMPILE_R2["c"]}
    state["qiling_analysis_results"] = deepcopy(SAMPLE_QILING_RESULTS)
    state["qiling_execution_cache"] = deepcopy(SAMPLE_QILING_RESULTS)
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
    async def test_returns_all_available_analyzers(self, client: AsyncClient):
        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}/analyzers")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        ids = [a["id"] for a in data]
        assert "ghidra" in ids
        assert "radare2" in ids
        assert "qiling" in ids

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
    async def test_analyzer_detail_qiling(self, client: AsyncClient):
        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}/analyzers/qiling")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "qiling"
        assert data["name"] == "Qiling Dynamic Analysis Agent"

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

    @pytest.mark.asyncio
    async def test_status_omits_runtime_progress_callback(self, client: AsyncClient, mock_store):
        state = mock_store.sessions["test-session"]
        state["progress_callback"] = "runtime-only"

        resp = await client.get("/status/test-session")
        assert resp.status_code == 200
        data = resp.json()
        assert "progress_callback" not in data["state"]


class TestAnalysisInfoEndpoint:
    @pytest.mark.asyncio
    async def test_analysis_info_includes_active_analyzers(self, client: AsyncClient):
        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["analyzer"] == "multi"
        assert "ghidra" in data["analyzers"]
        assert "radare2" in data["analyzers"]
        assert "qiling" in data["analyzers"]


class TestExportEndpoints:
    @pytest.mark.asyncio
    async def test_export_html(self, client: AsyncClient):
        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}/export/html")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "<!DOCTYPE html>" in resp.text or "<html" in resp.text
        assert "Qiling Dynamic Analysis" in resp.text

    @pytest.mark.asyncio
    async def test_export_text(self, client: AsyncClient):
        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}/export/text")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]
        assert "GHIDRA + RADARE2 + QILING BINARY ANALYSIS REPORT" in resp.text
        assert "QILING DYNAMIC ANALYSIS" in resp.text


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

    @pytest.mark.asyncio
    async def test_summary_report_includes_call_graph_sections(self, client: AsyncClient):
        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}/reports/summary")
        assert resp.status_code == 200
        content = resp.json()["content"]
        assert "Ghidra Call Graph & Attack Chains" in content
        assert "Radare2 Call Graph & Attack Chains" in content
        assert "Qiling Dynamic Highlights" in content

    @pytest.mark.asyncio
    async def test_qiling_report_endpoint(self, client: AsyncClient):
        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}/reports/qiling_summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "qiling_summary"
        assert "Qiling Dynamic Analysis Report" in data["content"]
        assert "Execution Trace" in data["content"]


class TestAgentExportEndpoints:
    @pytest.mark.asyncio
    async def test_export_agent_qiling_html(self, client: AsyncClient):
        resp = await client.get("/export/session/test-session/agent/qiling")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "Qiling Analysis Report" in resp.text
        assert "Runtime Overview" in resp.text
        assert "Syscalls" in resp.text

    @pytest.mark.asyncio
    async def test_export_agent_invalid(self, client: AsyncClient):
        resp = await client.get("/export/session/test-session/agent/invalid-agent")
        assert resp.status_code == 400
        assert "Invalid agent" in resp.text


class TestRawResultsEndpoints:
    @pytest.mark.asyncio
    async def test_ghidra_results_include_call_graph(self, client: AsyncClient):
        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}/results/ghidra")
        assert resp.status_code == 200
        data = resp.json()
        assert data["analyzer"] == "ghidra"
        assert data["call_graph"]["ok"] is True
        assert data["call_graph_analysis"]["ok"] is True

    @pytest.mark.asyncio
    async def test_radare2_results_include_call_graph(self, client: AsyncClient):
        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}/results/radare2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["analyzer"] == "radare2"
        assert data["call_graph"]["ok"] is True
        assert data["call_graph_analysis"]["ok"] is True

    @pytest.mark.asyncio
    async def test_qiling_results_include_dynamic_sections(self, client: AsyncClient):
        resp = await client.get(f"/api/analysis/{SAMPLE_HASH}/results/qiling")
        assert resp.status_code == 200
        data = resp.json()
        assert data["analyzer"] == "qiling"
        assert "execution_trace" in data
        assert "syscalls" in data


class TestProgressEventSmoke:
    @pytest.mark.asyncio
    async def test_run_with_events_emits_analyzer_progress_payload(self, mock_store):
        from ghidra_agent.api.main import _run_with_events

        session_state = _populated_state()
        session_state["session_id"] = "smoke-progress-session"
        session_state["status"] = "initialized"
        mock_store.sessions[session_state["session_id"]] = session_state
        mock_store.get_session = MagicMock(side_effect=lambda sid: mock_store.sessions[sid])
        mock_store.update_session = MagicMock(
            side_effect=lambda sid, st: mock_store.sessions.__setitem__(sid, st)
        )

        sent_events: list[dict] = []

        async def _capture_broadcast(_session_id: str, payload: dict):
            sent_events.append(payload)

        async def _fake_run_graph(state: dict, progress_callback):
            state["analyzer_progress"] = {"ghidra": 55, "radare2": 48, "qiling": 62}
            state["analyzer_status"] = {"ghidra": "running", "radare2": "running", "qiling": "running"}
            state["analyzer_step"] = {
                "ghidra": "decompiling_functions",
                "radare2": "r2_decompiling",
                "qiling": "qiling_parallel_analysis",
            }
            await progress_callback("qiling_parallel_analysis", 62)
            state["status"] = "completed"
            state["analyzer_status"] = {"ghidra": "completed", "radare2": "completed", "qiling": "completed"}
            state["analyzer_progress"] = {"ghidra": 100, "radare2": 100, "qiling": 100}
            state["analyzer_step"] = {
                "ghidra": "analysis_completed",
                "radare2": "r2_discovery_completed",
                "qiling": "qiling_discovery_completed",
            }
            return state

        with patch("ghidra_agent.api.main.manager.broadcast", side_effect=_capture_broadcast), \
             patch("ghidra_agent.api.main.run_graph", side_effect=_fake_run_graph), \
             patch("ghidra_agent.api.main.db.save_verdict", new_callable=AsyncMock), \
             patch("ghidra_agent.api.main.db.save_normalized", new_callable=AsyncMock):
            await _run_with_events(session_state)
            await asyncio.sleep(0)

        progress_events = [e for e in sent_events if e.get("type") == "analysis:progress"]
        completed_events = [e for e in sent_events if e.get("type") == "analysis:completed"]

        assert progress_events, "Expected at least one analysis:progress event"
        assert completed_events, "Expected analysis:completed event"

        first_progress = progress_events[0]["payload"]
        assert "analyzer_progress" in first_progress
        assert "analyzer_status" in first_progress
        assert "analyzer_step" in first_progress

        final_payload = completed_events[-1]["payload"]
        assert final_payload["analyzer_progress"]["qiling"] == 100
        assert final_payload["analyzer_status"]["qiling"] == "completed"
