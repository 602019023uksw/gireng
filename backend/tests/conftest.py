"""Shared fixtures for Radare2 + Ghidra agent tests."""

import sys
from copy import deepcopy
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Stub out heavy dependencies that aren't installed in the test venv
# (must happen before any ghidra_agent submodule import pulls them in)
# ---------------------------------------------------------------------------
for _mod in ("litellm",):
    sys.modules.setdefault(_mod, MagicMock())

from ghidra_agent.state import DEFAULT_STATE, AgentState
from tests.sample_data import (
    SAMPLE_BINARY_INFO_GHIDRA,
    SAMPLE_BINARY_INFO_R2,
    SAMPLE_DECOMPILE_R2,
    SAMPLE_FUNCTIONS_GHIDRA,
    SAMPLE_FUNCTIONS_R2,
    SAMPLE_HASH,
    SAMPLE_QILING_RESULTS,
    SAMPLE_STRINGS_GHIDRA,
    SAMPLE_STRINGS_R2,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def base_state() -> AgentState:
    """Return a clean AgentState with a fake session / hash pre-filled."""
    state = deepcopy(DEFAULT_STATE)
    state["session_id"] = "test-session-001"
    state["program_hash"] = SAMPLE_HASH
    state["binary_path"] = "/data/shared/test_binary"
    return state


@pytest.fixture
def populated_state(base_state: AgentState) -> AgentState:
    """State with both Ghidra and R2 results pre-populated."""
    base_state["analysis_results"] = {
        "binary": deepcopy(SAMPLE_BINARY_INFO_GHIDRA),
        "functions": deepcopy(SAMPLE_FUNCTIONS_GHIDRA),
        "strings": deepcopy(SAMPLE_STRINGS_GHIDRA),
    }
    base_state["decompilation_cache"] = {
        "main": "int main() { return 0; }",
    }
    base_state["r2_analysis_results"] = {
        "binary": deepcopy(SAMPLE_BINARY_INFO_R2),
        "functions": deepcopy(SAMPLE_FUNCTIONS_R2),
        "strings": deepcopy(SAMPLE_STRINGS_R2),
    }
    base_state["r2_decompilation_cache"] = {
        "main": SAMPLE_DECOMPILE_R2["c"],
    }
    base_state["qiling_analysis_results"] = deepcopy(SAMPLE_QILING_RESULTS)
    base_state["qiling_execution_cache"] = deepcopy(SAMPLE_QILING_RESULTS)
    base_state["status"] = "completed"
    base_state["summary"] = "Test malware analysis summary."
    return base_state
