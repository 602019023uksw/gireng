import shutil
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Dict

from ghidra_agent.config import settings
from ghidra_agent.graph import graph
from ghidra_agent.logging import logger
from ghidra_agent.state import AgentState, DEFAULT_STATE
from ghidra_agent.utils import compute_sha256, ensure_directory, safe_basename


class SessionStore:
    def __init__(self) -> None:
        self.sessions: Dict[str, AgentState] = {}

    def create_session(self, binary_path: str) -> AgentState:
        session_id = str(uuid.uuid4())
        path = Path(binary_path)
        shared_root = Path(settings.ghidra_shared_root)
        ensure_directory(shared_root)
        if not str(path).startswith(str(shared_root)):
            target_path = shared_root / safe_basename(path.name)
            shutil.copy2(path, target_path)
            path = target_path
        program_hash = compute_sha256(path)
        state: AgentState = {
            **deepcopy(DEFAULT_STATE),
            "binary_path": str(path),
            "program_hash": program_hash,
            "session_id": session_id,
        }
        self.sessions[session_id] = state
        return state

    def get_session(self, session_id: str) -> AgentState:
        if session_id not in self.sessions:
            raise KeyError(f"Session not found: {session_id}")
        return self.sessions[session_id]

    def update_session(self, session_id: str, state: AgentState) -> None:
        self.sessions[session_id] = state


store = SessionStore()


async def run_graph(state: AgentState) -> AgentState:
    logger.info("graph_run_started", session_id=state.get("session_id"), program_hash=state.get("program_hash"))
    result = await graph.ainvoke(state)
    logger.info("graph_run_completed", session_id=state.get("session_id"), status=result.get("status"))
    return result
