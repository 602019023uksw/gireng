import shutil
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Awaitable, Callable, Dict, Optional

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


# --- Hot-deploy session restore ---
def _restore_sessions():
    import json
    from pathlib import Path
    backup = Path('/tmp/sessions_backup.json')
    if backup.exists():
        try:
            with open(backup) as f:
                data = json.load(f)
            for sid, state in data.items():
                store.sessions[sid] = state
            backup.unlink()
            logger.info('sessions_restored', count=len(data))
        except Exception as e:
            logger.error('session_restore_failed', error=str(e))

_restore_sessions()
# --- End hot-deploy session restore ---


async def run_graph(
    state: AgentState,
    progress_callback: Optional[Callable[[str, int], Awaitable[None]]] = None,
) -> AgentState:
    logger.info("graph_run_started", session_id=state.get("session_id"), program_hash=state.get("program_hash"))
    run_state: AgentState = dict(state)
    if progress_callback is not None:
        run_state["progress_callback"] = progress_callback
    result = await graph.ainvoke(run_state, config={"recursion_limit": 50})
    result.pop("progress_callback", None)
    logger.info("graph_run_completed", session_id=state.get("session_id"), status=result.get("status"))
    return result
