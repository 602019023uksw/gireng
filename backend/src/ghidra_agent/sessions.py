import asyncio
import shutil
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Awaitable, Callable, Dict, Optional

from ghidra_agent.config import settings
from ghidra_agent.graph import graph
from ghidra_agent.langfuse_tracing import (
    create_langfuse_handler,
    reset_trace_context,
    set_trace_context,
)
from ghidra_agent.logging import logger
from ghidra_agent.state import DEFAULT_STATE, AgentState
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
        # Persist to DB (fire-and-forget)
        self._persist(state)
        return state

    def get_session(self, session_id: str) -> AgentState:
        if session_id not in self.sessions:
            raise KeyError(f"Session not found: {session_id}")
        return self.sessions[session_id]

    def update_session(self, session_id: str, state: AgentState) -> None:
        self.sessions[session_id] = state
        # Persist to DB (fire-and-forget)
        self._persist(state)

    async def load_session_from_db(self, session_id: str) -> AgentState:
        """Load a past session from the database into memory."""
        from ghidra_agent.database import load_state_json
        state_data = await load_state_json(session_id)
        if state_data is None:
            raise KeyError(f"Session not found in database: {session_id}")
        # Merge with defaults for any missing keys
        state: AgentState = {**deepcopy(DEFAULT_STATE), **state_data}
        state["progress_callback"] = None
        self.sessions[session_id] = state
        return state

    def _persist(self, state: AgentState) -> None:
        """Schedule async DB write without blocking the caller."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self._do_persist(state))
        except RuntimeError:
            # No event loop running — skip async persistence
            pass

    @staticmethod
    async def _do_persist(state: AgentState) -> None:
        try:
            from ghidra_agent.database import save_analysis
            await save_analysis(state)
        except Exception as exc:
            logger.error("db_persist_failed", error=str(exc))


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
                merged = dict(DEFAULT_STATE)
                merged.update(state)
                store.sessions[sid] = merged
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
    session_id = state.get("session_id", "")
    program_hash = state.get("program_hash", "")
    logger.info("graph_run_started", session_id=session_id, program_hash=program_hash)

    run_state: AgentState = dict(state)
    if progress_callback is not None:
        run_state["progress_callback"] = progress_callback

    # --- Langfuse: create a LangChain callback handler for node-level tracing ---
    handler, trace_id = create_langfuse_handler(
        session_id=session_id,
        program_hash=program_hash,
        trace_name="binary-analysis",
    )
    callbacks = [handler] if handler else []
    config = {"recursion_limit": 50}
    if callbacks:
        config["callbacks"] = callbacks  # type: ignore[assignment]

    # Set context vars so that call_llm() inside nodes links to the same trace
    tokens = set_trace_context(trace_id, session_id) if trace_id else None
    try:
        result = await graph.ainvoke(run_state, config=config)
    finally:
        if tokens:
            reset_trace_context(tokens)

    result.pop("progress_callback", None)
    logger.info("graph_run_completed", session_id=session_id, status=result.get("status"), langfuse_trace_id=trace_id or "disabled")
    return result
