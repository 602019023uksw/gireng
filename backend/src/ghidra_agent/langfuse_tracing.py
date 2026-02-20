"""Langfuse tracing integration for LangGraph node-level observability.

Provides two layers of tracing:
1. **LangGraph level** – a LangChain ``CallbackHandler`` passed to
   ``graph.ainvoke()`` that records every node start/end as Langfuse spans.
2. **LLM level** – metadata dict threaded via ``contextvars`` so that
   ``litellm.acompletion()`` calls are nested under the same Langfuse trace
   (via LiteLLM's built-in langfuse callback).
"""

from __future__ import annotations

import contextvars
import os
import uuid
from typing import Any, Dict, Optional, Tuple

from ghidra_agent.config import settings
from ghidra_agent.logging import logger

# ---------------------------------------------------------------------------
# Context variables – propagate trace info through async graph execution
# ---------------------------------------------------------------------------
_trace_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "langfuse_trace_id", default=""
)
_session_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "langfuse_session_id", default=""
)


# ---------------------------------------------------------------------------
# Handler creation (LangGraph level)
# ---------------------------------------------------------------------------
def create_langfuse_handler(
    session_id: str = "",
    program_hash: str = "",
    trace_name: str = "binary-analysis",
    user_id: str = "",
) -> Tuple[Any, str]:
    """Create a Langfuse LangChain ``CallbackHandler`` for LangGraph tracing.

    Returns ``(handler, trace_id)``.  ``handler`` is ``None`` when Langfuse
    is not configured or the import fails.
    """
    if not settings.langfuse_enabled:
        return None, ""

    pk = settings.langfuse_public_key or os.environ.get("LANGFUSE_PUBLIC_KEY", "")
    sk = settings.langfuse_secret_key or os.environ.get("LANGFUSE_SECRET_KEY", "")
    host = settings.langfuse_host or os.environ.get("LANGFUSE_HOST", "")

    if not pk or not sk:
        return None, ""

    try:
        from langfuse.callback import CallbackHandler  # type: ignore[import-untyped]
    except ImportError:
        logger.warning("langfuse_callback_import_failed")
        return None, ""

    trace_id = str(uuid.uuid4())

    try:
        handler = CallbackHandler(
            public_key=pk,
            secret_key=sk,
            host=host or "https://cloud.langfuse.com",
            trace_name=trace_name,
            session_id=session_id,
            user_id=user_id,
            trace_id=trace_id,
            metadata={
                "program_hash": program_hash,
                "session_id": session_id,
            },
            tags=["langgraph", "binary-analysis"],
        )
        logger.info(
            "langfuse_handler_created",
            trace_id=trace_id,
            session_id=session_id,
        )
        return handler, trace_id
    except Exception as exc:
        logger.warning("langfuse_handler_create_failed", error=str(exc))
        return None, ""


# ---------------------------------------------------------------------------
# Context management – set / reset / read trace context
# ---------------------------------------------------------------------------
def set_trace_context(
    trace_id: str, session_id: str = ""
) -> Tuple[contextvars.Token, contextvars.Token]:
    """Store trace identifiers in the current async context."""
    t1 = _trace_id_var.set(trace_id)
    t2 = _session_id_var.set(session_id)
    return t1, t2


def reset_trace_context(
    tokens: Tuple[contextvars.Token, contextvars.Token],
) -> None:
    """Restore previous trace context after a graph run."""
    _trace_id_var.reset(tokens[0])
    _session_id_var.reset(tokens[1])


def get_trace_metadata(generation_name: str = "") -> Dict[str, Any]:
    """Build a metadata dict that links a LiteLLM call to the active trace.

    Pass the returned dict as ``metadata=`` to ``call_llm()`` /
    ``litellm.acompletion()``.  The LiteLLM Langfuse callback will nest the
    LLM generation under the current LangGraph trace.
    """
    trace_id = _trace_id_var.get("")
    session_id = _session_id_var.get("")

    if not trace_id:
        return {}

    meta: Dict[str, Any] = {"trace_id": trace_id}
    if session_id:
        meta["session_id"] = session_id
    if generation_name:
        meta["generation_name"] = generation_name
    return meta


# ---------------------------------------------------------------------------
# Standalone trace helpers (for one-off LLM calls outside the graph)
# ---------------------------------------------------------------------------
def create_standalone_trace_metadata(
    session_id: str = "",
    trace_name: str = "",
    generation_name: str = "",
    program_hash: str = "",
) -> Dict[str, Any]:
    """Metadata for a LLM call that is *not* part of a LangGraph run.

    Used by the ``/query`` endpoint and other ad-hoc calls so they still
    appear as independent Langfuse traces with proper session linkage.
    """
    if not settings.langfuse_enabled:
        return {}

    meta: Dict[str, Any] = {}
    if trace_name:
        meta["trace_name"] = trace_name
    if session_id:
        meta["session_id"] = session_id
    if generation_name:
        meta["generation_name"] = generation_name
    if program_hash:
        meta["trace_metadata"] = {"program_hash": program_hash}
    return meta
