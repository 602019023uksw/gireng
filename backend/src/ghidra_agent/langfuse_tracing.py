"""Langfuse tracing integration for LangGraph node-level observability.

Uses the **Langfuse v2 decorator API** (``@observe()``) for rich,
hierarchical traces.  Each graph node is wrapped with ``@observe()`` so
that it appears as a named span in Langfuse — complete with curated
**input/output**, **metadata**, and **tags**.

LiteLLM's built-in ``langfuse`` callback auto-nests ``generation``
observations under the active span (no extra wiring needed).

Trace structure produced by a full analysis run::

    binary-analysis                     ← root trace (session, user, env)
     ├─ parse_intent                    ← span  in: user_query  out: intent
     ├─ initialize_ghidra              ← span  in: binary_path out: status
     ├─ discovery                       ← span
     │   ├─ ghidra_discovery           ← span  in: binary_path out: counts
     │   └─ r2_pipeline                ← span  in: binary_path out: r2 info
     ├─ focus_analysis                 ← span  in: target      out: decompile
     ├─ cross_reference                ← span  in: target      out: xrefs
     └─ synthesize                     ← span  in: prompt_len  out: summary
          └─ litellm.acompletion        ← generation (auto)

References
----------
- Langfuse v2 decorator API: ``langfuse.decorators.observe``
- Langfuse context: ``langfuse.decorators.langfuse_context``
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

from ghidra_agent.config import settings
from ghidra_agent.logging import logger

# ---------------------------------------------------------------------------
# Lazy-init flag — set True once configure_langfuse() succeeds.
# ---------------------------------------------------------------------------
_langfuse_ready: bool = False

# Environment label — attached to every trace for filtering in the UI.
_environment: str = os.environ.get("LANGFUSE_ENVIRONMENT", "development")


def configure_langfuse() -> bool:
    """Initialise the Langfuse SDK (idempotent).

    Must be called once at startup (e.g. in ``_init_langfuse`` inside
    ``llm.py``).  Returns ``True`` if the SDK is usable.
    """
    global _langfuse_ready
    if _langfuse_ready:
        return True

    if not settings.langfuse_enabled:
        return False

    pk = settings.langfuse_public_key or os.environ.get("LANGFUSE_PUBLIC_KEY", "")
    sk = settings.langfuse_secret_key or os.environ.get("LANGFUSE_SECRET_KEY", "")
    host = settings.langfuse_host or os.environ.get("LANGFUSE_HOST", "")

    if not pk or not sk:
        return False

    # The decorator API reads credentials from env vars.
    os.environ.setdefault("LANGFUSE_PUBLIC_KEY", pk)
    os.environ.setdefault("LANGFUSE_SECRET_KEY", sk)
    if host:
        os.environ.setdefault("LANGFUSE_HOST", host)

    try:
        from langfuse.decorators import langfuse_context  # noqa: F401
        _langfuse_ready = True
        logger.info("langfuse_decorator_api_ready", host=host)
        return True
    except Exception as exc:
        logger.warning("langfuse_configure_failed", error=str(exc))
        return False


def is_langfuse_ready() -> bool:
    return _langfuse_ready


# ---------------------------------------------------------------------------
# Trace lifecycle — called from sessions.run_graph()
# ---------------------------------------------------------------------------
def begin_trace(
    session_id: str = "",
    program_hash: str = "",
    trace_name: str = "binary-analysis",
    user_id: str = "",
    input: Any = None,  # noqa: A002
) -> str:
    """Create the root Langfuse trace and update the decorator context.

    Returns the ``trace_id`` (empty string if Langfuse is disabled).
    Must be called inside an ``@observe()``-decorated function so that
    ``langfuse_context`` is active.
    """
    if not _langfuse_ready:
        return ""

    try:
        from langfuse.decorators import langfuse_context

        trace_kwargs: Dict[str, Any] = dict(
            name=trace_name,
            session_id=session_id or None,
            user_id=user_id or None,
            metadata={
                "program_hash": program_hash,
                "session_id": session_id,
                "environment": _environment,
            },
            tags=["langgraph", "binary-analysis", _environment],
        )
        if input is not None:
            trace_kwargs["input"] = input

        langfuse_context.update_current_trace(**trace_kwargs)

        trace_id = langfuse_context.get_current_trace_id() or ""
        logger.info(
            "langfuse_trace_started",
            trace_id=trace_id,
            session_id=session_id,
        )
        return trace_id
    except Exception as exc:
        logger.warning("langfuse_begin_trace_failed", error=str(exc))
        return ""


def end_trace(output: Any = None) -> None:
    """Set trace-level output before flushing (call after graph completes)."""
    if not _langfuse_ready:
        return
    try:
        from langfuse.decorators import langfuse_context

        if output is not None:
            langfuse_context.update_current_trace(output=output)
    except Exception:
        pass  # best-effort


def flush_trace() -> None:
    """Flush pending Langfuse events (call after graph completes)."""
    if not _langfuse_ready:
        return
    try:
        from langfuse.decorators import langfuse_context
        langfuse_context.flush()
    except Exception as exc:
        logger.warning("langfuse_flush_failed", error=str(exc))


# ---------------------------------------------------------------------------
# Span helpers — annotate the current @observe() span with extra data
# ---------------------------------------------------------------------------
def update_current_span(
    name: str | None = None,
    metadata: Dict[str, Any] | None = None,
    input: Any = None,  # noqa: A002 — matches Langfuse API name
    output: Any = None,
) -> None:
    """Update the currently-active ``@observe()`` span with richer data.

    Call early in a node function to set ``input``, and again at the end
    to set ``output``.  Langfuse captures the timing automatically.
    """
    if not _langfuse_ready:
        return
    try:
        from langfuse.decorators import langfuse_context
        kwargs: Dict[str, Any] = {}
        if name:
            kwargs["name"] = name
        if metadata:
            kwargs["metadata"] = metadata
        if input is not None:
            kwargs["input"] = input
        if output is not None:
            kwargs["output"] = output
        if kwargs:
            langfuse_context.update_current_observation(**kwargs)
    except Exception:
        pass  # best-effort


def score_current_trace(name: str, value: float, comment: str = "") -> None:
    """Attach a numeric score to the current trace (e.g. quality rating)."""
    if not _langfuse_ready:
        return
    try:
        from langfuse.decorators import langfuse_context
        langfuse_context.score_current_trace(
            name=name, value=value, comment=comment or None,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# get_trace_metadata — kept for backward compat with call_llm()
# ---------------------------------------------------------------------------
def get_trace_metadata(generation_name: str = "") -> Dict[str, Any]:
    """Return metadata dict that links a LiteLLM call to the active trace.

    With the ``@observe()`` approach the LiteLLM langfuse callback
    auto-nests under the current span, so this is mainly a safety net.
    """
    if not _langfuse_ready:
        return {}

    try:
        from langfuse.decorators import langfuse_context
        trace_id = langfuse_context.get_current_trace_id()
        if not trace_id:
            return {}

        meta: Dict[str, Any] = {
            "trace_id": trace_id,
            "trace_name": "binary-analysis",
        }
        obs_id = langfuse_context.get_current_observation_id()
        if obs_id:
            meta["parent_observation_id"] = obs_id
        if generation_name:
            meta["generation_name"] = generation_name
        return meta
    except Exception:
        return {}


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
    meta["tags"] = [_environment]
    return meta
