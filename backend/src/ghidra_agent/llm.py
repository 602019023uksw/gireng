import asyncio
import os
from typing import Any, Dict
import litellm
from litellm import acompletion

from ghidra_agent.config import settings
from ghidra_agent.logging import logger

# Configurable via env; default bumped from 300→600 to accommodate large prompts
LLM_TIMEOUT_SECONDS = int(os.environ.get("LLM_TIMEOUT", "630"))
LLM_MAX_RETRIES = int(os.environ.get("LLM_MAX_RETRIES", "2"))

# ---------------------------------------------------------------------------
# Langfuse tracing – uses LiteLLM's built-in callback integration
# ---------------------------------------------------------------------------

def _init_langfuse() -> None:
    """Configure LiteLLM to send traces to Langfuse if credentials are set."""
    if not settings.langfuse_enabled:
        logger.info("langfuse_disabled")
        return

    pk = settings.langfuse_public_key or os.environ.get("LANGFUSE_PUBLIC_KEY", "")
    sk = settings.langfuse_secret_key or os.environ.get("LANGFUSE_SECRET_KEY", "")
    host = settings.langfuse_host or os.environ.get("LANGFUSE_HOST", "")

    if not pk or not sk:
        logger.warning("langfuse_no_credentials", hint="Set LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY to enable tracing")
        return

    # LiteLLM reads these env vars automatically for the langfuse callback
    os.environ.setdefault("LANGFUSE_PUBLIC_KEY", pk)
    os.environ.setdefault("LANGFUSE_SECRET_KEY", sk)
    if host:
        os.environ.setdefault("LANGFUSE_HOST", host)

    # Register the callback; LiteLLM handles the rest
    if "langfuse" not in litellm.success_callback:
        litellm.success_callback.append("langfuse")
    if "langfuse" not in litellm.failure_callback:
        litellm.failure_callback.append("langfuse")

    logger.info("langfuse_initialized", host=host)


# Run at module-load time so every LLM call is traced automatically
_init_langfuse()


async def _single_llm_call(prompt: str, timeout: int, metadata: Dict[str, Any] | None = None) -> str:
    """Attempt a single LLM call with the given timeout."""
    api_key = os.environ.get("LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY", "")
    api_base = os.environ.get("LLM_BASE_URL", "")
    model_name = settings.llm_model_name
    litellm_model = model_name if "/" in model_name else f"openai/{model_name}"

    response = await asyncio.wait_for(
        acompletion(
            model=litellm_model,
            messages=[{"role": "user", "content": prompt}],
            api_base=api_base or None,
            api_key=api_key or None,
            timeout=timeout,
            metadata=metadata or {},
        ),
        timeout=timeout,
    )

    choices = response.get("choices") or []
    if not choices:
        raise ValueError("no choices returned")
    return choices[0]["message"]["content"]


async def call_llm(prompt: str, metadata: Dict[str, Any] | None = None) -> str:
    api_key = os.environ.get("LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY", "")
    api_base = os.environ.get("LLM_BASE_URL", "")
    model_name = settings.llm_model_name
    litellm_model = model_name if "/" in model_name else f"openai/{model_name}"

    logger.info("llm_call_start", model=litellm_model, api_base=api_base, prompt_len=len(prompt))

    last_error = ""
    for attempt in range(1, LLM_MAX_RETRIES + 1):
        try:
            result = await _single_llm_call(prompt, LLM_TIMEOUT_SECONDS, metadata=metadata)
            logger.info("llm_call_complete", attempt=attempt)
            return result
        except asyncio.TimeoutError:
            last_error = f"timed out after {LLM_TIMEOUT_SECONDS}s"
            logger.warning("llm_call_timeout", timeout=LLM_TIMEOUT_SECONDS, attempt=attempt)
            # On retry: aggressively truncate prompt to reduce token count
            if attempt < LLM_MAX_RETRIES and len(prompt) > 15000:
                prompt = _truncate_prompt(prompt)
                logger.info("llm_retry_truncated", new_prompt_len=len(prompt), attempt=attempt + 1)
        except Exception as exc:
            last_error = str(exc)
            logger.warning("llm_call_failed", error=last_error, attempt=attempt)
            if attempt < LLM_MAX_RETRIES:
                await asyncio.sleep(2)

    logger.error("llm_call_exhausted", retries=LLM_MAX_RETRIES, last_error=last_error)
    return f"[LLM error: {last_error}]"


def _truncate_prompt(prompt: str) -> str:
    """Halve decompilation snippets and trim long sections for retry.

    Uses head+tail strategy: keeps the first 18 and last 10 lines of each
    decompile block so the LLM still sees setup AND dispatch/tail logic.
    """
    lines = prompt.split("\n")
    out: list[str] = []
    in_decomp_block = False
    block_lines: list[str] = []
    max_decomp_lines = 30  # keep at most 30 lines per function on retry
    head_lines = 18
    tail_lines = max_decomp_lines - head_lines  # 12

    def _flush_block():
        """Flush a collected decompile block with head+tail truncation."""
        if len(block_lines) <= max_decomp_lines:
            out.extend(block_lines)
        else:
            out.extend(block_lines[:head_lines])
            out.append("  /* ... [truncated for retry] ... */")
            out.extend(block_lines[-tail_lines:])

    for line in lines:
        if line.startswith("--- Function ") or line.startswith("--- R2 Function:"):
            if in_decomp_block:
                _flush_block()
                block_lines = []
            in_decomp_block = True
            block_lines = []
            out.append(line)
            continue
        if in_decomp_block:
            if line.startswith("--- ") or line.startswith("=== "):
                _flush_block()
                block_lines = []
                in_decomp_block = False
                out.append(line)
            else:
                block_lines.append(line)
            continue
        out.append(line)

    if in_decomp_block and block_lines:
        _flush_block()

    return "\n".join(out)
