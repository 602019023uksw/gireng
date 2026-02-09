import asyncio
import os
from typing import Any, Dict
from litellm import acompletion

from ghidra_agent.config import settings
from ghidra_agent.logging import logger

LLM_TIMEOUT_SECONDS = 300  # 5 minutes


async def call_llm(prompt: str) -> str:
    api_key = os.environ.get("LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY", "")
    api_base = os.environ.get("LLM_BASE_URL", "")
    model_name = settings.llm_model_name

    # LiteLLM needs provider prefix for custom endpoints
    litellm_model = model_name if "/" in model_name else f"openai/{model_name}"

    logger.info("llm_call_start", model=litellm_model, api_base=api_base, prompt_len=len(prompt))

    try:
        # Use asyncio.wait_for to enforce timeout (LiteLLM's timeout param is unreliable for async)
        response = await asyncio.wait_for(
            acompletion(
                model=litellm_model,
                messages=[{"role": "user", "content": prompt}],
                api_base=api_base or None,
                api_key=api_key or None,
                timeout=LLM_TIMEOUT_SECONDS,
            ),
            timeout=LLM_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.error("llm_call_timeout", timeout=LLM_TIMEOUT_SECONDS)
        return f"[LLM error: timed out after {LLM_TIMEOUT_SECONDS}s]"
    except Exception as exc:
        logger.error("llm_call_failed", error=str(exc))
        return f"[LLM error: {exc}]"

    logger.info("llm_call_complete")
    choices = response.get("choices") or []
    if not choices:
        logger.warning("llm_empty_choices")
        return "[LLM error: no choices returned]"
    return choices[0]["message"]["content"]
