import asyncio
import json
import os
from typing import Any, Callable, Dict, List, Optional

import litellm
from litellm import acompletion

from ghidra_agent.config import settings
from ghidra_agent.logging import logger

# Configurable via env; default 1200s (20 min) to accommodate large prompts with deep thinking
LLM_TIMEOUT_SECONDS = int(os.environ.get("LLM_TIMEOUT", "1200"))
LLM_MAX_RETRIES = int(os.environ.get("LLM_MAX_RETRIES", "2"))
LLM_REASONING_EFFORT = os.environ.get("LLM_REASONING_EFFORT", "high")
LLM_THINKING_MODE = os.environ.get("LLM_THINKING_MODE", "enabled")


def _first_env(*names: str) -> str:
    for name in names:
        value = os.environ.get(name, "")
        if value:
            return value
    return ""


def _llm_api_key() -> str:
    return _first_env("LLM_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY")


def _llm_api_base() -> str:
    return _first_env("LLM_BASE_URL", "DEEPSEEK_BASE_URL", "OPENAI_BASE_URL", "ANTHROPIC_BASE_URL")


def _llm_model_name(model: Optional[str] = None) -> str:
    return model or _first_env("LLM_MODEL_NAME", "DEEPSEEK_MODEL", "OPENAI_MODEL", "ANTHROPIC_MODEL") or settings.llm_model_name


def _llm_provider() -> str:
    return (_first_env("LLM_PROVIDER", "LLM_API_FORMAT") or settings.llm_provider or "openai").lower()


def _litellm_model_name(model: Optional[str] = None) -> str:
    model_name = _llm_model_name(model)
    if "/" in model_name:
        return model_name
    return f"{_llm_provider()}/{model_name}"


def _thinking_kwargs() -> Dict[str, Any]:
    thinking_mode = LLM_THINKING_MODE.lower()
    if thinking_mode not in {"enabled", "disabled"}:
        thinking_mode = "enabled"

    extra_body: Dict[str, Any] = {"thinking": {"type": thinking_mode}}
    if thinking_mode == "enabled":
        if _llm_provider() == "anthropic":
            extra_body["output_config"] = {"effort": LLM_REASONING_EFFORT}
            return {"extra_body": extra_body}
        return {
            "reasoning_effort": LLM_REASONING_EFFORT,
            "extra_body": extra_body,
        }

    return {"extra_body": extra_body}

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


async def _single_llm_call(
    prompt: str,
    timeout: int,
    metadata: Dict[str, Any] | None = None,
    messages: List[Dict[str, Any]] | None = None,
    tools: List[Dict[str, Any]] | None = None,
    tool_choice: str = "auto",
    model: Optional[str] = None,
) -> Dict[str, Any]:
    """Attempt a single LLM call with the given timeout.

    Args:
        prompt: The user prompt (used if messages is None)
        timeout: Request timeout in seconds
        metadata: Optional metadata for tracing
        messages: Optional conversation history (overrides prompt)
        tools: Optional list of tools for function calling
        tool_choice: Tool choice strategy ("auto", "none", or specific tool)

    Returns dict with:
        - 'content': The response content
        - 'reasoning_content': Deep thinking reasoning (if available)
        - 'tool_calls': List of function calls requested by the model
    """
    api_key = _llm_api_key()
    api_base = _llm_api_base()
    litellm_model = _litellm_model_name(model)

    # Use provided messages or create from prompt
    request_messages = messages if messages is not None else [{"role": "user", "content": prompt}]

    kwargs: Dict[str, Any] = {
        "model": litellm_model,
        "messages": request_messages,
        "api_base": api_base or None,
        "api_key": api_key or None,
        "timeout": timeout,
        "metadata": metadata or {},
        **_thinking_kwargs(),
    }

    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = tool_choice

    response = await asyncio.wait_for(
        acompletion(**kwargs),
        timeout=timeout,
    )

    choices = response.get("choices") or []
    if not choices:
        raise ValueError("no choices returned")

    message = choices[0].get("message", {})
    result = {
        "content": message.get("content", ""),
        "reasoning_content": message.get("reasoning_content", ""),
        "tool_calls": message.get("tool_calls"),
    }
    return result


async def call_llm(
    prompt: str,
    metadata: Dict[str, Any] | None = None,
    conversation_history: list[Dict[str, Any]] | None = None,
    tools: List[Dict[str, Any]] | None = None,
    tool_executor: Optional[Callable[[str, Dict[str, Any]], Any]] = None,
    max_tool_iterations: int = 5,
    model: Optional[str] = None,
    timeout: Optional[int] = None,
) -> Dict[str, Any]:
    """Call LLM with deep reasoning and optional function calling support.

    Args:
        prompt: The user prompt
        metadata: Optional metadata for tracing
        conversation_history: Optional conversation history for multi-turn context.
            Should include messages with 'role', 'content', and optionally 'reasoning_content'.
        tools: Optional list of OpenAI/Anthropic-compatible tools
        tool_executor: Optional async function to execute tools. Signature:
            async def tool_executor(name: str, arguments: dict) -> dict
        max_tool_iterations: Maximum number of tool call iterations

    Returns:
        Dict with:
            - 'content': The response content
            - 'reasoning_content': Deep thinking reasoning (if available)
            - 'tool_calls': List of tool calls made and their results
            - 'tool_results': List of tool execution results
    """
    api_base = _llm_api_base()
    litellm_model = _litellm_model_name(model)

    logger.info("llm_call_start", model=litellm_model, api_base=api_base, prompt_len=len(prompt), has_tools=tools is not None)

    # Build initial messages
    messages: List[Dict[str, Any]] = []
    if conversation_history:
        messages.extend(conversation_history)

    # If no history or last message is not user, add prompt
    if not messages or messages[-1].get("role") != "user":
        messages.append({"role": "user", "content": prompt})

    # Track tool calls and results
    tool_calls_made: List[Dict[str, Any]] = []
    tool_results: List[Dict[str, Any]] = []

    last_error = ""
    for iteration in range(max_tool_iterations + 1):
        if iteration > 0:
            logger.info("llm_tool_iteration", iteration=iteration)

        for attempt in range(1, LLM_MAX_RETRIES + 1):
            try:
                call_timeout = timeout if timeout is not None else LLM_TIMEOUT_SECONDS
                result = await _single_llm_call(
                    "",  # Prompt already in messages
                    call_timeout,
                    metadata=metadata,
                    messages=messages,
                    tools=tools if iteration == 0 else None,  # Only pass tools on first iteration
                    model=model,
                )
                logger.info("llm_call_complete", attempt=attempt, iteration=iteration)
                break
            except asyncio.TimeoutError:
                last_error = f"timed out after {call_timeout}s"
                logger.warning("llm_call_timeout", timeout=call_timeout, attempt=attempt, iteration=iteration)
                # On retry: aggressively truncate prompt to reduce token count
                if attempt < LLM_MAX_RETRIES and messages:
                    # Truncate the last user message
                    for msg in reversed(messages):
                        if msg.get("role") == "user" and len(msg.get("content", "")) > 15000:
                            msg["content"] = _truncate_prompt(msg["content"])
                            logger.info("llm_retry_truncated", new_prompt_len=len(msg["content"]), attempt=attempt + 1)
                            break
            except Exception as exc:
                last_error = str(exc)
                logger.warning("llm_call_failed", error=last_error, attempt=attempt, iteration=iteration)
                if attempt < LLM_MAX_RETRIES:
                    await asyncio.sleep(2)
        else:
            # All retries exhausted
            logger.error("llm_call_exhausted", retries=LLM_MAX_RETRIES, last_error=last_error)
            return {
                "content": f"[LLM error: {last_error}]",
                "reasoning_content": "",
                "tool_calls": tool_calls_made,
                "tool_results": tool_results,
            }

        # Add assistant message to conversation
        assistant_msg = {
            "role": "assistant",
            "content": result.get("content", ""),
        }
        if result.get("reasoning_content"):
            assistant_msg["reasoning_content"] = result["reasoning_content"]
        if result.get("tool_calls"):
            assistant_msg["tool_calls"] = result["tool_calls"]

        messages.append(assistant_msg)

        # Check if model wants to call tools
        if result.get("tool_calls") and tool_executor:
            for tool_call in result["tool_calls"]:
                function = tool_call.get("function", {})
                tool_name = function.get("name")
                arguments_str = function.get("arguments", "{}")

                try:
                    arguments = json.loads(arguments_str) if isinstance(arguments_str, str) else arguments_str

                    logger.info("llm_tool_call", name=tool_name, arguments=arguments)
                    tool_calls_made.append({
                        "id": tool_call.get("id"),
                        "name": tool_name,
                        "arguments": arguments,
                    })

                    # Execute the tool
                    tool_result = await tool_executor(tool_name, arguments)

                    # Add tool result message
                    messages.append({
                        "role": "tool",
                        "content": json.dumps(tool_result, ensure_ascii=False),
                        "tool_call_id": tool_call.get("id"),
                    })

                    tool_results.append({
                        "name": tool_name,
                        "arguments": arguments,
                        "result": tool_result,
                    })

                except Exception as e:
                    logger.error("tool_execution_error", name=tool_name, error=str(e))
                    # Add error as tool result
                    messages.append({
                        "role": "tool",
                        "content": json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False),
                        "tool_call_id": tool_call.get("id"),
                    })
                    tool_results.append({
                        "name": tool_name,
                        "arguments": arguments,
                        "error": str(e),
                    })

            # Continue loop to get final response after tool execution
            continue

        # No tool calls or no executor, we're done
        return {
            "content": result.get("content", ""),
            "reasoning_content": result.get("reasoning_content", ""),
            "tool_calls": tool_calls_made,
            "tool_results": tool_results,
        }

    # Max iterations reached
    logger.warning("llm_max_iterations_reached", max_iterations=max_tool_iterations)
    return {
        "content": result.get("content", "") + "\n\n[Note: Maximum tool iterations reached]",
        "reasoning_content": result.get("reasoning_content", ""),
        "tool_calls": tool_calls_made,
        "tool_results": tool_results,
    }


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


# ---------------------------------------------------------------------------
# Function Calling Support
# ---------------------------------------------------------------------------

def create_tool_executor():
    """Create a tool executor function from the global tool registry.

    Returns an async function that can be passed as tool_executor to call_llm.

    Example:
        executor = create_tool_executor()
        result = await call_llm(
            prompt="Analyze this binary",
            tools=get_tool_registry().to_openai_tools_list(),
            tool_executor=executor,
        )
    """
    from ghidra_agent.function_tools import get_tool_registry

    registry = get_tool_registry()

    async def executor(tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute a tool by name with arguments."""
        return await registry.execute_tool(tool_name, arguments)

    return executor


def get_function_calling_tools() -> List[Dict[str, Any]]:
    """Get all registered tools in OpenAI/Anthropic-compatible format.

    Initializes and registers all radare2 tools on first call.

    Returns:
        List of OpenAI-compatible tool definitions.
    """
    from ghidra_agent.function_tools import get_tool_registry, register_all_radare2_tools, register_utility_tools

    registry = get_tool_registry()

    # Register tools on first call
    if not registry.get_all_tools():
        register_all_radare2_tools()
        register_utility_tools()

    return registry.to_openai_tools_list()
