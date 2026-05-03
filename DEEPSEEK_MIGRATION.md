# DeepSeek Migration Notes

## Summary

The backend LLM integration now defaults to DeepSeek through an OpenAI-compatible Chat Completions configuration. Provider details are controlled by environment variables, so future model/provider changes should not require code edits.

## Default configuration

```dotenv
LLM_PROVIDER=openai
LLM_API_KEY=<your-deepseek-api-key>
LLM_BASE_URL=https://api.deepseek.com
LLM_MODEL_NAME=deepseek-v4-pro
LLM_REASONING_EFFORT=high
LLM_THINKING_MODE=enabled
```

The following aliases are also supported for compatibility with common SDK formats:

- `DEEPSEEK_API_KEY`, `DEEPSEEK_BASE_URL`, `DEEPSEEK_MODEL`
- `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL`
- `ANTHROPIC_API_KEY`, `ANTHROPIC_BASE_URL`, `ANTHROPIC_MODEL` with `LLM_PROVIDER=anthropic`

## Code changes

- `backend/src/ghidra_agent/llm.py` resolves API key, base URL, provider, and model from env variables and sends DeepSeek thinking controls via `extra_body`.
- `backend/src/ghidra_agent/function_tools.py` contains the OpenAI-compatible function/tool registry.
- `backend/src/ghidra_agent/glm_function_tools.py` remains as a backward-compatible import shim.
- `docker-compose.yml`, `.env.template`, README, API docs, and UI model defaults now point to DeepSeek models.
- The unused direct `zhipuai` dependency was removed because LiteLLM already handles OpenAI-compatible requests.

## Switching providers

For another OpenAI-compatible provider, set:

```dotenv
LLM_PROVIDER=openai
LLM_API_KEY=<provider-key>
LLM_BASE_URL=<provider-openai-compatible-base-url>
LLM_MODEL_NAME=<provider-model>
```

For an Anthropic-compatible provider, set:

```dotenv
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=<provider-key>
ANTHROPIC_BASE_URL=<provider-anthropic-compatible-base-url>
ANTHROPIC_MODEL=<provider-model>
```
