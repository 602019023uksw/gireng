#!/usr/bin/env python3
"""Test script to verify GLM-5 API connectivity"""

import asyncio
import os
import sys

# Add backend to path
sys.path.insert(0, '/home/danil/git/gireng/backend/src')

import litellm
from litellm import acompletion

async def test_glm5():
    """Test GLM-5 API with a simple prompt"""

    # Get config from environment
    api_key = os.environ.get("LLM_API_KEY") or os.environ.get("ANTHROPIC_API_KEY", "")
    api_base = os.environ.get("LLM_BASE_URL") or os.environ.get("ANTHROPIC_BASE_URL", "")
    model_name = os.environ.get("LLM_MODEL_NAME") or os.environ.get("ANTHROPIC_MODEL", "glm-5")

    print(f"Testing GLM-5 API...")
    print(f"Model: {model_name}")
    print(f"API Base: {api_base or 'default'}")
    print(f"API Key: {'***' + api_key[-4:] if api_key else 'NOT SET'}")
    print("-" * 50)

    if not api_key:
        print("❌ ERROR: No API key found!")
        print("   Set ANTHROPIC_API_KEY in .env")
        return False

    # Use litellm format for OpenAI-compatible endpoints
    litellm_model = f"openai/{model_name}"

    try:
        print("Sending test request...")
        response = await asyncio.wait_for(
            acompletion(
                model=litellm_model,
                messages=[{"role": "user", "content": "Say 'API test successful' in exactly those words."}],
                api_base=api_base or None,
                api_key=api_key,
                timeout=30,
            ),
            timeout=30,
        )

        content = response.get("choices", [{}])[0].get("message", {}).get("content", "")
        print(f"\n✅ API Call Successful!")
        print(f"Response: {content}")
        print(f"\nModel {model_name} is working correctly.")
        return True

    except asyncio.TimeoutError:
        print("\n❌ ERROR: Request timed out after 30 seconds")
        return False
    except Exception as e:
        print(f"\n❌ ERROR: {type(e).__name__}")
        print(f"   {str(e)}")
        return False

if __name__ == "__main__":
    # Load .env file
    from pathlib import Path
    env_path = Path("/home/danil/git/gireng/.env")
    if env_path.exists():
        print(f"Loading environment from {env_path}")
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ.setdefault(key, value)
        print()

    success = asyncio.run(test_glm5())
    sys.exit(0 if success else 1)
