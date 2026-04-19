"""Test GLM-5 Function Calling Implementation

This test verifies that:
1. Tools are correctly registered in GLM format
2. Tool executor correctly invokes tools
3. LLM can call tools during conversation
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.mark.asyncio
async def test_tool_registry_format():
    """Test that tools are correctly formatted for GLM function calling."""
    from ghidra_agent.glm_function_tools import ToolRegistry

    registry = ToolRegistry()

    # Register a simple test tool
    async def test_tool(param1: str, param2: int = 10) -> dict:
        """A test tool that does nothing."""
        return {"ok": True, "param1": param1, "param2": param2}

    registry.register_direct(
        name="test_tool",
        description="A test tool for verification",
        parameters={
            "type": "object",
            "properties": {
                "param1": {
                    "type": "string",
                    "description": "First parameter",
                },
                "param2": {
                    "type": "integer",
                    "description": "Second parameter",
                    "default": 10,
                },
            },
            "required": ["param1"],
        },
        handler=test_tool,
    )

    # Verify GLM format
    tools_list = registry.to_glm_tools_list()
    assert len(tools_list) == 1
    assert tools_list[0]["type"] == "function"
    assert tools_list[0]["function"]["name"] == "test_tool"
    assert tools_list[0]["function"]["description"] == "A test tool for verification"
    assert "param1" in tools_list[0]["function"]["parameters"]["properties"]


@pytest.mark.asyncio
async def test_tool_execution():
    """Test that tool executor correctly invokes tools."""
    from ghidra_agent.glm_function_tools import ToolRegistry

    registry = ToolRegistry()

    # Register a tool that returns specific data
    async def echo_tool(message: str) -> dict:
        """Echo the input message."""
        return {"ok": True, "echo": message}

    registry.register_direct(
        name="echo_tool",
        description="Echoes back the input",
        parameters={
            "type": "object",
            "properties": {
                "message": {"type": "string"},
            },
            "required": ["message"],
        },
        handler=echo_tool,
    )

    # Execute the tool
    result = await registry.execute_tool("echo_tool", {"message": "hello"})
    assert result["ok"] is True
    assert result["echo"] == "hello"


@pytest.mark.asyncio
async def test_tool_execution_error():
    """Test that tool execution errors are properly handled."""
    from ghidra_agent.glm_function_tools import ToolRegistry

    registry = ToolRegistry()

    async def failing_tool() -> dict:
        """A tool that always fails."""
        raise ValueError("Intentional failure")

    registry.register_direct(
        name="failing_tool",
        description="A tool that fails",
        parameters={"type": "object", "properties": {}, "required": []},
        handler=failing_tool,
    )

    result = await registry.execute_tool("failing_tool", {})
    assert result["ok"] is False
    assert "Intentional failure" in result["error"]


@pytest.mark.asyncio
async def test_unknown_tool():
    """Test that unknown tools return an error."""
    from ghidra_agent.glm_function_tools import ToolRegistry

    registry = ToolRegistry()
    result = await registry.execute_tool("unknown_tool", {})
    assert result["ok"] is False
    assert "Unknown tool" in result["error"]


@pytest.mark.asyncio
async def test_llm_call_with_tools():
    """Test that LLM call supports tool calling."""
    from ghidra_agent.llm import _single_llm_call

    # Mock the litellm completion
    mock_response = {
        "choices": [{
            "message": {
                "content": "I will help with that.",
                "reasoning_content": "Thinking about how to help...",
                "tool_calls": [{
                    "id": "call_123",
                    "function": {
                        "name": "test_tool",
                        "arguments": '{"param1": "value"}',
                    },
                }],
            },
        }],
    }

    with patch("ghidra_agent.llm.acompletion", new=AsyncMock(return_value=mock_response)):
        result = await _single_llm_call(
            prompt="Help me analyze this",
            timeout=30,
            messages=[{"role": "user", "content": "Help me analyze this"}],
            tools=[{
                "type": "function",
                "function": {
                    "name": "test_tool",
                    "description": "Test",
                    "parameters": {"type": "object", "properties": {}, "required": []},
                },
            }],
        )

        assert result["content"] == "I will help with that."
        assert result["reasoning_content"] == "Thinking about how to help..."
        assert result["tool_calls"] is not None
        assert len(result["tool_calls"]) == 1
        assert result["tool_calls"][0]["function"]["name"] == "test_tool"


@pytest.mark.asyncio
async def test_get_function_calling_tools():
    """Test that get_function_calling_tools returns valid tools."""
    from ghidra_agent.llm import get_function_calling_tools

    # Mock the tool registry to avoid actual registration
    with patch("ghidra_agent.llm.get_tool_registry") as mock_registry:
        mock_reg_instance = MagicMock()
        mock_reg_instance.get_all_tools.return_value = []
        mock_reg_instance.to_glm_tools_list.return_value = [
            {
                "type": "function",
                "function": {
                    "name": "test_tool",
                    "description": "Test",
                    "parameters": {"type": "object"},
                },
            }
        ]
        mock_registry.return_value = mock_reg_instance

        # Also mock the registration functions to do nothing
        with patch("ghidra_agent.llm.register_all_radare2_tools"):
            with patch("ghidra_agent.llm.register_utility_tools"):
                tools = get_function_calling_tools()

                assert len(tools) == 1
                assert tools[0]["type"] == "function"
                assert tools[0]["function"]["name"] == "test_tool"


def test_glm_tool_format_structure():
    """Test the GLM tool format structure is valid."""
    from ghidra_agent.glm_function_tools import GLMTool

    tool = GLMTool(
        name="test_function",
        description="A test function",
        parameters={
            "type": "object",
            "properties": {
                "input": {
                    "type": "string",
                    "description": "Input parameter",
                },
            },
            "required": ["input"],
        },
        handler=lambda x: {"ok": True},
    )

    glm_format = tool.to_glm_format()

    # Verify structure matches GLM spec
    assert "type" in glm_format
    assert glm_format["type"] == "function"
    assert "function" in glm_format
    assert "name" in glm_format["function"]
    assert "description" in glm_format["function"]
    assert "parameters" in glm_format["function"]
    assert glm_format["function"]["parameters"]["type"] == "object"
    assert "properties" in glm_format["function"]["parameters"]


if __name__ == "__main__":
    # Run basic sanity checks
    import asyncio

    async def sanity_check():
        print("Running GLM Function Calling sanity checks...")

        # Test 1: Tool registry
        registry = ToolRegistry()
        async def dummy() -> dict:
            return {"ok": True}

        registry.register_direct(
            "dummy",
            "Dummy tool",
            {"type": "object", "properties": {}, "required": []},
            dummy,
        )

        tools = registry.to_glm_tools_list()
        print(f"✓ Tool registry: {len(tools)} tool(s) registered")

        # Test 2: Tool execution
        result = await registry.execute_tool("dummy", {})
        print(f"✓ Tool execution: {result}")

        # Test 3: GLM format
        assert tools[0]["type"] == "function"
        print(f"✓ GLM format valid: {tools[0]}")

        print("\n✅ All sanity checks passed!")

    asyncio.run(sanity_check())
