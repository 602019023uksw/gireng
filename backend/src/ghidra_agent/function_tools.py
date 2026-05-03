"""OpenAI-compatible function calling tool registry.

Converts LangChain tools to Chat Completions function calling format and provides
a registry for the LLM to invoke analysis tools dynamically.
"""

import inspect
from typing import Any, Callable, Dict, List, Optional, Union, get_args, get_origin

from ghidra_agent.logging import logger


class FunctionTool:
    """Represents a function calling tool."""

    def __init__(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        handler: Callable,
    ):
        self.name = name
        self.description = description
        self.parameters = parameters
        self.handler = handler

    def to_openai_format(self) -> Dict[str, Any]:
        """Convert to OpenAI-compatible function calling format."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def to_glm_format(self) -> Dict[str, Any]:
        """Deprecated alias for older tests and integrations."""
        return self.to_openai_format()


GLMTool = FunctionTool


def _extract_pydantic_schema(model_class: type) -> Dict[str, Any]:
    """Extract JSON schema from a Pydantic model."""
    try:
        return model_class.model_json_schema()
    except AttributeError:
        # Fallback for older Pydantic versions
        return model_class.schema()


def _extract_function_schema(func: Callable) -> Dict[str, Any]:
    """Extract parameter schema from a function signature.

    Creates a JSON Schema for the function's parameters based on type hints.
    """
    sig = inspect.signature(func)
    parameters = {"type": "object", "properties": {}, "required": []}

    type_map = {
        str: "string",
        int: "integer",
        float: "number",
        bool: "boolean",
        list: "array",
        dict: "object",
    }

    for name, param in sig.parameters.items():
        if name == "self":
            continue

        param_info: Dict[str, Any] = {"type": "string"}
        is_optional = False

        # Get type from annotation
        if param.annotation != inspect.Parameter.empty:
            # Handle Optional types
            origin = get_origin(param.annotation)
            annotation_args = get_args(param.annotation)
            is_optional = origin is Union and type(None) in annotation_args
            if is_optional:
                # Optional field - not required
                pass
            else:
                param_type = param.annotation
                if param_type in type_map:
                    param_info["type"] = type_map[param_type]
                elif get_origin(param_type) is list:
                    param_info["type"] = "array"
                    # Try to extract item type
                    args = get_args(param_type) or (str,)
                    if args and args[0] in type_map:
                        param_info["items"] = {"type": type_map[args[0]]}

        # Add description if available from docstring
        if func.__doc__:
            # Try to extract parameter description from docstring
            doc_lines = func.__doc__.split("\n")
            for line in doc_lines:
                if f"{name}:" in line or f"{name} =" in line:
                    param_info["description"] = line.split(":", 1)[-1].strip()
                    break

        parameters["properties"][name] = param_info

        # Check if parameter is required
        if param.default == inspect.Parameter.empty and not is_optional:
            parameters["required"].append(name)

    return parameters


class ToolRegistry:
    """Registry for function calling tools.

    Maintains a collection of tools that can be invoked by the LLM
    during function calling.
    """

    def __init__(self):
        self._tools: Dict[str, FunctionTool] = {}

    def register_from_langchain(self, langchain_tool: Callable) -> None:
        """Register a LangChain @tool decorated function.

        Extracts the function schema and registers it for function calling.
        """
        name = langchain_tool.name  # type: ignore
        description = langchain_tool.description  # type: ignore
        handler = langchain_tool  # type: ignore

        # Try to extract args_schema from LangChain tool
        parameters = {"type": "object", "properties": {}, "required": []}

        if hasattr(langchain_tool, "args_schema") and langchain_tool.args_schema:
            parameters = _extract_pydantic_schema(langchain_tool.args_schema)
        else:
            # Fallback to function inspection
            parameters = _extract_function_schema(langchain_tool.func if hasattr(langchain_tool, "func") else langchain_tool)

        # Strip extraneous schema fields
        if "$defs" in parameters:
            del parameters["$defs"]

        self._tools[name] = FunctionTool(name, description, parameters, handler)
        logger.info("tool_registered", name=name)

    def register_direct(
        self,
        name: str,
        description: str,
        parameters: Dict[str, Any],
        handler: Callable,
    ) -> None:
        """Directly register a tool without LangChain."""
        self._tools[name] = FunctionTool(name, description, parameters, handler)
        logger.info("tool_registered_direct", name=name)

    def get_tool(self, name: str) -> Optional[FunctionTool]:
        """Get a tool by name."""
        return self._tools.get(name)

    def get_all_tools(self) -> List[FunctionTool]:
        """Get all registered tools."""
        return list(self._tools.values())

    def to_openai_tools_list(self) -> List[Dict[str, Any]]:
        """Export all tools in OpenAI-compatible function calling format."""
        return [tool.to_openai_format() for tool in self._tools.values()]

    def to_glm_tools_list(self) -> List[Dict[str, Any]]:
        """Deprecated alias for older tests and integrations."""
        return self.to_openai_tools_list()

    async def execute_tool(
        self,
        name: str,
        arguments: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute a tool by name with arguments.

        Returns:
            Dict with 'ok' status and 'result' or 'error' fields.
        """
        tool = self.get_tool(name)
        if not tool:
            return {"ok": False, "error": f"Unknown tool: {name}"}

        try:
            logger.info("tool_executing", name=name, arguments=arguments)
            result = await tool.handler(**arguments) if inspect.iscoroutinefunction(tool.handler) else tool.handler(**arguments)

            # Normalize result format
            if isinstance(result, dict):
                if "ok" not in result:
                    result = {"ok": True, "result": result}
                return result
            else:
                return {"ok": True, "result": result}
        except Exception as e:
            logger.error("tool_execution_failed", name=name, error=str(e))
            return {"ok": False, "error": str(e)}


# Global registry instance
_global_registry: Optional[ToolRegistry] = None


def get_tool_registry() -> ToolRegistry:
    """Get the global tool registry instance."""
    global _global_registry
    if _global_registry is None:
        _global_registry = ToolRegistry()
    return _global_registry


def register_all_radare2_tools() -> None:
    """Register all radare2 tools from r2_tools module."""
    from ghidra_agent.r2_tools import (
        r2_analyze_binary,
        r2_build_call_graph,
        r2_decompile_function,
        r2_disassemble_at,
        r2_find_strings,
        r2_find_xrefs,
        r2_list_functions,
        r2_search_bytes,
        r2_syscall_analysis,
    )

    registry = get_tool_registry()

    # Register each tool
    for langchain_tool in [
        r2_analyze_binary,
        r2_list_functions,
        r2_build_call_graph,
        r2_decompile_function,
        r2_disassemble_at,
        r2_find_strings,
        r2_find_xrefs,
        r2_search_bytes,
        r2_syscall_analysis,
    ]:
        registry.register_from_langchain(langchain_tool)


# Utility tools for common operations
def register_utility_tools() -> None:
    """Register utility tools for general analysis tasks."""
    registry = get_tool_registry()

    async def search_functions_tool(
        program_hash: str,
        query: str,
        limit: int = 10,
    ) -> Dict[str, Any]:
        """Search for functions by name or pattern."""
        from ghidra_agent import database as db

        try:
            functions = await db.search_functions(query, limit=limit)
            return {
                "ok": True,
                "functions": functions,
                "count": len(functions),
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}

    registry.register_direct(
        name="search_functions",
        description="Search for previously analyzed functions by name or pattern",
        parameters={
            "type": "object",
            "properties": {
                "program_hash": {
                    "type": "string",
                    "description": "Hash identifier for the binary program",
                },
                "query": {
                    "type": "string",
                    "description": "Search query for function names (supports partial matches)",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of results to return",
                    "default": 10,
                },
            },
            "required": ["program_hash", "query"],
        },
        handler=search_functions_tool,
    )

    async def get_decompilation_tool(
        program_hash: str,
        analyzer: str,
        function_name: str,
    ) -> Dict[str, Any]:
        """Retrieve cached decompilation for a function."""
        from ghidra_agent import database as db

        try:
            decomp = await db.get_decompilation(program_hash, analyzer, function_name)
            if decomp:
                return {
                    "ok": True,
                    "function_name": function_name,
                    "analyzer": analyzer,
                    "code": decomp,
                }
            return {
                "ok": False,
                "error": f"No decompilation found for {function_name}",
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}

    registry.register_direct(
        name="get_decompilation",
        description="Get cached decompiled code for a previously analyzed function",
        parameters={
            "type": "object",
            "properties": {
                "program_hash": {
                    "type": "string",
                    "description": "Hash identifier for the binary program",
                },
                "analyzer": {
                    "type": "string",
                    "description": "Analyzer used (ghidra or radare2)",
                    "enum": ["ghidra", "radare2"],
                },
                "function_name": {
                    "type": "string",
                    "description": "Name of the function to retrieve",
                },
            },
            "required": ["program_hash", "analyzer", "function_name"],
        },
        handler=get_decompilation_tool,
    )
