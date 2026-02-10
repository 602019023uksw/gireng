from pathlib import Path
from typing import Any, Dict, Optional

from langchain.tools import tool

from ghidra_agent.config import settings
from ghidra_agent.ghidra.runner import GhidraHeadlessRunner
from ghidra_agent.logging import logger
from ghidra_agent.utils import is_valid_hex, normalize_address


class ToolContext:
    def __init__(self, session_id: str, program_hash: str, binary_path: Optional[str]) -> None:
        self.session_id = session_id
        self.program_hash = program_hash
        self.binary_path = binary_path
        self.runner = GhidraHeadlessRunner()


def build_context(session_id: str, program_hash: str, binary_path: Optional[str]) -> ToolContext:
    return ToolContext(session_id=session_id, program_hash=program_hash, binary_path=binary_path)


async def _run_tool(
    script: str,
    context: ToolContext,
    payload: Dict[str, Any],
    allow_write: bool = False,
) -> Dict[str, Any]:
    result = await context.runner.run_task(
        session_id=context.session_id,
        program_hash=context.program_hash,
        script_name=script,
        payload=payload,
        binary_path=None if context.binary_path is None else Path(context.binary_path),
        allow_write=allow_write,
    )
    if not result.ok:
        logger.warning("ghidra_tool_failed", script=script, error=result.error)
    return result.payload


@tool
async def analyze_binary_structure(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Load the binary and return architecture, compiler, entry points, and segments."""
    context = build_context(session_id, program_hash, binary_path)
    return await _run_tool("analyze_binary_structure.py", context, {})


@tool
async def list_functions(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """List all functions with address, size, and xref count."""
    context = build_context(session_id, program_hash, binary_path)
    return await _run_tool("list_functions.py", context, {})


@tool
async def build_call_graph(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Build an inter-procedural function call graph (nodes + CALL edges)."""
    context = build_context(session_id, program_hash, binary_path)
    return await _run_tool("build_call_graph.py", context, {})


@tool
async def decompile_function(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
    function_name: Optional[str] = None,
    address: Optional[str] = None,
) -> Dict[str, Any]:
    """Decompile a function by name or address and return C pseudocode."""
    context = build_context(session_id, program_hash, binary_path)
    payload: Dict[str, Any] = {"function_name": function_name, "address": address}
    if address and not is_valid_hex(address):
        return {"ok": False, "error": "Invalid address format."}
    if address:
        payload["address"] = normalize_address(address)
    payload["max_time"] = settings.max_decompilation_time
    return await _run_tool("decompile_function.py", context, payload)


@tool
async def disassemble_at(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
    address: str = "",
    count: int = 32,
) -> Dict[str, Any]:
    """Disassemble instructions at an address."""
    context = build_context(session_id, program_hash, binary_path)
    if not is_valid_hex(address):
        return {"ok": False, "error": "Invalid address format."}
    payload = {"address": normalize_address(address), "count": count}
    return await _run_tool("disassemble_at.py", context, payload)


@tool
async def find_strings(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
    query: Optional[str] = None,
) -> Dict[str, Any]:
    """Find strings in the binary with optional query filtering."""
    context = build_context(session_id, program_hash, binary_path)
    payload = {"query": query}
    return await _run_tool("find_strings.py", context, payload)


@tool
async def find_xrefs(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
    address: str = "",
) -> Dict[str, Any]:
    """Find cross-references to and from a specific address."""
    context = build_context(session_id, program_hash, binary_path)
    if not is_valid_hex(address):
        return {"ok": False, "error": "Invalid address format."}
    payload = {"address": normalize_address(address)}
    return await _run_tool("find_xrefs.py", context, payload)


@tool
async def search_bytes(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
    pattern: str = "",
) -> Dict[str, Any]:
    """Search for a hex byte pattern in the binary."""
    context = build_context(session_id, program_hash, binary_path)
    payload = {"pattern": pattern}
    return await _run_tool("search_bytes.py", context, payload)


@tool
async def get_function_graph(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
    function_name: Optional[str] = None,
    address: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a control flow graph for the given function."""
    context = build_context(session_id, program_hash, binary_path)
    payload: Dict[str, Any] = {"function_name": function_name, "address": address}
    if address and not is_valid_hex(address):
        return {"ok": False, "error": "Invalid address format."}
    if address:
        payload["address"] = normalize_address(address)
    return await _run_tool("get_function_graph.py", context, payload)


@tool
async def rename_symbol(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
    address: str = "",
    new_name: str = "",
) -> Dict[str, Any]:
    """Rename a symbol at an address. Requires write mode enabled."""
    context = build_context(session_id, program_hash, binary_path)
    if not is_valid_hex(address):
        return {"ok": False, "error": "Invalid address format."}
    payload = {"address": normalize_address(address), "new_name": new_name}
    return await _run_tool("rename_symbol.py", context, payload, allow_write=True)


@tool
async def add_comment(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
    address: str = "",
    comment: str = "",
) -> Dict[str, Any]:
    """Add a comment at an address. Requires write mode enabled."""
    context = build_context(session_id, program_hash, binary_path)
    if not is_valid_hex(address):
        return {"ok": False, "error": "Invalid address format."}
    payload = {"address": normalize_address(address), "comment": comment}
    return await _run_tool("add_comment.py", context, payload, allow_write=True)
