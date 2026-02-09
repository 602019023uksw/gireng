"""Radare2 analysis tools — LangChain @tool wrappers around the R2 runner."""

from pathlib import Path
from typing import Any, Dict, List, Optional

from langchain.tools import tool

from ghidra_agent.logging import logger
from ghidra_agent.radare.runner import Radare2Runner


# Shared runner instance — use get_runner() for lazy access with verification
_runner: Optional[Radare2Runner] = None


def get_runner() -> Radare2Runner:
    """Return (and cache) the global Radare2Runner instance."""
    global _runner
    if _runner is None:
        _runner = Radare2Runner()
    return _runner


async def verify_r2_ready() -> Dict[str, Any]:
    """Verify the R2 container is up and probe available decompiler plugins.

    Returns a status dict suitable for a health-check endpoint.
    """
    runner = get_runner()
    alive = await runner.verify_container()
    decompilers: List[str] = []
    if alive:
        decompilers = await runner.detect_decompilers()
    return {
        "ready": alive,
        "container": runner.container,
        "decompilers": decompilers,
    }


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _bin(binary_path: Optional[str]) -> Path:
    if not binary_path:
        raise ValueError("binary_path is required for R2 analysis")
    return Path(binary_path)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@tool
async def r2_analyze_binary(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Analyze binary structure with Radare2 — architecture, sections, entry point, imports."""
    bp = _bin(binary_path)
    runner = get_runner()

    # iIj  = binary info JSON
    # iSj  = sections JSON
    # iej  = entry points JSON
    # iij  = imports JSON
    # Run aaa once, then gather all info in subsequent commands (no re-analysis)
    result = await runner.run_json_command(bp, "aaa;iIj")
    if not result.ok:
        return {"ok": False, "error": result.error}

    info = result.payload.get("json", {})

    # Gather sections (no aaa needed — already analyzed)
    sec_result = await runner.run_json_command(bp, "iSj")
    sections = []
    if sec_result.ok and isinstance(sec_result.payload.get("json"), list):
        sections = [s.get("name", "") for s in sec_result.payload["json"] if s.get("name")]

    # Entry point
    ep_result = await runner.run_json_command(bp, "iej")
    entry_points = []
    if ep_result.ok and isinstance(ep_result.payload.get("json"), list):
        entry_points = [hex(e.get("vaddr", 0)) for e in ep_result.payload["json"]]

    # Imports
    imp_result = await runner.run_json_command(bp, "iij")
    imports = []
    if imp_result.ok and isinstance(imp_result.payload.get("json"), list):
        imports = [i.get("name", "") for i in imp_result.payload["json"] if i.get("name")]

    return {
        "ok": True,
        "architecture": info.get("arch", "unknown"),
        "bits": info.get("bits", 0),
        "os": info.get("os", "unknown"),
        "binary_type": info.get("bintype", "unknown"),
        "compiler": info.get("compiler", "unknown"),
        "image_base": hex(info.get("baddr", 0)) if isinstance(info.get("baddr"), int) else str(info.get("baddr", "unknown")),
        "entry_points": entry_points,
        "sections": sections,
        "imports": imports[:100],
        "endian": info.get("endian", "unknown"),
        "stripped": info.get("stripped", False),
        "static": info.get("static", False),
    }


@tool
async def r2_list_functions(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """List all functions detected by Radare2 with address, size, and name."""
    bp = _bin(binary_path)
    runner = get_runner()
    result = await runner.run_json_command(bp, "aaa;aflj")  # aaa needed for function analysis
    if not result.ok:
        return {"ok": False, "error": result.error}

    funcs_raw = result.payload.get("json", [])
    if not isinstance(funcs_raw, list):
        return {"ok": False, "error": "Unexpected aflj output"}

    functions: List[Dict[str, Any]] = []
    for f in funcs_raw:
        # aflj may use 'offset' or 'addr' depending on r2 version
        raw_addr = f.get("addr", f.get("offset", 0))
        functions.append({
            "name": f.get("name", ""),
            "address": hex(raw_addr),
            "size": f.get("size", 0),
            "xrefs": f.get("nrefsTo", 0) + f.get("nrefsFrom", 0),
            "calltype": f.get("calltype", ""),
        })

    return {"ok": True, "functions": functions}


@tool
async def r2_decompile_function(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
    function_name: Optional[str] = None,
    address: Optional[str] = None,
) -> Dict[str, Any]:
    """Decompile a function using Radare2's r2dec / r2ghidra decompiler plugin."""
    bp = _bin(binary_path)
    runner = get_runner()

    # Determine seek target
    seek = function_name or address or "main"

    # Use detected decompiler chain (cached after first probe)
    decompiler_chain = await runner.detect_decompilers()

    for cmd_suffix in decompiler_chain:
        cmd = f"aaa;s {seek};{cmd_suffix}"  # aaa needed per fresh r2 process
        result = await runner.run_command(bp, cmd)
        if result.ok and result.payload.get("raw", "").strip():
            raw = result.payload["raw"].strip()
            # Strip ANSI escape codes for clean downstream use
            import re as _re
            raw = _re.sub(r'\x1b\[[0-9;]*m', '', raw)
            return {
                "ok": True,
                "c": raw,
                "function": seek,
                "decompiler": cmd_suffix,
            }

    return {"ok": False, "error": f"Could not decompile {seek}"}


@tool
async def r2_find_strings(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
    query: Optional[str] = None,
) -> Dict[str, Any]:
    """Find strings in the binary using Radare2."""
    bp = _bin(binary_path)
    runner = get_runner()
    result = await runner.run_json_command(bp, "izj")
    if not result.ok:
        return {"ok": False, "error": result.error}

    strings_raw = result.payload.get("json", [])
    if not isinstance(strings_raw, list):
        return {"ok": False, "error": "Unexpected izj output"}

    strings: List[Dict[str, Any]] = []
    for s in strings_raw:
        val = s.get("string", "")
        if query and query.lower() not in val.lower():
            continue
        if len(val) >= 4:  # skip very short strings
            strings.append({
                "value": val,
                "address": hex(s.get("vaddr", 0)),
                "length": s.get("length", 0),
                "section": s.get("section", ""),
                "type": s.get("type", ""),
            })

    return {"ok": True, "strings": strings}


@tool
async def r2_find_xrefs(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
    address: str = "",
) -> Dict[str, Any]:
    """Find cross-references to/from an address using Radare2."""
    bp = _bin(binary_path)
    runner = get_runner()
    cmd = f"aaa;s {address};axtj"
    result = await runner.run_json_command(bp, cmd)
    if not result.ok:
        return {"ok": False, "error": result.error}

    xrefs = result.payload.get("json", [])
    refs_to: List[Dict[str, str]] = []
    if isinstance(xrefs, list):
        for x in xrefs:
            refs_to.append({
                "from": hex(x.get("from", 0)),
                "type": x.get("type", ""),
                "opcode": x.get("opcode", ""),
            })

    return {"ok": True, "to": refs_to, "from": []}


@tool
async def r2_disassemble_at(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
    address: str = "",
    count: int = 32,
) -> Dict[str, Any]:
    """Disassemble instructions at an address using Radare2."""
    bp = _bin(binary_path)
    runner = get_runner()
    cmd = f"aaa;s {address};pdj {count}"
    result = await runner.run_json_command(bp, cmd)
    if not result.ok:
        return {"ok": False, "error": result.error}

    instrs_raw = result.payload.get("json", [])
    instructions: List[Dict[str, Any]] = []
    if isinstance(instrs_raw, list):
        for ins in instrs_raw:
            instructions.append({
                "address": hex(ins.get("offset", 0)),
                "mnemonic": ins.get("mnemonic", ""),
                "operands": ins.get("opcode", ""),
                "bytes": ins.get("bytes", ""),
                "size": ins.get("size", 0),
            })

    return {"ok": True, "instructions": instructions}


@tool
async def r2_syscall_analysis(
    session_id: str,
    program_hash: str,
    binary_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Detect syscalls and their usage in the binary using Radare2."""
    bp = _bin(binary_path)
    runner = get_runner()
    # asl = list syscalls, /c int 0x80 or syscall = find syscall instructions
    cmd = "aaa;aslj"
    result = await runner.run_json_command(bp, cmd)

    syscalls: List[Dict[str, Any]] = []
    if result.ok and isinstance(result.payload.get("json"), list):
        for sc in result.payload["json"]:
            syscalls.append({
                "name": sc.get("name", ""),
                "number": sc.get("sysnum", 0),
                "address": hex(sc.get("addr", 0)) if sc.get("addr") else "",
            })

    return {"ok": True, "syscalls": syscalls}
