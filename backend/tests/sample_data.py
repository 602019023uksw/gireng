"""Shared test data constants for R2 + Ghidra tests."""

from typing import Any, Dict

SAMPLE_HASH = "abcd1234" * 8  # 64-char hex

SAMPLE_BINARY_INFO_R2: Dict[str, Any] = {
    "ok": True,
    "architecture": "x86",
    "bits": 64,
    "os": "linux",
    "binary_type": "elf",
    "compiler": "gcc",
    "image_base": "0x400000",
    "entry_points": ["0x401000"],
    "sections": [".text", ".data", ".bss", ".rodata"],
    "imports": ["printf", "malloc", "free", "socket", "connect", "send", "recv"],
    "endian": "little",
    "stripped": False,
    "static": False,
}

SAMPLE_FUNCTIONS_R2: Dict[str, Any] = {
    "ok": True,
    "functions": [
        {"name": "main", "address": "0x401000", "size": 256, "xrefs": 5, "calltype": "amd64"},
        {"name": "sym.send_data", "address": "0x401200", "size": 128, "xrefs": 3, "calltype": "amd64"},
        {"name": "sym.recv_cmd", "address": "0x401400", "size": 96, "xrefs": 2, "calltype": "amd64"},
        {"name": "sym.encrypt", "address": "0x401500", "size": 200, "xrefs": 4, "calltype": "amd64"},
    ],
}

SAMPLE_STRINGS_R2: Dict[str, Any] = {
    "ok": True,
    "strings": [
        {"value": "http://evil.com/c2", "address": "0x402000", "length": 18, "section": ".rodata", "type": "ascii"},
        {"value": "/etc/passwd", "address": "0x402020", "length": 11, "section": ".rodata", "type": "ascii"},
        {"value": "AES-256-CBC", "address": "0x402040", "length": 11, "section": ".rodata", "type": "ascii"},
        {"value": "socket", "address": "0x402060", "length": 6, "section": ".rodata", "type": "ascii"},
        {"value": "connect failed", "address": "0x402070", "length": 14, "section": ".rodata", "type": "ascii"},
    ],
}

SAMPLE_DECOMPILE_R2: Dict[str, Any] = {
    "ok": True,
    "c": "int main(int argc, char **argv) {\n    int fd = socket(AF_INET, SOCK_STREAM, 0);\n    connect(fd, &addr, sizeof(addr));\n    send(fd, buf, len, 0);\n    return 0;\n}",
    "function": "main",
    "decompiler": "pdg",
}

SAMPLE_XREFS_R2: Dict[str, Any] = {
    "ok": True,
    "to": [
        {"from": "0x401050", "type": "CALL", "opcode": "call main"},
        {"from": "0x401200", "type": "CALL", "opcode": "call main"},
    ],
    "from": [],
}

SAMPLE_DISASM_R2: Dict[str, Any] = {
    "ok": True,
    "instructions": [
        {"address": "0x401000", "mnemonic": "push", "operands": "rbp", "bytes": "55", "size": 1},
        {"address": "0x401001", "mnemonic": "mov", "operands": "rbp, rsp", "bytes": "4889e5", "size": 3},
        {"address": "0x401004", "mnemonic": "sub", "operands": "rsp, 0x20", "bytes": "4883ec20", "size": 4},
    ],
}

SAMPLE_CALL_GRAPH: Dict[str, Any] = {
    "ok": True,
    "nodes": [
        {"name": "main", "address": "0x401000", "size": 256},
        {"name": "sym.send_data", "address": "0x401200", "size": 128},
        {"name": "sym.connect_c2", "address": "0x401300", "size": 96},
        {"name": "sym.imp.connect", "address": "0x403010", "size": 0},
        {"name": "sym.imp.send", "address": "0x403018", "size": 0},
    ],
    "edges": [
        {"from": "0x401000", "to": "0x401300", "from_name": "main", "to_name": "sym.connect_c2", "type": "CALL"},
        {"from": "0x401000", "to": "0x401200", "from_name": "main", "to_name": "sym.send_data", "type": "CALL"},
        {"from": "0x401300", "to": "0x403010", "from_name": "sym.connect_c2", "to_name": "sym.imp.connect", "type": "CALL"},
        {"from": "0x401200", "to": "0x403018", "from_name": "sym.send_data", "to_name": "sym.imp.send", "type": "CALL"},
    ],
    "entry_points": ["0x401000"],
}

SAMPLE_CALL_GRAPH_ANALYSIS: Dict[str, Any] = {
    "ok": True,
    "entries": ["main"],
    "adjacency": [
        {"function": "main", "calls": ["sym.connect_c2", "sym.send_data"]},
        {"function": "sym.connect_c2", "calls": ["sym.imp.connect"]},
        {"function": "sym.send_data", "calls": ["sym.imp.send"]},
    ],
    "chains": [
        {"category": "Network", "sink": "sym.imp.connect", "path": ["main", "sym.connect_c2", "sym.imp.connect"]},
        {"category": "Network", "sink": "sym.imp.send", "path": ["main", "sym.send_data", "sym.imp.send"]},
    ],
    "cycles": [],
    "stats": {"nodes": 5, "edges": 4, "entries": 1, "chains": 2, "cycles": 0},
}

# Ghidra equivalents
SAMPLE_BINARY_INFO_GHIDRA: Dict[str, Any] = {
    "ok": True,
    "architecture": "x86:LE:64:default",
    "image_base": "0x400000",
    "entry_points": ["0x401000"],
    "segments": [".text", ".data", ".bss"],
    "compiler": "gcc",
}

SAMPLE_FUNCTIONS_GHIDRA: Dict[str, Any] = {
    "ok": True,
    "functions": [
        {"name": "main", "address": "0x401000", "size": 256, "xrefs": 5},
        {"name": "FUN_00401200", "address": "0x401200", "size": 128, "xrefs": 3},
        {"name": "FUN_00401400", "address": "0x401400", "size": 96, "xrefs": 2},
    ],
}

SAMPLE_STRINGS_GHIDRA: Dict[str, Any] = {
    "ok": True,
    "strings": [
        {"value": "http://evil.com/c2", "address": "0x402000"},
        {"value": "/etc/passwd", "address": "0x402020"},
        {"value": "socket", "address": "0x402060"},
    ],
}
