# Ghidra Scripts

These scripts are mounted into the Ghidra headless container under `GHIDRA_SCRIPTS_ROOT`.
Each script accepts `input.json`, `output.json`, and `log.txt` paths in that order.

## Available Scripts

| Script | Purpose |
|--------|---------|
| `add_comment.py` | Add a comment to a specific address |
| `analyze_binary_structure.py` | Extract binary metadata (sections, imports, exports, entry point) |
| `build_call_graph.py` | Build the full function call graph |
| `decompile_function.py` | Decompile a specific function to C pseudocode |
| `disassemble_at.py` | Disassemble instructions at a given address |
| `find_strings.py` | Extract all defined strings from the binary |
| `find_xrefs.py` | Find cross-references to/from an address |
| `get_function_graph.py` | Get control-flow graph for a function |
| `list_functions.py` | List all functions with addresses and sizes |
| `rename_symbol.py` | Rename a symbol/function in the program |
| `search_bytes.py` | Search for a byte pattern in the binary |
