import json
from pathlib import Path


def _write_output(path, payload):
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_log(path, message):
    log_path = Path(path)
    log_path.write_text(message + "\n", encoding="utf-8")


def _symbol_name(symbol):
    try:
        return symbol.getName(True)
    except Exception:
        try:
            return symbol.getName()
        except Exception:
            return str(symbol)


def _collect_imports(program):
    imports = []
    seen = set()
    symtab = program.getSymbolTable()
    try:
        for sym in symtab.getExternalSymbols():
            name = _symbol_name(sym)
            if name and name not in seen:
                seen.add(name)
                imports.append(name)
    except Exception:
        pass
    return imports


def _collect_exports(program, entry_points):
    exports = []
    seen = set()
    symtab = program.getSymbolTable()
    for addr in entry_points:
        try:
            sym = symtab.getPrimarySymbol(addr)
            name = _symbol_name(sym) if sym else str(addr)
        except Exception:
            name = str(addr)
        if name and name not in seen:
            seen.add(name)
            exports.append(name)
    return exports


def main():
    args = getScriptArgs()
    input_path = args[0]
    output_path = args[1]
    log_path = args[2]
    payload = json.loads(Path(input_path).read_text(encoding="utf-8"))
    program = currentProgram

    entry_points = [addr for addr in program.getSymbolTable().getExternalEntryPointIterator()]
    imports = _collect_imports(program)
    exports = _collect_exports(program, entry_points)

    result = {
        "ok": True,
        "architecture": program.getLanguage().getProcessor().toString(),
        "compiler": program.getCompilerSpec().toString(),
        "entry_points": [str(addr) for addr in entry_points],
        "image_base": str(program.getImageBase()),
        "segments": [segment.getName() for segment in program.getMemory().getBlocks()],
        "imports": imports[:200],
        "exports": exports[:200],
    }
    _write_output(output_path, result)
    _write_log(log_path, "analyze_binary_structure completed")


if __name__ == "__main__":
    main()
