import json
from pathlib import Path


def _write_output(path, payload):
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_log(path, message):
    log_path = Path(path)
    log_path.write_text(message + "\n", encoding="utf-8")


def main():
    args = getScriptArgs()
    input_path = args[0]
    output_path = args[1]
    log_path = args[2]
    program = currentProgram
    listing = program.getListing()
    functions = []
    for function in listing.getFunctions(True):
        entry = function.getEntryPoint()
        xrefs = len(list(function.getSymbol().getReferences())) if function.getSymbol() else 0
        functions.append({
            "name": function.getName(),
            "address": str(entry),
            "size": function.getBody().getNumAddresses(),
            "xrefs": xrefs,
        })
    result = {"ok": True, "functions": functions}
    _write_output(output_path, result)
    _write_log(log_path, "list_functions completed")


if __name__ == "__main__":
    main()
