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
    payload = json.loads(Path(input_path).read_text(encoding="utf-8"))
    program = currentProgram

    address = program.getAddressFactory().getAddress(payload.get("address"))
    if address is None:
        _write_output(output_path, {"ok": False, "error": "Invalid address"})
        _write_log(log_path, "rename_symbol failed: invalid address")
        return

    symbol = program.getSymbolTable().getPrimarySymbol(address)
    if symbol is None:
        _write_output(output_path, {"ok": False, "error": "Symbol not found"})
        _write_log(log_path, "rename_symbol failed: symbol not found")
        return
    old_name = symbol.getName()
    symbol.setName(payload.get("new_name"), symbol.getSource())
    _write_output(output_path, {"ok": True, "old_name": old_name, "new_name": payload.get("new_name")})
    _write_log(log_path, "rename_symbol completed")


if __name__ == "__main__":
    main()
