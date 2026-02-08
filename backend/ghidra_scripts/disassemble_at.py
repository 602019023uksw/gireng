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
        _write_log(log_path, "disassemble_at failed: invalid address")
        return

    listing = program.getListing()
    instructions = []
    current = address
    count = int(payload.get("count", 32))
    for _ in range(count):
        inst = listing.getInstructionAt(current)
        if inst is None:
            break
        instructions.append({
            "address": str(inst.getAddress()),
            "mnemonic": inst.getMnemonicString(),
            "operands": inst.getDefaultOperandRepresentation(0),
            "comment": inst.getComment(0),
        })
        current = inst.getNext()
        if current is None:
            break

    _write_output(output_path, {"ok": True, "instructions": instructions})
    _write_log(log_path, "disassemble_at completed")


if __name__ == "__main__":
    main()
