import json
from pathlib import Path

from ghidra.program.model.block import BasicBlockModel


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

    function = None
    if payload.get("function_name"):
        target_name = payload["function_name"]
        for f in program.getFunctionManager().getFunctions(True):
            if f.getName() == target_name:
                function = f
                break
    if not function and payload.get("address"):
        address = program.getAddressFactory().getAddress(payload["address"])
        function = program.getFunctionManager().getFunctionContaining(address)

    if not function:
        _write_output(output_path, {"ok": False, "error": "Function not found"})
        _write_log(log_path, "get_function_graph failed: function not found")
        return

    model = BasicBlockModel(program)
    blocks = model.getCodeBlocksContaining(function.getBody(), None)
    nodes = []
    edges = []
    while blocks.hasNext():
        block = blocks.next()
        start = str(block.getFirstStartAddress())
        end = str(block.getMaxAddress())
        nodes.append({"id": start, "start": start, "end": end})
        dest_iter = block.getDestinations(None)
        while dest_iter.hasNext():
            dest = dest_iter.next()
            edges.append({"from": start, "to": str(dest.getDestinationAddress())})

    _write_output(output_path, {"ok": True, "nodes": nodes, "edges": edges})
    _write_log(log_path, "get_function_graph completed")


if __name__ == "__main__":
    main()
