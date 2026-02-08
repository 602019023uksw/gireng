import json
from pathlib import Path

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


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

    decompiler = DecompInterface()
    decompiler.openProgram(program)
    monitor = ConsoleTaskMonitor()

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
        _write_log(log_path, "decompile_function failed: function not found")
        return

    timeout = int(payload.get("max_time", 30))
    decomp_result = decompiler.decompileFunction(function, timeout, monitor)
    if not decomp_result.decompileCompleted():
        _write_output(output_path, {"ok": False, "error": "Decompilation failed"})
        _write_log(log_path, "decompile_function failed: decompilation failed")
        return

    c_code = decomp_result.getDecompiledFunction().getC()
    _write_output(output_path, {"ok": True, "function": function.getName(), "address": str(function.getEntryPoint()), "c": c_code})
    _write_log(log_path, "decompile_function completed")


if __name__ == "__main__":
    main()
