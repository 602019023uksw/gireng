import json
import re
from pathlib import Path

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def _write_output(path, payload):
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_log(path, message):
    log_path = Path(path)
    log_path.write_text(message + "\n", encoding="utf-8")


def _parse_address_from_func_name(name):
    """Extract hex address from FUN_xxxxxxxx pattern."""
    match = re.search(r'[0-9a-fA-F]{4,}', name)
    if match:
        try:
            return "0x" + match.group(0).lower()
        except ValueError:
            pass
    return None


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
    target_name = payload.get("function_name")
    target_address = payload.get("address")
    
    # B1/B2 FIX: Use address-based lookup first (fast), fallback to name search
    if target_address:
        # Fast O(1) address lookup
        addr = program.getAddressFactory().getAddress(target_address)
        if addr:
            function = program.getFunctionManager().getFunctionContaining(addr)
    
    if not function and target_name:
        # Try to extract address from FUN_xxx name pattern for fast lookup
        addr_from_name = _parse_address_from_func_name(target_name)
        if addr_from_name:
            addr = program.getAddressFactory().getAddress(addr_from_name)
            if addr:
                function = program.getFunctionManager().getFunctionContaining(addr)
        
        # Fallback to name search if address lookup failed
        if not function:
            for f in program.getFunctionManager().getFunctions(True):
                if f.getName() == target_name:
                    function = f
                    break

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
