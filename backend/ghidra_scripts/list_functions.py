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
    reference_manager = program.getReferenceManager()
    functions = []

    for function in listing.getFunctions(True):
        entry = function.getEntryPoint()

        # Count actual code references (calls) to this function, not symbol references
        call_count = 0
        for ref in reference_manager.getReferencesTo(entry):
            ref_type = ref.getReferenceType()
            # Count call and jump references (code flow to this function)
            if ref_type.isCall() or ref_type.isJump():
                call_count += 1

        functions.append({
            "name": function.getName(),
            "address": str(entry),
            "size": function.getBody().getNumAddresses(),
            "xrefs": call_count,
        })

    result = {"ok": True, "functions": functions}
    _write_output(output_path, result)
    _write_log(log_path, "list_functions completed")


if __name__ == "__main__":
    main()
