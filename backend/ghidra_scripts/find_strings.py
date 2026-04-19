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
    query = payload.get("query")

    listing = program.getListing()
    reference_manager = program.getReferenceManager()
    results = []
    for data in listing.getDefinedData(True):
        try:
            has_string = data.hasStringValue()
        except Exception:
            has_string = False
        if not has_string:
            continue
        value = data.getValue()
        if value is None:
            continue
        value_text = str(value)
        if query and query not in value_text:
            continue
        xrefs = [str(ref.getFromAddress()) for ref in reference_manager.getReferencesTo(data.getAddress())]
        results.append({"address": str(data.getAddress()), "value": value_text, "xrefs": xrefs})

    _write_output(output_path, {"ok": True, "strings": results})
    _write_log(log_path, "find_strings completed")


if __name__ == "__main__":
    main()
