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

    result = {
        "ok": True,
        "architecture": program.getLanguage().getProcessor().toString(),
        "compiler": program.getCompilerSpec().toString(),
        "entry_points": [str(addr) for addr in program.getSymbolTable().getExternalEntryPointIterator()],
        "image_base": str(program.getImageBase()),
        "segments": [segment.getName() for segment in program.getMemory().getBlocks()],
    }
    _write_output(output_path, result)
    _write_log(log_path, "analyze_binary_structure completed")


if __name__ == "__main__":
    main()
