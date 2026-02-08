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

    pattern = payload.get("pattern")
    try:
        needle = bytes.fromhex(pattern.replace(" ", "").replace("0x", ""))
    except Exception:
        _write_output(output_path, {"ok": False, "error": "Invalid pattern"})
        _write_log(log_path, "search_bytes failed: invalid pattern")
        return

    matches = []
    memory = program.getMemory()
    for block in memory.getBlocks():
        block_size = block.getSize()
        offset = 0
        while offset < block_size:
            chunk_size = min(1024 * 1024, block_size - offset)
            data = block.getBytes(block.getStart().add(offset), chunk_size)
            idx = data.find(needle)
            while idx != -1:
                addr = block.getStart().add(offset + idx)
                matches.append(str(addr))
                idx = data.find(needle, idx + 1)
            offset += chunk_size

    _write_output(output_path, {"ok": True, "matches": matches})
    _write_log(log_path, "search_bytes completed")


if __name__ == "__main__":
    main()
