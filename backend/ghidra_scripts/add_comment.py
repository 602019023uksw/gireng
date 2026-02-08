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
        _write_log(log_path, "add_comment failed: invalid address")
        return

    listing = program.getListing()
    listing.setComment(address, 0, payload.get("comment"))
    _write_output(output_path, {"ok": True, "address": payload.get("address"), "comment": payload.get("comment")})
    _write_log(log_path, "add_comment completed")


if __name__ == "__main__":
    main()
