import json
from pathlib import Path


def _write_output(path, payload):
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_log(path, message):
    Path(path).write_text(message + "\n", encoding="utf-8")


def _block_name(program, addr):
    if addr is None:
        return ""
    block = program.getMemory().getBlock(addr)
    return block.getName().lower() if block else ""


def _is_plt_got_edge(program, from_addr, to_addr):
    from_block = _block_name(program, from_addr)
    to_block = _block_name(program, to_addr)
    return ("plt" in from_block and "got" in to_block) or ("plt" in from_block and "plt" in to_block)


def main():
    args = getScriptArgs()
    input_path = args[0]
    output_path = args[1]
    log_path = args[2]

    # Input payload currently unused but consumed for parity with other scripts.
    _ = json.loads(Path(input_path).read_text(encoding="utf-8"))

    program = currentProgram
    listing = program.getListing()
    ref_manager = program.getReferenceManager()
    fn_manager = program.getFunctionManager()

    nodes = []
    edges = []
    seen_edges = set()

    entry_points = [str(addr) for addr in program.getSymbolTable().getExternalEntryPointIterator()]

    addr_to_name = {}
    for fn in listing.getFunctions(True):
        try:
            if fn.isThunk():
                continue
        except Exception:
            pass
        entry = fn.getEntryPoint()
        entry_str = str(entry)
        name = fn.getName()
        addr_to_name[entry_str] = name
        nodes.append({
            "name": name,
            "address": entry_str,
            "size": fn.getBody().getNumAddresses(),
        })

    for fn in listing.getFunctions(True):
        try:
            if fn.isThunk():
                continue
        except Exception:
            pass

        from_entry = fn.getEntryPoint()
        from_entry_str = str(from_entry)
        body = fn.getBody()
        addr_iter = body.getAddresses(True)

        while addr_iter.hasNext():
            ins_addr = addr_iter.next()
            for ref in ref_manager.getReferencesFrom(ins_addr):
                ref_type = ref.getReferenceType()
                if not ref_type.isCall():
                    continue

                to_addr = ref.getToAddress()
                if to_addr is None:
                    continue
                if _is_plt_got_edge(program, ins_addr, to_addr):
                    continue

                callee = fn_manager.getFunctionContaining(to_addr)
                if callee is None:
                    continue
                try:
                    if callee.isThunk():
                        continue
                except Exception:
                    pass

                to_entry = callee.getEntryPoint()
                to_entry_str = str(to_entry)
                edge_key = (from_entry_str, to_entry_str)
                if edge_key in seen_edges:
                    continue
                seen_edges.add(edge_key)

                edges.append({
                    "from": from_entry_str,
                    "to": to_entry_str,
                    "from_name": fn.getName(),
                    "to_name": callee.getName(),
                    "type": "CALL",
                })

    result = {
        "ok": True,
        "nodes": nodes,
        "edges": edges,
        "entry_points": entry_points,
    }
    _write_output(output_path, result)
    _write_log(log_path, "build_call_graph completed")


if __name__ == "__main__":
    main()
