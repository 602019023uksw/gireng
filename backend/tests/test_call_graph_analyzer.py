"""Unit tests for call graph chain/cycle analysis."""

from ghidra_agent.call_graph_analyzer import analyze_call_graph


def test_detects_attack_chains_from_entry():
    call_graph = {
        "ok": True,
        "nodes": [
            {"name": "main", "address": "0x401000", "size": 128},
            {"name": "decrypt_payload", "address": "0x401100", "size": 96},
            {"name": "sym.imp.connect", "address": "0x403010", "size": 0},
        ],
        "edges": [
            {"from": "0x401000", "to": "0x401100", "from_name": "main", "to_name": "decrypt_payload", "type": "CALL"},
            {"from": "0x401100", "to": "0x403010", "from_name": "decrypt_payload", "to_name": "sym.imp.connect", "type": "CALL"},
        ],
        "entry_points": ["0x401000"],
    }

    result = analyze_call_graph(call_graph)
    assert result["ok"] is True
    assert "main" in result["entries"]
    assert any(c["category"] == "Crypto" for c in result["chains"])
    assert any(c["category"] == "Network" for c in result["chains"])


def test_detects_cycles():
    call_graph = {
        "ok": True,
        "nodes": [
            {"name": "main", "address": "0x401000", "size": 128},
            {"name": "loop_a", "address": "0x401100", "size": 96},
            {"name": "loop_b", "address": "0x401180", "size": 96},
        ],
        "edges": [
            {"from": "0x401000", "to": "0x401100", "from_name": "main", "to_name": "loop_a", "type": "CALL"},
            {"from": "0x401100", "to": "0x401180", "from_name": "loop_a", "to_name": "loop_b", "type": "CALL"},
            {"from": "0x401180", "to": "0x401100", "from_name": "loop_b", "to_name": "loop_a", "type": "CALL"},
        ],
        "entry_points": ["0x401000"],
    }

    result = analyze_call_graph(call_graph)
    assert result["ok"] is True
    assert len(result["cycles"]) >= 1
    assert any("loop_a" in cycle and "loop_b" in cycle for cycle in result["cycles"])


def test_unavailable_call_graph_returns_error():
    result = analyze_call_graph({"ok": False, "error": "not available"})
    assert result["ok"] is False
    assert "error" in result
