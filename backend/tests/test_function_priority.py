"""Tests for composite function prioritization (xrefs + size)."""

from copy import deepcopy

from ghidra_agent.function_priority import (
    apply_priority_to_result,
    normalize_weights,
    prioritize_functions,
)


def test_normalize_weights_handles_zero_total():
    alpha, beta = normalize_weights(0.0, 0.0)
    assert alpha == 0.5
    assert beta == 0.5


def test_prioritize_functions_adds_scores_and_sorts_descending():
    funcs = [
        {"name": "tiny_hot", "xrefs": 50, "size": 10},
        {"name": "big_cold", "xrefs": 1, "size": 1000},
        {"name": "balanced", "xrefs": 40, "size": 800},
    ]

    ranked = prioritize_functions(funcs, alpha=0.7, beta=0.3)

    assert len(ranked) == 3
    assert "priority_score" in ranked[0]
    assert "norm_xrefs" in ranked[0]
    assert "norm_size" in ranked[0]
    assert ranked[0]["priority_score"] >= ranked[1]["priority_score"] >= ranked[2]["priority_score"]
    assert ranked[0]["name"] == "balanced"


def test_apply_priority_to_result_enriches_payload():
    result = {
        "ok": True,
        "functions": [
            {"name": "f1", "xrefs": 2, "size": 10},
            {"name": "f2", "xrefs": 5, "size": 8},
        ],
    }

    updated = apply_priority_to_result(deepcopy(result), alpha=0.8, beta=0.2)

    assert updated["ok"] is True
    assert updated["priority_weights"] == {"alpha": 0.8, "beta": 0.2}
    assert updated["functions"][0]["name"] == "f2"
    assert all("priority_score" in f for f in updated["functions"])


def test_apply_priority_to_result_noop_on_error_payload():
    result = {"ok": False, "error": "boom"}
    updated = apply_priority_to_result(deepcopy(result), alpha=0.7, beta=0.3)
    assert updated == result
