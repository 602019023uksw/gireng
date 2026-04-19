"""Shared ranking and sorting utilities for function analysis."""

from typing import Any, Dict


def _to_num(value: Any) -> float:
    """Best-effort numeric conversion for ranking metadata fields."""
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return 0.0
    return 0.0


def _function_priority_key(func: Dict[str, Any]) -> tuple[float, float, float, str]:
    """Sort by composite score first, with deterministic tie-breakers."""
    score = _to_num(func.get("priority_score"))
    if score <= 0.0:
        # Backward compatible fallback when score isn't present.
        score = _to_num(func.get("xrefs")) * 100.0 + _to_num(func.get("size"))
    return (
        score,
        _to_num(func.get("xrefs")),
        _to_num(func.get("size")),
        str(func.get("name", "")),
    )
