"""Function prioritization utilities.

Ranks functions by a composite score derived from normalized xref count and size:
    score = alpha * norm(xrefs) + beta * norm(size)
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple


def _to_float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return default
    return default


def _minmax(values: List[float]) -> List[float]:
    if not values:
        return []
    low = min(values)
    high = max(values)
    if high == low:
        # No spread: keep a stable neutral signal.
        return [0.0 for _ in values]
    scale = high - low
    return [(v - low) / scale for v in values]


def normalize_weights(alpha: float, beta: float) -> Tuple[float, float]:
    alpha = max(0.0, float(alpha))
    beta = max(0.0, float(beta))
    total = alpha + beta
    if total <= 0:
        return 0.5, 0.5
    return alpha / total, beta / total


def prioritize_functions(
    functions: Iterable[Dict[str, Any]],
    alpha: float,
    beta: float,
) -> List[Dict[str, Any]]:
    """Return functions sorted by composite score (descending).

    Adds:
    - ``priority_score``: weighted normalized score in [0, 1]
    - ``norm_xrefs``: normalized xrefs in [0, 1]
    - ``norm_size``: normalized size in [0, 1]
    """
    items = [dict(f) for f in functions]
    if not items:
        return []

    alpha, beta = normalize_weights(alpha, beta)

    xrefs_raw = [_to_float(f.get("xrefs", 0)) for f in items]
    size_raw = [_to_float(f.get("size", 0)) for f in items]
    norm_xrefs = _minmax(xrefs_raw)
    norm_size = _minmax(size_raw)

    scored: List[Dict[str, Any]] = []
    for idx, f in enumerate(items):
        nx = norm_xrefs[idx]
        ns = norm_size[idx]
        score = alpha * nx + beta * ns
        f["norm_xrefs"] = round(nx, 6)
        f["norm_size"] = round(ns, 6)
        f["priority_score"] = round(score, 6)
        scored.append(f)

    scored.sort(
        key=lambda f: (
            f.get("priority_score", 0.0),
            _to_float(f.get("xrefs", 0.0)),
            _to_float(f.get("size", 0.0)),
            str(f.get("name", "")),
        ),
        reverse=True,
    )
    return scored


def apply_priority_to_result(
    result: Dict[str, Any],
    alpha: float,
    beta: float,
) -> Dict[str, Any]:
    """Apply prioritization to a tool result shaped like ``{"ok": True, "functions": [...]}``."""
    if not result.get("ok"):
        return result
    funcs = result.get("functions")
    if not isinstance(funcs, list):
        return result
    alpha_n, beta_n = normalize_weights(alpha, beta)
    result["functions"] = prioritize_functions(funcs, alpha=alpha_n, beta=beta_n)
    result["priority_weights"] = {"alpha": round(alpha_n, 6), "beta": round(beta_n, 6)}
    return result

