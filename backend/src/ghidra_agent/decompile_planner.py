"""Shared decompilation planning logic.

Extracts the function-selection strategy used by both Ghidra and Radare2
pipelines so the two analyzers don't drift.
"""

from typing import Any, Dict, List, Optional, Tuple

from ghidra_agent.ranking_utils import _function_priority_key


def plan_decompilation(
    func_list: List[Dict[str, Any]],
    binary_info: Optional[Dict[str, Any]] = None,
    *,
    min_funcs: int = 10,
    max_funcs: int = 40,
    percent: float = 0.75,
    include_entry_point: bool = False,
) -> Tuple[List[Dict[str, Any]], Optional[str], Optional[str]]:
    """Return the list of functions that should be decompiled.

    Args:
        func_list: Raw list of functions from the analyzer.
        binary_info: Optional binary metadata (used when include_entry_point=True).
        min_funcs: Floor — always plan at least this many functions.
        max_funcs: Ceiling — never plan more than this many functions.
        percent: Fraction of *meaningful* functions to target.
        include_entry_point: If True, prepend the function whose address matches
            the first entry point and return its name/address.

    Returns:
        (funcs_to_decompile, entry_point_function_name, entry_point_address)
    """
    meaningful_funcs = [f for f in func_list if f.get("size", 0) > 6]
    sorted_funcs = sorted(meaningful_funcs, key=_function_priority_key, reverse=True)

    decompile_target = min(
        max_funcs,
        max(min_funcs, int(len(meaningful_funcs) * percent)),
    )

    funcs_to_decompile: List[Dict[str, Any]] = []
    seen_names: set[str] = set()
    entry_func_name: Optional[str] = None
    entry_addr: Optional[str] = None

    if include_entry_point and binary_info and binary_info.get("ok"):
        entry_points = binary_info.get("entry_points", [])
        if entry_points:
            ep = entry_points[0]
            for f in func_list:
                if f.get("address") == ep:
                    funcs_to_decompile.append(f)
                    seen_names.add(f.get("name", ""))
                    entry_func_name = f.get("name")
                    entry_addr = ep
                    break

    must_have: List[Dict[str, Any]] = []
    for f in sorted_funcs:
        fname = f.get("name", "")
        if fname in seen_names:
            continue
        if (fname or "").lower() in {"main", "_start", "entry0"}:
            must_have.append(f)
            seen_names.add(fname)
            continue
        if f.get("is_interesting_caller") or f.get("has_suspicious_strings"):
            must_have.append(f)
            seen_names.add(fname)
            continue

    funcs_to_decompile.extend(must_have)

    remaining_slots = max(0, decompile_target - len(funcs_to_decompile))
    top_fill = [f for f in sorted_funcs if f.get("name", "") not in seen_names][:remaining_slots]
    funcs_to_decompile.extend(top_fill)

    return funcs_to_decompile, entry_func_name, entry_addr
