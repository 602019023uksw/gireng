"""Call graph analysis helpers.

Builds attack chains from function-call edges without external graph dependencies.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple

ENTRY_HINTS = {"main", "_start", "entry0", "entry", "start", "winmain"}

SINK_PATTERNS = {
    "Execution": {"system", "popen", "execve", "execv", "execl", "createprocess", "winexec"},
    "Network": {"socket", "connect", "send", "sendto", "recv", "recvfrom", "wsastartup", "wsasocket"},
    "File I/O": {"fopen", "fwrite", "fclose", "open", "write", "read"},
    "Crypto": {"encrypt", "decrypt", "crypt", "aes", "rsa"},
}

MAX_CHAIN_DEPTH = 10
MAX_CHAINS = 80


def _normalize_name(name: str) -> str:
    normalized = (name or "").strip().lower()
    prefixes = ("sym.imp.", "imp.", "sym.", "fcn.", "__imp_")
    for prefix in prefixes:
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
    return normalized


def _match_sink_category(function_name: str) -> str | None:
    normalized = _normalize_name(function_name)
    if not normalized:
        return None
    for category, patterns in SINK_PATTERNS.items():
        for pattern in patterns:
            if pattern in normalized:
                return category
    return None


def _build_graph(call_graph: Dict[str, Any]) -> Tuple[Dict[str, Set[str]], Dict[str, int], Set[str]]:
    nodes = call_graph.get("nodes", []) or []
    edges = call_graph.get("edges", []) or []

    adjacency: Dict[str, Set[str]] = {}
    indegree: Dict[str, int] = {}
    known_nodes: Set[str] = set()

    addr_to_name: Dict[str, str] = {}
    for node in nodes:
        name = node.get("name", "")
        addr = str(node.get("address", ""))
        if not name:
            continue
        known_nodes.add(name)
        adjacency.setdefault(name, set())
        indegree.setdefault(name, 0)
        if addr:
            addr_to_name[addr] = name

    for edge in edges:
        src = edge.get("from_name") or addr_to_name.get(str(edge.get("from", "")), str(edge.get("from", "")))
        dst = edge.get("to_name") or addr_to_name.get(str(edge.get("to", "")), str(edge.get("to", "")))
        if not src or not dst:
            continue
        if src == dst:
            adjacency.setdefault(src, set()).add(dst)
            indegree.setdefault(src, 0)
            known_nodes.add(src)
            continue
        if dst not in adjacency.get(src, set()):
            adjacency.setdefault(src, set()).add(dst)
            indegree[dst] = indegree.get(dst, 0) + 1
            indegree.setdefault(src, indegree.get(src, 0))
            known_nodes.add(src)
            known_nodes.add(dst)

    for name in list(known_nodes):
        adjacency.setdefault(name, set())
        indegree.setdefault(name, 0)

    return adjacency, indegree, known_nodes


def _detect_entry_nodes(known_nodes: Set[str], indegree: Dict[str, int]) -> List[str]:
    preferred = [n for n in known_nodes if _normalize_name(n) in ENTRY_HINTS]
    if preferred:
        return sorted(preferred)
    inferred = sorted([n for n in known_nodes if indegree.get(n, 0) == 0])
    if inferred:
        return inferred[:10]
    return sorted(list(known_nodes))[:5]


def _find_chains_and_cycles(adjacency: Dict[str, Set[str]], entries: List[str]) -> Tuple[List[Dict[str, Any]], List[List[str]]]:
    chains: List[Dict[str, Any]] = []
    seen_chains: Set[Tuple[str, Tuple[str, ...]]] = set()
    cycles_set: Set[Tuple[str, ...]] = set()

    def dfs(path: List[str], depth: int) -> None:
        if depth > MAX_CHAIN_DEPTH or len(chains) >= MAX_CHAINS:
            return
        current = path[-1]
        category = _match_sink_category(current)
        if category and len(path) > 1:
            key = (category, tuple(path))
            if key not in seen_chains:
                seen_chains.add(key)
                chains.append(
                    {
                        "category": category,
                        "sink": current,
                        "path": path.copy(),
                        "description": f"Entry path reaches {category.lower()} sink `{current}`.",
                    }
                )
        for nxt in sorted(adjacency.get(current, set())):
            if nxt in path:
                cycle = path[path.index(nxt) :] + [nxt]
                cycle_key = tuple(cycle)
                cycles_set.add(cycle_key)
                continue
            dfs(path + [nxt], depth + 1)

    for entry in entries:
        dfs([entry], 0)
        if len(chains) >= MAX_CHAINS:
            break

    cycles = [list(c) for c in sorted(cycles_set, key=lambda x: (len(x), x))]
    chains.sort(key=lambda c: (len(c.get("path", [])), c.get("category", ""), c.get("sink", "")))
    return chains, cycles


def analyze_call_graph(call_graph: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze call graph and extract attack chains, cycles, and adjacency view."""
    if not call_graph or not call_graph.get("ok"):
        return {"ok": False, "error": "call graph unavailable", "chains": [], "cycles": []}

    adjacency, indegree, known_nodes = _build_graph(call_graph)
    if not known_nodes:
        return {"ok": False, "error": "empty call graph", "chains": [], "cycles": []}

    addr_to_name = {
        str(node.get("address", "")).lower(): str(node.get("name", ""))
        for node in (call_graph.get("nodes", []) or [])
        if node.get("address") and node.get("name")
    }
    entry_candidates: List[str] = []
    for raw_entry in call_graph.get("entry_points", []) or []:
        entry_str = str(raw_entry).strip()
        if not entry_str:
            continue
        if entry_str in known_nodes:
            entry_candidates.append(entry_str)
            continue
        mapped = addr_to_name.get(entry_str.lower())
        if mapped and mapped in known_nodes:
            entry_candidates.append(mapped)

    fallback_entries = _detect_entry_nodes(known_nodes, indegree)
    entries = sorted(set(entry_candidates or fallback_entries))
    chains, cycles = _find_chains_and_cycles(adjacency, entries)
    adjacency_rows = [
        {
            "function": fn,
            "calls": sorted(list(callees)),
        }
        for fn, callees in sorted(adjacency.items(), key=lambda x: x[0])
    ]

    return {
        "ok": True,
        "entries": entries,
        "adjacency": adjacency_rows[:300],
        "chains": chains,
        "cycles": cycles[:50],
        "stats": {
            "nodes": len(known_nodes),
            "edges": sum(len(v) for v in adjacency.values()),
            "entries": len(entries),
            "chains": len(chains),
            "cycles": len(cycles),
        },
    }
