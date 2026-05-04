"""Cross-engine evidence correlation for deep binary analysis."""

from typing import Any, Dict, List

from ghidra_agent.ioc_extractor import IOCs


def build_evidence_correlation(state: Dict[str, Any], iocs: IOCs | None = None) -> Dict[str, Any]:
    """Build analyst-facing links between IOCs, strings, functions, and runtime telemetry."""
    if iocs is None:
        from ghidra_agent.ioc_extractor import extract_iocs_from_state

        iocs = extract_iocs_from_state(state)

    ghidra_functions = _function_index(state.get("analysis_results", {}).get("functions", {}).get("functions", []))
    r2_functions = _function_index(state.get("r2_analysis_results", {}).get("functions", {}).get("functions", []))
    ioc_values = _ioc_values(iocs)

    findings: List[Dict[str, Any]] = []
    findings.extend(_string_findings("ghidra", state.get("analysis_results", {}).get("strings", {}).get("strings", []), ioc_values, ghidra_functions))
    findings.extend(_string_findings("radare2", state.get("r2_analysis_results", {}).get("strings", {}).get("strings", []), ioc_values, r2_functions))
    findings.extend(_dynamic_findings(state.get("qiling_analysis_results", {}), ioc_values))
    findings.extend(_decompilation_findings("ghidra", state.get("decompilation_cache", {}), ioc_values, ghidra_functions))
    findings.extend(_decompilation_findings("radare2", state.get("r2_decompilation_cache", {}), ioc_values, r2_functions))

    deduped = _dedupe_findings(findings)
    deduped.sort(key=lambda item: (item.get("confidence", 0), len(item.get("evidence", []))), reverse=True)

    return {
        "ok": True,
        "summary": {
            "total_findings": len(deduped),
            "engines": sorted({finding["engine"] for finding in deduped}),
            "linked_iocs": len({ioc for finding in deduped for ioc in finding.get("iocs", [])}),
        },
        "findings": deduped,
    }


def format_evidence_correlation(correlation: Dict[str, Any], limit: int = 12) -> str:
    """Format correlation findings for LLM context and text reports."""
    findings = correlation.get("findings", []) if isinstance(correlation, dict) else []
    if not findings:
        return "No cross-engine evidence correlations found."

    lines = ["Cross-Engine Evidence Correlation:"]
    for finding in findings[:limit]:
        iocs = ", ".join(str(ioc) for ioc in finding.get("iocs", [])[:4]) or "none"
        funcs = ", ".join(str(func) for func in finding.get("functions", [])[:4]) or "unknown"
        lines.append(
            f"- {finding.get('engine', 'unknown')} {finding.get('source', 'evidence')}: "
            f"{finding.get('description', '')}; iocs=[{iocs}]; functions=[{funcs}]"
        )
    if len(findings) > limit:
        lines.append(f"... and {len(findings) - limit} more correlations")
    return "\n".join(lines)


def _ioc_values(iocs: IOCs) -> List[str]:
    values: List[str] = []
    for key, raw_values in iocs.to_dict().items():
        if key == "suspicious_strings":
            continue
        for value in raw_values:
            clean = str(value)
            if key == "crypto_materials" and ": " in clean:
                clean = clean.rsplit(": ", 1)[-1]
            elif key == "decoded_strings" and " decoded: " in clean:
                clean = clean.split(" decoded: ", 1)[1]
            if clean and clean not in values:
                values.append(clean)
    values.sort(key=len, reverse=True)
    return values


def _function_index(functions: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    for func in functions or []:
        if not isinstance(func, dict):
            continue
        for key in ("address", "name"):
            value = func.get(key)
            if value:
                index[str(value).lower()] = func
    return index


def _string_findings(
    engine: str,
    strings: List[Dict[str, Any]],
    ioc_values: List[str],
    functions: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for item in strings or []:
        if not isinstance(item, dict):
            continue
        value = str(item.get("value", ""))
        linked = _matching_iocs(value, ioc_values)
        if not linked:
            continue
        xrefs = [str(x) for x in item.get("xrefs", []) or []]
        linked_functions = _functions_for_refs(xrefs, functions)
        if item.get("address"):
            linked_functions.extend(_functions_for_refs([str(item["address"])], functions))
        findings.append(
            {
                "engine": engine,
                "source": "string",
                "description": _shorten(value),
                "iocs": linked,
                "addresses": [str(item["address"])] if item.get("address") else [],
                "functions": _unique(linked_functions),
                "evidence": xrefs[:6],
                "confidence": 80 if linked_functions else 65,
            }
        )
    return findings


def _dynamic_findings(qiling: Dict[str, Any], ioc_values: List[str]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not isinstance(qiling, dict):
        return findings

    network = qiling.get("network_activity", {})
    if isinstance(network, dict):
        for conn in network.get("connections", []) or []:
            if not isinstance(conn, dict):
                continue
            address = conn.get("address")
            if not address:
                continue
            target = f"{address}:{conn.get('port')}" if conn.get("port") else str(address)
            linked = _matching_iocs(target, ioc_values) or ([target] if target else [])
            if linked:
                findings.append(_dynamic_finding("network", "runtime connection", linked, target, 95))
        for dns in network.get("dns_queries", []) or []:
            if isinstance(dns, dict) and dns.get("domain"):
                domain = str(dns["domain"])
                linked = _matching_iocs(domain, ioc_values) or [domain]
                findings.append(_dynamic_finding("network", "runtime DNS query", linked, domain, 95))

    syscalls = qiling.get("syscalls", {})
    if isinstance(syscalls, dict):
        for call in syscalls.get("syscalls", []) or []:
            if not isinstance(call, dict):
                continue
            args_text = " ".join(str(arg) for arg in call.get("args", []) or [])
            linked = _matching_iocs(args_text, ioc_values)
            if linked:
                findings.append(_dynamic_finding("syscall", str(call.get("name", "syscall")), linked, args_text, 90))

    api_calls = qiling.get("api_calls", {})
    if isinstance(api_calls, dict):
        for api in api_calls.get("api_calls", []) or []:
            if not isinstance(api, dict):
                continue
            args = api.get("args", {})
            args_text = " ".join(str(v) for v in args.values()) if isinstance(args, dict) else str(args)
            linked = _matching_iocs(args_text, ioc_values)
            if linked:
                findings.append(_dynamic_finding("api", str(api.get("name", "api_call")), linked, args_text, 90))

    return findings


def _dynamic_finding(source: str, name: str, iocs: List[str], evidence: str, confidence: int) -> Dict[str, Any]:
    return {
        "engine": "qiling",
        "source": source,
        "description": name,
        "iocs": iocs,
        "addresses": [],
        "functions": [],
        "evidence": [_shorten(evidence)],
        "confidence": confidence,
    }


def _decompilation_findings(
    engine: str,
    decompilation_cache: Dict[str, str],
    ioc_values: List[str],
    functions: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for func_name, code in (decompilation_cache or {}).items():
        code_text = str(code)
        linked = _matching_iocs(code_text, ioc_values)
        if not linked:
            continue
        func = functions.get(str(func_name).lower(), {})
        functions_out = [str(func.get("name") or func_name)]
        addresses = [str(func["address"])] if func.get("address") else []
        findings.append(
            {
                "engine": engine,
                "source": "decompiled_code",
                "description": f"decompiled function references IOC: {func_name}",
                "iocs": linked,
                "addresses": addresses,
                "functions": _unique(functions_out),
                "evidence": [_shorten(_context_for_ioc(code_text, linked[0]))],
                "confidence": 85,
            }
        )
    return findings


def _matching_iocs(text: str, ioc_values: List[str]) -> List[str]:
    lower = text.lower()
    matches: List[str] = []
    for ioc in ioc_values:
        if ioc and str(ioc).lower() in lower and ioc not in matches:
            matches.append(ioc)
        if len(matches) >= 8:
            break
    return matches


def _functions_for_refs(refs: List[str], functions: Dict[str, Dict[str, Any]]) -> List[str]:
    names: List[str] = []
    for ref in refs:
        func = functions.get(str(ref).lower())
        if func:
            name = str(func.get("name") or ref)
            address = str(func.get("address", ""))
            names.append(f"{name}@{address}" if address else name)
        elif ref:
            names.append(str(ref))
    return _unique(names)


def _context_for_ioc(text: str, ioc: str) -> str:
    idx = text.lower().find(str(ioc).lower())
    if idx < 0:
        return text[:240]
    start = max(0, idx - 100)
    end = min(len(text), idx + len(ioc) + 100)
    return text[start:end]


def _shorten(value: str, limit: int = 240) -> str:
    value = str(value).replace("\r", " ").replace("\n", " ").strip()
    return value if len(value) <= limit else value[: limit - 3] + "..."


def _unique(values: List[str]) -> List[str]:
    output: List[str] = []
    for value in values:
        if value and value not in output:
            output.append(value)
    return output


def _dedupe_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped: Dict[tuple[str, str, str], Dict[str, Any]] = {}
    for finding in findings:
        ioc_key = "|".join(str(ioc) for ioc in finding.get("iocs", [])[:3])
        key = (finding.get("engine", ""), finding.get("source", ""), ioc_key)
        if key not in deduped:
            deduped[key] = finding
            continue
        existing = deduped[key]
        existing["addresses"] = _unique(existing.get("addresses", []) + finding.get("addresses", []))
        existing["functions"] = _unique(existing.get("functions", []) + finding.get("functions", []))
        existing["evidence"] = _unique(existing.get("evidence", []) + finding.get("evidence", []))[:8]
        existing["confidence"] = max(existing.get("confidence", 0), finding.get("confidence", 0))
    return list(deduped.values())
