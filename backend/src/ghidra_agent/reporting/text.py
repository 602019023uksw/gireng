# -*- coding: utf-8 -*-
"""Plain-text report generation."""

from typing import Any, Dict

from ghidra_agent.reporting.common import *

def build_report_text(state: Dict[str, Any]) -> str:
    """Build a rich, sandbox.md-inspired plain text report for download.

    Extracts each section from the LLM summary via _extract_section(),
    presents structured binary metadata, verdict assessment, IoCs grouped
    by type, call graph analysis, and decompiled function appendices.
    """
    summary = state.get("summary", "No summary available.")
    program_hash = state.get("program_hash", "unknown")
    binary = state.get("analysis_results", {}).get("binary", {})
    r2_binary = state.get("r2_analysis_results", {}).get("binary", {})
    funcs = state.get("analysis_results", {}).get("functions", {})
    r2_funcs = state.get("r2_analysis_results", {}).get("functions", {})
    strings_data = state.get("analysis_results", {}).get("strings", {})
    r2_strings_data = state.get("r2_analysis_results", {}).get("strings", {})
    qiling = state.get("qiling_analysis_results", {})
    gh_call_graph_analysis = state.get("analysis_results", {}).get("call_graph_analysis", {})
    r2_call_graph_analysis = state.get("r2_analysis_results", {}).get("call_graph_analysis", {})
    decomp = state.get("decompilation_cache", {})
    r2_decomp = state.get("r2_decompilation_cache", {})
    has_qiling = bool(qiling)

    # --- Verdict ---
    iocs_obj = extract_iocs_from_state(state)
    verdict, verdict_class, indicators, score = calculate_verdict(iocs_obj, state)
    ioc_list = _parse_iocs_for_template(iocs_obj)

    # --- Extract LLM sections ---
    exec_summary   = _extract_section(summary, "Executive Summary") or summary[:3000]
    mitre_md       = (_extract_section(summary, "Threat Intel & MITRE ATT&CK")
                      or _extract_section(summary, "MITRE ATT&CK Tactics & Techniques") or "")
    capabilities_md = _extract_section(summary, "Malware Capabilities") or ""
    technical_md   = _extract_section(summary, "Technical Analysis") or ""
    functions_md   = _extract_section(summary, "Functions Analysis") or ""
    evidence_md    = _extract_section(summary, "Evidence of Malicious Activity") or ""
    operational_md = _extract_section(summary, "Operational Flow") or ""
    dynamic_md     = _extract_section(summary, "Dynamic Analysis") or ""
    conclusion_md  = _extract_section(summary, "Conclusion") or ""
    recommendations_list = _extract_recommendations(summary)

    # --- Helpers ---
    SEP  = "-" * 70
    SEP2 = "=" * 70

    def _md_plain(md: str) -> str:
        """Strip common markdown formatting for plain-text output."""
        lines_in = md.split("\n")
        out = []
        for line in lines_in:
            # Remove heading markers
            line2 = re.sub(r'^#{1,6}\s+', '', line.rstrip())
            # Bold / italic
            line2 = re.sub(r'\*{1,3}(.+?)\*{1,3}', r'\1', line2)
            # Inline code backticks → [code]
            line2 = re.sub(r'`(.+?)`', r'[\1]', line2)
            # Table separator rows
            if re.match(r'^\s*[\|\-\s]+$', line2):
                continue
            out.append(line2)
        return "\n".join(out).strip()

    report_title = (
        "GHIDRA + RADARE2 + QILING BINARY ANALYSIS REPORT"
        if has_qiling
        else "GHIDRA + RADARE2 BINARY ANALYSIS REPORT"
    )
    file_name = state.get("binary_path", "unknown").split("/")[-1].split("\\")[-1]
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: List[str] = [
        SEP2,
        report_title,
        SEP2,
        "",
        f"Sample:    {file_name}",
        f"SHA-256:   {program_hash}",
        f"Generated: {timestamp}",
        "",
    ]

    # ------------------------------------------------------------------ #
    # Verdict / Maliciousness Assessment
    # ------------------------------------------------------------------ #
    verdict_upper = verdict.upper()
    lines += [
        SEP,
        "MALICIOUSNESS ASSESSMENT",
        SEP,
        f"Verdict:     {verdict_upper}",
        f"Risk Score:  {score}/100",
        "",
    ]
    if indicators:
        lines.append("Key Indicators:")
        for ind in indicators[:10]:
            lines.append(f"  * {ind}")
        lines.append("")

    # ------------------------------------------------------------------ #
    # File Metadata  --  merged Ghidra + R2
    # ------------------------------------------------------------------ #
    arch = binary.get('architecture', r2_binary.get('architecture', 'unknown'))
    bits = r2_binary.get('bits', '?')
    os_name = r2_binary.get('os', 'unknown')
    fmt_raw = (str(binary.get('format', '')).lower()
               + str(r2_binary.get('format', '')).lower()
               + os_name.lower())
    if 'elf' in fmt_raw or os_name.lower() in ('linux',):
        fmt_str = 'ELF'
    elif 'pe' in fmt_raw or os_name.lower() in ('windows',):
        fmt_str = 'PE'
    elif 'mach' in fmt_raw or 'mac' in os_name.lower():
        fmt_str = 'Mach-O'
    else:
        fmt_str = 'Binary'

    gh_funcs_list  = funcs.get("functions", []) or []
    r2_funcs_list  = r2_funcs.get("functions", []) or []
    gh_exports     = binary.get("exports", [])
    r2_exports     = r2_binary.get("exports", [])
    gh_imports     = binary.get("imports", [])
    r2_imports_list = r2_binary.get("imports", [])
    stripped_val   = r2_binary.get('stripped', 'unknown')
    stripped_str   = ("Yes" if stripped_val is True
                      else "No" if stripped_val is False
                      else str(stripped_val))

    lines += [SEP, "FILE METADATA", SEP]
    meta_rows = [
        ("SHA-256",       program_hash),
        ("Architecture",  f"{arch} ({bits}-bit)" if bits and bits != '?' else str(arch)),
        ("Format",        f"{fmt_str}  -  {os_name}"),
        ("Image Base",    str(binary.get('image_base', 'unknown'))),
        ("Entry Points",  _format_entry_points(binary.get('entry_points', []))),
        ("Compiler",      _sanitize_compiler(binary.get('compiler',
                                                         r2_binary.get('compiler', 'unknown')))),
        ("Stripped",      stripped_str),
        ("Endianness",    r2_binary.get('endian', 'unknown')),
        ("Exports",       f"{len(gh_exports) or len(r2_exports)} symbols"),
        ("Functions",     (f"Ghidra: {len(gh_funcs_list)} ({len(decomp)} decompiled)"
                           f"  ·  R2: {len(r2_funcs_list)} ({len(r2_decomp)} decompiled)")),
        ("Strings",       (f"Ghidra: {len(strings_data.get('strings', []))}"
                           f"  ·  R2: {len(r2_strings_data.get('strings', []))}")),
    ]
    if gh_imports or r2_imports_list:
        meta_rows.append(("Imports", _format_import_export_list(gh_imports or r2_imports_list)))

    for label, value in meta_rows:
        lines.append(f"  {label:<16} {value}")
    lines.append("")

    # ------------------------------------------------------------------ #
    # Qiling Dynamic Analysis
    # ------------------------------------------------------------------ #
    if qiling:
        q_exec    = qiling.get("execution_trace", {})
        q_sys     = qiling.get("syscalls", {})
        q_network = qiling.get("network_activity", {})
        q_evasion = qiling.get("evasion_techniques", {})

        lines += [SEP, "QILING DYNAMIC ANALYSIS", SEP]
        if isinstance(q_exec, dict) and q_exec:
            lines += [
                f"  {'Execution Success':<22} {q_exec.get('success')}",
                f"  {'Architecture':<22} {q_exec.get('arch', 'unknown')}",
                f"  {'OS':<22} {q_exec.get('os', 'unknown')}",
                f"  {'Instructions':<22} {q_exec.get('instructions_executed', 0)}",
                f"  {'Duration (ms)':<22} {q_exec.get('duration_ms', 0)}",
                f"  {'Exit Reason':<22} {q_exec.get('exit_reason', 'unknown')}",
            ]
        if isinstance(q_sys, dict) and q_sys:
            q_sys_sum = q_sys.get("summary", {})
            lines.append(
                f"  {'Syscalls':<22} "
                f"{q_sys_sum.get('total_calls', 0) if isinstance(q_sys_sum, dict) else 0}"
            )
            if isinstance(q_sys_sum, dict):
                lines.append(f"  {'Categories':<22} {q_sys_sum.get('categories', {})}")
        if isinstance(q_network, dict) and q_network:
            ind_q = q_network.get("indicators", {})
            lines += [
                f"  {'C2 Candidates':<22} {ind_q.get('c2_candidates', []) if isinstance(ind_q, dict) else []}",
                f"  {'Protocols Used':<22} {ind_q.get('protocols_used', []) if isinstance(ind_q, dict) else []}",
            ]
        if isinstance(q_evasion, dict) and q_evasion:
            ev_sum = q_evasion.get("summary", {})
            if isinstance(ev_sum, dict):
                lines.append(
                    f"  {'Evasion':<22} {ev_sum.get('total_techniques', 0)}"
                    f" (risk={ev_sum.get('risk_level', 'low')})"
                )
        if qiling.get("errors"):
            lines.append(f"  {'Errors':<22} {qiling.get('errors')}")
        lines.append("")

    # ------------------------------------------------------------------ #
    # LLM Analysis Sections
    # ------------------------------------------------------------------ #
    def _append_sec(title: str, body: str) -> None:
        if not body or not body.strip():
            return
        lines.extend(["", SEP, title, SEP, _md_plain(body), ""])

    _append_sec("EXECUTIVE SUMMARY", exec_summary)
    _append_sec("THREAT INTEL & MITRE ATT&CK", mitre_md)
    _append_sec("MALWARE CAPABILITIES", capabilities_md)
    _append_sec("TECHNICAL ANALYSIS", technical_md)
    _append_sec("FUNCTIONS ANALYSIS", functions_md)
    _append_sec("EVIDENCE OF MALICIOUS ACTIVITY", evidence_md)
    _append_sec("OPERATIONAL FLOW", operational_md)
    if dynamic_md:
        _append_sec("DYNAMIC ANALYSIS", dynamic_md)
    _append_sec("CONCLUSION", conclusion_md)

    # ------------------------------------------------------------------ #
    # Recommendations
    # ------------------------------------------------------------------ #
    if recommendations_list:
        lines += ["", SEP, "RECOMMENDATIONS", SEP]
        for i, rec in enumerate(recommendations_list, 1):
            clean = re.sub(r'\*{1,3}(.+?)\*{1,3}', r'\1', rec).strip()
            lines.append(f"  {i}. {clean}")
        lines.append("")

    # ------------------------------------------------------------------ #
    # Indicators of Compromise (IoCs)  --  grouped by type
    # ------------------------------------------------------------------ #
    if ioc_list:
        lines += ["", SEP, "INDICATORS OF COMPROMISE (IoCs)", SEP]
        ioc_by_type: Dict[str, List[str]] = {}
        for ioc in ioc_list:
            ioc_by_type.setdefault(ioc['type'], []).append(ioc['value'])
        for ioc_type, values in ioc_by_type.items():
            lines.append(f"  [{ioc_type}]")
            for v in values:
                lines.append(f"    {v}")
            lines.append("")

    # ------------------------------------------------------------------ #
    # Call Graph & Attack Chains
    # ------------------------------------------------------------------ #
    def _append_call_graph_text(source: str, analysis: Dict[str, Any]) -> None:
        if not analysis or not analysis.get("ok"):
            return
        stats   = analysis.get("stats", {})
        entries = analysis.get("entries", []) or []
        chains  = analysis.get("chains", []) or []
        lines.append(f"  {source}:")
        lines.append(f"    Nodes: {stats.get('nodes', 0)},  Edges: {stats.get('edges', 0)}")
        if entries:
            lines.append(f"    Entry points: {', '.join(str(e) for e in entries[:5])}")
        if chains:
            deduped = _deduplicate_chains(chains)
            lines.append(f"    Attack chains ({len(deduped)} unique of {len(chains)} total):")
            for chain in deduped:
                path = " -> ".join(str(p) for p in chain.get("path", []))
                lines.append(f"      [{chain.get('category', 'Unknown')}] {path}")
        else:
            lines.append("    Attack chains: none detected")
        cycles = analysis.get("cycles", []) or []
        if cycles:
            lines.append(f"    Cycles (top 5 of {len(cycles)}):")
            for cycle in cycles[:5]:
                lines.append(f"      {' -> '.join(str(n) for n in cycle)}")
        lines.append("")

    if gh_call_graph_analysis.get("ok") or r2_call_graph_analysis.get("ok"):
        lines += ["", SEP, "CALL GRAPH & ATTACK CHAINS", SEP]
        _append_call_graph_text("Ghidra",  gh_call_graph_analysis)
        _append_call_graph_text("Radare2", r2_call_graph_analysis)

    # ------------------------------------------------------------------ #
    # Appendix: Decompiled Functions
    # ------------------------------------------------------------------ #
    if decomp:
        lines += [
            "",
            SEP,
            f"APPENDIX A: GHIDRA DECOMPILED FUNCTIONS ({len(decomp)})",
            SEP,
        ]
        for name, code in decomp.items():
            lines.append(f"\n--- {name} ---")
            lines.append(code[:4000])
            if len(code) > 4000:
                lines.append("/* ... [truncated at 4000 chars] ... */")
        lines.append("")

    if r2_decomp:
        lines += [
            "",
            SEP,
            f"APPENDIX B: RADARE2 DECOMPILED FUNCTIONS ({len(r2_decomp)})",
            SEP,
        ]
        for name, code in r2_decomp.items():
            lines.append(f"\n--- {name} ---")
            lines.append(code[:4000])
            if len(code) > 4000:
                lines.append("/* ... [truncated at 4000 chars] ... */")
        lines.append("")

    lines += [SEP2, "END OF REPORT", SEP2]

    return '\n'.join(lines)
