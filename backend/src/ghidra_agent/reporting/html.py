# -*- coding: utf-8 -*-
"""HTML report generation."""

import logging
import re
from datetime import datetime, timezone
from html import escape
from typing import Any, Dict

from ghidra_agent.evidence_correlator import build_evidence_correlation
from ghidra_agent.reporting.common import *
from ghidra_agent.ioc_extractor import extract_iocs_from_state, calculate_verdict

def build_report_html(state: Dict[str, Any]) -> str:
    """Build HTML report using a modern analyst-focused template."""

    iocs = extract_iocs_from_state(state)
    verdict, verdict_class, indicators, score = calculate_verdict(iocs, state)
    _set_report_tone(verdict_class)

    # ── Tone-aware labels ──
    _is_clean = verdict_class == "clean"
    _cap_section_title = "Capabilities" if _is_clean else "Malware Capabilities"
    _cap_subtitle = (
        "Behavioral capabilities identified through code analysis and pattern matching."
        if _is_clean else
        "Capability statements paired with direct evidence from function bodies or strings."
    )
    _ev_section_title = "Evidence & Findings" if _is_clean else "Evidence of Malicious Activity"
    _ev_subtitle = (
        "Structured findings that can be cited directly in documentation and review workflows."
        if _is_clean else
        "Structured findings that can be cited directly in IR and hunting workflows."
    )
    _chain_label = "Graph Chains" if _is_clean else "Attack Chains"
    _chain_desc = (
        "Connected graph paths discovered during static analysis."
        if _is_clean else
        "Sink-reaching graph paths"
    )
    _interesting_label = (
        "Decompiled or high-priority functions"
        if _is_clean else
        "Suspicious or high-priority functions"
    )

    analysis_results = state.get("analysis_results", {})
    r2_results = state.get("r2_analysis_results", {})
    qiling_results = state.get("qiling_analysis_results", {})
    binary = analysis_results.get("binary", {})
    r2_binary = r2_results.get("binary", {})
    funcs = analysis_results.get("functions", {})
    r2_funcs = r2_results.get("functions", {})
    strings_data = analysis_results.get("strings", {})
    r2_strings = r2_results.get("strings", {})
    gh_call_graph = analysis_results.get("call_graph_analysis", {})
    r2_call_graph = r2_results.get("call_graph_analysis", {})

    program_hash = state.get("program_hash", "unknown")
    summary_text = state.get("summary", "")
    file_name = escape(state.get("binary_path", "unknown").split("/")[-1])
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    task_id = state.get("session_id", "unknown")[:8]
    started_at = state.get("started_at_iso", "")
    completed_at = state.get("completed_at_iso", "")
    started_str = _format_timestamp(started_at) if started_at else "—"
    completed_str = _format_timestamp(completed_at) if completed_at else "—"

    logger.info("build_report_html: summary_text length=%d", len(summary_text))

    # --- Extract sections from LLM summary ---
    exec_summary = _extract_section(summary_text, "Executive Summary")
    if not exec_summary:
        fallback = re.sub(r'^#{2,3}\s+.*$', '', summary_text[:2000], flags=re.MULTILINE).strip()
        exec_summary = fallback or summary_text[:2000]

    
    mitre_md = _extract_section(summary_text, "Threat Intel & MITRE ATT&CK")
    if not mitre_md:
        mitre_md = _extract_section(summary_text, "MITRE ATT&CK Tactics & Techniques")
    capabilities_md = _extract_section(summary_text, "Malware Capabilities")
    technical_md = _extract_section(summary_text, "Technical Analysis")
    functions_md = _extract_section(summary_text, "Functions Analysis")
    operational_md = _extract_section(summary_text, "Operational Flow")
    evidence_md = _extract_section(summary_text, "Evidence of Malicious Activity")
    conclusion_text = _extract_section(summary_text, "Conclusion")
    dynamic_analysis_md = _extract_section(summary_text, "Dynamic Analysis")
    evidence_items = _extract_evidence(summary_text)
    recommendations = _extract_recommendations(summary_text)

    # Render sections with dedicated card-based renderers
    mitre_html = _render_mitre_cards(mitre_md)
    capabilities_html = _render_capabilities_cards(capabilities_md)
    technical_html = _render_technical_cards(technical_md)
    functions_html = _render_functions_cards(functions_md)
    operational_html = _render_operational_flow(operational_md)
    dynamic_analysis_html = _render_technical_cards(dynamic_analysis_md) if dynamic_analysis_md else ""
    ioc_list = _parse_iocs_for_template(iocs)
    evidence_correlation = build_evidence_correlation(state, iocs)

    # --- Verdict display config ---
    _VERDICT_CFG = {
        "malicious": ("Critical", "fa-skull-crossbones", "bg-red-100 dark:bg-red-900/30", "text-red-800 dark:text-red-300", "border-red-200 dark:border-red-800"),
        "suspicious": ("High Risk", "fa-exclamation-triangle", "bg-orange-100 dark:bg-orange-900/30", "text-orange-800 dark:text-orange-300", "border-orange-200 dark:border-orange-800"),
        "clean": ("Low Risk", "fa-check-circle", "bg-green-100 dark:bg-green-900/30", "text-green-800 dark:text-green-300", "border-green-200 dark:border-green-800"),
        "unknown": ("Unknown", "fa-question-circle", "bg-slate-100 dark:bg-slate-800", "text-slate-700 dark:text-slate-300", "border-[#131e36]"),
    }
    v_label, v_icon, v_badge_bg, v_badge_text, v_badge_border = _VERDICT_CFG.get(verdict_class, _VERDICT_CFG["unknown"])

    # Risk box gradient per verdict
    _RISK_GRADIENT = {
        "malicious": "background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);",
        "suspicious": "background: linear-gradient(135deg, #ea580c 0%, #9a3412 100%);",
        "clean": "background: linear-gradient(135deg, #16a34a 0%, #15803d 100%);",
        "unknown": "background: linear-gradient(135deg, #475569 0%, #334155 100%);",
    }
    risk_gradient = _RISK_GRADIENT.get(verdict_class, _RISK_GRADIENT["unknown"])

    # Binary format detection
    arch = binary.get('architecture', r2_binary.get('architecture', 'unknown'))
    bits = r2_binary.get('bits', '?')
    os_name = r2_binary.get('os', 'unknown')
    fmt_raw = str(binary.get('format', '')).lower() + str(r2_binary.get('format', '')).lower() + os_name.lower()
    if 'elf' in fmt_raw or os_name.lower() == 'linux':
        fmt_str = 'ELF'
    elif 'pe' in fmt_raw or os_name.lower() == 'windows':
        fmt_str = 'PE'
    elif 'mach' in fmt_raw or 'mac' in os_name.lower():
        fmt_str = 'Mach-O'
    else:
        fmt_str = 'Binary'
    format_badge = f"{fmt_str}{bits}" if bits != '?' else fmt_str

    hash_short = f"{program_hash[:6]}...{program_hash[-5:]}" if len(program_hash) > 16 else program_hash

    # High-level dashboard metrics for the report hero panel
    gh_funcs = funcs.get("functions", []) or []
    r2_func_list = r2_funcs.get("functions", []) or []
    total_functions = len(gh_funcs) + len(r2_func_list)
    decompiled_total = len(state.get("decompilation_cache", {})) + len(state.get("r2_decompilation_cache", {}))
    coverage_pct = int(round((decompiled_total / total_functions) * 100)) if total_functions else 0
    total_strings = len(strings_data.get("strings", [])) + len(r2_strings.get("strings", []))
    ioc_total = len(ioc_list)
    chain_total = len(gh_call_graph.get("chains", []) or []) + len(r2_call_graph.get("chains", []) or [])
    interesting_total = sum(
        1
        for func in (gh_funcs + r2_func_list)
        if func.get("is_interesting_caller") or func.get("has_suspicious_strings") or func.get("is_malicious")
    )
    if interesting_total == 0:
        interesting_total = decompiled_total

    # --- Render dynamic sections ---
    evidence_html = _render_evidence_cards(evidence_items, evidence_md)
    code_evidence_html = _render_code_evidence(state)
    call_graph_html = (
        '<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">'
        + _render_call_graph_section("Ghidra", gh_call_graph)
        + _render_call_graph_section("Radare2", r2_call_graph)
        + '</div>'
    )
    qiling_dynamic_html = _render_qiling_dynamic_section(qiling_results)
    iocs_rows = _render_iocs(ioc_list)
    evidence_correlation_html = _render_evidence_correlation(evidence_correlation)
    recommendations_html = _render_recommendations(recommendations)

    # Conclusion inner HTML
    if conclusion_text:
        conclusion_inner = _markdown_to_html(conclusion_text)
    else:
        conclusion_inner = (
            f'<p>This binary has been classified as <strong>{escape(verdict)}</strong> '
            f'with a risk score of {score}/100. Review the technical analysis and IOCs '
            f'above for detection and response guidance.</p>'
        )

    # Conclusion gradient colors
    _CC = {
        "malicious": ("from-red-50 to-orange-50 dark:from-red-900/20 dark:to-orange-900/10",
                       "border-red-200 dark:border-red-800/50", "text-red-900 dark:text-red-100",
                       "text-red-800 dark:text-red-200", "bg-red-100 dark:bg-red-800/50",
                       "text-red-600 dark:text-red-400"),
        "suspicious": ("from-orange-50 to-yellow-50 dark:from-orange-900/20 dark:to-yellow-900/10",
                        "border-orange-200 dark:border-orange-800/50", "text-orange-900 dark:text-orange-100",
                        "text-orange-800 dark:text-orange-200", "bg-orange-100 dark:bg-orange-800/50",
                        "text-orange-600 dark:text-orange-400"),
        "clean": ("from-green-50 to-emerald-50 dark:from-green-900/20 dark:to-emerald-900/10",
                   "border-green-200 dark:border-green-800/50", "text-green-900 dark:text-green-100",
                   "text-green-800 dark:text-green-200", "bg-green-100 dark:bg-green-800/50",
                   "text-green-600 dark:text-green-400"),
        "unknown": ("from-slate-50 to-slate-100 dark:from-slate-900/20 dark:to-slate-800/10",
                     "border-slate-200 dark:border-slate-700/50", "text-slate-900 dark:text-slate-100",
                     "text-slate-800 dark:text-slate-200", "bg-slate-100 dark:bg-slate-800/50",
                     "text-slate-600 dark:text-slate-400"),
    }
    cc_grad, cc_border, cc_title, cc_body, cc_icon_bg, cc_icon_txt = _CC.get(verdict_class, _CC["unknown"])

    # Binary info table rows
    _stripped_val = r2_binary.get('stripped', 'unknown')
    _stripped_str = 'Yes' if _stripped_val is True else ('No' if _stripped_val is False else str(_stripped_val))
    binary_rows = f'''
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400 w-1/4">SHA256</td>
                                        <td class="text-xs break-all">{escape(program_hash)}</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Architecture</td>
                                        <td>{escape(str(arch))} ({bits}-bit)</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Format</td>
                                        <td>{escape(fmt_str)}  --  {escape(str(os_name))}</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Image Base</td>
                                        <td class="font-mono">{escape(str(binary.get('image_base', 'unknown')))}</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Entry Points</td>
                                        <td class="font-mono text-xs">{escape(_format_entry_points(binary.get('entry_points', ['unknown'])))}</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Compiler</td>
                                        <td class="text-xs">{escape(_sanitize_compiler(binary.get('compiler', r2_binary.get('compiler', 'unknown'))))}</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Stripped</td>
                                        <td>{_stripped_str}</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Endianness</td>
                                        <td>{escape(str(r2_binary.get('endian', 'unknown')))}</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Imports</td>
                                        <td class="text-xs">{escape(_format_import_export_list(binary.get('imports', [])))}</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Exports</td>
                                        <td>{len(binary.get('exports', []))} symbols</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Functions</td>
                                        <td>Ghidra: {len(funcs.get('functions', []))} ({len(state.get('decompilation_cache', {}))}&nbsp;decompiled) &middot; R2: {len(r2_funcs.get('functions', []))} ({len(state.get('r2_decompilation_cache', {}))}&nbsp;decompiled)</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Strings</td>
                                        <td>Ghidra: {len(strings_data.get('strings', []))} &middot; R2: {len(r2_strings.get('strings', []))} extracted</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Analysis Started</td>
                                        <td>{started_str}</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Analysis Completed</td>
                                        <td>{completed_str}</td></tr>'''

    has_qiling = bool(qiling_results)
    qiling_section_no = "12" if has_qiling else "11"
    evidence_correlation_section_no = "13" if has_qiling else "12"
    iocs_section_no = "14" if has_qiling else "13"
    recommendations_section_no = "15" if has_qiling else "14"
    conclusion_section_no = "16" if has_qiling else "15"
    report_scope_label = "Ghidra + Radare2 + Qiling Analysis" if has_qiling else "Ghidra + Radare2 Analysis"
    report_fusion_copy = (
        "This report fuses Ghidra, Radare2, and Qiling findings into a readable intelligence layout while preserving exact evidence from decompiled code and extracted indicators."
        if has_qiling
        else "This report fuses Ghidra and Radare2 findings into a readable intelligence layout while preserving exact evidence from decompiled code and extracted indicators."
    )
    has_investigation_trace = bool(state.get("investigation_trace"))
    investigation_trace_nav_link = (
        '<a href="#investigation-trace" class="nav-link px-3 py-2 rounded"><i class="fas fa-route"></i><span>Investigation Trace</span></a>'
        if has_investigation_trace
        else ""
    )
    investigation_trace_html = (
        '<section id="investigation-trace" class="scroll-mt-20 section-card">'
        '<div class="section-title-wrap">'
        '<div class="section-icon"><i class="fas fa-magnifying-glass"></i></div>'
        '<div>'
        '<p class="section-eyebrow">02 · Planner Rationale</p>'
        '<h2 class="section-headline">Investigation Trace</h2>'
        '<p class="section-subtitle">Breakpoint-driven investigation strategy and reasoning recorded by the analysis planner.</p>'
        '</div>'
        '</div>'
        '<div class="section-body md-content text-slate-700 dark:text-slate-300 leading-relaxed space-y-4 text-base">'
        '<p class="mb-3">' + _markdown_to_html(state.get("investigation_trace", "")) + '</p>'
        '</div>'
        '</section>'
        if has_investigation_trace
        else ""
    )
    qiling_nav_link = (
        '<a href="#qiling-dynamic" class="nav-link px-3 py-2 rounded"><i class="fas fa-vial"></i><span>Qiling Dynamic</span></a>'
        if has_qiling
        else ""
    )
    qiling_mobile_link = (
        '<a href="#qiling-dynamic" class="px-3 py-1.5 rounded-full border border-slate-600/40 bg-slate-900/60 text-xs uppercase font-bold tracking-wide">Qiling</a>'
        if has_qiling
        else ""
    )
    # Build LLM dynamic analysis narrative block (if the LLM produced one)
    dynamic_narrative_block = ""
    if dynamic_analysis_html:
        dynamic_narrative_block = (
            '<div class="mb-6">'
            '<h3 class="text-sm font-bold text-slate-400 uppercase tracking-wider mb-3">'
            '<i class="fas fa-brain mr-2 text-cyan-400"></i>AI Analysis Narrative</h3>'
            f'{dynamic_analysis_html}'
            '</div>'
            '<h3 class="text-sm font-bold text-slate-400 uppercase tracking-wider mb-3">'
            '<i class="fas fa-chart-bar mr-2 text-cyan-400"></i>Raw Telemetry Data</h3>'
        )

    qiling_section_html = (
        f'''
                    <!-- 8b. Qiling Dynamic -->
                    <section id="qiling-dynamic" class="scroll-mt-20 section-card">
                        <div class="section-title-wrap">
                            <div class="section-icon"><i class="fas fa-vial"></i></div>
                            <div>
                                <p class="section-eyebrow">{qiling_section_no} · Runtime Behavior</p>
                                <h2 class="section-headline">Qiling Dynamic Analysis</h2>
                                <p class="section-subtitle">Runtime telemetry from emulation: syscalls, network behavior, memory indicators, instruction traces, and evasive activity.</p>
                            </div>
                        </div>
                        <div class="section-body">{dynamic_narrative_block}{qiling_dynamic_html}</div>
                    </section>
'''
        if has_qiling
        else ""
    )

    evidence_correlation_section_html = f'''
                    <!-- Cross-engine evidence correlation -->
                    <section id="evidence-correlation" class="scroll-mt-20 section-card">
                        <div class="section-title-wrap">
                            <div class="section-icon"><i class="fas fa-project-diagram"></i></div>
                            <div>
                                <p class="section-eyebrow">{evidence_correlation_section_no} · Evidence Linking</p>
                                <h2 class="section-headline">Cross-Engine Evidence Correlation</h2>
                                <p class="section-subtitle">Links IOCs to static strings, decompiled functions, and Qiling runtime telemetry.</p>
                            </div>
                        </div>
                        <div class="section-body">{evidence_correlation_html}</div>
                    </section>
'''

    # --- Assemble full HTML ---
    html = f'''<!DOCTYPE html>
<html lang="en" class="scroll-smooth dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reverse Engineering Report - {file_name}</title>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Manrope:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {{
            darkMode: 'class',
            theme: {{
                extend: {{
                    fontFamily: {{
                        sans: ['Manrope', 'sans-serif'],
                        display: ['Space Grotesk', 'sans-serif'],
                        mono: ['IBM Plex Mono', 'monospace'],
                    }}
                }}
            }}
        }}
    </script>
    <style>
        :root {{
            --bg-0: #050915;
            --bg-1: #08142f;
            --surface-1: rgba(10, 20, 43, 0.9);
            --surface-2: rgba(13, 26, 52, 0.88);
            --line: rgba(108, 136, 180, 0.38);
            --line-soft: rgba(108, 136, 180, 0.24);
            --text-0: #f8fbff;
            --text-1: #dce7f7;
            --text-2: #a7bad5;
        }}
        html, body {{
            min-height: 100%;
        }}
        body {{
            margin: 0;
            color: var(--text-1);
            background:
                radial-gradient(950px 480px at -12% -12%, rgba(34, 211, 238, 0.22), transparent 65%),
                radial-gradient(760px 420px at 110% -10%, rgba(244, 114, 182, 0.2), transparent 58%),
                linear-gradient(180deg, var(--bg-0) 0%, #081027 52%, #050916 100%);
        }}
        .report-bg-grid {{
            position: fixed;
            inset: 0;
            z-index: -1;
            pointer-events: none;
            background-image:
                linear-gradient(rgba(63, 86, 128, 0.15) 1px, transparent 1px),
                linear-gradient(90deg, rgba(63, 86, 128, 0.15) 1px, transparent 1px);
            background-size: 30px 30px;
            mask-image: radial-gradient(circle at center, #000 50%, transparent 90%);
        }}
        .no-print {{
            -webkit-print-color-adjust: exact;
            print-color-adjust: exact;
        }}
        @media print {{
            @page {{ size: A4; margin: 6mm 8mm; }}
            html, body {{
                background: #0b1325 !important;
                color: #e2e8f0 !important;
                font-size: 9pt !important;
                min-height: 0 !important;
            }}
            .no-print {{ display: none !important; }}
            .page-break {{ /* page-break disabled for compact PDF */ }}
            /* Only avoid breaks inside small cards, NOT entire sections */
            .capability-card, .tech-card, .func-card, .evidence-card, .rec-card, .function-box {{
                page-break-inside: avoid;
                break-inside: avoid;
            }}
            /* Allow sections to break across pages freely */
            section, .section-card {{
                page-break-inside: auto !important;
                break-inside: auto !important;
            }}
            /* Hide sidebar & hamburger */
            #report-nav, .hamburger-btn {{ display: none !important; }}
            /* Remove sidebar margin & min-height */
            .lg\\:ml-72 {{ margin-left: 0 !important; min-height: 0 !important; }}
            .min-h-screen {{ min-height: 0 !important; }}
            .lg\\:p-6 {{ padding: 0.35rem !important; }}
            /* Remove shell decoration in print */
            .report-shell {{
                border: none !important;
                box-shadow: none !important;
                border-radius: 0 !important;
                background: transparent !important;
            }}
            /* Compact hero */
            .hero-panel {{ padding: 0.8rem 1rem !important; }}
            .hero-panel h1 {{ font-size: 1.25rem !important; line-height: 1.2; margin-bottom: 0.25rem !important; }}
            .hero-panel p {{ font-size: 0.65rem !important; margin-bottom: 0.15rem !important; }}
            .hero-panel .badge-chip {{ font-size: 0.55rem !important; padding: 0.1rem 0.4rem !important; }}
            /* Compact stat cards */
            .stat-card {{ padding: 0.35rem 0.5rem !important; }}
            .stat-card .text-xl {{ font-size: 0.85rem !important; }}
            .stat-card .text-xs, .stat-card .text-\\[11px\\] {{ font-size: 0.5rem !important; }}
            /* Section cards  --  minimal padding */
            .section-card {{
                padding: 0.65rem 0.8rem !important;
                margin-bottom: 0.35rem !important;
                border-radius: 0.4rem !important;
            }}
            .section-headline {{ font-size: 0.8rem !important; margin-top: 0 !important; }}
            .section-eyebrow {{ font-size: 0.5rem !important; }}
            .section-subtitle {{ font-size: 0.6rem !important; margin-top: 0.1rem !important; }}
            .section-icon {{ width: 1.3rem !important; height: 1.3rem !important; font-size: 0.6rem !important; }}
            .section-title-wrap {{ margin-bottom: 0.4rem !important; gap: 0.5rem !important; }}
            .section-body {{ font-size: 0.7rem !important; }}
            /* Tables */
            table.data-table th {{ font-size: 0.5rem !important; padding: 0.25rem 0.4rem !important; }}
            table.data-table td {{ font-size: 0.6rem !important; padding: 0.25rem 0.4rem !important; }}
            /* Function boxes */
            .function-box {{ padding: 0.45rem !important; margin-bottom: 0.3rem !important; }}
            .function-box .text-sm {{ font-size: 0.6rem !important; }}
            .function-box .font-mono {{ font-size: 0.55rem !important; }}
            /* Flow */
            .flow-item {{ padding: 0.3rem 0.6rem !important; font-size: 0.55rem !important; }}
            .flow-arrow {{ font-size: 0.75rem !important; }}
            /* Verdict */
            .text-2xl {{ font-size: 0.9rem !important; }}
            .text-lg {{ font-size: 0.75rem !important; }}
            .text-sm {{ font-size: 0.65rem !important; }}
            .text-xs {{ font-size: 0.55rem !important; }}
            /* Evidence cards */
            .evidence-compact {{ padding: 0.35rem 0.5rem !important; font-size: 0.6rem !important; margin-bottom: 0.25rem !important; }}
            .evidence-card {{ padding: 0.4rem 0.6rem !important; margin-bottom: 0.25rem !important; }}
            /* Code blocks */
            pre, code {{ font-size: 0.55rem !important; line-height: 1.3 !important; }}
            pre {{ padding: 0.4rem !important; margin: 0.25rem 0 !important; }}
            /* Spacing  --  aggressive compaction */
            .space-y-8 > :not(:first-child) {{ margin-top: 0.5rem !important; }}
            .space-y-6 > :not(:first-child) {{ margin-top: 0.4rem !important; }}
            .space-y-4 > :not(:first-child) {{ margin-top: 0.3rem !important; }}
            .space-y-3 > :not(:first-child) {{ margin-top: 0.2rem !important; }}
            .gap-6 {{ gap: 0.35rem !important; }}
            .gap-4 {{ gap: 0.3rem !important; }}
            .gap-3 {{ gap: 0.2rem !important; }}
            .gap-2 {{ gap: 0.15rem !important; }}
            .mb-4 {{ margin-bottom: 0.25rem !important; }}
            .mb-3 {{ margin-bottom: 0.2rem !important; }}
            .mb-2 {{ margin-bottom: 0.15rem !important; }}
            .mt-4 {{ margin-top: 0.25rem !important; }}
            .py-4 {{ padding-top: 0.25rem !important; padding-bottom: 0.25rem !important; }}
            .p-4, .p-6, .p-8 {{ padding: 0.4rem !important; }}
            .px-4 {{ padding-left: 0.4rem !important; padding-right: 0.4rem !important; }}
            .max-w-6xl {{ max-width: 100% !important; }}
            /* Grid  --  keep multi-column */
            .grid.lg\\:grid-cols-5 {{ grid-template-columns: repeat(5, 1fr) !important; }}
            .grid.lg\\:grid-cols-3 {{ grid-template-columns: repeat(3, 1fr) !important; }}
            .grid.lg\\:grid-cols-2 {{ grid-template-columns: repeat(2, 1fr) !important; }}
            .grid.lg\\:grid-cols-\\[1fr_260px\\] {{ grid-template-columns: 1fr 180px !important; }}
            /* Floating buttons */
            .fixed.bottom-6 {{ display: none !important; }}
            /* Background grid */
            .report-bg-grid {{ display: none !important; }}
            /* Remove rounded corners on main wrapper for continuous flow */
            .rounded-xl {{ border-radius: 0.3rem !important; }}
        }}
        .report-shell {{
            background: linear-gradient(180deg, rgba(10, 20, 43, 0.95), rgba(7, 14, 31, 0.92));
            border: 1px solid var(--line);
            box-shadow: 0 24px 56px rgba(2, 8, 23, 0.52);
        }}
        .hero-panel {{
            background:
                radial-gradient(circle at 8% 8%, rgba(34, 211, 238, 0.2), transparent 42%),
                radial-gradient(circle at 92% 0%, rgba(244, 114, 182, 0.17), transparent 36%),
                linear-gradient(180deg, rgba(8, 18, 39, 0.97), rgba(8, 15, 33, 0.94));
            border-bottom: 1px solid var(--line-soft);
        }}
        .badge-chip {{
            border-radius: 9999px;
            padding: 0.25rem 0.65rem;
            font-size: 0.72rem;
            letter-spacing: 0.04em;
            text-transform: uppercase;
            font-weight: 800;
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
            border: 1px solid transparent;
        }}
        .stat-card {{
            border: 1px solid var(--line-soft);
            background: linear-gradient(180deg, rgba(14, 26, 50, 0.9), rgba(10, 18, 36, 0.92));
            border-radius: 0.8rem;
        }}
        .section-card {{
            border: 1px solid var(--line-soft);
            border-radius: 0.95rem;
            background: linear-gradient(180deg, rgba(13, 24, 47, 0.95), rgba(10, 18, 37, 0.94));
            box-shadow: 0 14px 32px rgba(2, 8, 23, 0.34);
        }}
        .section-title-wrap {{
            display: flex;
            align-items: flex-start;
            gap: 0.8rem;
            margin-bottom: 0.85rem;
        }}
        .section-icon {{
            width: 2.1rem;
            height: 2.1rem;
            flex-shrink: 0;
            border-radius: 0.65rem;
            border: 1px solid var(--line);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: rgba(22, 38, 70, 0.82);
            color: #d3e5ff;
        }}
        .section-eyebrow {{
            margin: 0;
            color: #8ea6cb;
            text-transform: uppercase;
            font-size: 0.65rem;
            letter-spacing: 0.14em;
            font-weight: 800;
        }}
        .section-headline {{
            margin: 0.18rem 0 0;
            font-family: 'Space Grotesk', sans-serif;
            color: #f8fbff;
            font-size: 1.23rem;
            font-weight: 700;
        }}
        .section-subtitle {{
            margin-top: 0.34rem;
            color: #9bb1d1;
            font-size: 0.84rem;
            line-height: 1.5;
        }}
        .section-body {{
            margin-top: 0.15rem;
        }}
        table.data-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        table.data-table th {{
            background: rgba(29, 44, 75, 0.95);
            color: #d8e6f9;
            font-weight: 700;
            text-align: left;
            padding: 0.62rem 0.85rem;
            font-size: 0.7rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            border-bottom: 1px solid var(--line-soft);
        }}
        table.data-table td {{
            padding: 0.68rem 0.85rem;
            border-bottom: 1px solid rgba(71, 85, 105, 0.44);
            font-size: 0.84rem;
            font-family: 'IBM Plex Mono', monospace;
            color: #d5e3f6;
        }}
        .flow-container {{ display: flex; align-items: center; gap: 0.5rem; overflow-x: auto; padding: 1rem 0; }}
        .flow-item {{ flex-shrink: 0; background: rgba(15, 26, 50, 0.96); border: 1px solid var(--line); padding: 0.75rem 1.5rem; border-radius: 0.5rem; font-size: 0.875rem; font-weight: 600; color: #dbe8fb; white-space: nowrap; }}
        .flow-item.active {{ background: #dc2626; color: white; border-color: #dc2626; }}
        .flow-arrow {{ color: #9ca3af; font-size: 1.25rem; flex-shrink: 0; }}
        .function-box {{ border: 1px solid var(--line-soft); transition: all 0.2s; }}
        .function-box:hover {{ border-color: rgba(251, 146, 60, 0.75); box-shadow: 0 8px 20px rgba(3, 7, 18, 0.45); }}
        .evidence-compact {{ border-left: 3px solid #ef4444; transition: all 0.2s; }}
        .evidence-compact:hover {{ background-color: rgba(15, 26, 50, 0.85); padding-left: 1.25rem; }}
        .capability-card, .tech-card, .func-card, .evidence-card, .rec-card {{
            transition: all 0.25s ease;
        }}
        .evidence-card:hover {{ transform: translateX(4px); }}
        .rec-card:hover {{ transform: translateY(-2px); box-shadow: 0 14px 30px rgba(2, 8, 23, 0.45); }}
        .tlp-banner {{
            background: repeating-linear-gradient(45deg, #f59e0b, #f59e0b 10px, #d97706 10px, #d97706 20px);
            color: white;
            text-shadow: 0 1px 2px rgba(0,0,0,0.3);
            font-weight: 700;
            padding: 0.25rem 0.75rem;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .risk-box {{ {risk_gradient} color: white; position: relative; overflow: hidden; }}
        .risk-box::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: repeating-linear-gradient(45deg, transparent, transparent 10px, rgba(255,255,255,0.06) 10px, rgba(255,255,255,0.06) 20px);
        }}
        @keyframes slide {{ 0% {{ transform: translateX(0); }} 100% {{ transform: translateX(40px); }} }}
        .md-content p {{ margin-bottom: 0.8rem; line-height: 1.72; color: #d4e1f4; }}
        .md-content ul {{ list-style-type: disc; padding-left: 1.5rem; margin-bottom: 0.8rem; color: #d4e1f4; }}
        .md-content ol {{ list-style-type: decimal; padding-left: 1.5rem; margin-bottom: 0.8rem; color: #d4e1f4; }}
        .md-content li {{ margin-bottom: 0.35rem; }}
        .md-content pre {{ background: #0f172a; border: 1px solid rgba(71, 85, 105, 0.7); border-radius: 0.5rem; padding: 0.9rem; overflow-x: auto; font-size: 0.8rem; margin: 0.95rem 0; color: #e2e8f0; }}
        .md-content code {{ font-family: 'IBM Plex Mono', monospace; background: rgba(30, 58, 92, 0.58); padding: 0.125rem 0.375rem; font-size: 0.85em; color: #bae6fd; border: 1px solid rgba(125, 211, 252, 0.35); border-radius: 0.25rem; }}
        .md-content pre code {{ color: #e2e8f0; background: none; padding: 0; border: none; }}
        .md-content h3 {{ font-size: 1.08rem; font-weight: 700; margin-top: 1.35rem; margin-bottom: 0.65rem; }}
        .md-content h4 {{ font-size: 0.98rem; font-weight: 600; margin-top: 1.2rem; margin-bottom: 0.5rem; }}
        .md-content table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.875rem; }}
        .md-content th {{ background: rgba(29, 44, 75, 0.95); font-weight: 700; text-transform: uppercase; font-size: 0.7rem; padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid var(--line-soft); }}
        .md-content td {{ padding: 0.5rem 0.75rem; border-bottom: 1px solid rgba(71, 85, 105, 0.45); }}
        /* ── Contrast bump ── */
        .text-slate-700, .text-slate-600 {{ color: #d4e1f4 !important; }}
        .text-slate-500 {{ color: #a7bad5 !important; }}
        .text-slate-400 {{ color: #bdd0e8 !important; }}
        .text-slate-300 {{ color: #e0ecf8 !important; }}
        .text-white {{ color: #f8fbff !important; }}
        [class*="bg-[#0B1324]"], [class*="bg-[#060B14]"], .capability-card, .tech-card, .func-card, .evidence-card, .evidence-row, .rec-card, .function-box {{
            background: linear-gradient(180deg, rgba(15, 27, 52, 0.95), rgba(11, 20, 40, 0.93)) !important;
            border-color: rgba(102, 131, 176, 0.4) !important;
        }}
        [class*="border-[#131e36]"] {{
            border-color: rgba(102, 131, 176, 0.4) !important;
        }}
        /* ── Navigation ── */
        .nav-link {{
            display: flex; align-items: center; gap: 0.6rem;
            color: #8ea6cb; font-size: 0.84rem; font-weight: 500;
            transition: all 0.18s; text-decoration: none;
        }}
        .nav-link:hover {{ color: #e2ecfa; background: rgba(34, 211, 238, 0.08); }}
        .nav-link.is-active {{
            color: #00f0ff; background: rgba(0, 240, 255, 0.1);
            border-left: 2px solid #00f0ff; font-weight: 700;
        }}
        .nav-link i {{ width: 1.1rem; text-align: center; font-size: 0.76rem; }}
        /* ── Entity chips ── */
        .entity-chip {{
            display: inline; padding: 0.1rem 0.4rem; border-radius: 0.25rem;
            font-family: 'IBM Plex Mono', monospace; font-size: 0.78em;
            font-weight: 500;
        }}
        .entity-chip.path  {{ background: rgba(16,185,129,0.15); color: #6ee7b7; border: 1px solid rgba(16,185,129,0.3); }}
        .entity-chip.mitre {{ background: rgba(249,115,22,0.15); color: #fdba74; border: 1px solid rgba(249,115,22,0.3); }}
        .entity-chip.func  {{ background: rgba(139,92,246,0.15); color: #c4b5fd; border: 1px solid rgba(139,92,246,0.3); }}
        .entity-chip.addr  {{ background: rgba(56,189,248,0.12); color: #7dd3fc; border: 1px solid rgba(56,189,248,0.25); }}
        /* ── Evidence accent rows ── */
        .evidence-row {{ border-left: 3px solid; transition: all 0.2s; }}
        .evidence-row:hover {{ transform: translateX(4px); }}
        .evidence-row.sev-critical {{ border-left-color: #ef4444; }}
        .evidence-row.sev-high     {{ border-left-color: #f97316; }}
        .evidence-row.sev-medium   {{ border-left-color: #eab308; }}
        .evidence-row.sev-low      {{ border-left-color: #3b82f6; }}
        .evidence-row.sev-info     {{ border-left-color: #8b5cf6; }}
        details summary::-webkit-details-marker {{ display: none; }}
        details[open] summary .fa-chevron-right {{ transform: rotate(90deg); }}
        /* ── Hamburger (mobile) ── */
        .hamburger-btn {{
            display: none; position: fixed; top: 1rem; left: 1rem; z-index: 50;
            width: 2.5rem; height: 2.5rem; border-radius: 0.5rem;
            background: rgba(10,20,43,0.92); border: 1px solid rgba(102,131,176,0.4);
            color: #e2ecfa; cursor: pointer; align-items: center; justify-content: center;
            font-size: 1.1rem;
        }}
        @media (max-width: 1023px) {{ .hamburger-btn {{ display: flex; }} }}
        .section-card {{ padding: 1.75rem; }}
    </style>
</head>
<body class="font-sans antialiased text-slate-200">
    <div class="report-bg-grid"></div>

    <!-- Floating Tools -->
    <div class="fixed bottom-6 right-6 z-50 no-print flex flex-col gap-2">
        <button onclick="exportPDF()" class="w-11 h-11 rounded-full text-white bg-gradient-to-br from-red-500 to-pink-600 border border-red-200/25 shadow-xl hover:scale-105 transition-transform" title="Download PDF" id="pdf-btn">
            <i class="fas fa-file-pdf"></i>
        </button>
        <button onclick="window.print()" class="w-11 h-11 rounded-full text-white bg-gradient-to-br from-cyan-500 to-blue-600 border border-cyan-200/25 shadow-xl hover:scale-105 transition-transform" title="Print report">
            <i class="fas fa-print"></i>
        </button>
    </div>

    <!-- Hamburger Toggle (mobile) -->
    <button class="hamburger-btn no-print" onclick="document.getElementById('report-nav').classList.toggle('-translate-x-full')" aria-label="Toggle navigation menu">
        <i class="fas fa-bars"></i>
    </button>

    <!-- Navigation Sidebar -->
    <nav id="report-nav" class="fixed left-0 top-0 h-full w-72 bg-[#0B1324]/95 border-r border-[#131e36] overflow-y-auto z-40 transform -translate-x-full lg:translate-x-0 transition-transform no-print shadow-xl backdrop-blur-md" role="navigation" aria-label="Report sections">
        <div class="p-6 border-b border-[#131e36]">
            <div class="text-[10px] font-bold text-slate-400 uppercase tracking-[0.22em] mb-1">Reverse Engineering</div>
            <div class="font-mono text-sm font-bold text-white break-all">{file_name}</div>
            <div class="text-[11px] text-slate-500 mt-2">SHA256: {escape(hash_short)}</div>
        </div>
        <div class="p-4 space-y-1 text-sm">
            <a href="#executive-summary" class="nav-link px-3 py-2 rounded"><i class="fas fa-binoculars"></i><span>Executive Summary</span></a>
            {investigation_trace_nav_link}
            <a href="#mitre-attack" class="nav-link px-3 py-2 rounded"><i class="fas fa-spider"></i><span>Threat Intel</span></a>
            <a href="#capabilities" class="nav-link px-3 py-2 rounded"><i class="fas fa-bolt"></i><span>{_cap_section_title}</span></a>
            <a href="#binary-info" class="nav-link px-3 py-2 rounded"><i class="fas fa-file-code"></i><span>Binary Information</span></a>
            <a href="#technical-analysis" class="nav-link px-3 py-2 rounded"><i class="fas fa-microscope"></i><span>Technical Analysis</span></a>
            <a href="#functions-analysis" class="nav-link px-3 py-2 rounded"><i class="fas fa-cubes"></i><span>Functions Analysis</span></a>
            <a href="#evidence" class="nav-link px-3 py-2 rounded"><i class="fas fa-fingerprint"></i><span>{_ev_section_title}</span></a>
            <a href="#code-evidence" class="nav-link px-3 py-2 rounded"><i class="fas fa-code"></i><span>Code Evidence</span></a>
            <a href="#operational-flow" class="nav-link px-3 py-2 rounded"><i class="fas fa-route"></i><span>Operational Flow</span></a>
            <a href="#call-graph" class="nav-link px-3 py-2 rounded"><i class="fas fa-project-diagram"></i><span>Call Graph</span></a>
            {qiling_nav_link}
            <a href="#iocs" class="nav-link px-3 py-2 rounded"><i class="fas fa-network-wired"></i><span>IOCs</span></a>
            <a href="#recommendations" class="nav-link px-3 py-2 rounded"><i class="fas fa-shield-alt"></i><span>Recommendations</span></a>
            <a href="#conclusion" class="nav-link px-3 py-2 rounded"><i class="fas fa-gavel"></i><span>Conclusion</span></a>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="lg:ml-72 min-h-screen px-4 py-4 lg:p-6">
        <div class="max-w-6xl mx-auto space-y-4">
            <div class="flex lg:hidden gap-2 overflow-x-auto whitespace-nowrap no-print pb-1">
                <a href="#executive-summary" class="px-3 py-1.5 rounded-full border border-slate-600/40 bg-slate-900/60 text-xs uppercase font-bold tracking-wide">Summary</a>
                <a href="#capabilities" class="px-3 py-1.5 rounded-full border border-slate-600/40 bg-slate-900/60 text-xs uppercase font-bold tracking-wide">Capabilities</a>
                <a href="#technical-analysis" class="px-3 py-1.5 rounded-full border border-slate-600/40 bg-slate-900/60 text-xs uppercase font-bold tracking-wide">Technical</a>
                <a href="#functions-analysis" class="px-3 py-1.5 rounded-full border border-slate-600/40 bg-slate-900/60 text-xs uppercase font-bold tracking-wide">Functions</a>
                {qiling_mobile_link}
                <a href="#iocs" class="px-3 py-1.5 rounded-full border border-slate-600/40 bg-slate-900/60 text-xs uppercase font-bold tracking-wide">IOCs</a>
            </div>
            <div class="report-shell rounded-xl overflow-hidden">

                <!-- Header -->
                <header class="hero-panel p-6 lg:p-8" role="banner">
                    <div class="grid lg:grid-cols-[1fr_260px] gap-6 items-start">
                        <div>
                            <p class="text-[10px] font-bold uppercase tracking-[0.2em] text-cyan-300/90 mb-2">{escape(report_scope_label)}</p>
                            <h1 class="text-3xl lg:text-4xl font-display font-bold text-white mb-2 tracking-tight">Reverse Engineering Report</h1>
                            <p class="text-sm lg:text-[15px] text-slate-300 max-w-3xl leading-relaxed">
                                {escape(report_fusion_copy)}
                            </p>
                            <div class="flex flex-wrap items-center gap-2 mt-4">
                                <span class="badge-chip {v_badge_bg} {v_badge_text} border {v_badge_border}"><i class="fas {v_icon}"></i>{escape(v_label)}</span>
                                <span class="badge-chip bg-slate-900/70 border border-slate-600/50 text-slate-200"><i class="fas fa-microchip"></i>{escape(format_badge)}</span>
                                <span class="tlp-banner rounded"><i class="fas fa-lock"></i> TLP:AMBER</span>
                            </div>
                        </div>
                        <div class="stat-card p-4">
                            <div class="text-[10px] font-bold uppercase tracking-[0.18em] text-slate-400 mb-2">Analysis Metadata</div>
                            <div class="space-y-2 text-xs">
                                <div class="flex justify-between gap-3"><span class="text-slate-400">Sample</span><span class="font-mono text-slate-200 break-all text-right">{file_name}</span></div>
                                <div class="flex justify-between gap-3"><span class="text-slate-400">Session</span><span class="font-mono text-slate-200">{escape(task_id)}</span></div>
                                <div class="flex justify-between gap-3"><span class="text-slate-400">Generated</span><span class="font-mono text-slate-200">{escape(timestamp)}</span></div>
                                <div class="flex justify-between gap-3"><span class="text-slate-400">Verdict</span><span class="font-semibold text-white">{escape(verdict)}</span></div>
                            </div>
                        </div>
                    </div>
                </header>

                <!-- Risk Banner -->
                <div class="risk-box p-5 text-center relative border-y border-[#131e36]" role="status" aria-label="Risk assessment: {escape(v_label)}, score {score}/100">
                    <div class="relative z-10 flex items-center justify-center gap-3 flex-wrap">
                        <i class="fas {v_icon} text-2xl opacity-80"></i>
                        <div class="text-2xl font-bold uppercase tracking-wider">{escape(v_label)}</div>
                        <div class="text-xs uppercase tracking-[0.12em] text-slate-100/90 font-semibold">Risk Score {score}/100</div>
                    </div>
                </div>

                <!-- Quick Stats -->
                <div class="px-6 lg:px-8 pt-6">
                    <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3">
                        <div class="stat-card p-3">
                            <div class="text-[10px] uppercase tracking-[0.15em] text-slate-400 font-bold">Functions</div>
                            <div class="text-xl font-display font-bold text-white mt-1">{total_functions}</div>
                            <div class="text-[11px] text-slate-400">Discovered across both engines</div>
                        </div>
                        <div class="stat-card p-3">
                            <div class="text-[10px] uppercase tracking-[0.15em] text-slate-400 font-bold">Decompiled</div>
                            <div class="text-xl font-display font-bold text-white mt-1">{decompiled_total}</div>
                            <div class="text-[11px] text-slate-400">{coverage_pct}% function coverage</div>
                        </div>
                        <div class="stat-card p-3">
                            <div class="text-[10px] uppercase tracking-[0.15em] text-slate-400 font-bold">Interesting</div>
                            <div class="text-xl font-display font-bold text-white mt-1">{interesting_total}</div>
                            <div class="text-[11px] text-slate-400">{_interesting_label}</div>
                        </div>
                        <div class="stat-card p-3">
                            <div class="text-[10px] uppercase tracking-[0.15em] text-slate-400 font-bold">{_chain_label}</div>
                            <div class="text-xl font-display font-bold text-white mt-1">{chain_total}</div>
                            <div class="text-[11px] text-slate-400">{_chain_desc}</div>
                        </div>
                        <div class="stat-card p-3">
                            <div class="text-[10px] uppercase tracking-[0.15em] text-slate-400 font-bold">IOCs</div>
                            <div class="text-xl font-display font-bold text-white mt-1">{ioc_total}</div>
                            <div class="text-[11px] text-slate-400">{total_strings} strings reviewed</div>
                        </div>
                    </div>
                </div>

                <div class="p-6 lg:p-8 space-y-8">

                    <!-- 1. Executive Summary -->
                    <section id="executive-summary" class="scroll-mt-20 section-card">
                        <div class="section-title-wrap">
                            <div class="section-icon"><i class="fas fa-binoculars"></i></div>
                            <div>
                                <p class="section-eyebrow">01 · Analyst Snapshot</p>
                                <h2 class="section-headline">Executive Summary</h2>
                                <p class="section-subtitle">High-level assessment and impact synopsis grounded in extracted code evidence.</p>
                            </div>
                        </div>
                        <div class="section-body md-content text-slate-700 dark:text-slate-300 leading-relaxed space-y-4 text-base">
                            {_markdown_to_html(exec_summary)}
                        </div>
                    </section>

                    <!-- 1b. Investigation Trace -->
                    {investigation_trace_html}

                    
                    <!-- MITRE ATT&CK -->
                    {('<section id="mitre-attack" class="scroll-mt-20 section-card"><div class="section-title-wrap"><div class="section-icon"><i class="fas fa-spider"></i></div><div><p class="section-eyebrow">03 · Threat Context</p><h2 class="section-headline">Threat Intel &amp; MITRE ATT&amp;CK</h2><p class="section-subtitle">Mapped tactics and techniques linked to concrete static-analysis artifacts.</p></div></div><div class="section-body">' + mitre_html + '</div></section>') if mitre_html else ''}

                    <!-- 2. {_cap_section_title} -->
                    <section id="capabilities" class="scroll-mt-20 section-card">
                        <div class="section-title-wrap">
                            <div class="section-icon"><i class="fas fa-bolt"></i></div>
                            <div>
                                <p class="section-eyebrow">04 · Behavior Deck</p>
                                <h2 class="section-headline">{_cap_section_title}</h2>
                                <p class="section-subtitle">{_cap_subtitle}</p>
                            </div>
                        </div>
                        <div class="section-body">{capabilities_html}</div>
                    </section>

                    <!-- 3. Binary Information -->
                    <section id="binary-info" class="scroll-mt-20 section-card">
                        <div class="section-title-wrap">
                            <div class="section-icon"><i class="fas fa-file-code"></i></div>
                            <div>
                                <p class="section-eyebrow">05 · Binary Profile</p>
                                <h2 class="section-headline">Binary Information</h2>
                                <p class="section-subtitle">Core metadata baseline from toolchain output before behavior interpretation.</p>
                            </div>
                        </div>
                        <div class="section-body overflow-hidden rounded-lg border border-[#131e36]">
                            <table class="data-table">
                                <thead>
                                    <tr><th>Field</th><th>Value</th></tr>
                                </thead>
                                <tbody>{binary_rows}</tbody>
                            </table>
                        </div>
                    </section>

                    <!-- 4. Technical Analysis -->
                    <section id="technical-analysis" class="scroll-mt-20 section-card">
                        <div class="section-title-wrap">
                            <div class="section-icon"><i class="fas fa-microscope"></i></div>
                            <div>
                                <p class="section-eyebrow">06 · Deep Technical Dive</p>
                                <h2 class="section-headline">Technical Analysis</h2>
                                <p class="section-subtitle">Component-level internals with code snippets proving each behavioral claim.</p>
                            </div>
                        </div>
                        <div class="section-body">{technical_html}</div>
                    </section>

                    <!-- 5. Functions Analysis -->
                    <section id="functions-analysis" class="scroll-mt-20 section-card">
                        <div class="section-title-wrap">
                            <div class="section-icon"><i class="fas fa-cubes"></i></div>
                            <div>
                                <p class="section-eyebrow">07 · Function Triage</p>
                                <h2 class="section-headline">Functions Analysis</h2>
                                <p class="section-subtitle">Purpose, maliciousness status, and primary code evidence per high-priority function.</p>
                            </div>
                        </div>
                        <div class="section-body">{functions_html}</div>
                    </section>

                    <!-- 6. Evidence -->
                    <section id="evidence" class="scroll-mt-20 section-card">
                        <div class="section-title-wrap">
                            <div class="section-icon"><i class="fas fa-fingerprint"></i></div>
                            <div>
                                <p class="section-eyebrow">08 · Evidence Register</p>
                                <h2 class="section-headline">{_ev_section_title}</h2>
                                <p class="section-subtitle">{_ev_subtitle}</p>
                            </div>
                        </div>
                        <div class="section-body">{evidence_html}</div>
                    </section>

                    <!-- 6b. Code Evidence -->
                    <section id="code-evidence" class="scroll-mt-20 section-card">
                        <div class="section-title-wrap">
                            <div class="section-icon"><i class="fas fa-code"></i></div>
                            <div>
                                <p class="section-eyebrow">09 · Code Anchors</p>
                                <h2 class="section-headline">Code Evidence (Suspicious API Calls)</h2>
                                <p class="section-subtitle">Exact decompiled lines where suspicious APIs are invoked.</p>
                            </div>
                        </div>
                        <p class="text-sm text-slate-500 dark:text-slate-400 mb-4 italic">Application logic is prioritized over library internals to reduce noise.</p>
                        <div class="section-body">{code_evidence_html}</div>
                    </section>

                    <!-- 7. Operational Flow -->
                    <section id="operational-flow" class="scroll-mt-20 section-card">
                        <div class="section-title-wrap">
                            <div class="section-icon"><i class="fas fa-route"></i></div>
                            <div>
                                <p class="section-eyebrow">10 · Execution Story</p>
                                <h2 class="section-headline">Operational Flow</h2>
                                <p class="section-subtitle">Timeline from initialization to command handling and persistence behavior.</p>
                            </div>
                        </div>
                        <div class="section-body">{operational_html}</div>
                    </section>

                    <!-- 8. Call Graph -->
                    <section id="call-graph" class="scroll-mt-20 section-card">
                        <div class="section-title-wrap">
                            <div class="section-icon"><i class="fas fa-project-diagram"></i></div>
                            <div>
                                <p class="section-eyebrow">11 · Graph Intelligence</p>
                                <h2 class="section-headline">Call Graph &amp; {_chain_label}</h2>
                                <p class="section-subtitle">Graph-derived routes from entry points to suspicious sinks.</p>
                            </div>
                        </div>
                        <div class="section-body">{call_graph_html}</div>
                    </section>
                    {qiling_section_html}
                    {evidence_correlation_section_html}

                    <!-- 9. IOCs -->
                    <section id="iocs" class="scroll-mt-20 section-card">
                        <div class="section-title-wrap">
                            <div class="section-icon"><i class="fas fa-network-wired"></i></div>
                            <div>
                                <p class="section-eyebrow">{iocs_section_no} · Detection Inputs</p>
                                <h2 class="section-headline">Indicators of Compromise (IOCs)</h2>
                                <p class="section-subtitle">Actionable observables for SIEM, EDR, and threat-hunting detections.</p>
                            </div>
                        </div>
                        <div class="section-body bg-[#0B1324] rounded-lg shadow-sm border border-[#131e36] overflow-hidden">
                            <table class="w-full text-left">
                                <thead>
                                    <tr class="text-xs uppercase tracking-[0.1em] text-slate-400 bg-[#060B14]">
                                        <th class="px-6 py-3">Type</th>
                                        <th class="px-6 py-3">Indicator</th>
                                        <th class="w-10 no-print"></th>
                                    </tr>
                                </thead>
                                <tbody class="divide-y divide-slate-200 dark:divide-slate-700 text-sm">
                                    {iocs_rows}
                                </tbody>
                            </table>
                        </div>
                    </section>

                    <!-- 10. Recommendations -->
                    <section id="recommendations" class="scroll-mt-20 section-card">
                        <div class="section-title-wrap">
                            <div class="section-icon"><i class="fas fa-shield-alt"></i></div>
                            <div>
                                <p class="section-eyebrow">{recommendations_section_no} · Response Plan</p>
                                <h2 class="section-headline">Recommendations</h2>
                                <p class="section-subtitle">Prioritized actions for containment, detection engineering, and hardening.</p>
                            </div>
                        </div>
                        <div class="section-body">{recommendations_html}</div>
                    </section>

                    <!-- 11. Conclusion -->
                    <section id="conclusion" class="scroll-mt-20 section-card">
                        <div class="section-title-wrap">
                            <div class="section-icon"><i class="fas fa-gavel"></i></div>
                            <div>
                                <p class="section-eyebrow">{conclusion_section_no} · Final Assessment</p>
                                <h2 class="section-headline">Conclusion</h2>
                                <p class="section-subtitle">Final threat classification with supporting narrative from reverse-engineering evidence.</p>
                            </div>
                        </div>
                        <div class="section-body bg-gradient-to-r {cc_grad} border-2 {cc_border} rounded-lg p-6">
                            <div class="flex items-start gap-4">
                                <div class="hidden md:flex w-12 h-12 {cc_icon_bg} rounded-full items-center justify-center flex-shrink-0">
                                    <i class="fas fa-exclamation-triangle {cc_icon_txt} text-xl"></i>
                                </div>
                                <div>
                                    <h3 class="text-lg font-bold {cc_title} mb-2">Verdict: {escape(verdict)}</h3>
                                    <div class="{cc_body} leading-relaxed text-sm mb-3 md-content">
                                        {conclusion_inner}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </section>

                </div>

                <!-- Footer -->
                <footer class="bg-[#060B14] border-t border-[#131e36] p-6 mt-6">
                    <div class="flex flex-col md:flex-row justify-between items-center gap-4 text-sm text-slate-500 dark:text-slate-400">
                        <div class="flex items-center gap-2">
                            <i class="fas fa-lock"></i>
                            <span>Confidential &amp; Proprietary &mdash; Do Not Distribute Without Authorization</span>
                        </div>
                        <div class="font-mono text-xs">ID: {escape(task_id)}</div>
                    </div>
                </footer>
            </div>
        </div>
    </div>

    <script>
        // Export PDF via backend API
        function exportPDF() {{
            const btn = document.getElementById('pdf-btn');
            const origHTML = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
            btn.disabled = true;
            // Build PDF URL  -  use embedded API base for file:// contexts
            const EMBEDDED_API_BASE = 'http://localhost:8080';
            const loc = window.location;
            const isLocal = loc.protocol === 'file:';
            const origin = isLocal ? EMBEDDED_API_BASE : loc.origin;
            let pdfUrl = '';
            const sessMatch = !isLocal && loc.pathname.match(/\\/session\\/([^\\/]+)/);
            const hashMatch = !isLocal && loc.pathname.match(/\\/analysis\\/([^\\/]+)/);
            if (sessMatch) {{
                pdfUrl = origin + '/export/session/' + sessMatch[1] + '/pdf';
            }} else if (hashMatch) {{
                pdfUrl = origin + '/api/analysis/' + hashMatch[1] + '/export/pdf';
            }} else {{
                const hashEl = document.querySelector('[data-hash]');
                const hash = hashEl ? hashEl.dataset.hash : '{escape(program_hash)}';
                pdfUrl = origin + '/api/analysis/' + hash + '/export/pdf';
            }}
            // Use window.open for direct download (avoids CORS issues on file://)
            window.open(pdfUrl, '_blank');
            btn.innerHTML = origHTML;
            btn.disabled = false;
        }}
        // Copy to clipboard
        function copyToClipboard(text) {{
            navigator.clipboard.writeText(text).then(() => {{
                const toast = document.createElement('div');
                toast.className = 'fixed bottom-24 right-6 bg-slate-800 text-white px-4 py-2 rounded-lg shadow-lg z-50 text-sm flex items-center gap-2';
                toast.innerHTML = '<i class="fas fa-check text-emerald-400"></i> Copied';
                document.body.appendChild(toast);
                setTimeout(() => toast.remove(), 1700);
            }});
        }}
        // Smooth scroll
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {{
            anchor.addEventListener('click', function (e) {{
                const target = document.querySelector(this.getAttribute('href'));
                if (!target) {{
                    return;
                }}
                e.preventDefault();
                target.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
            }});
        }});
        // Intersection observer for nav highlight
        const navLinks = document.querySelectorAll('.nav-link');
        const observer = new IntersectionObserver((entries) => {{
            entries.forEach(entry => {{
                if (entry.isIntersecting) {{
                    navLinks.forEach(link => {{
                        const isActive = link.getAttribute('href') === '#' + entry.target.id;
                        link.classList.toggle('is-active', isActive);
                        if (isActive) link.setAttribute('aria-current', 'true');
                        else link.removeAttribute('aria-current');
                    }});
                }}
            }});
        }}, {{ root: null, rootMargin: '-24% 0px -64% 0px', threshold: 0.05 }});
        document.querySelectorAll('section[id]').forEach(section => {{ observer.observe(section); }});
    </script>
</body>
</html>'''

    _set_report_tone('neutral')
    return html


def build_agent_report_html(state: Dict[str, Any], agent: str) -> str:
    """Build a per-agent HTML report showing what a specific tool discovered.

    Args:
        state: The analysis state dict.
        agent: One of 'ghidra', 'r2'/'radare2', or 'qiling'.
    """
    agent_key = agent.lower()
    is_ghidra = agent_key in ("ghidra", "ghidra_agent")
    is_qiling = agent_key in ("qiling", "qiling_agent", "ql")
    if is_ghidra:
        agent_name = "Ghidra"
        agent_color = "#1a73e8"
    elif is_qiling:
        agent_name = "Qiling"
        agent_color = "#0f766e"
    else:
        agent_name = "Radare2"
        agent_color = "#e8710a"

    program_hash = state.get("program_hash", "unknown")
    file_name = escape(state.get("binary_path", "unknown").split("/")[-1])
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    session_id = state.get("session_id", "unknown")[:8]

    # Select per-agent data
    qiling_runtime_section = ""
    if is_ghidra:
        analysis = state.get("analysis_results", {})
        decomp_cache = state.get("decompilation_cache", {})
    elif is_qiling:
        qiling = state.get("qiling_analysis_results", {})
        execution = qiling.get("execution_trace", {}) if isinstance(qiling, dict) else {}
        syscalls = qiling.get("syscalls", {}) if isinstance(qiling, dict) else {}
        network = qiling.get("network_activity", {}) if isinstance(qiling, dict) else {}
        evasion = qiling.get("evasion_techniques", {}) if isinstance(qiling, dict) else {}

        syscall_rows_raw = syscalls.get("syscalls", []) if isinstance(syscalls, dict) else []
        if not isinstance(syscall_rows_raw, list):
            syscall_rows_raw = []
        syscall_rows = [
            {
                "name": str(call.get("name", "unknown")),
                "address": str(call.get("address", "N/A")),
                "size": str(call.get("timestamp_ms", call.get("size", "N/A"))),
                "xrefs": str(call.get("category", "unknown")),
            }
            for call in syscall_rows_raw
            if isinstance(call, dict)
        ]

        q_strings: List[Dict[str, Any]] = []
        if isinstance(network, dict):
            for conn in network.get("connections", []) or []:
                if isinstance(conn, dict):
                    addr = conn.get("address")
                    port = conn.get("port")
                    if addr:
                        q_strings.append({"address": "", "value": f"{addr}:{port}" if port else str(addr)})
            for dns in network.get("dns_queries", []) or []:
                if isinstance(dns, dict) and dns.get("domain"):
                    q_strings.append({"address": "", "value": str(dns.get("domain"))})

        execution_ok = bool(execution.get("success")) if isinstance(execution, dict) else False
        syscall_summary = syscalls.get("summary", {}) if isinstance(syscalls, dict) else {}
        total_calls = syscall_summary.get("total_calls", len(syscall_rows)) if isinstance(syscall_summary, dict) else len(syscall_rows)
        suspicious_calls = syscall_summary.get("suspicious_calls", []) if isinstance(syscall_summary, dict) else []
        total_connections = len(network.get("connections", []) or []) if isinstance(network, dict) else 0
        total_dns = len(network.get("dns_queries", []) or []) if isinstance(network, dict) else 0
        evasion_summary = evasion.get("summary", {}) if isinstance(evasion, dict) else {}
        evasion_total = evasion_summary.get("total_techniques", 0) if isinstance(evasion_summary, dict) else 0
        evasion_risk = evasion_summary.get("risk_level", "low") if isinstance(evasion_summary, dict) else "low"

        qiling_runtime_section = f"""
        <h2 class="section-header">Runtime Overview</h2>
        <table class="data-table">
            <tbody>
                <tr><td class="prop">Execution Success</td><td>{escape(str(execution_ok))}</td></tr>
                <tr><td class="prop">Instructions Executed</td><td>{escape(str(execution.get('instructions_executed', 0) if isinstance(execution, dict) else 0))}</td></tr>
                <tr><td class="prop">Duration (ms)</td><td>{escape(str(execution.get('duration_ms', 0) if isinstance(execution, dict) else 0))}</td></tr>
                <tr><td class="prop">Exit Reason</td><td>{escape(str(execution.get('exit_reason', 'unknown') if isinstance(execution, dict) else 'unknown'))}</td></tr>
                <tr><td class="prop">Syscalls Observed</td><td>{escape(str(total_calls))}</td></tr>
                <tr><td class="prop">Suspicious Syscalls</td><td>{escape(str(len(suspicious_calls) if isinstance(suspicious_calls, list) else 0))}</td></tr>
                <tr><td class="prop">Network Connections</td><td>{escape(str(total_connections))}</td></tr>
                <tr><td class="prop">DNS Queries</td><td>{escape(str(total_dns))}</td></tr>
                <tr><td class="prop">Evasion Techniques</td><td>{escape(str(evasion_total))}</td></tr>
                <tr><td class="prop">Evasion Risk</td><td>{escape(str(evasion_risk))}</td></tr>
            </tbody>
        </table>
        """

        analysis = {
            "binary": {
                "architecture": execution.get("arch", "unknown") if isinstance(execution, dict) else "unknown",
                "bits": execution.get("bits", "unknown") if isinstance(execution, dict) else "unknown",
                "os": execution.get("os", "unknown") if isinstance(execution, dict) else "unknown",
                "image_base": "N/A",
                "imports": [],
                "exports": [],
                "endian": "N/A",
                "stripped": "N/A",
            },
            "functions": {"functions": syscall_rows},
            "strings": {"strings": q_strings},
        }
        decomp_cache = {}
    else:
        analysis = state.get("r2_analysis_results", {})
        decomp_cache = state.get("r2_decompilation_cache", {})

    binary = analysis.get("binary", {})
    funcs_data = analysis.get("functions", {})
    strings_data = analysis.get("strings", {})
    func_list = funcs_data.get("functions", [])
    string_list = strings_data.get("strings", [])

    # --- Binary Info Table ---
    if is_ghidra:
        binary_rows = f"""
        <tr><td class="prop">Architecture</td><td>{escape(str(binary.get('architecture', 'unknown')))}</td></tr>
        <tr><td class="prop">Image Base</td><td class="mono">{escape(str(binary.get('image_base', 'unknown')))}</td></tr>
        <tr><td class="prop">Compiler</td><td>{escape(_sanitize_compiler(binary.get('compiler', 'unknown')))}</td></tr>
        <tr><td class="prop">Entry Points</td><td class="mono" style="word-break:break-all">{escape(_format_entry_points(binary.get('entry_points', ['unknown'])))}</td></tr>
        <tr><td class="prop">Imports</td><td class="mono" style="word-break:break-all">{escape(_format_import_export_list(binary.get('imports', [])))}</td></tr>
        <tr><td class="prop">Exports</td><td>{len(binary.get('exports', []))} symbols</td></tr>
        <tr><td class="prop">Segments</td><td>{len(binary.get('segments', []))}</td></tr>
        <tr><td class="prop">Functions Discovered</td><td>{len(func_list)}</td></tr>
        <tr><td class="prop">Functions Decompiled</td><td>{len(decomp_cache)}</td></tr>"""
    elif is_qiling:
        binary_rows = f"""
        <tr><td class="prop">Architecture</td><td>{escape(str(binary.get('architecture', 'unknown')))}</td></tr>
        <tr><td class="prop">Bits</td><td>{escape(str(binary.get('bits', 'unknown')))}</td></tr>
        <tr><td class="prop">OS</td><td>{escape(str(binary.get('os', 'unknown')))}</td></tr>
        <tr><td class="prop">Execution Type</td><td>Dynamic emulation</td></tr>
        <tr><td class="prop">Syscalls Captured</td><td>{len(func_list)}</td></tr>
        <tr><td class="prop">Dynamic Observables</td><td>{len(string_list)}</td></tr>"""
    else:
        binary_rows = f"""
        <tr><td class="prop">Architecture</td><td>{escape(str(binary.get('architecture', 'unknown')))}</td></tr>
        <tr><td class="prop">Bits</td><td>{escape(str(binary.get('bits', 'unknown')))}</td></tr>
        <tr><td class="prop">OS</td><td>{escape(str(binary.get('os', 'unknown')))}</td></tr>
        <tr><td class="prop">Endian</td><td>{escape(str(binary.get('endian', 'unknown')))}</td></tr>
        <tr><td class="prop">Stripped</td><td>{escape(str(binary.get('stripped', 'unknown')))}</td></tr>
        <tr><td class="prop">Imports</td><td class="mono" style="word-break:break-all">{escape(_format_import_export_list(binary.get('imports', [])))}</td></tr>
        <tr><td class="prop">Exports</td><td>{len(binary.get('exports', []))} symbols</td></tr>
        <tr><td class="prop">Functions Discovered</td><td>{len(func_list)}</td></tr>
        <tr><td class="prop">Functions Decompiled</td><td>{len(decomp_cache)}</td></tr>"""

    # --- Functions Table ---
    func_rows = ""
    for f in func_list:
        name = f.get("name", "?")
        addr = f.get("address", "?")
        size = f.get("size", "?")
        xrefs = f.get("xrefs", 0)
        if is_qiling:
            decompiled = "Yes"
        else:
            decompiled = "Yes" if name in decomp_cache else "No"
        func_rows += f'<tr><td class="mono">{escape(name)}</td><td class="mono">{escape(str(addr))}</td><td>{size}</td><td>{xrefs}</td><td>{decompiled}</td></tr>\n'

    # --- Decompiled Code Blocks ---
    decomp_blocks = ""
    for fname, code in decomp_cache.items():
        decomp_blocks += f'''
        <div class="decomp-block">
            <div class="decomp-header">{escape(fname)}</div>
            <pre><code>{escape(code)}</code></pre>
        </div>'''

    # --- Strings Table ---
    string_rows = ""
    for s in string_list:  # Include all strings
        if isinstance(s, dict):
            val = s.get("value", s.get("string", str(s)))
            addr = s.get("address", s.get("vaddr", ""))
        else:
            val = str(s)
            addr = ""
        # Skip very short or empty strings
        if len(str(val)) < 3:
            continue
        string_rows += f'<tr><td class="mono">{escape(str(addr))}</td><td>{escape(str(val)[:200])}</td></tr>\n'

    # --- Summary (shared LLM synthesis) ---
    summary_text = state.get("summary", "")
    summary_html = _markdown_to_html(summary_text) if summary_text else "<p>No LLM summary available.</p>"

    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{agent_name} Analysis Report - {file_name}</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&family=Roboto+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{ --agent-color: {agent_color}; --primary: #1f2937; --border: #e5e7eb; }}
        body {{ font-family: 'Roboto', sans-serif; background-color: #f3f4f6; color: #111827; }}
        .page-container {{ max-width: 1100px; margin: 20px auto; background: white; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); padding: 32px 40px; }}
        .mono {{ font-family: 'Roboto Mono', monospace; font-size: 0.85rem; }}
        .agent-badge {{ display: inline-block; background: var(--agent-color); color: white; padding: 4px 16px; border-radius: 4px; font-weight: 700; font-size: 14px; letter-spacing: 0.05em; text-transform: uppercase; }}
        h1 {{ font-size: 26px; font-weight: 700; color: var(--primary); margin: 0 0 4px 0; }}
        h2.section-header {{ font-size: 14pt; font-weight: 700; text-transform: uppercase; color: var(--primary); border-bottom: 2px solid var(--agent-color); padding-bottom: 6px; margin-top: 36px; margin-bottom: 16px; }}
        .meta-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; background: #f9fafb; border: 1px solid #d1d5db; padding: 14px; margin-bottom: 24px; font-size: 0.9rem; }}
        .meta-label {{ font-weight: 600; color: #4b5563; text-transform: uppercase; font-size: 0.7rem; }}
        table.data-table {{ width: 100%; border-collapse: collapse; margin: 12px 0 24px 0; font-size: 0.88rem; }}
        table.data-table th {{ background: #e5e7eb; font-weight: 700; text-transform: uppercase; font-size: 0.72rem; color: #374151; padding: 8px 10px; text-align: left; border-bottom: 2px solid #9ca3af; }}
        table.data-table td {{ padding: 6px 10px; border-bottom: 1px solid #e5e7eb; }}
        table.data-table td.prop {{ font-weight: 600; color: #4b5563; width: 180px; white-space: nowrap; }}
        table.data-table tr:hover {{ background: #f9fafb; }}
        .decomp-block {{ margin-bottom: 20px; border: 1px solid #d1d5db; border-radius: 4px; overflow: hidden; }}
        .decomp-header {{ background: var(--agent-color); color: white; padding: 8px 14px; font-family: 'Roboto Mono', monospace; font-size: 0.85rem; font-weight: 500; }}
        .decomp-block pre {{ margin: 0; padding: 14px; background: #f8f9fa; overflow-x: auto; font-size: 0.82rem; line-height: 1.5; }}
        .decomp-block code {{ font-family: 'Roboto Mono', monospace; color: #1f2937; }}
        .summary-box {{ background: #f9fafb; border: 1px solid #d1d5db; padding: 20px; border-radius: 4px; margin-top: 8px; }}
        .summary-box p {{ margin-bottom: 10px; line-height: 1.6; font-size: 10.5pt; }}
        .summary-box ul {{ list-style-type: disc; padding-left: 1.5rem; margin-bottom: 10px; }}
        .summary-box li {{ margin-bottom: 5px; }}
        .summary-box pre {{ background: #f3f4f6; border: 1px solid #d1d5db; border-left: 4px solid #6b7280; padding: 12px; overflow-x: auto; font-size: 0.82rem; margin: 14px 0; }}
        .summary-box code {{ font-family: 'Roboto Mono', monospace; background: #f3f4f6; padding: 2px 4px; font-size: 0.88em; color: #b91c1c; }}
        .summary-box pre code {{ color: #374151; background: none; padding: 0; }}
        .summary-box h3 {{ font-size: 1.05rem; font-weight: 700; color: #1f2937; margin-top: 1.2rem; margin-bottom: 0.6rem; border-bottom: 1px dotted #d1d5db; padding-bottom: 4px; }}
        .summary-box table {{ width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 0.88rem; border: 1px solid #d1d5db; }}
        .summary-box th {{ background: #e5e7eb; font-weight: 700; text-transform: uppercase; font-size: 0.72rem; padding: 8px 10px; text-align: left; border-bottom: 2px solid #9ca3af; }}
        .summary-box td {{ padding: 6px 10px; border-bottom: 1px solid #e5e7eb; }}
        .stat {{ display: inline-block; background: #f3f4f6; border: 1px solid #d1d5db; padding: 12px 20px; border-radius: 4px; text-align: center; margin: 6px; }}
        .stat .num {{ font-size: 28px; font-weight: 700; color: var(--agent-color); }}
        .stat .lbl {{ font-size: 0.72rem; color: #6b7280; text-transform: uppercase; font-weight: 600; }}
        .no-print {{ }}
        @media print {{ body {{ background: white; }} .page-container {{ margin: 0; box-shadow: none; }} .no-print {{ display: none !important; }} }}
    </style>
</head>
<body>
    <div class="no-print" style="position: fixed; bottom: 32px; right: 32px; z-index: 50;">
        <button onclick="window.print()" style="background: var(--agent-color); color: white; padding: 10px 20px; border: none; cursor: pointer; font-weight: 600; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.2);">Print / Save PDF</button>
    </div>

    <div class="page-container">
        <!-- Header -->
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 3px solid var(--agent-color); padding-bottom: 16px; margin-bottom: 20px;">
            <div>
                <div style="margin-bottom: 8px;"><span class="agent-badge">{agent_name}</span></div>
                <h1>Agent Analysis Report</h1>
                <div style="font-size: 13px; color: #6b7280;">Per-tool findings for binary <span class="mono">{file_name}</span></div>
            </div>
            <div style="text-align: right; font-size: 13px; color: #6b7280;">
                <div>{timestamp}</div>
                <div class="mono">Session: {session_id}</div>
            </div>
        </div>

        <!-- Stats -->
        <div style="text-align: center; margin-bottom: 24px;">
            <div class="stat"><div class="num">{len(func_list)}</div><div class="lbl">Functions Found</div></div>
            <div class="stat"><div class="num">{len(decomp_cache)}</div><div class="lbl">Decompiled</div></div>
            <div class="stat"><div class="num">{len(string_list)}</div><div class="lbl">Strings</div></div>
        </div>

        <!-- Binary Information -->
        <h2 class="section-header">Binary Information</h2>
        <table class="data-table">
            <tbody>
                <tr><td class="prop">SHA-256</td><td class="mono" style="word-break:break-all">{escape(program_hash)}</td></tr>
                {binary_rows}
            </tbody>
        </table>

        {qiling_runtime_section}

        <!-- Functions -->
        <h2 class="section-header">{'Syscalls' if is_qiling else 'Functions'} ({len(func_list)} discovered)</h2>
        <table class="data-table">
            <thead><tr><th>Name</th><th>Address</th><th>{'Timestamp / Size' if is_qiling else 'Size'}</th><th>{'Category' if is_qiling else 'XRefs'}</th><th>{'Observed' if is_qiling else 'Decompiled'}</th></tr></thead>
            <tbody>{func_rows}</tbody>
        </table>

        <!-- Decompiled Code -->
        <h2 class="section-header">Decompiled Code ({len(decomp_cache)} functions)</h2>
        {decomp_blocks if decomp_blocks else '<div style="color:#6b7280; font-style:italic;">No decompiled functions available.</div>'}

        <!-- Strings -->
        <h2 class="section-header">Strings ({len(string_list)} extracted)</h2>
        <table class="data-table">
            <thead><tr><th>Address</th><th>Value</th></tr></thead>
            <tbody>{string_rows if string_rows else '<tr><td colspan="2" style="color:#6b7280;font-style:italic;">No strings extracted.</td></tr>'}</tbody>
        </table>

        <!-- LLM Synthesis (shared) -->
        <h2 class="section-header">LLM Analysis Summary</h2>
        <div style="font-size: 0.82rem; color: #6b7280; font-style: italic; margin-bottom: 8px;">
            This summary was generated by the LLM using combined data from all active agents.
        </div>
        <div class="summary-box">{summary_html}</div>

        <!-- Footer -->
        <div style="margin-top: 40px; padding-top: 16px; border-top: 1px solid #d1d5db; display: flex; justify-content: space-between; font-size: 11px; color: #9ca3af;">
            <div>Confidential &amp; Proprietary</div>
            <div>Generated by {agent_name} Analysis Agent</div>
        </div>
    </div>
</body>
</html>'''
    return html
