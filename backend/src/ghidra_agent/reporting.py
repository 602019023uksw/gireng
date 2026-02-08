"""Enhanced HTML report generation matching professional template format."""

import json
import re
from datetime import datetime, timezone
from html import escape
from typing import Any, Dict, List

from ghidra_agent.ioc_extractor import extract_iocs_from_state, IOCs, calculate_verdict


def _extract_section(text: str, section_name: str) -> str:
    """Extract a section from markdown text."""
    if not text:
        return ""
    
    patterns = [
        rf'##\s*\d*\.?\s*{re.escape(section_name)}\s*\n(.*?)(?=##|\Z)',
        rf'###\s*{re.escape(section_name)}\s*\n(.*?)(?=###|##|\Z)',
        rf'\*\*{re.escape(section_name)}\*\*[:\s]*\n(.*?)(?=\*\*|##|\Z)',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
    
    return ""


def _markdown_to_html(text: str) -> str:
    """Convert markdown to HTML for template rendering."""
    if not text:
        return "<p>No information available.</p>"
    
    # Escape HTML first
    text = escape(text)
    
    # Headers
    text = re.sub(r'####\s+(.+)$', r'<h4>\1</h4>', text, flags=re.MULTILINE)
    text = re.sub(r'###\s+(.+)$', r'<h3>\1</h3>', text, flags=re.MULTILINE)
    text = re.sub(r'##\s+(.+)$', r'<h2>\1</h2>', text, flags=re.MULTILINE)
    
    # Bold and italic
    text = re.sub(r'\*\*\*(.+?)\*\*\*', r'<strong><em>\1</em></strong>', text)
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
    
    # Code blocks
    text = re.sub(r'```(\w+)?\n(.*?)```', r'<pre><code>\2</code></pre>', text, flags=re.DOTALL)
    text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
    
    # Tables
    lines = text.split('\n')
    result = []
    i = 0
    in_table = False
    table_html = []
    
    while i < len(lines):
        line = lines[i]
        if '|' in line and not line.strip().startswith('#') and not line.strip().startswith('<'):
            if not in_table:
                in_table = True
                table_html = ['<table class="w-full text-left border-collapse">']
                if i + 1 < len(lines) and re.match(r'^[\|\-\s]+$', lines[i + 1]):
                    i += 1
            
            cells = [c.strip() for c in line.split('|') if c.strip()]
            if cells:
                row_tag = 'th' if len(table_html) == 1 else 'td'
                table_html.append('<tr>')
                for cell in cells:
                    table_html.append(f'<{row_tag}>{cell}</{row_tag}>')
                table_html.append('</tr>')
        else:
            if in_table:
                table_html.append('</table>')
                result.append(''.join(table_html))
                in_table = False
                table_html = []
            result.append(line)
        i += 1
    
    if in_table:
        table_html.append('</table>')
        result.append(''.join(table_html))
    
    text = '\n'.join(result)
    
    # Bullet lists
    lines = text.split('\n')
    result = []
    in_list = False
    
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('- ') or stripped.startswith('* '):
            if not in_list:
                result.append('<ul class="list-disc pl-6 mb-4">')
                in_list = True
            item = stripped[2:]
            result.append(f'<li class="mb-2">{item}</li>')
        else:
            if in_list and stripped and not stripped.startswith('<'):
                result.append('</ul>')
                in_list = False
            result.append(line)
    
    if in_list:
        result.append('</ul>')
    
    text = '\n'.join(result)
    
    # Paragraphs
    lines = text.split('\n')
    result = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('<') and not stripped.startswith('|'):
            result.append(f'<p class="mb-3">{stripped}</p>')
        else:
            result.append(line)
    
    return '\n'.join(result)


def _parse_iocs_for_template(iocs: IOCs) -> List[Dict[str, str]]:
    """Parse IOCs into template format."""
    results = []
    
    for ip in iocs.ips[:10]:
        results.append({"type": "IP/Domain", "value": ip})
    for domain in iocs.domains[:10]:
        results.append({"type": "Domain", "value": domain})
    for url in iocs.urls[:5]:
        results.append({"type": "URL", "value": url})
    for path in iocs.file_paths[:10]:
        results.append({"type": "File Path", "value": path})
    for email in iocs.emails[:5]:
        results.append({"type": "Email", "value": email})
    for reg in iocs.registry_keys[:5]:
        results.append({"type": "Registry", "value": reg})
    for mutex in iocs.mutexes[:5]:
        results.append({"type": "Mutex", "value": mutex})
    
    return results


def _extract_recommendations(summary: str) -> List[str]:
    """Extract recommendations from summary."""
    recs = []
    matches = re.findall(r'\d+\.\s+(.+?)(?=\d+\.\s+|\Z)', summary, re.DOTALL)
    for match in matches:
        cleaned = match.strip()
        if cleaned and len(cleaned) > 10:
            recs.append(cleaned)
    return recs if recs else ["Conduct dynamic analysis in sandbox environment", "Monitor network traffic for C2 communications"]


def _extract_evidence(summary: str) -> List[str]:
    """Extract evidence items from summary."""
    evidence = []
    # Look for evidence patterns
    match = re.search(r'Evidence:\s*\n((?:(?:.+\n)+))', summary, re.IGNORECASE)
    if not match:
        match = re.search(r'Key Evidence:\s*\n((?:(?:.+\n)+))', summary, re.IGNORECASE)
    if not match:
        match = re.search(r'Indicators:\s*\n((?:(?:.+\n)+))', summary, re.IGNORECASE)
    
    if match:
        text = match.group(1)
        for line in text.split('\n'):
            line = line.strip()
            if line and (line.startswith('-') or line.startswith('*') or re.match(r'\d+\.', line)):
                evidence.append(re.sub(r'^[-*\d.\s]+', '', line))
    return evidence


def _render_evidence(evidence: List[str]) -> str:
    """Render evidence items as HTML."""
    if not evidence:
        return '<div class="text-gray-500 italic">Evidence extracted from analysis data. Review summary for details.</div>'
    html = ''
    for i, item in enumerate(evidence, 1):
        html += f'<div class="finding-item"><div class="finding-title">Evidence {i}</div><div class="finding-desc text-sm leading-relaxed pl-4">{escape(item)}</div></div>'
    return html


def _render_recommendations(recommendations: List[str]) -> str:
    """Render recommendations as HTML."""
    if not recommendations:
        return '<div class="text-gray-500 italic">No specific recommendations available.</div>'
    html = ''
    for i, rec in enumerate(recommendations, 1):
        html += f'<div class="flex gap-4 items-start pb-4 border-b border-dashed border-gray-200 last:border-0"><div class="flex-shrink-0 w-6 h-6 rounded-full bg-gray-800 text-white flex items-center justify-center text-xs font-bold">{i}</div><div class="text-sm pt-0.5 text-gray-800">{escape(rec)}</div></div>'
    return html


def _render_iocs(iocs: List[Dict[str, str]]) -> str:
    """Render IOCs as table rows."""
    if not iocs:
        return '<tr><td colspan="2" class="text-gray-500 italic">No IOCs extracted.</td></tr>'
    html = ''
    for ioc in iocs:
        html += f'<tr><td class="font-bold text-xs text-gray-500 uppercase">{escape(ioc["type"])}</td><td class="font-mono text-sm break-all">{escape(ioc["value"])}</td></tr>'
    return html


def build_report_html(state: Dict[str, Any]) -> str:
    """Build HTML report matching professional template format."""
    
    iocs = extract_iocs_from_state(state)
    verdict, verdict_class, indicators, score = calculate_verdict(iocs, state)
    
    analysis_results = state.get("analysis_results", {})
    binary = analysis_results.get("binary", {})
    funcs = analysis_results.get("functions", {})
    strings_data = analysis_results.get("strings", {})
    
    program_hash = state.get("program_hash", "unknown")
    summary_text = state.get("summary", "")
    
    report_data = {
        "file_name": escape(state.get("binary_path", "unknown").split("/")[-1]),
        "summary": _markdown_to_html(summary_text),
        "malware_capabilities": _markdown_to_html(_extract_section(summary_text, "Malware Capabilities")),
        "binary_info": _markdown_to_html(f"""| Property | Value |
|----------|-------|
| SHA256 | {program_hash} |
| Architecture | {binary.get('architecture', 'unknown')} |
| Type | ELF/PE (inferred) |
| Image Base | {binary.get('image_base', 'unknown')} |
| Entry Point | {', '.join(binary.get('entry_points', ['unknown']))} |
| Compiler | {binary.get('compiler', 'unknown')} |
| Functions | {len(funcs.get('functions', []))} total ({len(state.get('decompilation_cache', {}))} decompiled) |
| Strings | {len(strings_data.get('strings', []))} extracted |"""),
        "technical_analysis": _markdown_to_html(_extract_section(summary_text, "Technical Analysis")),
        "functions_analysis": _markdown_to_html(_extract_section(summary_text, "Functions Analysis")),
        "how_it_works": _markdown_to_html(_extract_section(summary_text, "Operational Flow")),
        "c2_analysis": _markdown_to_html(_extract_section(summary_text, "C2 & Networking")),
        "evidence": _extract_evidence(summary_text),
        "recommendations": _extract_recommendations(summary_text),
        "iocs": _parse_iocs_for_template(iocs),
        "conclusion": _markdown_to_html(_extract_section(summary_text, "Conclusion")),
    }
    
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    task_id = state.get("session_id", "unknown")[:8]
    
    risk_class = {
        "malicious": "risk-critical",
        "suspicious": "risk-high",
        "clean": "risk-low",
        "unknown": "risk-clean"
    }.get(verdict_class, "risk-clean")
    
    # Build HTML sections
    sections_html = f'''
        <!-- Executive Summary -->
        <div>
            <h2 class="section-header">1. Executive Summary</h2>
            <div class="markdown-content">{report_data['summary']}</div>
        </div>

        <!-- Malware Capabilities -->
        <div>
            <h2 class="section-header">2. Malware Capabilities</h2>
            <div class="text-sm text-gray-600 mb-4 italic border-l-2 border-gray-300 pl-3">Identified capabilities and behaviors exhibited by this malware sample.</div>
            <div class="markdown-content">{report_data['malware_capabilities'] if report_data['malware_capabilities'] else '<p>Capabilities analysis not available.</p>'}</div>
        </div>

        <!-- Binary Information -->
        <div>
            <h2 class="section-header">3. Binary Information</h2>
            <div class="markdown-content">{report_data['binary_info']}</div>
        </div>

        <!-- Technical Analysis -->
        <div>
            <h2 class="section-header">4. Technical Analysis</h2>
            <div class="text-sm text-gray-600 mb-4 italic border-l-2 border-gray-300 pl-3">In-depth technical examination of the malware code structure, algorithms, and implementation details.</div>
            <div class="markdown-content">{report_data['technical_analysis'] if report_data['technical_analysis'] else '<p>Detailed technical analysis not available.</p>'}</div>
        </div>

        <!-- Functions Analysis -->
        <div>
            <h2 class="section-header">5. Functions Analysis</h2>
            <div class="text-sm text-gray-600 mb-4 italic border-l-2 border-gray-300 pl-3">Key functions identified during static analysis, including decompiled pseudocode and behavioral descriptions.</div>
            <div class="markdown-content">{report_data['functions_analysis'] if report_data['functions_analysis'] else '<p>Function analysis not available.</p>'}</div>
        </div>

        <!-- Evidence -->
        <div>
            <h2 class="section-header">6. Evidence of Malicious Activity</h2>
            <div>{_render_evidence(report_data['evidence'])}</div>
        </div>

        <!-- Operational Flow -->
        <div>
            <h2 class="section-header">7. Operational Flow</h2>
            <div class="markdown-content">{report_data['how_it_works'] if report_data['how_it_works'] else '<p>Operational flow analysis not available.</p>'}</div>
        </div>

        <!-- C2 & Networking -->
        <div>
            <h2 class="section-header">8. C2 & Networking</h2>
            <div class="markdown-content">{report_data['c2_analysis'] if report_data['c2_analysis'] else '<p>C2 analysis not available.</p>'}</div>
        </div>

        <!-- Recommendations -->
        <div>
            <h2 class="section-header">9. Recommendations</h2>
            <div class="space-y-4">{_render_recommendations(report_data['recommendations'])}</div>
        </div>

        <!-- IOCs -->
        <div>
            <h2 class="section-header">10. Indicators of Compromise (IOCs)</h2>
            <div class="markdown-content">
                <table class="w-full text-left">
                    <thead><tr><th width="20%">Type</th><th>Value</th></tr></thead>
                    <tbody>{_render_iocs(report_data['iocs'])}</tbody>
                </table>
            </div>
        </div>

        <!-- Conclusion -->
        <div>
            <h2 class="section-header">11. Conclusion</h2>
            <div class="markdown-content" style="background-color: #f9fafb; border: 1px solid #e5e7eb; padding: 16px; border-radius: 4px;">
                {report_data['conclusion'] if report_data['conclusion'] else f'<p>This binary has been classified as <strong>{verdict}</strong> with a risk score of {score}/100. Review the technical analysis and IOCs above for detection and response guidance.</p>'}
            </div>
        </div>
    '''
    
    # CSS styles
    css_styles = '''
        :root { --primary: #1f2937; --accent: #b91c1c; --border: #e5e7eb; }
        body { font-family: 'Roboto', sans-serif; background-color: #f3f4f6; color: #111827; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        .page-container { width: 210mm; min-height: 297mm; padding: 20mm; margin: 20px auto; background: white; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); position: relative; }
        .font-mono { font-family: 'Roboto Mono', monospace; }
        h2.section-header { font-size: 14pt; font-weight: 700; text-transform: uppercase; color: var(--primary); border-bottom: 1px solid #9ca3af; padding-bottom: 4px; margin-top: 32px; margin-bottom: 16px; display: flex; align-items: center; }
        h2.section-header::before { content: ''; display: inline-block; width: 6px; height: 18px; background-color: var(--accent); margin-right: 12px; }
        .meta-box { border: 1px solid #d1d5db; background-color: #f9fafb; padding: 12px; font-size: 0.9rem; display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 32px; }
        .meta-label { font-weight: 600; color: #4b5563; text-transform: uppercase; font-size: 0.75rem; }
        .risk-banner { text-align: center; padding: 6px; font-weight: bold; text-transform: uppercase; font-size: 0.9rem; letter-spacing: 0.1em; margin-bottom: 20px; border: 1px solid; }
        .risk-critical { background-color: #fee2e2; color: #991b1b; border-color: #fca5a5; }
        .risk-high { background-color: #ffedd5; color: #9a3412; border-color: #fdba74; }
        .risk-medium { background-color: #fef9c3; color: #854d0e; border-color: #fde047; }
        .risk-low { background-color: #dcfce7; color: #166534; border-color: #86efac; }
        .risk-clean { background-color: #f3f4f6; color: #374151; border-color: #d1d5db; }
        .markdown-content p { margin-bottom: 12px; line-height: 1.6; font-size: 10.5pt; }
        .markdown-content ul { list-style-type: disc; padding-left: 1.5rem; margin-bottom: 12px; }
        .markdown-content li { margin-bottom: 6px; }
        .markdown-content pre { background-color: #f3f4f6; border: 1px solid #d1d5db; border-left: 4px solid #6b7280; padding: 12px; overflow-x: auto; font-size: 0.85rem; margin: 16px 0; }
        .markdown-content code { font-family: 'Roboto Mono', monospace; background-color: #f3f4f6; padding: 2px 4px; font-size: 0.9em; color: #b91c1c; }
        .markdown-content pre code { color: #374151; background: none; padding: 0; }
        .markdown-content h3 { font-size: 1.1rem; font-weight: 700; color: #1f2937; margin-top: 1.5rem; margin-bottom: 0.75rem; border-bottom: 1px dotted #d1d5db; padding-bottom: 4px; }
        .markdown-content h4 { font-size: 1rem; font-weight: 600; color: #374151; margin-top: 1.25rem; margin-bottom: 0.5rem; }
        .markdown-content table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 0.9rem; border: 1px solid #d1d5db; }
        .markdown-content th { background-color: #e5e7eb; font-weight: 700; text-transform: uppercase; font-size: 0.75rem; color: #374151; padding: 8px 12px; text-align: left; border-bottom: 2px solid #9ca3af; }
        .markdown-content td { padding: 8px 12px; border-bottom: 1px solid #e5e7eb; color: #1f2937; }
        .finding-item { margin-bottom: 16px; border-bottom: 1px dashed #d1d5db; padding-bottom: 12px; }
        .finding-title { font-weight: 700; color: #1f2937; font-size: 1rem; margin-bottom: 4px; }
        .finding-desc { color: #4b5563; }
        @media print { body { background: white; } .page-container { margin: 0; padding: 15mm; box-shadow: none; width: 100%; } .no-print { display: none !important; } }
    '''
    
    # Complete HTML document
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malware Analysis Report - {report_data['file_name']}</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&family=Roboto+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>{css_styles}</style>
</head>
<body>
    <div class="fixed bottom-8 right-8 no-print" style="z-index: 50;">
        <button onclick="window.print()" style="background: #1f2937; color: white; padding: 12px 24px; border: none; cursor: pointer; font-weight: 500;">
            Print / Save PDF
        </button>
    </div>

    <div class="page-container">
        <!-- Header -->
        <div style="display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 8px; border-bottom: 2px solid #1f2937; padding-bottom: 16px;">
            <div>
                <div style="font-size: 12px; font-weight: bold; color: #6b7280; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 4px;">Confidential & Proprietary</div>
                <h1 style="font-size: 30px; font-weight: bold; color: #111827; text-transform: uppercase; letter-spacing: 0.05em; margin: 0;">Reverse Engineering Report</h1>
            </div>
            <div style="text-align: right;">
                <div style="font-weight: bold; color: #111827;">CYBER SECURITY DIVISION</div>
                <div style="font-size: 14px; color: #6b7280;">Incident Response Team</div>
            </div>
        </div>

        <!-- Metadata -->
        <div class="meta-box">
            <div>
                <div class="meta-label">File Name</div>
                <div class="font-mono">{report_data['file_name']}</div>
            </div>
            <div style="text-align: right;">
                <div class="meta-label" style="text-align: right;">Analysis ID</div>
                <div class="font-mono">{task_id}</div>
            </div>
            <div>
                <div class="meta-label">Date Generated</div>
                <div>{timestamp}</div>
            </div>
            <div style="text-align: right;">
                <div class="meta-label" style="text-align: right;">Classification</div>
                <div style="display: inline-block; background: black; color: #FFC000; padding: 2px 8px; font-size: 12px; font-weight: bold;">TLP:AMBER</div>
            </div>
        </div>

        <!-- Risk Banner -->
        <div class="risk-banner {risk_class}">
            THREAT ASSESSMENT: {verdict.upper()}
        </div>

        {sections_html}

        <!-- Footer -->
        <div style="margin-top: 48px; padding-top: 24px; border-top: 1px solid #d1d5db; display: flex; justify-content: space-between; font-size: 12px; color: #9ca3af;" class="no-print">
            <div>Confidential & Proprietary - Do Not Distribute Without Authorization</div>
            <div>Generated by Ghidra Analysis Agent</div>
        </div>
    </div>
</body>
</html>'''
    
    return html


def build_report_text(state: Dict[str, Any]) -> str:
    """Build plain text report for download."""
    summary = state.get("summary", "No summary available.")
    program_hash = state.get("program_hash", "unknown")
    
    lines = [
        "=" * 70,
        "GHIDRA BINARY ANALYSIS REPORT",
        "=" * 70,
        "",
        f"SHA-256: {program_hash}",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "-" * 70,
        "EXECUTIVE SUMMARY",
        "-" * 70,
        summary,
        "",
        "=" * 70,
        "END OF REPORT",
        "=" * 70,
    ]
    
    return '\n'.join(lines)
