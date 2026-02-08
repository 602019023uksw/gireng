"""Enhanced HTML report generation matching professional template format."""

import re
from datetime import datetime, timezone
from html import escape
from typing import Any, Dict, List

from ghidra_agent.ioc_extractor import extract_iocs_from_state, calculate_verdict


def _markdown_to_html(text: str) -> str:
    """Convert markdown to HTML for template rendering."""
    if not text:
        return ""
    
    # Escape HTML first
    text = escape(text)
    
    # Headers - convert markdown headers to HTML
    text = re.sub(r'^####\s+(.+)$', r'<h4>\1</h4>', text, flags=re.MULTILINE)
    text = re.sub(r'^###\s+(.+)$', r'<h3>\1</h3>', text, flags=re.MULTILINE)
    text = re.sub(r'^##\s+(.+)$', r'<h2>\1</h2>', text, flags=re.MULTILINE)
    
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
        if '|' in line and not line.strip().startswith('<') and not line.strip().startswith('#'):
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
            if in_list and stripped and not stripped.startswith('<') and not stripped.startswith('|') and not stripped.startswith('#'):
                result.append('</ul>')
                in_list = False
            result.append(line)
    
    if in_list:
        result.append('</ul>')
    
    text = '\n'.join(result)
    
    # Paragraphs for remaining text
    lines = text.split('\n')
    result = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('<') and not stripped.startswith('|'):
            result.append(f'<p class="mb-3">{stripped}</p>')
        else:
            result.append(line)
    
    return '\n'.join(result)


def _parse_iocs_for_template(iocs) -> List[Dict[str, str]]:
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


def _extract_list_items(text: str, keywords: List[str]) -> List[str]:
    """Extract list items following keywords."""
    items = []
    for keyword in keywords:
        # Look for keyword followed by list
        pattern = rf'{re.escape(keyword)}[:\s]*\n((?:\s*[-*]\s*.+\n)+)'
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            list_text = match.group(1)
            for line in list_text.split('\n'):
                line = line.strip()
                if line.startswith('- ') or line.startswith('* '):
                    item = line[2:].strip()
                    if item and item not in items:
                        items.append(item)
    return items


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
    
    file_name = escape(state.get("binary_path", "unknown").split("/")[-1])
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    task_id = state.get("session_id", "unknown")[:8]
    
    # Convert summary to HTML
    summary_html = _markdown_to_html(summary_text)
    
    # Extract recommendations from summary or use defaults
    rec_items = _extract_list_items(summary_text, ["Recommendations", "Recommended", "Detection"])
    if not rec_items:
        rec_items = [
            "Monitor network traffic for connections to identified C2 infrastructure",
            "Hunt for the IOCs listed in this report across the environment",
            "Conduct dynamic analysis in sandbox to observe runtime behavior"
        ]
    
    # Extract evidence from indicators
    evidence_items = indicators if indicators else ["Analysis of binary revealed suspicious characteristics. See technical details above."]
    
    # IOCs table
    ioc_list = _parse_iocs_for_template(iocs)
    
    # Risk class
    risk_class = {
        "malicious": "risk-critical",
        "suspicious": "risk-high",
        "clean": "risk-low",
        "unknown": "risk-clean"
    }.get(verdict_class, "risk-clean")
    
    # Build recommendations HTML
    recs_html = ""
    for i, rec in enumerate(rec_items, 1):
        recs_html += f'<div class="flex gap-4 items-start pb-4 border-b border-dashed border-gray-200 last:border-0"><div class="flex-shrink-0 w-6 h-6 rounded-full bg-gray-800 text-white flex items-center justify-center text-xs font-bold">{i}</div><div class="text-sm pt-0.5 text-gray-800">{escape(rec)}</div></div>'
    
    # Build evidence HTML
    evidence_html = ""
    for i, item in enumerate(evidence_items[:10], 1):
        evidence_html += f'<div class="finding-item"><div class="finding-title">Evidence {i}</div><div class="finding-desc text-sm leading-relaxed pl-4">{escape(item)}</div></div>'
    
    # Build IOCs HTML
    iocs_html = ""
    if ioc_list:
        for ioc in ioc_list:
            iocs_html += f'<tr><td class="font-bold text-xs text-gray-500 uppercase">{escape(ioc["type"])}</td><td class="font-mono text-sm break-all">{escape(ioc["value"])}</td></tr>'
    else:
        iocs_html = '<tr><td colspan="2" class="text-gray-500 italic">No IOCs extracted from this sample.</td></tr>'
    
    # Function count
    func_count = len(funcs.get("functions", []))
    decomp_count = len(state.get("decompilation_cache", {}))
    string_count = len(strings_data.get("strings", []))
    
    # CSS styles
    css = """
        :root { --primary: #1f2937; --accent: #b91c1c; }
        body { font-family: 'Segoe UI', Roboto, sans-serif; background: #f3f4f6; color: #111; margin: 0; padding: 20px; }
        .page { max-width: 900px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .header { display: flex; justify-content: space-between; align-items: flex-end; border-bottom: 3px solid #1f2937; padding-bottom: 16px; margin-bottom: 20px; }
        .header-title { font-size: 28px; font-weight: bold; text-transform: uppercase; color: #1f2937; margin: 0; }
        .header-meta { text-align: right; font-size: 14px; color: #666; }
        .meta-box { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; background: #f9fafb; border: 1px solid #d1d5db; padding: 16px; margin-bottom: 20px; font-size: 13px; }
        .meta-label { font-weight: 600; color: #666; text-transform: uppercase; font-size: 11px; }
        .risk-banner { text-align: center; padding: 10px; font-weight: bold; text-transform: uppercase; font-size: 14px; margin-bottom: 24px; border: 2px solid; }
        .risk-critical { background: #fee2e2; color: #991b1b; border-color: #991b1b; }
        .risk-high { background: #ffedd5; color: #9a3412; border-color: #9a3412; }
        .risk-medium { background: #fef9c3; color: #854d0e; border-color: #854d0e; }
        .risk-low { background: #dcfce7; color: #166534; border-color: #166534; }
        .risk-clean { background: #f3f4f6; color: #374151; border-color: #9ca3af; }
        h2 { font-size: 16px; font-weight: bold; text-transform: uppercase; color: #1f2937; border-bottom: 2px solid #e5e7eb; padding-bottom: 6px; margin-top: 32px; margin-bottom: 16px; }
        h2::before { content: ''; display: inline-block; width: 4px; height: 16px; background: #b91c1c; margin-right: 8px; vertical-align: middle; }
        .section-desc { font-size: 13px; color: #666; font-style: italic; border-left: 3px solid #d1d5db; padding-left: 12px; margin-bottom: 16px; }
        .content p { margin-bottom: 12px; line-height: 1.6; }
        .content ul { margin-bottom: 16px; padding-left: 24px; }
        .content li { margin-bottom: 6px; }
        .content code { background: #f3f4f6; padding: 2px 6px; font-family: monospace; font-size: 0.9em; color: #b91c1c; }
        .content pre { background: #f8f9fa; border: 1px solid #e5e7eb; border-left: 4px solid #6b7280; padding: 16px; overflow-x: auto; margin: 16px 0; }
        .content pre code { background: none; color: #374151; }
        .content h3 { font-size: 15px; font-weight: bold; color: #374151; margin-top: 20px; margin-bottom: 10px; }
        .content h4 { font-size: 14px; font-weight: 600; color: #4b5563; margin-top: 16px; margin-bottom: 8px; }
        .content table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; border: 1px solid #d1d5db; }
        .content th { background: #e5e7eb; font-weight: 600; text-transform: uppercase; font-size: 11px; padding: 10px 12px; text-align: left; border-bottom: 2px solid #9ca3af; }
        .content td { padding: 10px 12px; border-bottom: 1px solid #e5e7eb; }
        .finding-item { margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px dashed #d1d5db; }
        .finding-title { font-weight: bold; color: #1f2937; margin-bottom: 4px; }
        .finding-desc { color: #4b5563; font-size: 13px; }
        .mono { font-family: 'Consolas', monospace; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #d1d5db; font-size: 11px; color: #9ca3af; text-align: center; }
        @media print { body { background: white; } .page { box-shadow: none; max-width: 100%; padding: 20px; } .no-print { display: none; } }
    """
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Malware Analysis Report - {file_name}</title>
    <style>{css}</style>
</head>
<body>
    <div class="no-print" style="position: fixed; bottom: 20px; right: 20px;">
        <button onclick="window.print()" style="background: #1f2937; color: white; border: none; padding: 12px 24px; cursor: pointer; font-weight: 500;">Print / Save PDF</button>
    </div>

    <div class="page">
        <!-- Header -->
        <div class="header">
            <div>
                <div style="font-size: 11px; font-weight: bold; color: #666; text-transform: uppercase; margin-bottom: 4px;">Confidential & Proprietary</div>
                <h1 class="header-title">Malware Analysis Report</h1>
            </div>
            <div class="header-meta">
                <div style="font-weight: bold; color: #1f2937;">CYBER SECURITY DIVISION</div>
                <div>Incident Response Team</div>
            </div>
        </div>

        <!-- Metadata -->
        <div class="meta-box">
            <div><div class="meta-label">File Name</div><div class="mono">{file_name}</div></div>
            <div style="text-align: right;"><div class="meta-label">Analysis ID</div><div class="mono">{task_id}</div></div>
            <div><div class="meta-label">Date Generated</div><div>{timestamp}</div></div>
            <div style="text-align: right;"><div class="meta-label">Classification</div><div style="display: inline-block; background: #1f2937; color: #FFC000; padding: 2px 8px; font-size: 11px; font-weight: bold;">TLP:AMBER</div></div>
        </div>

        <!-- Risk Banner -->
        <div class="risk-banner {risk_class}">
            THREAT ASSESSMENT: {verdict.upper()} (Score: {score}/100)
        </div>

        <!-- Executive Summary -->
        <h2>1. Executive Summary</h2>
        <div class="content">
            {summary_html}
        </div>

        <!-- Binary Information -->
        <h2>2. Binary Information</h2>
        <div class="content">
            <table>
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>SHA256</td><td class="mono">{program_hash}</td></tr>
                <tr><td>Architecture</td><td>{binary.get('architecture', 'Unknown')}</td></tr>
                <tr><td>Image Base</td><td class="mono">{binary.get('image_base', 'Unknown')}</td></tr>
                <tr><td>Entry Point</td><td class="mono">{', '.join(binary.get('entry_points', ['Unknown']))}</td></tr>
                <tr><td>Compiler</td><td>{binary.get('compiler', 'Unknown')}</td></tr>
                <tr><td>Total Functions</td><td>{func_count:,}</td></tr>
                <tr><td>Decompiled</td><td>{decomp_count}</td></tr>
                <tr><td>Strings Extracted</td><td>{string_count:,}</td></tr>
            </table>
        </div>

        <!-- Indicators -->
        <h2>3. Indicators of Compromise (IOCs)</h2>
        <div class="section-desc">Extracted network, file system, and behavioral indicators.</div>
        <div class="content">
            <table>
                <tr><th style="width: 20%">Type</th><th>Value</th></tr>
                {iocs_html}
            </table>
        </div>

        <!-- Evidence -->
        <h2>4. Evidence of Malicious Activity</h2>
        <div>
            {evidence_html}
        </div>

        <!-- Recommendations -->
        <h2>5. Recommendations</h2>
        <div>
            {recs_html}
        </div>

        <!-- Footer -->
        <div class="footer">
            Confidential & Proprietary - Do Not Distribute Without Authorization | Generated by Ghidra Analysis Agent
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
