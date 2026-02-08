"""Enhanced HTML report generation matching professional template format."""

import re
from datetime import datetime, timezone
from html import escape
from typing import Any, Dict, List

from ghidra_agent.ioc_extractor import extract_iocs_from_state, calculate_verdict


# ---------------------------------------------------------------------------
# Section headings the LLM is instructed to produce (see prompts.py).
# Order matters: we walk the summary text and split on these.
# ---------------------------------------------------------------------------
_SECTION_PATTERNS: List[Dict[str, str]] = [
    {"key": "executive_summary",    "pattern": r"(?:Executive\s+Summary)"},
    {"key": "malware_capabilities", "pattern": r"(?:Malware\s+Capabilities)"},
    {"key": "binary_info",          "pattern": r"(?:Binary\s+Information)"},
    {"key": "technical_analysis",   "pattern": r"(?:Technical\s+Analysis)"},
    {"key": "functions_analysis",   "pattern": r"(?:Functions?\s+Analysis)"},
    {"key": "operational_flow",     "pattern": r"(?:Operational\s+Flow)"},
    {"key": "c2_analysis",          "pattern": r"(?:C2\s*[&]\s*Networking|C2\s+Analysis|C2\s+and\s+Networking|Command\s+and\s+Control)"},
    {"key": "evidence",             "pattern": r"(?:Evidence\s+of\s+Malicious\s+Activity)"},
    {"key": "recommendations",      "pattern": r"(?:Recommendations?)"},
    {"key": "iocs_text",            "pattern": r"(?:IOCs?\s*\(Indicators\s+of\s+Compromise\)|Indicators?\s+of\s+Compromise|IOCs)"},
    {"key": "mitre_attack",         "pattern": r"(?:MITRE\s+ATT&CK|MITRE\s+ATT&CK\s+Matrix)"},
    {"key": "conclusion",           "pattern": r"(?:Conclusion)"},
]


def _split_summary_into_sections(text: str) -> Dict[str, str]:
    """Split the LLM-generated summary into named sections by headings."""
    if not text:
        return {}

    # Build one big regex alternation to find all section headings.
    # Each heading looks like:  ### 5. Functions Analysis  or  ## Functions Analysis
    heading_alts = []
    for sp in _SECTION_PATTERNS:
        # Match: optional ### / ## markers, optional number, heading text
        heading_alts.append(
            rf'(?P<{sp["key"]}>^\s*#{{2,4}}\s*(?:\d+\.?\s*)?{sp["pattern"]}\s*$)'
        )

    combined = "|".join(heading_alts)
    heading_re = re.compile(combined, re.IGNORECASE | re.MULTILINE)

    matches = list(heading_re.finditer(text))
    sections: Dict[str, str] = {}

    for idx, m in enumerate(matches):
        # Determine which named group matched
        key = None
        for sp in _SECTION_PATTERNS:
            if m.group(sp["key"]):
                key = sp["key"]
                break
        if not key:
            continue

        start = m.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        content = text[start:end].strip()
        if content:
            sections[key] = content

    # If no sections found at all, treat everything as executive_summary
    if not sections:
        sections["executive_summary"] = text.strip()

    return sections


# ---------------------------------------------------------------------------
# Robust Markdown → HTML converter
# ---------------------------------------------------------------------------

def _markdown_to_html(text: str) -> str:
    """Convert markdown text to clean HTML suitable for the report template.

    Processing order matters:
    1. Extract fenced code blocks first (protect from further transforms).
    2. Convert tables.
    3. Convert inline formatting (bold, italic, inline code).
    4. Convert headers.
    5. Convert ordered and unordered lists.
    6. Wrap remaining bare lines as paragraphs.
    7. Re-inject code blocks.
    """
    if not text:
        return ""

    # ── Step 0: Normalise line endings ──
    text = text.replace('\r\n', '\n').replace('\r', '\n')

    # ── Step 1: Extract fenced code blocks ──
    code_blocks: List[str] = []

    def _stash_code(m: re.Match) -> str:
        lang = m.group(1) or ""
        code = m.group(2)
        # Escape HTML inside code
        code_escaped = escape(code).rstrip('\n')
        lang_attr = f' class="language-{escape(lang)}"' if lang else ''
        block_html = (
            f'<pre><code{lang_attr}>{code_escaped}</code></pre>'
        )
        idx = len(code_blocks)
        code_blocks.append(block_html)
        return f'\x00CODEBLOCK{idx}\x00'

    text = re.sub(r'```(\w+)?\s*\n(.*?)```', _stash_code, text, flags=re.DOTALL)

    # ── Step 2: Escape HTML in remaining text ──
    # But NOT the placeholders
    parts = re.split(r'(\x00CODEBLOCK\d+\x00)', text)
    escaped_parts = []
    for part in parts:
        if part.startswith('\x00CODEBLOCK'):
            escaped_parts.append(part)
        else:
            escaped_parts.append(escape(part))
    text = ''.join(escaped_parts)

    # ── Step 3: Inline formatting ──
    text = re.sub(r'\*\*\*(.+?)\*\*\*', r'<strong><em>\1</em></strong>', text)
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)', r'<em>\1</em>', text)
    text = re.sub(r'`([^`]+?)`', r'<code>\1</code>', text)

    # ── Step 4: Process line by line ──
    lines = text.split('\n')
    result: List[str] = []
    in_ul = False
    in_ol = False
    in_table = False
    table_html: List[str] = []
    i = 0

    def _close_lists():
        nonlocal in_ul, in_ol
        if in_ul:
            result.append('</ul>')
            in_ul = False
        if in_ol:
            result.append('</ol>')
            in_ol = False

    def _close_table():
        nonlocal in_table
        if in_table:
            table_html.append('</tbody></table>')
            result.append('\n'.join(table_html))
            table_html.clear()
            in_table = False

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # ── Code block placeholder ──
        if stripped.startswith('\x00CODEBLOCK'):
            _close_lists()
            _close_table()
            result.append(stripped)
            i += 1
            continue

        # ── Empty line ──
        if not stripped:
            _close_lists()
            _close_table()
            i += 1
            continue

        # ── Headers ──
        hdr_match = re.match(r'^(#{2,6})\s+(.+)$', stripped)
        if hdr_match:
            _close_lists()
            _close_table()
            level = len(hdr_match.group(1))
            hdr_text = hdr_match.group(2)
            # Strip leading "N." numbering since the template adds its own
            hdr_text = re.sub(r'^\d+\.?\s*', '', hdr_text)
            result.append(f'<h{level}>{hdr_text}</h{level}>')
            i += 1
            continue

        # ── Table rows ──
        if '|' in stripped and not stripped.startswith('<'):
            # Check if it's a separator row
            if re.match(r'^[\|\-\s:]+$', stripped):
                i += 1
                continue
            cells = [c.strip() for c in stripped.split('|')]
            cells = [c for c in cells if c]  # remove empty edge cells
            if cells:
                if not in_table:
                    _close_lists()
                    in_table = True
                    table_html.append('<table>')
                    table_html.append('<thead><tr>')
                    for c in cells:
                        table_html.append(f'<th>{c}</th>')
                    table_html.append('</tr></thead><tbody>')
                    # Skip the separator line if next
                    if i + 1 < len(lines) and re.match(r'^[\|\-\s:]+$', lines[i + 1].strip()):
                        i += 1
                else:
                    table_html.append('<tr>')
                    for c in cells:
                        table_html.append(f'<td>{c}</td>')
                    table_html.append('</tr>')
            i += 1
            continue

        # ── Unordered list ──
        ul_match = re.match(r'^(\s*)([-*])\s+(.+)$', stripped)
        if ul_match:
            _close_table()
            if in_ol:
                result.append('</ol>')
                in_ol = False
            if not in_ul:
                result.append('<ul>')
                in_ul = True
            content = ul_match.group(3)
            result.append(f'<li>{content}</li>')
            i += 1
            continue

        # ── Ordered list ──
        ol_match = re.match(r'^(\d+)[.)]\s+(.+)$', stripped)
        if ol_match:
            _close_table()
            if in_ul:
                result.append('</ul>')
                in_ul = False
            if not in_ol:
                result.append('<ol>')
                in_ol = True
            content = ol_match.group(2)
            result.append(f'<li>{content}</li>')
            i += 1
            continue

        # ── Regular paragraph line ──
        _close_lists()
        _close_table()
        result.append(f'<p>{stripped}</p>')
        i += 1

    _close_lists()
    _close_table()

    html = '\n'.join(result)

    # ── Step 5: Re-inject code blocks ──
    for idx, block in enumerate(code_blocks):
        html = html.replace(f'\x00CODEBLOCK{idx}\x00', block)

    return html


def _parse_iocs_for_template(iocs) -> List[Dict[str, str]]:
    """Parse IOCs into template format."""
    results = []

    for ip in iocs.ips[:10]:
        results.append({"type": "IP Address", "value": ip})
    for domain in iocs.domains[:10]:
        results.append({"type": "Domain", "value": domain})
    for url in iocs.urls[:5]:
        results.append({"type": "URL", "value": url})
    for path in iocs.file_paths[:10]:
        results.append({"type": "File Path", "value": path})
    for email in iocs.emails[:5]:
        results.append({"type": "Email", "value": email})
    for reg in iocs.registry_keys[:5]:
        results.append({"type": "Registry Key", "value": reg})
    for mutex in iocs.mutexes[:5]:
        results.append({"type": "Mutex", "value": mutex})

    return results


def build_report_html(state: Dict[str, Any]) -> str:
    """Build HTML report matching the professional print template format.

    The LLM summary is split into named sections (Executive Summary, Functions
    Analysis, etc.) and each is rendered into its own properly-styled section.
    """

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

    # ── Parse summary into sections ──
    sections = _split_summary_into_sections(summary_text)

    # Convert each section's markdown to HTML
    section_html: Dict[str, str] = {}
    for key, md in sections.items():
        section_html[key] = _markdown_to_html(md)

    # ── Structured data from analysis results ──
    func_count = len(funcs.get("functions", []))
    decomp_count = len(state.get("decompilation_cache", {}))
    string_count = len(strings_data.get("strings", []))

    # Risk class mapping
    risk_class = {
        "malicious": "risk-critical",
        "suspicious": "risk-high",
        "clean": "risk-low",
        "unknown": "risk-clean",
    }.get(verdict_class, "risk-clean")

    # IOC table from extractor
    ioc_list = _parse_iocs_for_template(iocs)

    # ── Build IOCs HTML rows ──
    iocs_rows = ""
    if ioc_list:
        for ioc in ioc_list:
            iocs_rows += (
                f'<tr>'
                f'<td class="ioc-type">{escape(ioc["type"])}</td>'
                f'<td class="ioc-value">{escape(ioc["value"])}</td>'
                f'</tr>'
            )
    else:
        iocs_rows = '<tr><td colspan="2" class="no-data">No IOCs extracted from this sample.</td></tr>'

    # Also merge IOC text from LLM if present
    iocs_section_html = section_html.get("iocs_text", "")

    # ── Evidence HTML ──
    evidence_html = ""
    if indicators:
        for i, item in enumerate(indicators[:15], 1):
            evidence_html += (
                f'<div class="finding-item">'
                f'<div class="finding-title">Finding {i}</div>'
                f'<div class="finding-desc">{escape(item)}</div>'
                f'</div>'
            )

    # Also use LLM evidence section if present
    evidence_section_html = section_html.get("evidence", "")

    # ── Recommendations HTML ──
    rec_section_html = section_html.get("recommendations", "")

    # ── Binary info ──
    # Prefer LLM section, but always add structured table
    binary_info_html = section_html.get("binary_info", "")
    binary_table = f'''<table>
        <thead><tr><th>Property</th><th>Value</th></tr></thead>
        <tbody>
            <tr><td>SHA256</td><td class="mono">{escape(program_hash)}</td></tr>
            <tr><td>Architecture</td><td>{escape(str(binary.get("architecture", "Unknown")))}</td></tr>
            <tr><td>Image Base</td><td class="mono">{escape(str(binary.get("image_base", "Unknown")))}</td></tr>
            <tr><td>Entry Point</td><td class="mono">{escape(", ".join(binary.get("entry_points", ["Unknown"])))}</td></tr>
            <tr><td>Compiler</td><td>{escape(str(binary.get("compiler", "Unknown")))}</td></tr>
            <tr><td>Total Functions</td><td>{func_count:,}</td></tr>
            <tr><td>Decompiled</td><td>{decomp_count}</td></tr>
            <tr><td>Strings Extracted</td><td>{string_count:,}</td></tr>
        </tbody>
    </table>'''

    # ── Section numbering helper ──
    sec_num = 0

    def _next_sec() -> int:
        nonlocal sec_num
        sec_num += 1
        return sec_num

    # ── Assemble optional sections ──
    optional_sections = ""

    # Malware Capabilities
    cap_html = section_html.get("malware_capabilities", "")
    if cap_html:
        n = _next_sec()
        optional_sections += f'''
        <h2>{n}. Malware Capabilities</h2>
        <div class="section-desc">Identified capabilities and behaviors exhibited by this sample.</div>
        <div class="content">{cap_html}</div>'''

    # Binary Information (always show)
    n = _next_sec()
    optional_sections += f'''
    <h2>{n}. Binary Information</h2>
    <div class="content">
        {binary_table}
        {binary_info_html}
    </div>'''

    # Technical Analysis
    tech_html = section_html.get("technical_analysis", "")
    if tech_html:
        n = _next_sec()
        optional_sections += f'''
        <h2>{n}. Technical Analysis</h2>
        <div class="section-desc">In-depth technical examination of the binary&#39;s code structure, algorithms, and implementation details.</div>
        <div class="content">{tech_html}</div>'''

    # Functions Analysis
    func_html = section_html.get("functions_analysis", "")
    if func_html:
        n = _next_sec()
        optional_sections += f'''
        <div class="page-break"></div>
        <h2>{n}. Functions Analysis</h2>
        <div class="section-desc">Key functions identified during static analysis, including decompiled pseudocode and behavioral descriptions.</div>
        <div class="content">{func_html}</div>'''

    # Operational Flow
    flow_html = section_html.get("operational_flow", "")
    if flow_html:
        n = _next_sec()
        optional_sections += f'''
        <h2>{n}. Operational Flow</h2>
        <div class="content">{flow_html}</div>'''

    # C2 & Networking
    c2_html = section_html.get("c2_analysis", "")
    if c2_html:
        n = _next_sec()
        optional_sections += f'''
        <h2>{n}. C2 &amp; Networking</h2>
        <div class="content">{c2_html}</div>'''

    # Evidence of Malicious Activity
    if evidence_section_html or evidence_html:
        n = _next_sec()
        optional_sections += f'''
        <h2>{n}. Evidence of Malicious Activity</h2>
        <div class="content">
            {evidence_section_html if evidence_section_html else evidence_html}
        </div>'''

    # Recommendations
    if rec_section_html:
        n = _next_sec()
        optional_sections += f'''
        <div class="page-break"></div>
        <h2>{n}. Recommendations</h2>
        <div class="content">{rec_section_html}</div>'''

    # MITRE ATT&CK
    mitre_html = section_html.get("mitre_attack", "")
    if mitre_html:
        n = _next_sec()
        optional_sections += f'''
        <h2>{n}. MITRE ATT&amp;CK Matrix</h2>
        <div class="content">{mitre_html}</div>'''

    # IOCs
    n = _next_sec()
    optional_sections += f'''
    <h2>{n}. Indicators of Compromise (IOCs)</h2>
    <div class="section-desc">Extracted network, file system, and behavioral indicators.</div>
    <div class="content">
        {iocs_section_html}
        <table>
            <thead><tr><th style="width:20%">Type</th><th>Value</th></tr></thead>
            <tbody>{iocs_rows}</tbody>
        </table>
    </div>'''

    # Conclusion
    conclusion_html = section_html.get("conclusion", "")
    if conclusion_html:
        n = _next_sec()
        optional_sections += f'''
        <div class="page-break"></div>
        <h2>{n}. Conclusion</h2>
        <div class="content conclusion-box">{conclusion_html}</div>'''

    # ── Executive summary (section 1, always present) ──
    exec_summary_html = section_html.get("executive_summary", "<p>No summary provided.</p>")

    # ── CSS ──
    css = _report_css()

    # ── Final HTML ──
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malware Analysis Report - {file_name}</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&family=Roboto+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>{css}</style>
</head>
<body>
    <div class="no-print" style="position:fixed;bottom:24px;right:24px;z-index:50;">
        <button onclick="window.print()" style="background:#1f2937;color:white;border:none;padding:12px 24px;cursor:pointer;font-weight:500;font-size:14px;display:flex;align-items:center;gap:8px;">
            &#128438; Print / Save PDF
        </button>
    </div>

    <div class="page">
        <!-- Header -->
        <div class="header">
            <div>
                <div class="header-classification">Confidential &amp; Proprietary</div>
                <h1 class="header-title">Reverse Engineering Report</h1>
            </div>
            <div class="header-right">
                <div class="header-org">CYBER SECURITY DIVISION</div>
                <div class="header-team">Incident Response Team</div>
            </div>
        </div>

        <!-- Metadata -->
        <div class="meta-box">
            <div><div class="meta-label">File Name</div><div class="mono">{file_name}</div></div>
            <div class="text-right"><div class="meta-label">Analysis ID</div><div class="mono">{task_id}</div></div>
            <div><div class="meta-label">Date Generated</div><div>{timestamp}</div></div>
            <div class="text-right"><div class="meta-label">Classification</div><div class="tlp-badge">TLP:AMBER</div></div>
        </div>

        <!-- Risk Banner -->
        <div class="risk-banner {risk_class}">
            THREAT ASSESSMENT: {verdict.upper()} (Score: {score}/100)
        </div>

        <!-- 1. Executive Summary -->
        <h2>1. Executive Summary</h2>
        <div class="content">
            {exec_summary_html}
        </div>

        {optional_sections}

        <!-- Footer -->
        <div class="footer">
            Confidential &amp; Proprietary &mdash; Do Not Distribute Without Authorization
        </div>
    </div>
</body>
</html>'''

    return html


def _report_css() -> str:
    """Return the full CSS for the standalone report."""
    return '''
    :root {
        --primary: #1f2937;
        --accent: #b91c1c;
        --border: #e5e7eb;
        --bg-light: #f9fafb;
        --text: #111827;
        --text-secondary: #4b5563;
        --text-muted: #6b7280;
        --code-bg: #f3f4f6;
        --code-color: #b91c1c;
    }
    * { box-sizing: border-box; }
    body {
        font-family: 'Roboto', 'Segoe UI', sans-serif;
        background: #f3f4f6;
        color: var(--text);
        margin: 0;
        padding: 20px;
        -webkit-print-color-adjust: exact;
        print-color-adjust: exact;
    }

    /* ── Page container ── */
    .page {
        max-width: 210mm;
        margin: 0 auto;
        background: white;
        padding: 40px 48px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }

    /* ── Header ── */
    .header {
        display: flex;
        justify-content: space-between;
        align-items: flex-end;
        border-bottom: 3px solid var(--primary);
        padding-bottom: 16px;
        margin-bottom: 20px;
    }
    .header-classification {
        font-size: 10px;
        font-weight: 700;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 0.1em;
        margin-bottom: 4px;
    }
    .header-title {
        font-size: 24px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.04em;
        color: var(--primary);
        margin: 0;
    }
    .header-right { text-align: right; }
    .header-org { font-weight: 700; color: var(--primary); font-size: 14px; }
    .header-team { font-size: 13px; color: var(--text-muted); }

    /* ── Metadata Box ── */
    .meta-box {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 10px;
        background: var(--bg-light);
        border: 1px solid #d1d5db;
        padding: 14px 16px;
        margin-bottom: 20px;
        font-size: 13px;
    }
    .meta-label {
        font-weight: 600;
        color: var(--text-muted);
        text-transform: uppercase;
        font-size: 10px;
        letter-spacing: 0.05em;
    }
    .text-right { text-align: right; }
    .mono { font-family: 'Roboto Mono', Consolas, monospace; font-size: 12px; }
    .tlp-badge {
        display: inline-block;
        background: var(--primary);
        color: #FFC000;
        padding: 2px 10px;
        font-size: 11px;
        font-weight: 700;
    }

    /* ── Risk Banner ── */
    .risk-banner {
        text-align: center;
        padding: 8px 12px;
        font-weight: 700;
        text-transform: uppercase;
        font-size: 13px;
        letter-spacing: 0.08em;
        margin-bottom: 24px;
        border: 2px solid;
    }
    .risk-critical { background: #fee2e2; color: #991b1b; border-color: #ef4444; }
    .risk-high     { background: #ffedd5; color: #9a3412; border-color: #f97316; }
    .risk-medium   { background: #fef9c3; color: #854d0e; border-color: #eab308; }
    .risk-low      { background: #dcfce7; color: #166534; border-color: #22c55e; }
    .risk-clean    { background: var(--code-bg); color: #374151; border-color: #9ca3af; }

    /* ── Section Headers ── */
    h2 {
        font-size: 14px;
        font-weight: 700;
        text-transform: uppercase;
        color: var(--primary);
        border-bottom: 2px solid var(--border);
        padding-bottom: 6px;
        margin-top: 36px;
        margin-bottom: 16px;
        display: flex;
        align-items: center;
        letter-spacing: 0.03em;
    }
    h2::before {
        content: '';
        display: inline-block;
        width: 5px;
        height: 16px;
        background: var(--accent);
        margin-right: 10px;
        flex-shrink: 0;
    }
    .section-desc {
        font-size: 12px;
        color: var(--text-muted);
        font-style: italic;
        border-left: 3px solid #d1d5db;
        padding-left: 12px;
        margin-bottom: 16px;
    }

    /* ── Content area ── */
    .content {
        font-size: 10.5pt;
        line-height: 1.65;
    }
    .content p {
        margin-bottom: 10px;
        text-align: left;
    }

    /* Lists */
    .content ul {
        list-style: disc;
        padding-left: 24px;
        margin: 8px 0 14px 0;
    }
    .content ol {
        list-style: decimal;
        padding-left: 24px;
        margin: 8px 0 14px 0;
    }
    .content li {
        margin-bottom: 6px;
        padding-left: 2px;
        line-height: 1.6;
    }
    .content li > p { margin-bottom: 2px; }

    /* Sub-headers inside content */
    .content h3 {
        font-size: 12pt;
        font-weight: 700;
        color: var(--primary);
        margin-top: 22px;
        margin-bottom: 10px;
        border-bottom: 1px dotted #d1d5db;
        padding-bottom: 4px;
    }
    .content h4 {
        font-size: 11pt;
        font-weight: 600;
        color: #374151;
        margin-top: 18px;
        margin-bottom: 8px;
    }
    .content h5, .content h6 {
        font-size: 10.5pt;
        font-weight: 600;
        color: var(--text-secondary);
        margin-top: 14px;
        margin-bottom: 6px;
    }
    .content strong { font-weight: 700; color: var(--text); }

    /* Inline code */
    .content code {
        font-family: 'Roboto Mono', Consolas, monospace;
        background: var(--code-bg);
        border: 1px solid #e5e7eb;
        padding: 1px 5px;
        font-size: 0.88em;
        color: var(--code-color);
        border-radius: 2px;
        word-break: break-all;
    }

    /* Code blocks */
    .content pre {
        background: #f8f9fa;
        border: 1px solid #d1d5db;
        border-left: 4px solid var(--text-muted);
        padding: 14px 16px;
        overflow-x: auto;
        margin: 14px 0;
        border-radius: 2px;
        font-size: 9pt;
        line-height: 1.5;
    }
    .content pre code {
        background: none;
        border: none;
        padding: 0;
        color: #374151;
        font-size: inherit;
        word-break: normal;
    }

    /* Tables */
    .content table {
        width: 100%;
        border-collapse: collapse;
        margin: 14px 0;
        font-size: 10pt;
        border: 1px solid #d1d5db;
    }
    .content th {
        background: #e5e7eb;
        font-weight: 700;
        text-transform: uppercase;
        font-size: 9pt;
        color: #374151;
        padding: 8px 12px;
        text-align: left;
        border-bottom: 2px solid #9ca3af;
        letter-spacing: 0.03em;
    }
    .content td {
        padding: 8px 12px;
        border-bottom: 1px solid var(--border);
        color: var(--text);
        vertical-align: top;
    }
    .content tr:last-child td { border-bottom: none; }

    /* IOC table cells */
    .ioc-type {
        font-weight: 700;
        font-size: 9pt;
        color: var(--text-muted);
        text-transform: uppercase;
        width: 20%;
    }
    .ioc-value {
        font-family: 'Roboto Mono', Consolas, monospace;
        font-size: 10pt;
        word-break: break-all;
    }
    .no-data {
        color: var(--text-muted);
        font-style: italic;
    }

    /* Evidence / Findings */
    .finding-item {
        margin-bottom: 14px;
        padding-bottom: 12px;
        border-bottom: 1px dashed #d1d5db;
    }
    .finding-item:last-child { border-bottom: none; }
    .finding-title {
        font-weight: 700;
        color: var(--primary);
        font-size: 10.5pt;
        margin-bottom: 4px;
    }
    .finding-desc {
        color: var(--text-secondary);
        font-size: 10pt;
        line-height: 1.6;
        padding-left: 12px;
    }

    /* Conclusion box */
    .conclusion-box {
        background: var(--bg-light);
        border: 1px solid var(--border);
        padding: 16px 20px;
        border-radius: 3px;
    }

    /* Page breaks */
    .page-break { page-break-before: always; }

    /* Footer */
    .footer {
        margin-top: 44px;
        padding-top: 16px;
        border-top: 1px solid #d1d5db;
        font-size: 10px;
        color: #9ca3af;
        text-align: center;
        letter-spacing: 0.02em;
    }

    /* Print overrides */
    @media print {
        body { background: white; padding: 0; }
        .page {
            box-shadow: none;
            max-width: 100%;
            padding: 15mm;
        }
        .no-print { display: none !important; }
        a { text-decoration: none; color: black; }
    }
    '''


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
