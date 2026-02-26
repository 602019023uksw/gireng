"""Enhanced HTML report generation matching professional template format."""

import logging
import re
from datetime import datetime, timezone
from html import escape
from typing import Any, Dict, List

from ghidra_agent.function_priority import is_library_function
from ghidra_agent.ioc_extractor import IOCs, calculate_verdict, extract_iocs_from_state

logger = logging.getLogger(__name__)

# Maximum number of entry points to display in the report
_MAX_ENTRY_POINTS = 5

# Regex to detect Java-style toString() output (e.g. "ghidra.program.database.ProgramCompilerSpec@33c6625c")
_JAVA_TOSTRING_RE = re.compile(r'^[\w.]+@[0-9a-fA-F]+$')


def _sanitize_compiler(raw: str) -> str:
    """Clean up a compiler string, replacing Java toString leaks with the class's simple name."""
    if not raw or raw == 'unknown':
        return raw
    s = str(raw)
    if _JAVA_TOSTRING_RE.match(s):
        # Extract just the simple class name from e.g. "ghidra.program.database.ProgramCompilerSpec@33c6625c"
        class_part = s.split('@')[0].rsplit('.', 1)[-1]
        return class_part
    return s


def _format_entry_points(entry_points: list, limit: int = _MAX_ENTRY_POINTS) -> str:
    """Format entry points list, capping output and indicating overflow."""
    if not entry_points:
        return 'unknown'
    shown = entry_points[:limit]
    result = ', '.join(str(e) for e in shown)
    if len(entry_points) > limit:
        result += f' … (+{len(entry_points) - limit} more)'
    return result


_MAX_IMPORT_EXPORT = 15  # Max imports/exports to show inline


def _clean_import_name(name: str) -> str:
    """Strip Ghidra's ``<EXTERNAL>::`` prefix from import names."""
    if name.startswith("<EXTERNAL>::"):
        return name[len("<EXTERNAL>::"):]
    return name


def _format_import_export_list(items: list, limit: int = _MAX_IMPORT_EXPORT) -> str:
    """Format an imports/exports list, cleaning noise and capping length."""
    if not items:
        return 'N/A'
    cleaned = [_clean_import_name(str(i)) for i in items]
    shown = cleaned[:limit]
    result = ', '.join(shown)
    if len(cleaned) > limit:
        result += f' … (+{len(cleaned) - limit} more)'
    return result


def _extract_section(text: str, section_name: str) -> str:
    """Extract a section from markdown text using a robust split-based approach."""
    if not text:
        return ""

    # Normalize line endings
    text = text.replace('\r\n', '\n').replace('\r', '\n')

    # Find all markdown headers (## or ###) with their positions
    header_pattern = re.compile(r'^(#{2,3})\s+(.*?)$', re.MULTILINE)
    headers = list(header_pattern.finditer(text))

    if not headers:
        logger.warning("extract_section: no markdown headers found in text (%d chars)", len(text))
        return ""

    target = section_name.lower().strip()

    for i, hdr in enumerate(headers):
        header_text = hdr.group(2).strip()
        # Strip leading number like "1." or "9."
        clean = re.sub(r'^\d+\.?\s*', '', header_text).strip()

        if clean.lower() == target:
            # Extract content from end of header line to start of next header
            start = hdr.end()
            end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
            content = text[start:end].strip()
            logger.info("extract_section: found '%s' (%d chars content)", section_name, len(content))
            return content

    # Fallback: substring match (e.g. "Evidence of Malicious Activity" in "Evidence of Malicious Activity and Threats")
    for i, hdr in enumerate(headers):
        header_text = hdr.group(2).strip()
        clean = re.sub(r'^\d+\.?\s*', '', header_text).strip()

        if target in clean.lower() or clean.lower() in target:
            start = hdr.end()
            end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
            content = text[start:end].strip()
            logger.info("extract_section: fuzzy matched '%s' via header '%s' (%d chars)",
                        section_name, header_text, len(content))
            return content

    logger.warning("extract_section: section '%s' not found. Available headers: %s",
                   section_name, [h.group(2).strip() for h in headers])
    return ""


def _markdown_to_html(text: str) -> str:
    """Convert markdown to HTML for template rendering."""
    if not text:
        return "<p>No information available.</p>"

    # Escape HTML first
    text = escape(text)

    # Extract code blocks first to protect their content from formatting
    code_blocks = []
    def _save_code_block(m):
        code_blocks.append(m.group(2))
        return f'\x00CODEBLOCK{len(code_blocks) - 1}\x00'
    text = re.sub(r'```(\w+)?\n(.*?)```', _save_code_block, text, flags=re.DOTALL)

    # Extract inline code to protect from formatting
    inline_codes = []
    def _save_inline_code(m):
        inline_codes.append(m.group(1))
        return f'\x00INLINE{len(inline_codes) - 1}\x00'
    text = re.sub(r'`(.+?)`', _save_inline_code, text)

    # Headers
    text = re.sub(r'####\s+(.+)$', r'<h4>\1</h4>', text, flags=re.MULTILINE)
    text = re.sub(r'###\s+(.+)$', r'<h3>\1</h3>', text, flags=re.MULTILINE)
    text = re.sub(r'##\s+(.+)$', r'<h2>\1</h2>', text, flags=re.MULTILINE)

    # Bold and italic
    text = re.sub(r'\*\*\*(.+?)\*\*\*', r'<strong><em>\1</em></strong>', text)
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)

    # Tables — skip lines inside <pre><code> blocks
    lines = text.split('\n')
    result = []
    i = 0
    in_table = False
    in_pre_block = False
    table_html = []

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if '<pre>' in stripped or '<pre ' in stripped:
            in_pre_block = True
        if '</pre>' in stripped:
            in_pre_block = False

        if not in_pre_block and '|' in line and not stripped.startswith('#') and not stripped.startswith('<'):
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

    # Ordered (numbered) lists: 1. text, 2. text, etc.
    lines = text.split('\n')
    result = []
    in_ol = False

    for line in lines:
        stripped = line.strip()
        m = re.match(r'^(\d+)\.\s+(.+)', stripped)
        if m and not stripped.startswith('<'):
            if not in_ol:
                result.append('<ol class="list-decimal pl-6 mb-4">')
                in_ol = True
            result.append(f'<li class="mb-2">{m.group(2)}</li>')
        else:
            if in_ol and stripped and not stripped.startswith('<'):
                result.append('</ol>')
                in_ol = False
            result.append(line)

    if in_ol:
        result.append('</ol>')

    text = '\n'.join(result)

    # Paragraphs — skip lines inside <pre><code> blocks and placeholder lines
    lines = text.split('\n')
    result = []
    in_pre = False
    for line in lines:
        stripped = line.strip()
        if '<pre>' in stripped or '<pre ' in stripped:
            in_pre = True
        if '</pre>' in stripped:
            in_pre = False
            result.append(line)
            continue
        if in_pre:
            result.append(line)
            continue
        if stripped and not stripped.startswith('<') and not stripped.startswith('|') and '\x00CODEBLOCK' not in stripped:
            result.append(f'<p class="mb-3">{stripped}</p>')
        else:
            result.append(line)

    text = '\n'.join(result)

    # Restore code blocks and inline code from placeholders
    for i, block in enumerate(code_blocks):
        text = text.replace(f'\x00CODEBLOCK{i}\x00', f'<pre><code>{block}</code></pre>')
    for i, code in enumerate(inline_codes):
        text = text.replace(f'\x00INLINE{i}\x00', f'<code>{code}</code>')

    return text


def _parse_iocs_for_template(iocs: IOCs) -> List[Dict[str, str]]:
    """Parse IOCs into template format — include ALL IOCs without truncation."""
    results = []

    for ip in iocs.ips:
        results.append({"type": "IP/Domain", "value": ip})
    for domain in iocs.domains:
        results.append({"type": "Domain", "value": domain})
    for url in iocs.urls:
        results.append({"type": "URL", "value": url})
    for path in iocs.file_paths:
        results.append({"type": "File Path", "value": path})
    for email in iocs.emails:
        results.append({"type": "Email", "value": email})
    for reg in iocs.registry_keys:
        results.append({"type": "Registry", "value": reg})
    for mutex in iocs.mutexes:
        results.append({"type": "Mutex", "value": mutex})

    return results


def _extract_recommendations(summary: str) -> List[str]:
    """Extract recommendations from the Recommendations section only."""
    # First, extract the Recommendations section from the summary
    rec_section = _extract_section(summary, "Recommendations")
    if not rec_section:
        logger.warning("extract_recommendations: section not found, using defaults")
        return ["Conduct dynamic analysis in sandbox environment", "Monitor network traffic for C2 communications"]

    logger.info("extract_recommendations: section found (%d chars)", len(rec_section))
    recs = []
    # Try numbered items: 1. xxx  2. xxx
    numbered = re.findall(r'\d+\.\s*\*\*(.+?)\*\*[:\s]*(.+?)(?=\d+\.\s*\*\*|$)', rec_section, re.DOTALL)
    if numbered:
        for title, desc in numbered:
            cleaned = f"{title.strip()}: {desc.strip()}"
            if len(cleaned) > 10:
                recs.append(cleaned)
    else:
        # Try bullet items
        bullets = re.findall(r'[-*]\s+\*\*(.+?)\*\*[:\s]*(.+?)(?=[-*]\s+\*\*|$)', rec_section, re.DOTALL)
        if bullets:
            for title, desc in bullets:
                cleaned = f"{title.strip()}: {desc.strip()}"
                if len(cleaned) > 10:
                    recs.append(cleaned)
        else:
            # Fallback: plain numbered or bullet lines
            for line in rec_section.split('\n'):
                line = line.strip()
                line = re.sub(r'^[\d.\-*]+\s*', '', line).strip()
                if line and len(line) > 10:
                    recs.append(line)

    return recs if recs else ["Conduct dynamic analysis in sandbox environment", "Monitor network traffic for C2 communications"]


def _extract_evidence(summary: str) -> List[str]:
    """Extract evidence items from the Evidence section."""
    evidence = []
    # Try to extract the specific section
    ev_section = _extract_section(summary, "Evidence of Malicious Activity")
    if not ev_section:
        ev_section = _extract_section(summary, "Evidence")
    if not ev_section:
        # Fallback patterns
        match = re.search(r'Evidence:\s*\n((?:(?:.+\n)+))', summary, re.IGNORECASE)
        if not match:
            match = re.search(r'Key Evidence:\s*\n((?:(?:.+\n)+))', summary, re.IGNORECASE)
        if match:
            ev_section = match.group(1)

    if ev_section:
        # Pattern: N. **Finding**: Description - Evidence: details
        findings = re.findall(r'\*\*Finding\*\*[:\s]*(.+?)(?=\d+\.\s*\*\*Finding|$)', ev_section, re.DOTALL)
        if findings:
            for f in findings:
                cleaned = f.strip().rstrip('.')
                if cleaned and len(cleaned) > 5:
                    evidence.append(cleaned)
        else:
            for line in ev_section.split('\n'):
                line = line.strip()
                if line and (line.startswith('-') or line.startswith('*') or re.match(r'\d+\.', line)):
                    cleaned = re.sub(r'^[-*\d.\s]+', '', line).strip()
                    if cleaned and len(cleaned) > 5:
                        evidence.append(cleaned)
    return evidence


# Icon/color cycle for recommendation cards
_REC_STYLES = [
    ("fas fa-shield-alt", "blue"),
    ("fas fa-search", "purple"),
    ("fas fa-ban", "red"),
    ("fas fa-file-invoice", "green"),
    ("fas fa-network-wired", "orange"),
    ("fas fa-user-secret", "cyan"),
]


def _render_evidence(evidence: List[str]) -> str:
    """Render evidence items as compact horizontal cards (revamp template style)."""
    if not evidence:
        return '<p class="text-sm text-slate-500 italic">Evidence extracted from analysis data. Review summary for details.</p>'

    parts = ['<div class="space-y-3">']
    for i, item in enumerate(evidence, 1):
        # Split on " - Evidence:" if present
        chunks = item.split(' - Evidence:', 1)
        if len(chunks) == 2:
            title = chunks[0].strip()
            desc = chunks[1].strip()
        else:
            # Try to grab first sentence as title
            raw = item.strip()
            dot = raw.find('.')
            if 0 < dot < 80:
                title = raw[:dot]
                desc = raw[dot + 1:].strip()
            else:
                title = raw[:80]
                desc = raw[80:].strip() if len(raw) > 80 else ''

        circle_bg = 'bg-red-100 dark:bg-red-900/30' if i <= 3 else 'bg-orange-100 dark:bg-orange-900/30'
        circle_txt = 'text-red-600 dark:text-red-400' if i <= 3 else 'text-orange-600 dark:text-orange-400'

        desc_html = f'<p class="text-xs text-slate-500 dark:text-slate-400 mt-1 leading-relaxed">{escape(desc)}</p>' if desc else ''
        parts.append(
            f'<div class="evidence-compact bg-white dark:bg-slate-800 p-4 rounded shadow-sm flex items-start gap-4">'
            f'<span class="flex-shrink-0 w-6 h-6 rounded-full {circle_bg} {circle_txt} flex items-center justify-center text-xs font-bold">{i}</span>'
            f'<div class="flex-1">'
            f'<div class="font-bold text-slate-900 dark:text-white text-sm">{escape(title)}</div>'
            f'{desc_html}'
            f'</div></div>'
        )
    parts.append('</div>')
    return '\n'.join(parts)


def _render_recommendations(recommendations: List[str]) -> str:
    """Render recommendations as styled cards in a 2-column grid."""
    if not recommendations:
        return '<p class="text-sm text-slate-500 italic">No specific recommendations available.</p>'

    cards: List[str] = []
    for i, rec in enumerate(recommendations):
        icon, color = _REC_STYLES[i % len(_REC_STYLES)]
        safe = escape(rec)
        safe = re.sub(r'\*\*(.+?)\*\*', r'\1', safe)
        safe = re.sub(r'\s*#{2,3}\s*$', '', safe).strip()

        if ':' in safe:
            title, desc = safe.split(':', 1)
            title, desc = title.strip(), desc.strip()
        else:
            title = f'Recommendation {i + 1}'
            desc = safe

        col_span = ' md:col-span-2' if (i == len(recommendations) - 1 and len(recommendations) % 2 == 1 and len(recommendations) > 1) else ''
        cards.append(
            f'<div class="rec-card bg-white dark:bg-slate-800 p-5 rounded-lg shadow-sm{col_span}">'
            f'<div class="flex items-start gap-3">'
            f'<div class="w-8 h-8 rounded-lg bg-{color}-100 dark:bg-{color}-900/30 text-{color}-600 dark:text-{color}-400 flex items-center justify-center flex-shrink-0">'
            f'<i class="{icon}"></i></div>'
            f'<div><h4 class="font-bold text-slate-900 dark:text-white mb-1 text-sm">{title}</h4>'
            f'<p class="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">{desc}</p>'
            f'</div></div></div>'
        )
    joined = "\n".join(cards)
    return f'<div class="grid grid-cols-1 md:grid-cols-2 gap-4">{joined}</div>'


# ---------------------------------------------------------------------------
# Section-specific renderers (card-based layouts)
# ---------------------------------------------------------------------------

# Icon/color cycle for capability cards
_CAP_ICONS = [
    ("fas fa-server", "red"),
    ("fas fa-network-wired", "blue"),
    ("fas fa-terminal", "purple"),
    ("fas fa-eye", "orange"),
    ("fas fa-key", "green"),
    ("fas fa-bug", "pink"),
    ("fas fa-bolt", "cyan"),
    ("fas fa-shield-virus", "yellow"),
]

# Icon/color cycle for technical analysis cards
_TECH_ICONS = [
    ("fas fa-satellite-dish", "blue"),
    ("fas fa-code", "purple"),
    ("fas fa-lock", "red"),
    ("fas fa-terminal", "green"),
    ("fas fa-database", "orange"),
    ("fas fa-microchip", "cyan"),
    ("fas fa-shield-virus", "pink"),
    ("fas fa-cogs", "slate"),
]


def _inline_code_html(text: str) -> str:
    """Escape text and convert backtick-wrapped spans to styled <code> tags."""
    s = escape(text)
    s = re.sub(
        r'`(.+?)`',
        r'<code class="bg-slate-100 dark:bg-slate-800 text-red-600 dark:text-red-400 px-1 py-0.5 rounded text-xs font-mono">\1</code>',
        s,
    )
    s = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', s)
    return s


def _render_capabilities_cards(md_text: str) -> str:
    """Render Malware Capabilities as a 2-col grid of icon cards with evidence boxes."""
    if not md_text:
        return '<p class="text-slate-500 italic">Capabilities analysis not available.</p>'

    # Parse bullets: - **Title**: ... / sub-bullets with Evidence
    # Split on top-level bullets that have a bold title
    raw_blocks: List[str] = []
    current: List[str] = []
    for line in md_text.split('\n'):
        stripped = line.strip()
        if re.match(r'^[-*]\s+\*\*', stripped):
            if current:
                raw_blocks.append('\n'.join(current))
            current = [stripped]
        else:
            current.append(line)
    if current:
        raw_blocks.append('\n'.join(current))

    if not raw_blocks or not re.match(r'^[-*]\s+\*\*', raw_blocks[0].strip()):
        return _markdown_to_html(md_text)

    cards: List[str] = []
    for idx, block in enumerate(raw_blocks):
        block = block.strip()
        if not block:
            continue
        # Title line
        title_m = re.match(r'^[-*]\s+\*\*(.+?)\*\*[:\s]*(.*)', block, re.DOTALL)
        if not title_m:
            continue
        title = escape(title_m.group(1).strip())
        rest = title_m.group(2).strip()

        # Gather evidence and description lines
        evidence_lines: List[str] = []
        desc_lines: List[str] = []
        for line in rest.split('\n'):
            line = line.strip()
            ev_m = re.match(r'^[-*]\s+\*\*Evidence\*\*[:\s]*(.*)', line)
            if ev_m:
                evidence_lines.append(ev_m.group(1).strip())
                continue
            ev_m2 = re.match(r'^Evidence[:\s]+(.*)', line, re.IGNORECASE)
            if ev_m2:
                evidence_lines.append(ev_m2.group(1).strip())
                continue
            cleaned = re.sub(r'^[-*]\s+', '', line).strip()
            if cleaned:
                desc_lines.append(cleaned)

        icon, color = _CAP_ICONS[idx % len(_CAP_ICONS)]

        # Evidence box
        evidence_html = ''
        if evidence_lines:
            ev_items = ''.join(
                '<div>' + _inline_code_html(ev) + '</div>'
                for ev in evidence_lines
            )
            evidence_html = (
                '<div class="mt-3 bg-slate-50 dark:bg-slate-900/50 rounded-lg p-3 border border-slate-200 dark:border-slate-700">'
                '<div class="text-[10px] font-bold text-slate-400 dark:text-slate-500 mb-1 uppercase tracking-widest">Evidence</div>'
                '<div class="text-xs text-slate-700 dark:text-slate-300 font-mono leading-relaxed space-y-1">'
                + ev_items + '</div></div>'
            )

        desc_html = ''
        if desc_lines:
            joined_desc = '<br>'.join(escape(d) for d in desc_lines)
            desc_html = f'<p class="text-xs text-slate-500 dark:text-slate-400 mt-1.5 leading-relaxed">{joined_desc}</p>'

        cards.append(
            f'<div class="capability-card bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-5 '
            f'hover:shadow-lg hover:border-{color}-400 dark:hover:border-{color}-600 transition-all duration-200">'
            f'<div class="flex items-start gap-3">'
            f'<div class="w-9 h-9 rounded-lg bg-{color}-100 dark:bg-{color}-900/30 text-{color}-500 dark:text-{color}-400 '
            f'flex items-center justify-center flex-shrink-0 text-sm"><i class="{icon}"></i></div>'
            f'<div class="flex-1 min-w-0">'
            f'<h4 class="font-bold text-slate-900 dark:text-white text-sm leading-snug">{title}</h4>'
            f'{desc_html}{evidence_html}'
            f'</div></div></div>'
        )

    if not cards:
        return _markdown_to_html(md_text)

    joined = "\n".join(cards)
    return f'<div class="grid grid-cols-1 md:grid-cols-2 gap-4">{joined}</div>'


def _render_technical_cards(md_text: str) -> str:
    """Render Technical Analysis sub-sections as stacked cards with code blocks."""
    if not md_text:
        return '<p class="text-slate-500 italic">Technical analysis not available.</p>'

    # Protect code blocks first
    code_blocks: List[tuple] = []

    def _save_code(m):
        code_blocks.append((m.group(1) or 'c', m.group(2)))
        return f'\x00TCODE{len(code_blocks) - 1}\x00'

    protected = re.sub(r'```(\w+)?\n(.*?)```', _save_code, md_text, flags=re.DOTALL)

    # Split on **bold headings** at the start of a line
    parts = re.split(r'(?m)^(\*\*[^*\n]+\*\*)', protected)

    # parts = [preamble, heading1, body1, heading2, body2, ...]
    sections: List[tuple] = []  # (title, body)
    preamble = ''
    i = 0
    while i < len(parts):
        p = parts[i].strip()
        if p.startswith('**') and p.endswith('**'):
            title = p.strip('*').strip()
            body = parts[i + 1] if i + 1 < len(parts) else ''
            sections.append((title, body.strip()))
            i += 2
        else:
            if p:
                preamble = p
            i += 1

    if not sections:
        return _markdown_to_html(md_text)

    cards: List[str] = []

    # Preamble text (if any)
    if preamble:
        cards.append(f'<div class="text-sm text-slate-600 dark:text-slate-400 mb-2 leading-relaxed">{_inline_code_html(preamble)}</div>')

    sec_idx = 0
    skip_next = False
    for j, (title, body) in enumerate(sections):
        if skip_next:
            skip_next = False
            continue

        # Skip "Code Evidence" sub-headers — fold them into previous card
        if title.lower().startswith('code evidence'):
            continue

        icon, color = _TECH_ICONS[sec_idx % len(_TECH_ICONS)]
        sec_idx += 1

        # Check if next section is a "Code Evidence" block and merge
        merged_body = body
        if j + 1 < len(sections) and sections[j + 1][0].lower().startswith('code evidence'):
            merged_body = body + '\n' + sections[j + 1][1]
            skip_next = True

        # Build body HTML
        body_parts: List[str] = []
        for line in merged_body.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue
            code_m = re.match(r'\x00TCODE(\d+)\x00', stripped)
            if code_m:
                ci = int(code_m.group(1))
                lang, code = code_blocks[ci]
                body_parts.append(
                    '<div class="mt-3 bg-slate-900 rounded-lg overflow-hidden">'
                    f'<div class="px-3 py-1.5 bg-slate-800 border-b border-slate-700 text-[10px] text-slate-400 font-mono uppercase tracking-wider">{escape(lang)}</div>'
                    f'<pre class="p-3 text-xs text-slate-300 font-mono leading-relaxed overflow-x-auto whitespace-pre-wrap"><code>{escape(code)}</code></pre></div>'
                )
            elif stripped.startswith('- ') or stripped.startswith('* '):
                body_parts.append(f'<div class="flex items-start gap-2 text-sm text-slate-600 dark:text-slate-400">'
                                  f'<span class="text-slate-400 mt-0.5">&bull;</span><span>{_inline_code_html(stripped[2:])}</span></div>')
            else:
                body_parts.append(f'<p class="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">{_inline_code_html(stripped)}</p>')

        inner = "\n".join(body_parts)
        cards.append(
            f'<div class="tech-card bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden '
            f'hover:shadow-lg hover:border-{color}-400 dark:hover:border-{color}-600 transition-all duration-200">'
            f'<div class="flex items-center gap-3 px-5 py-3 bg-slate-50 dark:bg-slate-800/80 border-b border-slate-200 dark:border-slate-700">'
            f'<div class="w-7 h-7 rounded-lg bg-{color}-100 dark:bg-{color}-900/30 text-{color}-500 dark:text-{color}-400 '
            f'flex items-center justify-center flex-shrink-0 text-xs"><i class="{icon}"></i></div>'
            f'<h3 class="font-bold text-slate-900 dark:text-white text-sm">{_inline_code_html(title)}</h3></div>'
            f'<div class="p-5 space-y-2">{inner}</div></div>'
        )

    if not cards:
        return _markdown_to_html(md_text)

    joined = "\n".join(cards)
    return f'<div class="space-y-4">{joined}</div>'


def _render_functions_cards(md_text: str) -> str:
    """Render Functions Analysis as cards with nested code boxes."""
    if not md_text:
        return '<p class="text-slate-500 italic">Functions analysis not available.</p>'

    # Protect code blocks
    code_blocks: List[tuple] = []

    def _save_code(m):
        code_blocks.append((m.group(1) or 'c', m.group(2)))
        return f'\x00FCODE{len(code_blocks) - 1}\x00'

    protected = re.sub(r'```(\w+)?\n(.*?)```', _save_code, md_text, flags=re.DOTALL)

    # Split on function headers: **FunctionName @ 0xADDR (N xrefs)**
    # or **FunctionName** at the start of a line
    parts = re.split(r'(?m)^(\*\*[^*\n]+\*\*)', protected)

    sections: List[tuple] = []
    i = 0
    while i < len(parts):
        p = parts[i].strip()
        if p.startswith('**') and p.endswith('**'):
            title = p.strip('*').strip()
            body = parts[i + 1] if i + 1 < len(parts) else ''
            sections.append((title, body.strip()))
            i += 2
        else:
            i += 1

    if not sections:
        return _markdown_to_html(md_text)

    cards: List[str] = []
    for idx, (title, body) in enumerate(sections):
        # Parse title: "FunctionName @ 0xADDR (N xrefs)" or just "FunctionName"
        addr_m = re.match(r'(.+?)\s*@\s*(0x[\da-fA-F]+)(?:\s*\((.+?)\))?', title)
        if addr_m:
            fname = addr_m.group(1).strip()
            faddr = addr_m.group(2).strip()
            fxrefs = addr_m.group(3).strip() if addr_m.group(3) else ''
        else:
            fname = title
            faddr = ''
            fxrefs = ''

        # Parse body: Purpose, Malicious, Key Code Evidence
        purpose = ''
        malicious = ''
        is_malicious = False
        body_lines: List[str] = []
        code_html: List[str] = []

        for line in body.split('\n'):
            stripped = line.strip()
            if not stripped:
                continue
            code_m = re.match(r'\x00FCODE(\d+)\x00', stripped)
            if code_m:
                ci = int(code_m.group(1))
                lang, code = code_blocks[ci]
                code_html.append(
                    '<div class="mt-3 bg-slate-900 rounded-lg overflow-hidden border border-slate-700">'
                    f'<div class="px-3 py-1 bg-slate-800 border-b border-slate-700 text-[10px] text-slate-500 font-mono uppercase tracking-wider">{escape(lang)}</div>'
                    f'<pre class="p-3 text-xs text-slate-300 font-mono leading-relaxed overflow-x-auto whitespace-pre-wrap"><code>{escape(code)}</code></pre></div>'
                )
                continue
            # Check for Purpose line
            purp_m = re.match(r'^[-*]\s+\*\*Purpose\*\*[:\s]*(.*)', stripped)
            if purp_m:
                purpose = purp_m.group(1).strip()
                continue
            mal_m = re.match(r'^[-*]\s+\*\*Malicious(?:/Interesting)?\*\*[:\s]*(.*)', stripped)
            if mal_m:
                malicious = mal_m.group(1).strip()
                if re.match(r'^yes', malicious, re.IGNORECASE):
                    is_malicious = True
                continue
            # Skip "Key Code Evidence:" header
            if stripped.lower().startswith('- **key code') or stripped.lower().startswith('**key code'):
                continue
            body_lines.append(stripped)

        # Card border color
        border_cls = 'border-red-300 dark:border-red-700' if is_malicious else 'border-slate-200 dark:border-slate-700'
        badge_cls = ('bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400', 'Malicious') if is_malicious else ('bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400', 'Clean')

        # Header badges
        addr_badge = f'<span class="text-xs font-mono text-slate-500 bg-slate-100 dark:bg-slate-700 px-2 py-0.5 rounded">{escape(faddr)}</span>' if faddr else ''
        xref_badge = f'<span class="text-xs text-slate-500 bg-slate-100 dark:bg-slate-700 px-2 py-0.5 rounded">{escape(fxrefs)}</span>' if fxrefs else ''
        mal_badge = f'<span class="text-[10px] font-bold px-2 py-0.5 rounded-full {badge_cls[0]} uppercase">{badge_cls[1]}</span>'

        # Purpose row
        purpose_html = ''
        if purpose:
            purpose_html = (
                '<div class="flex items-start gap-2 text-sm">'
                '<span class="text-xs font-bold text-slate-400 dark:text-slate-500 uppercase w-16 flex-shrink-0 mt-0.5">Purpose</span>'
                f'<span class="text-slate-700 dark:text-slate-300">{_inline_code_html(purpose)}</span></div>'
            )

        malicious_html = ''
        if malicious:
            malicious_html = (
                '<div class="flex items-start gap-2 text-sm">'
                '<span class="text-xs font-bold text-slate-400 dark:text-slate-500 uppercase w-16 flex-shrink-0 mt-0.5">Status</span>'
                f'<span class="text-slate-700 dark:text-slate-300">{_inline_code_html(malicious)}</span></div>'
            )

        extra_lines = ''
        if body_lines:
            extras = ''.join(f'<p class="text-xs text-slate-500 dark:text-slate-400">{_inline_code_html(bl)}</p>' for bl in body_lines)
            extra_lines = f'<div class="mt-2 space-y-1">{extras}</div>'

        code_block_html = "\n".join(code_html) if code_html else ''

        cards.append(
            f'<div class="func-card bg-white dark:bg-slate-800 rounded-xl border-2 {border_cls} overflow-hidden '
            f'hover:shadow-lg transition-all duration-200">'
            f'<div class="px-5 py-3 bg-slate-50 dark:bg-slate-800/80 border-b border-slate-200 dark:border-slate-700 '
            f'flex flex-wrap items-center gap-2">'
            f'<i class="fas fa-cube text-xs text-slate-400"></i>'
            f'<span class="font-bold text-slate-900 dark:text-white text-sm font-mono">{escape(fname)}</span>'
            f'{addr_badge}{xref_badge}{mal_badge}</div>'
            f'<div class="p-5 space-y-2">'
            f'{purpose_html}{malicious_html}{extra_lines}{code_block_html}'
            f'</div></div>'
        )

    if not cards:
        return _markdown_to_html(md_text)

    joined = "\n".join(cards)
    return f'<div class="space-y-4">{joined}</div>'


def _render_evidence_cards(evidence_items: List[str], md_text: str) -> str:
    """Render Evidence of Malicious Activity as severity-colored cards."""
    if not evidence_items and not md_text:
        return '<p class="text-sm text-slate-500 italic">No evidence of malicious activity identified.</p>'

    # Try structured evidence items first
    if evidence_items:
        cards: List[str] = []
        _ev_colors = [
            ("bg-red-500", "border-red-200 dark:border-red-800", "bg-red-50 dark:bg-red-900/10"),
            ("bg-orange-500", "border-orange-200 dark:border-orange-800", "bg-orange-50 dark:bg-orange-900/10"),
            ("bg-yellow-500", "border-yellow-200 dark:border-yellow-800", "bg-yellow-50 dark:bg-yellow-900/10"),
            ("bg-blue-500", "border-blue-200 dark:border-blue-800", "bg-blue-50 dark:bg-blue-900/10"),
            ("bg-purple-500", "border-purple-200 dark:border-purple-800", "bg-purple-50 dark:bg-purple-900/10"),
        ]
        for i, item in enumerate(evidence_items):
            dot_bg, border, card_bg = _ev_colors[i % len(_ev_colors)]

            # Split on common patterns
            parts = re.split(r'\s*[-—]\s*(?:Function|Evidence|Code)[:\s]', item, maxsplit=1)
            if len(parts) == 2:
                title_str = parts[0].strip()
                detail_str = parts[1].strip()
            else:
                s = item.strip()
                dot = s.find('.')
                if 0 < dot < 80:
                    title_str = s[:dot]
                    detail_str = s[dot + 1:].strip()
                else:
                    title_str = s[:100]
                    detail_str = s[100:].strip() if len(s) > 100 else ''

            detail_html = ''
            if detail_str:
                detail_html = (
                    f'<div class="mt-2 bg-slate-50 dark:bg-slate-900/50 rounded p-2.5 border border-slate-200 dark:border-slate-700">'
                    f'<div class="text-xs text-slate-600 dark:text-slate-400 font-mono leading-relaxed">{_inline_code_html(detail_str)}</div></div>'
                )

            cards.append(
                f'<div class="evidence-card {card_bg} border {border} rounded-xl p-4 hover:shadow-md transition-all duration-200">'
                f'<div class="flex items-start gap-3">'
                f'<div class="flex-shrink-0 mt-1"><div class="w-3 h-3 rounded-full {dot_bg} ring-2 ring-white dark:ring-slate-900 shadow-sm"></div></div>'
                f'<div class="flex-1 min-w-0">'
                f'<div class="font-semibold text-slate-900 dark:text-white text-sm">{_inline_code_html(title_str)}</div>'
                f'{detail_html}'
                f'</div>'
                f'<span class="flex-shrink-0 text-[10px] font-bold text-slate-400 bg-slate-100 dark:bg-slate-700 px-2 py-0.5 rounded-full">#{i + 1}</span>'
                f'</div></div>'
            )

        joined = "\n".join(cards)
        return f'<div class="space-y-3">{joined}</div>'

    # Fallback: use markdown text as evidence section
    if md_text:
        return _markdown_to_html(md_text)

    return '<p class="text-sm text-slate-500 italic">No evidence of malicious activity identified.</p>'


def _render_operational_flow(md_text: str) -> str:
    """Render Operational Flow as a vertical timeline with connected steps."""
    if not md_text:
        return '<p class="text-slate-500 italic">Operational flow analysis not available.</p>'

    # Parse numbered steps: 1. **Title**: Description — Evidence: ...
    steps: List[tuple] = []  # (title, desc, evidence)
    for line in md_text.split('\n'):
        stripped = line.strip()
        if not stripped:
            continue
        m = re.match(r'^(\d+)\.\s+\*\*(.+?)\*\*[:\s]*(.*)', stripped)
        if m:
            title = m.group(2).strip()
            rest = m.group(3).strip()
            # Split evidence from description
            ev_split = re.split(r'\s*[-—]\s*Evidence[:\s]*', rest, maxsplit=1)
            if len(ev_split) == 2:
                desc = ev_split[0].strip()
                evidence = ev_split[1].strip()
            else:
                desc = rest
                evidence = ''
            steps.append((title, desc, evidence))
        elif steps:
            # Continuation line — append to last step's description
            prev_title, prev_desc, prev_ev = steps[-1]
            cleaned = re.sub(r'^[-*]\s+', '', stripped).strip()
            if cleaned:
                steps[-1] = (prev_title, prev_desc + ' ' + cleaned, prev_ev)

    if not steps:
        # Fallback: try bullet format
        for line in md_text.split('\n'):
            stripped = line.strip()
            m = re.match(r'^[-*]\s+\*\*(.+?)\*\*[:\s]*(.*)', stripped)
            if m:
                title = m.group(1).strip()
                rest = m.group(2).strip()
                ev_split = re.split(r'\s*[-—]\s*Evidence[:\s]*', rest, maxsplit=1)
                if len(ev_split) == 2:
                    steps.append((title, ev_split[0].strip(), ev_split[1].strip()))
                else:
                    steps.append((title, rest, ''))

    if not steps:
        return _markdown_to_html(md_text)

    _flow_colors = ['red', 'orange', 'yellow', 'blue', 'purple', 'green', 'cyan', 'pink']

    items: List[str] = []
    for idx, (title, desc, evidence) in enumerate(steps):
        color = _flow_colors[idx % len(_flow_colors)]
        is_last = idx == len(steps) - 1

        # Timeline connector
        connector = '' if is_last else (
            f'<div class="absolute left-[18px] top-10 bottom-0 w-0.5 bg-slate-200 dark:bg-slate-700"></div>'
        )

        ev_html = ''
        if evidence:
            ev_html = (
                f'<div class="mt-2 flex items-start gap-1.5 text-xs text-slate-500 dark:text-slate-400">'
                f'<i class="fas fa-fingerprint text-[10px] mt-0.5 text-slate-400"></i>'
                f'<span class="font-mono">{_inline_code_html(evidence)}</span></div>'
            )

        items.append(
            f'<div class="relative pl-12">'
            f'{connector}'
            f'<div class="absolute left-0 top-0 w-9 h-9 rounded-full bg-{color}-100 dark:bg-{color}-900/30 '
            f'border-2 border-{color}-400 dark:border-{color}-600 flex items-center justify-center '
            f'text-xs font-bold text-{color}-600 dark:text-{color}-400 z-10">{idx + 1}</div>'
            f'<div class="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-4 '
            f'hover:shadow-md hover:border-{color}-300 dark:hover:border-{color}-700 transition-all duration-200">'
            f'<h4 class="font-bold text-slate-900 dark:text-white text-sm">{escape(title)}</h4>'
            f'<p class="text-sm text-slate-600 dark:text-slate-400 mt-1 leading-relaxed">{_inline_code_html(desc)}</p>'
            f'{ev_html}'
            f'</div></div>'
        )

    joined = "\n".join(items)
    return f'<div class="space-y-6">{joined}</div>'


def _render_iocs(iocs: List[Dict[str, str]]) -> str:
    """Render IOCs as table rows with copy-to-clipboard buttons."""
    if not iocs:
        return '<tr><td colspan="3" class="px-6 py-3 text-slate-500 italic">No IOCs extracted.</td></tr>'
    rows: List[str] = []
    for ioc in iocs:
        ioc_type = escape(ioc['type'])
        ioc_value = escape(ioc['value'])
        js_val = ioc['value'].replace('\\', '\\\\').replace("'", "\\'")
        rows.append(
            f'<tr class="hover:bg-slate-50 dark:hover:bg-slate-800/50 group">'
            f'<td class="px-6 py-3 font-semibold text-slate-600 dark:text-slate-400 w-1/4">{ioc_type}</td>'
            f'<td class="px-6 py-3 font-mono text-xs break-all">{ioc_value}</td>'
            f'<td class="w-10 no-print"><button onclick="copyToClipboard(\'{js_val}\')" '
            f'class="opacity-0 group-hover:opacity-100 text-slate-400 hover:text-red-600 px-3">'
            f'<i class="fas fa-copy"></i></button></td></tr>'
        )
    return '\n'.join(rows)


def _deduplicate_chains(chains: List[Dict[str, Any]], limit: int = 15) -> List[Dict[str, Any]]:
    """Remove attack chains that are strict sub-paths of longer chains.

    If chain A's path is a prefix of chain B's path within the same category,
    keep only B (the longer, more informative chain).  Then cap at *limit*.
    """
    if not chains:
        return []

    # Group by category
    by_cat: Dict[str, List[List[str]]] = {}
    for c in chains:
        cat = c.get("category", "Unknown")
        path = [str(p) for p in c.get("path", [])]
        by_cat.setdefault(cat, []).append(path)

    # For each category, remove sub-paths
    kept: List[Dict[str, Any]] = []
    for cat, paths in by_cat.items():
        # Sort by length descending so longer chains come first
        paths.sort(key=len, reverse=True)
        unique: List[List[str]] = []
        for path in paths:
            # Is this path a prefix of an already-kept (longer) path?
            is_subpath = False
            for existing in unique:
                if len(path) < len(existing) and existing[:len(path)] == path:
                    is_subpath = True
                    break
            if not is_subpath:
                unique.append(path)
        for path in unique:
            kept.append({"category": cat, "path": path})

    # Sort by category then path length for a clean presentation
    kept.sort(key=lambda c: (c["category"], len(c["path"])))
    return kept[:limit]


def _render_call_graph_section(source: str, analysis: Dict[str, Any]) -> str:
    """Render call-graph analysis as a styled card (revamp template).

    Returns one card div.  The caller wraps two cards in a grid.
    """
    icon_color = 'text-purple-500' if source == 'Ghidra' else 'text-blue-500'

    if not analysis or not analysis.get('ok'):
        return (
            f'<div class="bg-white dark:bg-slate-800 rounded-lg p-6 shadow-sm border border-slate-200 dark:border-slate-700">'
            f'<h3 class="font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-2">'
            f'<i class="fas fa-project-diagram {icon_color}"></i> {escape(source)} Analysis</h3>'
            f'<p class="text-sm text-slate-500 italic">Call graph data not available.</p></div>'
        )

    stats = analysis.get('stats', {})
    chains = analysis.get('chains', []) or []
    nodes = stats.get('nodes', 0)
    edges = stats.get('edges', 0)
    num_chains = len(chains)

    # Chain stat cell styling
    if num_chains > 0:
        chain_cell = 'bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800'
        chain_num_cls = ' text-red-600'
    else:
        chain_cell = 'bg-slate-50 dark:bg-slate-700/50'
        chain_num_cls = ''

    # Chain items
    if chains:
        deduped = _deduplicate_chains(chains)
        items: List[str] = []
        for chain in deduped[:5]:
            category = escape(str(chain.get('category', 'Unknown')))
            path = ' \u2192 '.join(escape(str(p)) for p in chain.get('path', []))
            cat_lower = category.lower()
            if any(k in cat_lower for k in ('execution', 'crypto', 'file')):
                cls = 'bg-red-50 dark:bg-red-900/10 text-red-800 dark:text-red-300'
            else:
                cls = 'bg-slate-50 dark:bg-slate-700/50 text-slate-600 dark:text-slate-400'
            items.append(f'<div class="{cls} p-2 rounded">[{category}] {path}</div>')
        chain_html = '<div class="space-y-1 text-xs font-mono">' + '\n'.join(items) + '</div>'
        if len(deduped) > 5:
            chain_html += f'<p class="text-xs text-slate-500 mt-2 italic">\u2026 and {len(deduped) - 5} more chains</p>'
    else:
        chain_html = '<p class="text-sm text-slate-500 italic">No sink-reaching attack chains detected.</p>'

    return (
        f'<div class="bg-white dark:bg-slate-800 rounded-lg p-6 shadow-sm border border-slate-200 dark:border-slate-700">'
        f'<h3 class="font-bold text-slate-900 dark:text-white mb-4 flex items-center gap-2">'
        f'<i class="fas fa-project-diagram {icon_color}"></i> {escape(source)} Analysis</h3>'
        f'<div class="grid grid-cols-3 gap-4 mb-4 text-center">'
        f'<div class="bg-slate-50 dark:bg-slate-700/50 p-3 rounded"><div class="text-xl font-bold">{nodes}</div><div class="text-xs text-slate-500">Nodes</div></div>'
        f'<div class="bg-slate-50 dark:bg-slate-700/50 p-3 rounded"><div class="text-xl font-bold">{edges}</div><div class="text-xs text-slate-500">Edges</div></div>'
        f'<div class="{chain_cell} p-3 rounded"><div class="text-xl font-bold{chain_num_cls}">{num_chains}</div><div class="text-xs text-slate-500">Chains</div></div>'
        f'</div>{chain_html}</div>'
    )


# ---------------------------------------------------------------------------
# Suspicious API patterns for code evidence section.
# Uses *word-boundary* matching (not substring) to avoid false positives.
# ---------------------------------------------------------------------------

# High-value APIs: always interesting in application code
_HIGH_VALUE_APIS = {
    "system", "popen", "pclose", "execve", "execv", "execl", "exec", "fork",
    "socket", "connect", "send", "sendto", "recv", "recvfrom", "bind", "listen", "accept",
    "fopen", "fwrite", "fread", "open", "write", "read", "unlink", "remove", "rename",
    "mmap", "mprotect", "ptrace", "dlopen", "dlsym",
    "gethostname", "uname", "getifaddrs", "getpwuid", "getuid", "getenv", "getcwd",
    "gethostbyname", "getaddrinfo", "getnameinfo",
    "sleep", "usleep", "nanosleep", "poll", "select",
    "snprintf", "sprintf", "sscanf", "strchr", "strcasecmp", "strftime",
    "createprocess", "winexec", "shellexecute", "virtualalloc", "virtualprotect",
    "writeprocessmemory", "createremotethread", "ntcreatethreadex",
    "regsetvalue", "regcreatekey", "createservice", "schtasks",
    "getprocaddress", "loadlibrary", "getenvironmentvariable",
}

# APIs that are only interesting in *non-library* functions (too noisy otherwise)
_CONTEXT_APIS = {
    "encrypt", "decrypt", "crypt", "aes", "rsa",
    "malloc", "free", "realloc", "memcpy", "memset",
    "strcmp", "strstr",
}

# Compiled word-boundary regex for each API
_API_WORD_RE = {api: re.compile(r'\b' + re.escape(api) + r'\b', re.IGNORECASE) for api in (_HIGH_VALUE_APIS | _CONTEXT_APIS)}

# APIs that are too generic to be interesting on their own — if a function
# ONLY triggers these and nothing from _HIGH_VALUE_APIS, skip it.
_GENERIC_ONLY_APIS = {"memcpy", "memset", "malloc", "free", "realloc", "strcmp", "strstr"}

# Regex for OpenSSL / crypto-library internal strings that mark a function
# as library code even when its name is an anonymous ``fcn.XXXXXXXX``.
_OPENSSL_CONTENT_RE = re.compile(
    r'OPENSSL_|dtls1_|ssl3_|ssl_|tls1_|SSL_|BIO_|EVP_|X509_|ASN1_|PEM_|RSA_|EC_|DH_|'
    r'CRYPTO_|ENGINE_|RAND_|PKCS|HMAC_|SHA\d+_|AES_|DES_|ECDSA_|ECDH_|'
    r'OpenSSL|openssl|libcrypto|libssl|BoringSSL|wolfSSL',
)


def _is_library_content(func_name: str, code: str, found_apis: list) -> bool:
    """Detect library functions by *content* when the name is anonymous.

    Returns True when:
    - Code contains OpenSSL / crypto-library internal identifiers, OR
    - The only matched APIs are from the generic-only set (memcpy, memset, …).
    """
    # Only apply to anonymous / unhelpful function names
    if not re.match(r'^(?:fcn\.|sub_|FUN_)', func_name):
        return False

    # OpenSSL / crypto library internal strings in the code body
    if _OPENSSL_CONTENT_RE.search(code):
        return True

    # Function only matched low-value generic APIs — skip it
    if found_apis and all(api in _GENERIC_ONLY_APIS for api in found_apis):
        return True

    return False


def _render_code_evidence(state: Dict[str, Any]) -> str:
    """Render code evidence section showing malicious/interesting code snippets.

    Scans decompiled functions for suspicious API calls.  Library functions
    (OpenSSL, zlib, libc internals) are excluded to reduce noise.
    Application-code functions are rendered first.
    """
    decomp_cache = state.get("decompilation_cache", {})
    r2_decomp_cache = state.get("r2_decompilation_cache", {})
    func_data = state.get("analysis_results", {}).get("functions", {})
    r2_func_data = state.get("r2_analysis_results", {}).get("functions", {})

    # Build name→address lookup
    addr_map: Dict[str, str] = {}
    for flist in [func_data.get("functions", []), r2_func_data.get("functions", [])]:
        for f in flist:
            addr_map[f.get("name", "")] = f.get("address", "?")

    app_blocks: List[str] = []   # Non-library function blocks
    lib_blocks: List[str] = []   # Library function blocks (shown after app)

    for source, cache in [("Ghidra", decomp_cache), ("Radare2", r2_decomp_cache)]:
        for func_name, code in cache.items():
            is_lib = is_library_function(func_name)

            # Choose which API set to match against
            api_set = _HIGH_VALUE_APIS if is_lib else (_HIGH_VALUE_APIS | _CONTEXT_APIS)

            # Word-boundary matching (not substring)
            found_apis = [api for api in api_set if _API_WORD_RE[api].search(code)]
            if not found_apis:
                continue

            # Content-based library detection for anonymous function names
            if not is_lib and _is_library_content(func_name, code, found_apis):
                is_lib = True

            # For library functions, only keep if genuinely high-value API found
            if is_lib:
                # Skip library functions that only match generic crypto names
                non_crypto = [a for a in found_apis if a not in _CONTEXT_APIS]
                if not non_crypto:
                    continue
                found_apis = non_crypto

            addr = addr_map.get(func_name, "?")

            # Extract the specific lines containing the suspicious calls (max 10 lines)
            interesting_lines: List[str] = []
            for line in code.split("\n"):
                line_stripped = line.strip()
                if any(_API_WORD_RE[api].search(line_stripped) for api in found_apis):
                    interesting_lines.append(line.rstrip())
                    if len(interesting_lines) >= 10:
                        break

            if not interesting_lines:
                continue

            snippet = escape("\n".join(interesting_lines))
            apis_str = ", ".join(sorted(set(found_apis)))

            block = (
                f'<div class="bg-slate-900 rounded-lg overflow-hidden mb-4">'
                f'<div class="flex items-center justify-between px-4 py-2 bg-slate-800 border-b border-slate-700">'
                f'<span class="text-xs text-slate-400 font-mono">[{escape(source)}] {escape(func_name)} @ {escape(str(addr))}</span>'
                f'<span class="text-xs text-yellow-400 font-mono">{escape(apis_str)}</span></div>'
                f'<div class="p-4 overflow-x-auto">'
                f'<pre class="font-mono text-xs text-slate-300 leading-relaxed whitespace-pre-wrap"><code>{snippet}</code></pre>'
                f'</div></div>'
            )

            if is_lib:
                lib_blocks.append(block)
            else:
                app_blocks.append(block)

    # Application-logic functions first, then library (capped at 3)
    # Total capped at 10 to keep the report focused
    evidence_blocks = app_blocks[:10] + lib_blocks[:max(0, 10 - len(app_blocks[:10]))]

    if not evidence_blocks:
        return '<p class="text-sm text-slate-500 italic">No suspicious API calls detected in decompiled code.</p>'

    return "\n".join(evidence_blocks)


def build_report_html(state: Dict[str, Any]) -> str:
    """Build HTML report using the revamp template (Tailwind + dark mode + sidebar)."""

    iocs = extract_iocs_from_state(state)
    verdict, verdict_class, indicators, score = calculate_verdict(iocs, state)

    analysis_results = state.get("analysis_results", {})
    r2_results = state.get("r2_analysis_results", {})
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

    logger.info("build_report_html: summary_text length=%d", len(summary_text))

    # --- Extract sections from LLM summary ---
    exec_summary = _extract_section(summary_text, "Executive Summary")
    if not exec_summary:
        fallback = re.sub(r'^#{2,3}\s+.*$', '', summary_text[:2000], flags=re.MULTILINE).strip()
        exec_summary = fallback or summary_text[:2000]

    capabilities_md = _extract_section(summary_text, "Malware Capabilities")
    technical_md = _extract_section(summary_text, "Technical Analysis")
    functions_md = _extract_section(summary_text, "Functions Analysis")
    operational_md = _extract_section(summary_text, "Operational Flow")
    evidence_md = _extract_section(summary_text, "Evidence of Malicious Activity")
    conclusion_text = _extract_section(summary_text, "Conclusion")
    evidence_items = _extract_evidence(summary_text)
    recommendations = _extract_recommendations(summary_text)

    # Render sections with dedicated card-based renderers
    capabilities_html = _render_capabilities_cards(capabilities_md)
    technical_html = _render_technical_cards(technical_md)
    functions_html = _render_functions_cards(functions_md)
    operational_html = _render_operational_flow(operational_md)
    ioc_list = _parse_iocs_for_template(iocs)

    # --- Verdict display config ---
    _VERDICT_CFG = {
        "malicious": ("Critical", "fa-skull-crossbones", "bg-red-100 dark:bg-red-900/30", "text-red-800 dark:text-red-300", "border-red-200 dark:border-red-800"),
        "suspicious": ("High Risk", "fa-exclamation-triangle", "bg-orange-100 dark:bg-orange-900/30", "text-orange-800 dark:text-orange-300", "border-orange-200 dark:border-orange-800"),
        "clean": ("Low Risk", "fa-check-circle", "bg-green-100 dark:bg-green-900/30", "text-green-800 dark:text-green-300", "border-green-200 dark:border-green-800"),
        "unknown": ("Unknown", "fa-question-circle", "bg-slate-100 dark:bg-slate-800", "text-slate-700 dark:text-slate-300", "border-slate-200 dark:border-slate-700"),
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

    # --- Render dynamic sections ---
    evidence_html = _render_evidence_cards(evidence_items, evidence_md)
    code_evidence_html = _render_code_evidence(state)
    call_graph_html = (
        '<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">'
        + _render_call_graph_section("Ghidra", gh_call_graph)
        + _render_call_graph_section("Radare2", r2_call_graph)
        + '</div>'
    )
    iocs_rows = _render_iocs(ioc_list)
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
    }
    cc_grad, cc_border, cc_title, cc_body, cc_icon_bg, cc_icon_txt = _CC.get(verdict_class, _CC["malicious"])

    # Binary info table rows
    binary_rows = f'''
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400 w-1/4">SHA256</td>
                                        <td class="text-xs break-all">{escape(program_hash)}</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Architecture</td>
                                        <td>{escape(str(arch))} ({bits}-bit)</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Format</td>
                                        <td>{escape(fmt_str)} - {escape(str(os_name))}</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Image Base</td>
                                        <td class="font-mono">{escape(str(binary.get('image_base', 'unknown')))}</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Entry Points</td>
                                        <td class="font-mono text-xs">{escape(_format_entry_points(binary.get('entry_points', ['unknown'])))}</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Compiler</td>
                                        <td class="text-xs">{escape(_sanitize_compiler(binary.get('compiler', 'unknown')))}</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Imports</td>
                                        <td class="text-xs">{escape(_format_import_export_list(binary.get('imports', [])))}</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Exports</td>
                                        <td>{len(binary.get('exports', []))} symbols</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Functions</td>
                                        <td>Ghidra: {len(funcs.get('functions', []))} ({len(state.get('decompilation_cache', {}))}&nbsp;decompiled) &middot; R2: {len(r2_funcs.get('functions', []))} ({len(state.get('r2_decompilation_cache', {}))}&nbsp;decompiled)</td></tr>
                                    <tr><td class="font-semibold text-slate-600 dark:text-slate-400">Strings</td>
                                        <td>Ghidra: {len(strings_data.get('strings', []))} &middot; R2: {len(r2_strings.get('strings', []))} extracted</td></tr>'''

    # --- Assemble full HTML ---
    html = f'''<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malware Analysis Report - {file_name}</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {{
            darkMode: 'class',
            theme: {{
                extend: {{
                    fontFamily: {{
                        sans: ['Inter', 'sans-serif'],
                        mono: ['JetBrains Mono', 'monospace'],
                    }},
                    colors: {{
                        primary: '#0f2937',
                        accent: '#dc2626',
                    }}
                }}
            }}
        }}
    </script>
    <style>
        @media print {{
            @page {{ size: A4; margin: 10mm; }}
            body {{ background: white !important; color: black !important; }}
            .no-print {{ display: none !important; }}
            .page-break {{ page-break-before: always; }}
            .flow-arrow {{ color: black !important; }}
        }}
        .code-block {{ background: #1e1e1e; border-radius: 0.5rem; position: relative; overflow: hidden; }}
        .code-content {{ padding: 1rem; overflow-x: auto; font-family: 'JetBrains Mono', monospace; font-size: 0.875rem; line-height: 1.5rem; color: #d4d4d4; }}
        .code-keyword {{ color: #569cd6; }} .code-string {{ color: #ce9178; }} .code-function {{ color: #dcdcaa; }}
        .code-comment {{ color: #6a9955; font-style: italic; }} .code-number {{ color: #b5cea8; }}
        .code-operator {{ color: #d4d4d4; }} .code-variable {{ color: #9cdcfe; }}
        .section-header-accent {{ position: relative; padding-left: 1rem; }}
        .section-header-accent::before {{ content: ''; position: absolute; left: 0; top: 0.25rem; bottom: 0.25rem; width: 4px; background: #dc2626; border-radius: 2px; }}
        table.data-table {{ width: 100%; border-collapse: separate; border-spacing: 0; }}
        table.data-table th {{ background: #f3f4f6; color: #374151; font-weight: 600; text-align: left; padding: 0.75rem 1rem; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 2px solid #e5e7eb; }}
        .dark table.data-table th {{ background: #1f2937; color: #d1d5db; border-bottom-color: #374151; }}
        table.data-table td {{ padding: 0.75rem 1rem; border-bottom: 1px solid #e5e7eb; font-size: 0.875rem; font-family: 'JetBrains Mono', monospace; }}
        .dark table.data-table td {{ border-bottom-color: #374151; color: #e5e7eb; }}
        .flow-container {{ display: flex; align-items: center; gap: 0.5rem; overflow-x: auto; padding: 1rem 0; }}
        .flow-item {{ flex-shrink: 0; background: white; border: 2px solid #e5e7eb; padding: 0.75rem 1.5rem; border-radius: 0.5rem; font-size: 0.875rem; font-weight: 600; color: #374151; white-space: nowrap; }}
        .dark .flow-item {{ background: #1f2937; border-color: #374151; color: #e5e7eb; }}
        .flow-item.active {{ background: #dc2626; color: white; border-color: #dc2626; }}
        .flow-arrow {{ color: #9ca3af; font-size: 1.25rem; flex-shrink: 0; }}
        .function-box {{ border: 2px solid #e5e7eb; transition: all 0.2s; }}
        .function-box:hover {{ border-color: #dc2626; box-shadow: 0 4px 12px rgba(220, 38, 38, 0.15); }}
        .dark .function-box {{ border-color: #374151; }}
        .dark .function-box:hover {{ border-color: #dc2626; box-shadow: 0 4px 12px rgba(220, 38, 38, 0.3); }}
        .evidence-compact {{ border-left: 3px solid #dc2626; transition: all 0.2s; }}
        .evidence-compact:hover {{ background-color: #f9fafb; padding-left: 1.25rem; }}
        .dark .evidence-compact:hover {{ background-color: #1f2937; }}
        /* Card component styles */
        .capability-card {{ transition: all 0.25s ease; }}
        .tech-card {{ transition: all 0.25s ease; }}
        .func-card {{ transition: all 0.25s ease; }}
        .evidence-card {{ transition: all 0.25s ease; }}
        .evidence-card:hover {{ transform: translateX(4px); }}
        .rec-card {{ transition: all 0.3s; border: 1px solid #e5e7eb; }}
        .rec-card:hover {{ transform: translateY(-2px); box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1); border-color: #dc2626; }}
        .dark .rec-card {{ border-color: #374151; }}
        .dark .rec-card:hover {{ border-color: #dc2626; }}
        .tlp-banner {{ background: repeating-linear-gradient(45deg, #f59e0b, #f59e0b 10px, #d97706 10px, #d97706 20px); color: white; text-shadow: 0 1px 2px rgba(0,0,0,0.3); font-weight: bold; padding: 0.25rem 0.75rem; font-size: 0.75rem; letter-spacing: 0.05em; text-transform: uppercase; display: inline-flex; align-items: center; gap: 0.5rem; }}
        .risk-box {{ {risk_gradient} color: white; position: relative; overflow: hidden; }}
        .risk-box::before {{ content: ''; position: absolute; top: 0; left: 0; right: 0; bottom: 0;
            background: repeating-linear-gradient(45deg, transparent, transparent 10px, rgba(255,255,255,0.05) 10px, rgba(255,255,255,0.05) 20px);
            animation: slide 20s linear infinite; }}
        @keyframes slide {{ 0% {{ transform: translateX(0); }} 100% {{ transform: translateX(40px); }} }}
        /* markdown-content overrides for Tailwind context */
        .md-content p {{ margin-bottom: 0.75rem; line-height: 1.7; }}
        .md-content ul {{ list-style-type: disc; padding-left: 1.5rem; margin-bottom: 0.75rem; }}
        .md-content ol {{ list-style-type: decimal; padding-left: 1.5rem; margin-bottom: 0.75rem; }}
        .md-content li {{ margin-bottom: 0.375rem; }}
        .md-content pre {{ background: #1e293b; border: 1px solid #334155; border-radius: 0.5rem; padding: 1rem; overflow-x: auto; font-size: 0.8rem; margin: 1rem 0; color: #e2e8f0; }}
        .md-content code {{ font-family: 'JetBrains Mono', monospace; background: #f1f5f9; padding: 0.125rem 0.375rem; font-size: 0.85em; color: #dc2626; border-radius: 0.25rem; }}
        .md-content pre code {{ color: #e2e8f0; background: none; padding: 0; }}
        .md-content h3 {{ font-size: 1.125rem; font-weight: 700; margin-top: 1.5rem; margin-bottom: 0.75rem; }}
        .md-content h4 {{ font-size: 1rem; font-weight: 600; margin-top: 1.25rem; margin-bottom: 0.5rem; }}
        .md-content table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.875rem; }}
        .md-content th {{ background: #f1f5f9; font-weight: 700; text-transform: uppercase; font-size: 0.7rem; padding: 0.5rem 0.75rem; text-align: left; border-bottom: 2px solid #cbd5e1; }}
        .md-content td {{ padding: 0.5rem 0.75rem; border-bottom: 1px solid #e2e8f0; }}
        .dark .md-content code {{ background: #1e293b; color: #f87171; }}
        .dark .md-content th {{ background: #1e293b; border-bottom-color: #475569; }}
        .dark .md-content td {{ border-bottom-color: #334155; }}
    </style>
</head>
<body class="bg-slate-100 text-slate-900 dark:bg-slate-950 dark:text-slate-200 font-sans">

    <!-- Floating Tools -->
    <div class="fixed bottom-6 right-6 z-50 flex flex-col gap-3 no-print">
        <button onclick="toggleDarkMode()" class="bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-200 p-3 rounded-full shadow-lg border border-slate-200 dark:border-slate-700 hover:scale-110 transition-transform">
            <i class="fas fa-moon dark:hidden"></i>
            <i class="fas fa-sun hidden dark:block"></i>
        </button>
        <button onclick="window.print()" class="bg-red-600 text-white p-3 rounded-full shadow-lg hover:bg-red-700 hover:scale-110 transition-all">
            <i class="fas fa-print"></i>
        </button>
    </div>

    <!-- Navigation Sidebar -->
    <nav class="fixed left-0 top-0 h-full w-72 bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 overflow-y-auto z-40 transform -translate-x-full lg:translate-x-0 transition-transform no-print shadow-xl">
        <div class="p-6 border-b border-slate-200 dark:border-slate-800">
            <div class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Malware Analysis</div>
            <div class="font-mono text-lg font-bold text-slate-800 dark:text-slate-100 truncate">{file_name}</div>
            <div class="text-xs text-slate-500 mt-1">SHA256: {escape(hash_short)}</div>
        </div>
        <div class="p-4 space-y-1 text-sm">
            <a href="#executive-summary" class="block px-3 py-2 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">Executive Summary</a>
            <a href="#capabilities" class="block px-3 py-2 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">Malware Capabilities</a>
            <a href="#binary-info" class="block px-3 py-2 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">Binary Information</a>
            <a href="#technical-analysis" class="block px-3 py-2 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">Technical Analysis</a>
            <a href="#functions-analysis" class="block px-3 py-2 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">Functions Analysis</a>
            <a href="#evidence" class="block px-3 py-2 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">Evidence</a>
            <a href="#code-evidence" class="block px-3 py-2 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">Code Evidence</a>
            <a href="#operational-flow" class="block px-3 py-2 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">Operational Flow</a>
            <a href="#call-graph" class="block px-3 py-2 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">Call Graph</a>
            <a href="#iocs" class="block px-3 py-2 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">IOCs</a>
            <a href="#recommendations" class="block px-3 py-2 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">Recommendations</a>
            <a href="#conclusion" class="block px-3 py-2 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">Conclusion</a>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="lg:ml-72 min-h-screen">
        <div class="max-w-6xl mx-auto p-4 lg:p-8 space-y-8">
            <div class="bg-white dark:bg-slate-900 rounded-lg shadow-xl border border-slate-200 dark:border-slate-800 overflow-hidden">

                <!-- Header -->
                <header class="bg-slate-50 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800 p-8">
                    <div class="flex flex-col lg:flex-row justify-between gap-6">
                        <div class="flex-1">
                            <div class="flex items-center gap-3 mb-3">
                                <span class="px-2 py-1 {v_badge_bg} {v_badge_text} text-xs font-bold rounded-full border {v_badge_border}">{escape(v_label).upper()}</span>
                                <span class="px-2 py-1 bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs font-bold rounded-full">{escape(format_badge)}</span>
                                <span class="tlp-banner rounded"><i class="fas fa-lock"></i> TLP:AMBER</span>
                            </div>
                            <h1 class="text-4xl font-bold text-slate-900 dark:text-white mb-2 tracking-tight">Reverse Engineering Report</h1>
                            <p class="text-xl text-slate-600 dark:text-slate-400 font-mono">Sample: <span class="text-slate-900 dark:text-slate-100 font-bold">{file_name}</span></p>
                        </div>
                        <div class="lg:text-right space-y-2">
                            <div class="text-sm font-bold text-slate-900 dark:text-white text-lg">Cyber Security Division</div>
                            <div class="text-sm text-slate-600 dark:text-slate-400">Incident Response Team</div>
                            <div class="font-mono text-xs text-slate-500 dark:text-slate-500 mt-2 space-y-1">
                                <div>Analysis ID: <span class="text-slate-700 dark:text-slate-300">{escape(task_id)}</span></div>
                                <div>Generated: <span class="text-slate-700 dark:text-slate-300">{escape(timestamp)}</span></div>
                            </div>
                        </div>
                    </div>
                </header>

                <!-- Risk Banner -->
                <div class="risk-box p-6 text-center relative">
                    <div class="relative z-10 flex items-center justify-center gap-3">
                        <i class="fas {v_icon} text-3xl opacity-80"></i>
                        <div class="text-3xl font-bold uppercase tracking-widest">{escape(v_label)}</div>
                    </div>
                </div>

                <div class="p-8 space-y-12">

                    <!-- 1. Executive Summary -->
                    <section id="executive-summary" class="scroll-mt-20">
                        <h2 class="text-2xl font-bold text-slate-900 dark:text-white mb-6 section-header-accent">1. Executive Summary</h2>
                        <div class="md-content text-slate-700 dark:text-slate-300 leading-relaxed space-y-4 text-base">
                            {_markdown_to_html(exec_summary)}
                        </div>
                    </section>

                    <!-- 2. Malware Capabilities -->
                    <section id="capabilities" class="scroll-mt-20 page-break">
                        <h2 class="text-2xl font-bold text-slate-900 dark:text-white mb-6 section-header-accent">2. Malware Capabilities</h2>
                        {capabilities_html}
                    </section>

                    <!-- 3. Binary Information -->
                    <section id="binary-info" class="scroll-mt-20">
                        <h2 class="text-2xl font-bold text-slate-900 dark:text-white mb-6 section-header-accent">3. Binary Information</h2>
                        <div class="overflow-hidden rounded-lg border border-slate-200 dark:border-slate-700">
                            <table class="data-table">
                                <tbody>{binary_rows}</tbody>
                            </table>
                        </div>
                    </section>

                    <!-- 4. Technical Analysis -->
                    <section id="technical-analysis" class="scroll-mt-20 page-break">
                        <h2 class="text-2xl font-bold text-slate-900 dark:text-white mb-6 section-header-accent">4. Technical Analysis</h2>
                        {technical_html}
                    </section>

                    <!-- 5. Functions Analysis -->
                    <section id="functions-analysis" class="scroll-mt-20">
                        <h2 class="text-2xl font-bold text-slate-900 dark:text-white mb-6 section-header-accent">5. Functions Analysis</h2>
                        {functions_html}
                    </section>

                    <!-- 6. Evidence -->
                    <section id="evidence" class="scroll-mt-20">
                        <h2 class="text-2xl font-bold text-slate-900 dark:text-white mb-6 section-header-accent">6. Evidence of Malicious Activity</h2>
                        {evidence_html}
                    </section>

                    <!-- 6b. Code Evidence -->
                    <section id="code-evidence" class="scroll-mt-20">
                        <h2 class="text-2xl font-bold text-slate-900 dark:text-white mb-6 section-header-accent">6b. Code Evidence (Suspicious API Calls)</h2>
                        <p class="text-sm text-slate-500 dark:text-slate-400 mb-4 italic">Exact code locations where suspicious API calls were found in decompiled functions.</p>
                        {code_evidence_html}
                    </section>

                    <!-- 7. Operational Flow -->
                    <section id="operational-flow" class="scroll-mt-20 page-break">
                        <h2 class="text-2xl font-bold text-slate-900 dark:text-white mb-6 section-header-accent">7. Operational Flow</h2>
                        {operational_html}
                    </section>

                    <!-- 8. Call Graph -->
                    <section id="call-graph" class="scroll-mt-20">
                        <h2 class="text-2xl font-bold text-slate-900 dark:text-white mb-6 section-header-accent">8. Call Graph &amp; Attack Chains</h2>
                        {call_graph_html}
                    </section>

                    <!-- 9. IOCs -->
                    <section id="iocs" class="scroll-mt-20 page-break">
                        <h2 class="text-2xl font-bold text-slate-900 dark:text-white mb-6 section-header-accent">9. Indicators of Compromise (IOCs)</h2>
                        <div class="bg-white dark:bg-slate-800 rounded-lg shadow-sm border border-slate-200 dark:border-slate-700 overflow-hidden">
                            <table class="w-full text-left">
                                <tbody class="divide-y divide-slate-200 dark:divide-slate-700 text-sm">
                                    {iocs_rows}
                                </tbody>
                            </table>
                        </div>
                    </section>

                    <!-- 10. Recommendations -->
                    <section id="recommendations" class="scroll-mt-20">
                        <h2 class="text-2xl font-bold text-slate-900 dark:text-white mb-6 section-header-accent">10. Recommendations</h2>
                        {recommendations_html}
                    </section>

                    <!-- 11. Conclusion -->
                    <section id="conclusion" class="scroll-mt-20">
                        <h2 class="text-2xl font-bold text-slate-900 dark:text-white mb-6 section-header-accent">11. Conclusion</h2>
                        <div class="bg-gradient-to-r {cc_grad} border-2 {cc_border} rounded-lg p-6">
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
                <footer class="bg-slate-50 dark:bg-slate-950 border-t border-slate-200 dark:border-slate-800 p-6 mt-12">
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
        // Dark mode
        if (localStorage.theme === 'dark' || (!('theme' in localStorage) && window.matchMedia('(prefers-color-scheme: dark)').matches)) {{
            document.documentElement.classList.add('dark');
        }} else {{
            document.documentElement.classList.remove('dark');
        }}
        function toggleDarkMode() {{
            if (document.documentElement.classList.contains('dark')) {{
                document.documentElement.classList.remove('dark');
                localStorage.theme = 'light';
            }} else {{
                document.documentElement.classList.add('dark');
                localStorage.theme = 'dark';
            }}
        }}
        // Copy to clipboard
        function copyToClipboard(text) {{
            navigator.clipboard.writeText(text).then(() => {{
                const toast = document.createElement('div');
                toast.className = 'fixed bottom-24 right-6 bg-slate-800 text-white px-4 py-2 rounded-lg shadow-lg z-50 text-sm flex items-center gap-2 animate-bounce';
                toast.innerHTML = '<i class="fas fa-check text-green-400"></i> Copied';
                document.body.appendChild(toast);
                setTimeout(() => toast.remove(), 2000);
            }});
        }}
        // Smooth scroll
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {{
            anchor.addEventListener('click', function (e) {{
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({{ behavior: 'smooth', block: 'start' }});
            }});
        }});
        // Intersection observer for nav highlight
        const observer = new IntersectionObserver((entries) => {{
            entries.forEach(entry => {{
                if (entry.isIntersecting) {{
                    document.querySelectorAll('nav a').forEach(link => {{
                        link.classList.remove('bg-slate-200', 'dark:bg-slate-700', 'text-red-600');
                        if (link.getAttribute('href') === '#' + entry.target.id) {{
                            link.classList.add('bg-slate-200', 'dark:bg-slate-700', 'text-red-600');
                        }}
                    }});
                }}
            }});
        }}, {{ root: null, rootMargin: '-20% 0px -80% 0px', threshold: 0 }});
        document.querySelectorAll('section[id]').forEach(section => {{ observer.observe(section); }});
    </script>
</body>
</html>'''

    return html


def build_agent_report_html(state: Dict[str, Any], agent: str) -> str:
    """Build a per-agent HTML report showing what a specific tool discovered.

    Args:
        state: The analysis state dict.
        agent: Either 'ghidra' or 'r2' (radare2).
    """
    is_ghidra = agent.lower() in ("ghidra", "ghidra_agent")
    agent_name = "Ghidra" if is_ghidra else "Radare2"
    agent_color = "#1a73e8" if is_ghidra else "#e8710a"

    program_hash = state.get("program_hash", "unknown")
    file_name = escape(state.get("binary_path", "unknown").split("/")[-1])
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    session_id = state.get("session_id", "unknown")[:8]

    # Select per-agent data
    if is_ghidra:
        analysis = state.get("analysis_results", {})
        decomp_cache = state.get("decompilation_cache", {})
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

        <!-- Functions -->
        <h2 class="section-header">Functions ({len(func_list)} discovered)</h2>
        <table class="data-table">
            <thead><tr><th>Name</th><th>Address</th><th>Size</th><th>XRefs</th><th>Decompiled</th></tr></thead>
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


def build_report_text(state: Dict[str, Any]) -> str:
    """Build plain text report for download."""
    summary = state.get("summary", "No summary available.")
    program_hash = state.get("program_hash", "unknown")
    binary = state.get("analysis_results", {}).get("binary", {})
    r2_binary = state.get("r2_analysis_results", {}).get("binary", {})
    funcs = state.get("analysis_results", {}).get("functions", {})
    r2_funcs = state.get("r2_analysis_results", {}).get("functions", {})
    gh_call_graph_analysis = state.get("analysis_results", {}).get("call_graph_analysis", {})
    r2_call_graph_analysis = state.get("r2_analysis_results", {}).get("call_graph_analysis", {})
    decomp = state.get("decompilation_cache", {})
    r2_decomp = state.get("r2_decompilation_cache", {})

    lines = [
        "=" * 70,
        "GHIDRA + RADARE2 BINARY ANALYSIS REPORT",
        "=" * 70,
        "",
        f"SHA-256: {program_hash}",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
    ]

    # Ghidra info
    if binary.get("ok"):
        lines.append("-" * 70)
        lines.append("GHIDRA BINARY INFO")
        lines.append("-" * 70)
        lines.append(f"Architecture: {binary.get('architecture', 'unknown')}")
        lines.append(f"Image Base:   {binary.get('image_base', 'unknown')}")
        lines.append(f"Entry Points: {_format_entry_points(binary.get('entry_points', []))}")
        lines.append(f"Compiler:     {_sanitize_compiler(binary.get('compiler', 'unknown'))}")
        gh_imports = binary.get("imports", [])
        if gh_imports:
            lines.append(f"Imports:      {_format_import_export_list(gh_imports)}")
        gh_exports = binary.get("exports", [])
        if gh_exports:
            lines.append(f"Exports:      {len(gh_exports)} symbols")
        lines.append(f"Functions:    {len(funcs.get('functions', []))} ({len(decomp)} decompiled)")
        lines.append("")

    # R2 info
    if r2_binary.get("ok"):
        lines.append("-" * 70)
        lines.append("RADARE2 BINARY INFO")
        lines.append("-" * 70)
        lines.append(f"Architecture: {r2_binary.get('architecture', 'unknown')}")
        lines.append(f"Bits:         {r2_binary.get('bits', 'unknown')}")
        lines.append(f"OS:           {r2_binary.get('os', 'unknown')}")
        lines.append(f"Endian:       {r2_binary.get('endian', 'unknown')}")
        lines.append(f"Stripped:     {r2_binary.get('stripped', 'unknown')}")
        imports = r2_binary.get("imports", [])
        if imports:
            lines.append(f"Imports:      {_format_import_export_list(imports)}")
        exports = r2_binary.get("exports", [])
        if exports:
            lines.append(f"Exports:      {len(exports)} symbols")
        lines.append(f"Functions:    {len(r2_funcs.get('functions', []))} ({len(r2_decomp)} decompiled)")
        lines.append("")

    # Executive summary first (most important for readers)
    lines.extend([
        "-" * 70,
        "EXECUTIVE SUMMARY",
        "-" * 70,
        summary,
        "",
    ])

    def _append_call_graph_text(source: str, analysis: Dict[str, Any]) -> None:
        if not analysis or not analysis.get("ok"):
            return
        stats = analysis.get("stats", {})
        entries = analysis.get("entries", []) or []
        chains = analysis.get("chains", []) or []
        lines.append(f"{source}: nodes={stats.get('nodes', 0)}, edges={stats.get('edges', 0)}, entries={len(entries)}")
        if entries:
            lines.append(f"  Entry points: {', '.join(entries[:5])}")
        if chains:
            deduped = _deduplicate_chains(chains)
            lines.append(f"  Attack chains ({len(deduped)} unique of {len(chains)} total):")
            for chain in deduped:
                path = " -> ".join(str(p) for p in chain.get("path", []))
                lines.append(f"    - [{chain.get('category', 'Unknown')}] {path}")
        else:
            lines.append("  Attack chains: none detected")
        cycles = analysis.get("cycles", []) or []
        if cycles:
            lines.append(f"  Cycles (top 5 of {len(cycles)}):")
            for cycle in cycles[:5]:
                lines.append(f"    - {' -> '.join(cycle)}")
        lines.append("")

    if gh_call_graph_analysis.get("ok") or r2_call_graph_analysis.get("ok"):
        lines.append("-" * 70)
        lines.append("CALL GRAPH & ATTACK CHAINS")
        lines.append("-" * 70)
        _append_call_graph_text("Ghidra", gh_call_graph_analysis)
        _append_call_graph_text("Radare2", r2_call_graph_analysis)

    # Decompiled code appendix
    if decomp:
        lines.append("-" * 70)
        lines.append(f"APPENDIX A: GHIDRA DECOMPILED FUNCTIONS ({len(decomp)})")
        lines.append("-" * 70)
        for name, code in decomp.items():
            lines.append(f"\n--- {name} ---")
            lines.append(code[:4000])
            if len(code) > 4000:
                lines.append("/* ... [truncated at 4000 chars] ... */")
        lines.append("")

    if r2_decomp:
        lines.append("-" * 70)
        lines.append(f"APPENDIX B: RADARE2 DECOMPILED FUNCTIONS ({len(r2_decomp)})")
        lines.append("-" * 70)
        for name, code in r2_decomp.items():
            lines.append(f"\n--- {name} ---")
            lines.append(code[:4000])
            if len(code) > 4000:
                lines.append("/* ... [truncated at 4000 chars] ... */")
        lines.append("")

    lines.extend([
        "=" * 70,
        "END OF REPORT",
        "=" * 70,
    ])

    return '\n'.join(lines)
