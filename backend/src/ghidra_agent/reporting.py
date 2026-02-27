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
            f'<div class="evidence-compact bg-[#0B1324] p-4 rounded shadow-sm flex items-start gap-4">'
            f'<span class="flex-shrink-0 w-6 h-6 rounded-full {circle_bg} {circle_txt} flex items-center justify-center text-xs font-bold">{i}</span>'
            f'<div class="flex-1">'
            f'<div class="font-bold text-white text-sm">{escape(title)}</div>'
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
            f'<div class="rec-card bg-[#0B1324] p-5 rounded-lg shadow-sm{col_span}">'
            f'<div class="flex items-start gap-3">'
            f'<div class="w-8 h-8 rounded-lg bg-{color}-100 dark:bg-{color}-900/30 text-{color}-600 dark:text-{color}-400 flex items-center justify-center flex-shrink-0">'
            f'<i class="{icon}"></i></div>'
            f'<div><h4 class="font-bold text-white mb-1 text-sm">{title}</h4>'
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
    """Escape text, convert backtick spans to <code>, and auto-chip key entities."""
    s = escape(text)

    # Protect backtick code in placeholders to avoid double-wrapping with chips
    _ic_spans: List[str] = []

    def _save_ic(m):
        _ic_spans.append(
            '<code class="bg-slate-100 dark:bg-slate-800 text-red-600 '
            'dark:text-red-400 px-1 py-0.5 rounded text-xs font-mono">'
            + m.group(1) + '</code>'
        )
        return f'\x00IC{len(_ic_spans) - 1}\x00'

    s = re.sub(r'`(.+?)`', _save_ic, s)
    s = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', s)

    # Entity chips — file paths, MITRE IDs, function names, hex addresses
    s = re.sub(
        r'(?<!["\w/])(/(?:etc|usr|var|tmp|bin|dev|proc|sys|home|opt|lib|sbin|run)(?:/[\w._-]+)+)',
        r'<span class="entity-chip path" title="File path">\1</span>', s)
    s = re.sub(
        r'\b(T\d{4}(?:\.\d{3})?)\b',
        r'<span class="entity-chip mitre" title="MITRE ATT&amp;CK">\1</span>', s)
    s = re.sub(
        r'\b((?:FUN_|fcn\.|sub_)[0-9a-fA-Fx_]+)\b',
        r'<span class="entity-chip func" title="Function">\1</span>', s)
    s = re.sub(
        r'\b(0x[0-9a-fA-F]{4,})\b',
        r'<span class="entity-chip addr" title="Address">\1</span>', s)

    # Restore protected code spans
    for i, html in enumerate(_ic_spans):
        s = s.replace(f'\x00IC{i}\x00', html)

    return s



def _render_mitre_cards(md_text: str) -> str:
    """Render MITRE ATT&CK as modern cyber cards."""
    if not md_text:
        return ''
    
    cards = []
    for line in md_text.split('\n'):
        # Match - **Tactic**: Technique (ID) - Description
        # Or variations
        m = re.match(r'^[-*]\s+\*\*\[?(.+?)\]?\*\*:\s*\[?([^-]+?)(?:\s+\((T\d+)\))?\]?\s*-\s*(.+)', line.strip())
        if m:
            tactic = m.group(1).strip()
            technique = m.group(2).strip()
            tech_id = m.group(3) or ''
            desc = m.group(4).strip()
            tech_text = f"{technique} ({tech_id})" if tech_id else technique
            
            cards.append(
                f'<div class="bg-[#0B1324] border border-[#131e36] p-4 rounded-xl hover:shadow-[0_0_15px_rgba(0,255,65,0.2)] hover:border-[#00ff41] transition-all duration-300 group">'
                f'<div class="flex items-center gap-3 mb-2">'
                f'<div class="w-2 h-2 rounded-full bg-[#00ff41] shadow-[0_0_5px_#00ff41] group-hover:animate-pulse"></div>'
                f'<div class="text-[#00ff41] font-mono text-xs uppercase tracking-widest">{escape(tactic)}</div>'
                f'</div>'
                f'<h4 class="font-bold text-white text-sm mb-1">{escape(tech_text)}</h4>'
                f'<p class="text-slate-400 text-xs leading-relaxed">{escape(desc)}</p>'
                f'</div>'
            )
            
    if not cards:
        return _markdown_to_html(md_text)
        
    return f'<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">{chr(10).join(cards)}</div>'

def _render_capabilities_cards(md_text: str) -> str:
    """Render Malware Capabilities as a single unified table-like card."""
    if not md_text:
        return '<p class="text-slate-500 italic">Capabilities analysis not available.</p>'

    # Parse bullets: - **Title**: ... / sub-bullets with Evidence
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

    # --- Merge capability + evidence pairs ---
    # Each raw_block has a title line.  If the title starts with "Evidence"
    # or "Capability", group them: a Capability followed by one or more
    # Evidence blocks become a single merged entry.
    merged: List[dict] = []  # [{title, desc_lines, evidence_lines}]
    for block in raw_blocks:
        block = block.strip()
        if not block:
            continue
        title_m = re.match(r'^[-*]\s+\*\*(.+?)\*\*[:\s]*(.*)', block, re.DOTALL)
        if not title_m:
            continue
        raw_title = title_m.group(1).strip()
        rest = title_m.group(2).strip()

        # Collect sub-lines
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

        # Detect if this block IS an evidence line (title starts with "Evidence")
        is_evidence_block = raw_title.lower().startswith('evidence')
        # Detect if this block IS a capability label (title starts with "Capability")
        is_cap_label = raw_title.lower().startswith('capability')

        if is_evidence_block:
            # Strip "Evidence" prefix to get the actual evidence text
            ev_text = re.sub(r'^Evidence\s*[-:—]\s*', '', raw_title, flags=re.IGNORECASE).strip()
            if rest.strip():
                ev_text = ev_text + ' ' + rest.strip() if ev_text else rest.strip()
            if merged:
                merged[-1]['evidence_lines'].append(ev_text)
            else:
                merged.append({'title': 'Finding', 'desc_lines': [], 'evidence_lines': [ev_text]})
        elif is_cap_label:
            # Strip "Capability" prefix: "Capability — Raw Socket" → "Raw Socket"
            cap_name = re.sub(r'^Capability\s*[-:—]+\s*', '', raw_title, flags=re.IGNORECASE).strip()
            if not cap_name:
                cap_name = raw_title
            merged.append({'title': cap_name, 'desc_lines': desc_lines, 'evidence_lines': evidence_lines})
        else:
            merged.append({'title': raw_title, 'desc_lines': desc_lines, 'evidence_lines': evidence_lines})

    rows: List[str] = []
    for idx, entry in enumerate(merged):
        title = escape(entry['title'])
        icon, color = _CAP_ICONS[idx % len(_CAP_ICONS)]
        is_last = idx == len(merged) - 1
        border_b = '' if is_last else ' border-b border-[#131e36]/60'

        desc_html = ''
        if entry['desc_lines']:
            joined_desc = ' '.join(_inline_code_html(d) for d in entry['desc_lines'])
            desc_html = f'<span class="text-slate-400 text-xs"> &mdash; {joined_desc}</span>'

        # Evidence rendered inline as a compact mono line
        evidence_html = ''
        if entry['evidence_lines']:
            ev_parts = '; '.join(_inline_code_html(ev) for ev in entry['evidence_lines'])
            evidence_html = (
                f'<div class="mt-1.5 flex items-start gap-1.5">'
                f'<i class="fas fa-terminal text-[9px] text-[#00f0ff]/70 mt-0.5 shrink-0"></i>'
                f'<span class="text-[11px] text-slate-300/90 font-mono leading-snug break-words">{ev_parts}</span>'
                f'</div>'
            )

        rows.append(
            f'<div class="flex items-start gap-3 py-3 px-4{border_b} hover:bg-white/[0.02] transition-colors">'
            f'<div class="w-6 h-6 mt-0.5 rounded shrink-0 bg-{color}-500/10 text-{color}-400 '
            f'flex items-center justify-center text-[11px] border border-{color}-500/20">'
            f'<i class="{icon}"></i></div>'
            f'<div class="flex-1 min-w-0">'
            f'<div class="text-[13px] text-slate-100 font-semibold leading-snug">{title}{desc_html}</div>'
            f'{evidence_html}'
            f'</div></div>'
        )

    if not rows:
        return _markdown_to_html(md_text)

    joined = "\n".join(rows)
    return (
        f'<div class="capability-card bg-[#0B1324] rounded-xl border border-[#131e36] '
        f'overflow-hidden shadow-lg">'
        f'<div class="px-4 py-2.5 bg-[#060B14] border-b border-[#131e36] '
        f'flex items-center gap-2 text-[10px] font-bold text-slate-400 uppercase tracking-[0.14em]">'
        f'<i class="fas fa-bolt text-[#00f0ff]"></i>Identified Capabilities'
        f'<span class="ml-auto text-slate-500">{len(merged)} findings</span></div>'
        f'{joined}</div>'
    )


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
            f'<div class="tech-card bg-[#0B1324] rounded-xl border border-[#131e36] overflow-hidden '
            f'hover:shadow-[0_0_15px_rgba(0,240,255,0.15)] hover:border-{color}-400 dark:hover:border-{color}-600 transition-all duration-200">'
            f'<div class="flex items-center gap-3 px-5 py-3 bg-[#060B14] border-b border-[#131e36]">'
            f'<div class="w-7 h-7 rounded-lg bg-{color}-100 dark:bg-{color}-900/30 text-{color}-500 dark:text-{color}-400 '
            f'flex items-center justify-center flex-shrink-0 text-xs"><i class="{icon}"></i></div>'
            f'<h3 class="font-bold text-white text-sm">{_inline_code_html(title)}</h3></div>'
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
        border_cls = 'border-red-300 dark:border-red-700' if is_malicious else 'border-[#131e36]'
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
            f'<div class="func-card bg-[#0B1324] rounded-xl border-2 {border_cls} overflow-hidden '
            f'hover:shadow-[0_0_15px_rgba(0,240,255,0.15)] transition-all duration-200">'
            f'<div class="px-5 py-3 bg-[#060B14] border-b border-[#131e36] '
            f'flex flex-wrap items-center gap-2">'
            f'<i class="fas fa-cube text-xs text-slate-400"></i>'
            f'<span class="font-bold text-white text-sm font-mono">{escape(fname)}</span>'
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
    """Render Evidence of Malicious Activity with accent bars, severity labels, and collapsible detail."""
    if not evidence_items and not md_text:
        return '<p class="text-sm text-slate-500 italic" role="status">No evidence of malicious activity identified.</p>'

    # Severity tiers: first findings are most critical, later ones taper
    _SEV_CFG = [
        ("sev-critical", "Critical", "fas fa-circle-exclamation", "text-red-400"),
        ("sev-critical", "Critical", "fas fa-circle-exclamation", "text-red-400"),
        ("sev-high",     "High",     "fas fa-triangle-exclamation", "text-orange-400"),
        ("sev-high",     "High",     "fas fa-triangle-exclamation", "text-orange-400"),
        ("sev-medium",   "Medium",   "fas fa-circle-info", "text-yellow-400"),
        ("sev-medium",   "Medium",   "fas fa-circle-info", "text-yellow-400"),
        ("sev-low",      "Low",      "fas fa-circle-check", "text-blue-400"),
        ("sev-info",     "Info",     "fas fa-circle-question", "text-purple-400"),
    ]

    # Try structured evidence items first
    if evidence_items:
        cards: List[str] = []
        for i, item in enumerate(evidence_items):
            sev_cls, sev_label, sev_icon, sev_color = _SEV_CFG[min(i, len(_SEV_CFG) - 1)]

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
                    f'<details class="mt-3">'
                    f'<summary class="text-xs text-slate-400 cursor-pointer hover:text-slate-200 select-none">'
                    f'<i class="fas fa-chevron-right text-[10px] mr-1 transition-transform duration-150"></i>Show detail</summary>'
                    f'<div class="mt-2 bg-[#060B14] rounded-lg p-3 border border-slate-700/50">'
                    f'<div class="text-xs text-slate-300 font-mono leading-relaxed break-words">{_inline_code_html(detail_str)}</div>'
                    f'</div></details>'
                )

            meta_html = (
                f'<div class="flex items-center gap-3 mt-2 text-[10px] text-slate-500">'
                f'<span title="Evidence source"><i class="fas fa-microscope mr-1"></i>Static Analysis</span>'
                f'<span title="Finding number">#EV-{i + 1:03d}</span>'
                f'</div>'
            )

            cards.append(
                f'<div class="evidence-row {sev_cls} bg-[#0B1324] rounded-lg p-5 '
                f'hover:shadow-[0_0_12px_rgba(0,240,255,0.06)] transition-all duration-200" '
                f'role="article" aria-label="Evidence finding {i + 1}: {escape(title_str[:60])}">'
                f'<div class="flex items-start gap-3">'
                f'<div class="flex-1 min-w-0">'
                f'<div class="flex items-center gap-2 mb-1">'
                f'<i class="{sev_icon} {sev_color} text-sm" title="{sev_label} severity"></i>'
                f'<span class="text-[10px] font-bold uppercase tracking-wider {sev_color}">{sev_label}</span>'
                f'</div>'
                f'<div class="font-semibold text-white text-sm leading-snug">{_inline_code_html(title_str)}</div>'
                f'{meta_html}'
                f'{detail_html}'
                f'</div>'
                f'<span class="flex-shrink-0 text-[10px] font-bold text-slate-500 bg-slate-800 px-2 py-0.5 rounded-full">#{i + 1}</span>'
                f'</div></div>'
            )

        joined = "\n".join(cards)
        return f'<div class="space-y-4">{joined}</div>'

    # Fallback: use markdown text as evidence section
    if md_text:
        return _markdown_to_html(md_text)

    return '<p class="text-sm text-slate-500 italic" role="status">No evidence of malicious activity identified.</p>'


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
            f'<div class="absolute left-[11px] top-7 bottom-0 w-px bg-slate-700/60"></div>'
        )

        ev_html = ''
        if evidence:
            ev_html = (
                f'<span class="text-[10px] text-slate-500 font-mono"> &bull; {_inline_code_html(evidence)}</span>'
            )

        items.append(
            f'<div class="relative pl-8">'
            f'{connector}'
            f'<div class="absolute left-0 top-0 w-[22px] h-[22px] rounded-full bg-{color}-900/30 '
            f'border border-{color}-500/50 flex items-center justify-center '
            f'text-[10px] font-bold text-{color}-400 z-10">{idx + 1}</div>'
            f'<div class="py-2">'
            f'<span class="font-semibold text-white text-[13px]">{escape(title)}</span>'
            f'<span class="text-xs text-slate-400 ml-1">{_inline_code_html(desc)}</span>'
            f'{ev_html}'
            f'</div></div>'
        )

    joined = "\n".join(items)
    return f'<div class="space-y-1">{joined}</div>'


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
            f'<div class="bg-[#0B1324] rounded-lg p-6 shadow-sm border border-[#131e36]">'
            f'<h3 class="font-bold text-white mb-4 flex items-center gap-2">'
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
        f'<div class="bg-[#0B1324] rounded-lg p-6 shadow-sm border border-[#131e36]">'
        f'<h3 class="font-bold text-white mb-4 flex items-center gap-2">'
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
    """Build HTML report using a modern analyst-focused template."""

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

    
    mitre_md = _extract_section(summary_text, "Threat Intel & MITRE ATT&CK")
    if not mitre_md:
        mitre_md = _extract_section(summary_text, "MITRE ATT&CK Tactics & Techniques")
    capabilities_md = _extract_section(summary_text, "Malware Capabilities")
    technical_md = _extract_section(summary_text, "Technical Analysis")
    functions_md = _extract_section(summary_text, "Functions Analysis")
    operational_md = _extract_section(summary_text, "Operational Flow")
    evidence_md = _extract_section(summary_text, "Evidence of Malicious Activity")
    conclusion_text = _extract_section(summary_text, "Conclusion")
    evidence_items = _extract_evidence(summary_text)
    recommendations = _extract_recommendations(summary_text)

    # Render sections with dedicated card-based renderers
    mitre_html = _render_mitre_cards(mitre_md)
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
            /* Section cards — minimal padding */
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
            /* Spacing — aggressive compaction */
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
            /* Grid — keep multi-column */
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
            animation: slide 18s linear infinite;
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
            <a href="#mitre-attack" class="nav-link px-3 py-2 rounded"><i class="fas fa-spider"></i><span>Threat Intel</span></a>
            <a href="#capabilities" class="nav-link px-3 py-2 rounded"><i class="fas fa-bolt"></i><span>Malware Capabilities</span></a>
            <a href="#binary-info" class="nav-link px-3 py-2 rounded"><i class="fas fa-file-code"></i><span>Binary Information</span></a>
            <a href="#technical-analysis" class="nav-link px-3 py-2 rounded"><i class="fas fa-microscope"></i><span>Technical Analysis</span></a>
            <a href="#functions-analysis" class="nav-link px-3 py-2 rounded"><i class="fas fa-cubes"></i><span>Functions Analysis</span></a>
            <a href="#evidence" class="nav-link px-3 py-2 rounded"><i class="fas fa-fingerprint"></i><span>Evidence</span></a>
            <a href="#code-evidence" class="nav-link px-3 py-2 rounded"><i class="fas fa-code"></i><span>Code Evidence</span></a>
            <a href="#operational-flow" class="nav-link px-3 py-2 rounded"><i class="fas fa-route"></i><span>Operational Flow</span></a>
            <a href="#call-graph" class="nav-link px-3 py-2 rounded"><i class="fas fa-project-diagram"></i><span>Call Graph</span></a>
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
                <a href="#iocs" class="px-3 py-1.5 rounded-full border border-slate-600/40 bg-slate-900/60 text-xs uppercase font-bold tracking-wide">IOCs</a>
            </div>
            <div class="report-shell rounded-xl overflow-hidden">

                <!-- Header -->
                <header class="hero-panel p-6 lg:p-8" role="banner">
                    <div class="grid lg:grid-cols-[1fr_260px] gap-6 items-start">
                        <div>
                            <p class="text-[10px] font-bold uppercase tracking-[0.2em] text-cyan-300/90 mb-2">Ghidra &amp; Radare2 Analysis</p>
                            <h1 class="text-3xl lg:text-4xl font-display font-bold text-white mb-2 tracking-tight">Reverse Engineering Report</h1>
                            <p class="text-sm lg:text-[15px] text-slate-300 max-w-3xl leading-relaxed">
                                This report fuses Ghidra and Radare2 findings into a readable intelligence layout while preserving exact evidence from decompiled code and extracted indicators.
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
                            <div class="text-[11px] text-slate-400">Suspicious or high-priority functions</div>
                        </div>
                        <div class="stat-card p-3">
                            <div class="text-[10px] uppercase tracking-[0.15em] text-slate-400 font-bold">Attack Chains</div>
                            <div class="text-xl font-display font-bold text-white mt-1">{chain_total}</div>
                            <div class="text-[11px] text-slate-400">Sink-reaching graph paths</div>
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

                    
                    <!-- MITRE ATT&CK -->
                    {('<section id="mitre-attack" class="scroll-mt-20 section-card"><div class="section-title-wrap"><div class="section-icon"><i class="fas fa-spider"></i></div><div><p class="section-eyebrow">02 · Threat Context</p><h2 class="section-headline">Threat Intel &amp; MITRE ATT&amp;CK</h2><p class="section-subtitle">Mapped tactics and techniques linked to concrete static-analysis artifacts.</p></div></div><div class="section-body">' + mitre_html + '</div></section>') if mitre_html else ''}

                    <!-- 2. Malware Capabilities -->
                    <section id="capabilities" class="scroll-mt-20 section-card">
                        <div class="section-title-wrap">
                            <div class="section-icon"><i class="fas fa-bolt"></i></div>
                            <div>
                                <p class="section-eyebrow">03 · Behavior Deck</p>
                                <h2 class="section-headline">Malware Capabilities</h2>
                                <p class="section-subtitle">Capability statements paired with direct evidence from function bodies or strings.</p>
                            </div>
                        </div>
                        <div class="section-body">{capabilities_html}</div>
                    </section>

                    <!-- 3. Binary Information -->
                    <section id="binary-info" class="scroll-mt-20 section-card">
                        <div class="section-title-wrap">
                            <div class="section-icon"><i class="fas fa-file-code"></i></div>
                            <div>
                                <p class="section-eyebrow">04 · Binary Profile</p>
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
                                <p class="section-eyebrow">05 · Deep Technical Dive</p>
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
                                <p class="section-eyebrow">06 · Function Triage</p>
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
                                <p class="section-eyebrow">07 · Evidence Register</p>
                                <h2 class="section-headline">Evidence of Malicious Activity</h2>
                                <p class="section-subtitle">Structured findings that can be cited directly in IR and hunting workflows.</p>
                            </div>
                        </div>
                        <div class="section-body">{evidence_html}</div>
                    </section>

                    <!-- 6b. Code Evidence -->
                    <section id="code-evidence" class="scroll-mt-20 section-card">
                        <div class="section-title-wrap">
                            <div class="section-icon"><i class="fas fa-code"></i></div>
                            <div>
                                <p class="section-eyebrow">08 · Code Anchors</p>
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
                                <p class="section-eyebrow">09 · Execution Story</p>
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
                                <p class="section-eyebrow">10 · Graph Intelligence</p>
                                <h2 class="section-headline">Call Graph &amp; Attack Chains</h2>
                                <p class="section-subtitle">Graph-derived routes from entry points to suspicious sinks.</p>
                            </div>
                        </div>
                        <div class="section-body">{call_graph_html}</div>
                    </section>

                    <!-- 9. IOCs -->
                    <section id="iocs" class="scroll-mt-20 section-card">
                        <div class="section-title-wrap">
                            <div class="section-icon"><i class="fas fa-network-wired"></i></div>
                            <div>
                                <p class="section-eyebrow">11 · Detection Inputs</p>
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
                                <p class="section-eyebrow">12 · Response Plan</p>
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
                                <p class="section-eyebrow">13 · Final Assessment</p>
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
            // Build PDF URL – use embedded API base for file:// contexts
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


async def build_report_pdf(state: Dict[str, Any]) -> bytes:
    """Render the HTML report to an A4 PDF using Playwright headless Chromium.

    Returns the raw PDF bytes.  The layout matches the HTML report exactly
    because we render the same HTML in a real browser engine.
    """
    from playwright.async_api import async_playwright  # lazy import

    html = build_report_html(state)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        # Use a wide viewport so the desktop layout renders properly
        # before being scaled down to A4 by the PDF engine.
        page = await browser.new_page(viewport={"width": 1280, "height": 900})

        # Load the full HTML (with CDN assets) and wait for fonts/scripts
        await page.set_content(html, wait_until="networkidle")

        # Small delay to ensure Tailwind JIT + fonts finish
        await page.wait_for_timeout(2000)

        # Trigger print media so @media print rules apply
        await page.emulate_media(media="print")

        pdf_bytes = await page.pdf(
            format="A4",
            print_background=True,
            margin={"top": "6mm", "right": "5mm", "bottom": "6mm", "left": "5mm"},
            prefer_css_page_size=False,
            scale=0.65,
        )
        await browser.close()

    return pdf_bytes


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
