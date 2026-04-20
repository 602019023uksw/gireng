# -*- coding: utf-8 -*-
"""Enhanced HTML report generation matching professional template format."""

import logging
import re
from datetime import datetime, timezone
from html import escape
from typing import Any, Dict, List

from ghidra_agent.function_priority import is_library_function
from ghidra_agent.ioc_extractor import IOCs, calculate_verdict, extract_iocs_from_state

logger = logging.getLogger(__name__)

# ── Report tone context (set per-build_report_html call) ──
_report_tone: str = "neutral"  # neutral | clean | suspicious | malicious


def _set_report_tone(tone: str) -> None:
    global _report_tone
    _report_tone = tone


def _code_color() -> str:
    """Return Tailwind color name for inline code based on report tone."""
    if _report_tone == "clean":
        return "cyan"
    if _report_tone == "suspicious":
        return "orange"
    if _report_tone == "malicious":
        return "red"
    return "sky"


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
        result += f' ... (+{len(entry_points) - limit} more)'
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
        result += f' ... (+{len(cleaned) - limit} more)'
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

    # Tables  --  skip lines inside <pre><code> blocks
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

    # Paragraphs  --  skip lines inside <pre><code> blocks and placeholder lines
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
    """Parse IOCs into template format  --  include ALL IOCs without truncation."""
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
    # B7 FIX: Include crypto materials and suspicious strings in report table.
    for crypto in iocs.crypto_materials:
        results.append({"type": "Crypto Material", "value": crypto})
    for susp in iocs.suspicious_strings:
        results.append({"type": "Suspicious String", "value": susp})

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

    c = _code_color()

    def _save_ic(m):
        _ic_spans.append(
            f'<code class="bg-slate-100 dark:bg-slate-800 text-{c}-600 '
            f'dark:text-{c}-400 px-1 py-0.5 rounded text-xs font-mono">'
            + m.group(1) + '</code>'
        )
        return f'\x00IC{len(_ic_spans) - 1}\x00'

    s = re.sub(r'`(.+?)`', _save_ic, s)
    s = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', s)

    # Entity chips  --  file paths, MITRE IDs, function names, hex addresses
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
            ev_text = re.sub(r'^Evidence\s*[-: -- ]\s*', '', raw_title, flags=re.IGNORECASE).strip()
            if rest.strip():
                ev_text = ev_text + ' ' + rest.strip() if ev_text else rest.strip()
            if merged:
                merged[-1]['evidence_lines'].append(ev_text)
            else:
                merged.append({'title': 'Finding', 'desc_lines': [], 'evidence_lines': [ev_text]})
        elif is_cap_label:
            # Strip "Capability" prefix: "Capability  --  Raw Socket" → "Raw Socket"
            cap_name = re.sub(r'^Capability\s*[-: -- ]+\s*', '', raw_title, flags=re.IGNORECASE).strip()
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

        # Skip "Code Evidence" sub-headers  --  fold them into previous card
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

    # Severity tiers: first findings are most critical, later ones taper.
    # For clean binaries, tone down to Info/Note severity.
    if _report_tone == "clean":
        _SEV_CFG = [
            ("sev-info", "Note", "fas fa-circle-check", "text-blue-400"),
        ] * 8
    elif _report_tone == "suspicious":
        _SEV_CFG = [
            ("sev-high",     "High",     "fas fa-triangle-exclamation", "text-orange-400"),
            ("sev-high",     "High",     "fas fa-triangle-exclamation", "text-orange-400"),
            ("sev-medium",   "Medium",   "fas fa-circle-info", "text-yellow-400"),
            ("sev-medium",   "Medium",   "fas fa-circle-info", "text-yellow-400"),
            ("sev-low",      "Low",      "fas fa-circle-check", "text-blue-400"),
            ("sev-low",      "Low",      "fas fa-circle-check", "text-blue-400"),
            ("sev-info",     "Info",     "fas fa-circle-question", "text-purple-400"),
            ("sev-info",     "Info",     "fas fa-circle-question", "text-purple-400"),
        ]
    else:
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
            parts = re.split(r'\s*[- -- ]\s*(?:Function|Evidence|Code)[:\s]', item, maxsplit=1)
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

    # Parse numbered steps: 1. **Title**: Description  --  Evidence: ...
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
            ev_split = re.split(r'\s*[- -- ]\s*Evidence[:\s]*', rest, maxsplit=1)
            if len(ev_split) == 2:
                desc = ev_split[0].strip()
                evidence = ev_split[1].strip()
            else:
                desc = rest
                evidence = ''
            steps.append((title, desc, evidence))
        elif steps:
            # Continuation line  --  append to last step's description
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
                ev_split = re.split(r'\s*[- -- ]\s*Evidence[:\s]*', rest, maxsplit=1)
                if len(ev_split) == 2:
                    steps.append((title, ev_split[0].strip(), ev_split[1].strip()))
                else:
                    steps.append((title, rest, ''))

    if not steps:
        return _markdown_to_html(md_text)

    if _report_tone == "clean":
        _flow_colors = ['blue', 'cyan', 'green', 'purple', 'sky', 'teal', 'indigo', 'emerald']
    elif _report_tone == "suspicious":
        _flow_colors = ['orange', 'yellow', 'amber', 'blue', 'purple', 'green', 'cyan', 'pink']
    else:
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


def _render_qiling_dynamic_section(qiling: Dict[str, Any]) -> str:
    if not isinstance(qiling, dict) or not qiling:
        return '<p class="text-sm text-slate-500 italic">Qiling dynamic analysis not available for this sample.</p>'

    cards: List[str] = []

    # ── 1. Execution Overview Card ──────────────────────────────────────
    execution = qiling.get("execution_trace", {})
    if isinstance(execution, dict) and execution:
        success = execution.get("success", False)
        status_color = "emerald" if success else "red"
        status_icon = "fa-check-circle" if success else "fa-times-circle"
        status_text = "Completed" if success else "Failed / Partial"
        instr_count = execution.get("instructions_executed", 0)
        duration = execution.get("duration_ms", 0)
        exit_reason = escape(str(execution.get("exit_reason", "unknown")))
        os_name = escape(str(execution.get("os", "unknown")))
        arch_name = escape(str(execution.get("arch", "unknown")))

        metrics_html = f'''
            <div class="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3">
                <div class="bg-[#060B14] rounded-lg p-3 border border-[#131e36] text-center">
                    <div class="text-xs text-slate-500 uppercase tracking-wider mb-1">Status</div>
                    <div class="text-sm font-bold text-{status_color}-400"><i class="fas {status_icon} mr-1"></i>{status_text}</div>
                </div>
                <div class="bg-[#060B14] rounded-lg p-3 border border-[#131e36] text-center">
                    <div class="text-xs text-slate-500 uppercase tracking-wider mb-1">Instructions</div>
                    <div class="text-sm font-bold text-cyan-400 font-mono">{instr_count:,}</div>
                </div>
                <div class="bg-[#060B14] rounded-lg p-3 border border-[#131e36] text-center">
                    <div class="text-xs text-slate-500 uppercase tracking-wider mb-1">Duration</div>
                    <div class="text-sm font-bold text-blue-400">{duration:,} ms</div>
                </div>
                <div class="bg-[#060B14] rounded-lg p-3 border border-[#131e36] text-center">
                    <div class="text-xs text-slate-500 uppercase tracking-wider mb-1">Exit Reason</div>
                    <div class="text-sm font-bold text-slate-300 truncate" title="{exit_reason}">{exit_reason}</div>
                </div>
            </div>
            <div class="flex flex-wrap gap-2 mt-3">
                <span class="px-2.5 py-1 rounded-full bg-slate-800 border border-slate-700 text-xs text-slate-300"><i class="fas fa-desktop mr-1 text-slate-500"></i>{os_name}</span>
                <span class="px-2.5 py-1 rounded-full bg-slate-800 border border-slate-700 text-xs text-slate-300"><i class="fas fa-microchip mr-1 text-slate-500"></i>{arch_name}</span>
            </div>'''

        cards.append(
            '<div class="bg-[#0B1324] rounded-xl border border-[#131e36] overflow-hidden hover:shadow-[0_0_15px_rgba(0,240,255,0.15)] transition-all duration-200">'
            '<div class="flex items-center gap-3 px-5 py-3 bg-[#060B14] border-b border-[#131e36]">'
            '<div class="w-7 h-7 rounded-lg bg-cyan-900/30 text-cyan-400 flex items-center justify-center flex-shrink-0 text-xs"><i class="fas fa-play-circle"></i></div>'
            '<h3 class="font-bold text-white text-sm">Execution Overview</h3></div>'
            f'<div class="p-5">{metrics_html}</div></div>'
        )

    # ── 2. Instruction Trace Card ───────────────────────────────────────
    instruction_trace = qiling.get("instruction_trace", {})
    if isinstance(instruction_trace, dict) and instruction_trace:
        it_summary = instruction_trace.get("summary", {})
        total_insn = it_summary.get("total_executed", 0) if isinstance(it_summary, dict) else 0
        unique_insn = it_summary.get("unique_mnemonics", 0) if isinstance(it_summary, dict) else 0

        # Mnemonic frequency badges (top_mnemonics is a list of {"mnemonic": str, "count": int})
        freq = it_summary.get("top_mnemonics", []) if isinstance(it_summary, dict) else []
        mnemonic_badges = ""
        if isinstance(freq, list) and freq:
            badge_items = []
            for entry in freq[:20]:
                if not isinstance(entry, dict):
                    continue
                mnem = entry.get("mnemonic", "?")
                count = entry.get("count", 0)
                pct = (count / total_insn * 100) if total_insn > 0 else 0
                # Color-code by category
                if mnem in ("call", "ret", "syscall", "int", "svc"):
                    badge_color = "red"
                elif mnem in ("jmp", "je", "jne", "jz", "jnz", "jg", "jl", "jge", "jle", "ja", "jb", "jae", "jbe", "jc", "jnc", "jo", "jno", "js", "jns", "b", "bl", "bx", "beq", "bne"):
                    badge_color = "amber"
                elif mnem in ("push", "pop", "mov", "lea", "ldr", "str", "stp", "ldp"):
                    badge_color = "blue"
                else:
                    badge_color = "slate"
                badge_items.append(
                    f'<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-{badge_color}-900/30 border border-{badge_color}-700/50 text-xs">'
                    f'<span class="font-mono text-{badge_color}-400">{escape(str(mnem))}</span>'
                    f'<span class="text-{badge_color}-500">{count:,}</span>'
                    f'<span class="text-{badge_color}-600 text-[10px]">({pct:.1f}%)</span></span>'
                )
            mnemonic_badges = f'<div class="flex flex-wrap gap-1.5 mt-3">{" ".join(badge_items)}</div>'

        # OEP candidates
        oep_candidates = instruction_trace.get("oep_candidates", [])
        oep_html = ""
        if isinstance(oep_candidates, list) and oep_candidates:
            oep_rows = []
            for oep in oep_candidates[:5]:
                if isinstance(oep, dict):
                    conf = oep.get("confidence", "unknown")
                    conf_color = "emerald" if conf == "high" else "amber" if conf == "medium" else "slate"
                    oep_rows.append(
                        f'<div class="flex items-center gap-3 px-3 py-2 bg-[#060B14] rounded-lg border border-[#131e36]">'
                        f'<span class="font-mono text-xs text-cyan-400">{escape(str(oep.get("address", "?")))}</span>'
                        f'<span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase bg-{conf_color}-900/30 text-{conf_color}-400 border border-{conf_color}-700/50">{escape(str(conf))}</span>'
                        f'<span class="text-xs text-slate-400">{escape(str(oep.get("reason", "")))}</span></div>'
                    )
            if oep_rows:
                oep_html = (
                    '<div class="mt-4">'
                    '<div class="text-xs font-bold text-amber-400 uppercase tracking-wider mb-2"><i class="fas fa-crosshairs mr-1"></i>Original Entry Point Candidates</div>'
                    f'<div class="space-y-1.5">{"".join(oep_rows)}</div></div>'
                )

        # Sample instructions (first + last)
        instructions = instruction_trace.get("instructions", [])
        sample_html = ""
        if isinstance(instructions, list) and instructions:
            sample_lines = []
            display_insns = instructions[:8]
            if len(instructions) > 16:
                display_insns = instructions[:8] + [None] + instructions[-8:]
            for insn in display_insns:
                if insn is None:
                    sample_lines.append(f'<div class="text-center text-xs text-slate-600 py-0.5">⋮ {len(instructions) - 16:,} more instructions ⋮</div>')
                elif isinstance(insn, dict):
                    addr = escape(str(insn.get("address", "")))
                    mnem = escape(str(insn.get("mnemonic", "")))
                    ops = escape(str(insn.get("operands", "")))
                    sample_lines.append(
                        f'<div class="flex gap-3 font-mono text-xs leading-relaxed">'
                        f'<span class="text-slate-600 w-24 flex-shrink-0">{addr}</span>'
                        f'<span class="text-cyan-400 w-12 flex-shrink-0">{mnem}</span>'
                        f'<span class="text-slate-400">{ops}</span></div>'
                    )
            if sample_lines:
                sample_html = (
                    '<div class="mt-4">'
                    '<div class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2"><i class="fas fa-code mr-1"></i>Instruction Sample</div>'
                    f'<div class="bg-[#060B14] rounded-lg p-3 border border-[#131e36] overflow-x-auto">{"".join(sample_lines)}</div></div>'
                )

        cards.append(
            '<div class="bg-[#0B1324] rounded-xl border border-[#131e36] overflow-hidden hover:shadow-[0_0_15px_rgba(0,240,255,0.15)] transition-all duration-200">'
            '<div class="flex items-center gap-3 px-5 py-3 bg-[#060B14] border-b border-[#131e36]">'
            '<div class="w-7 h-7 rounded-lg bg-violet-900/30 text-violet-400 flex items-center justify-center flex-shrink-0 text-xs"><i class="fas fa-microchip"></i></div>'
            '<h3 class="font-bold text-white text-sm">Instruction Trace</h3>'
            f'<span class="ml-auto px-2 py-0.5 rounded-full bg-violet-900/30 text-violet-400 text-xs font-mono">{total_insn:,} total · {unique_insn:,} unique</span></div>'
            f'<div class="p-5">{mnemonic_badges}{oep_html}{sample_html}</div></div>'
        )

    # ── 3. Syscall Analysis Card ────────────────────────────────────────
    syscalls = qiling.get("syscalls", {})
    if isinstance(syscalls, dict) and syscalls:
        summary = syscalls.get("summary", {})
        if isinstance(summary, dict) and summary:
            total_calls = summary.get("total_calls", 0)
            categories = summary.get("categories", {})

            # Category breakdown as mini-bars
            cat_html = ""
            if isinstance(categories, dict) and categories:
                sorted_cats = sorted(categories.items(), key=lambda x: x[1], reverse=True)
                cat_items = []
                max_count = max(categories.values()) if categories else 1
                _cat_colors = ["cyan", "blue", "violet", "amber", "emerald", "rose", "slate"]
                for idx, (cat_name, cat_count) in enumerate(sorted_cats[:7]):
                    pct = (cat_count / total_calls * 100) if total_calls > 0 else 0
                    bar_width = max(5, int(cat_count / max_count * 100))
                    color = _cat_colors[idx % len(_cat_colors)]
                    cat_items.append(
                        f'<div class="flex items-center gap-3">'
                        f'<span class="text-xs text-slate-400 w-28 flex-shrink-0 truncate" title="{escape(str(cat_name))}">{escape(str(cat_name))}</span>'
                        f'<div class="flex-1 bg-[#060B14] rounded-full h-2 overflow-hidden"><div class="h-full bg-{color}-500 rounded-full" style="width:{bar_width}%"></div></div>'
                        f'<span class="text-xs font-mono text-{color}-400 w-16 text-right">{cat_count:,} <span class="text-slate-600">({pct:.0f}%)</span></span></div>'
                    )
                cat_html = f'<div class="space-y-2 mt-3">{"".join(cat_items)}</div>'

            # Suspicious syscalls
            suspicious = summary.get("suspicious_calls", [])
            suspicious_html = ""
            if isinstance(suspicious, list) and suspicious:
                sus_items = []
                for item in suspicious[:12]:
                    name = item.get("name", str(item)) if isinstance(item, dict) else str(item)
                    reason = item.get("reason", "") if isinstance(item, dict) else ""
                    sus_items.append(
                        f'<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-red-900/30 border border-red-700/50 text-xs">'
                        f'<i class="fas fa-exclamation-triangle text-[9px] text-red-500"></i>'
                        f'<span class="text-red-400">{escape(str(name))}</span></span>'
                    )
                suspicious_html = (
                    '<div class="mt-4">'
                    '<div class="text-xs font-bold text-red-400 uppercase tracking-wider mb-2"><i class="fas fa-shield-alt mr-1"></i>Suspicious Syscalls</div>'
                    f'<div class="flex flex-wrap gap-1.5">{"".join(sus_items)}</div></div>'
                )

            cards.append(
                '<div class="bg-[#0B1324] rounded-xl border border-[#131e36] overflow-hidden hover:shadow-[0_0_15px_rgba(0,240,255,0.15)] transition-all duration-200">'
                '<div class="flex items-center gap-3 px-5 py-3 bg-[#060B14] border-b border-[#131e36]">'
                '<div class="w-7 h-7 rounded-lg bg-blue-900/30 text-blue-400 flex items-center justify-center flex-shrink-0 text-xs"><i class="fas fa-terminal"></i></div>'
                '<h3 class="font-bold text-white text-sm">Syscall Analysis</h3>'
                f'<span class="ml-auto px-2 py-0.5 rounded-full bg-blue-900/30 text-blue-400 text-xs font-mono">{total_calls:,} calls</span></div>'
                f'<div class="p-5">{cat_html}{suspicious_html}</div></div>'
            )

    # ── 4. API Calls Card ───────────────────────────────────────────────
    api_calls = qiling.get("api_calls", {})
    if isinstance(api_calls, dict) and api_calls:
        api_summary = api_calls.get("summary", {})
        api_list = api_calls.get("api_calls", [])
        dynamic_imports = api_calls.get("dynamic_imports", [])
        if isinstance(api_summary, dict):
            api_total = api_summary.get("total_calls", len(api_list) if isinstance(api_list, list) else 0)
            modules = api_summary.get("modules_used", [])
            suspicious_apis = api_summary.get("suspicious_apis", [])
            dynamic_total = (
                api_summary.get("dynamic_imports_count", len(dynamic_imports))
                if isinstance(dynamic_imports, list)
                else 0
            )

            # Module badges
            mod_html = ""
            if isinstance(modules, list) and modules:
                mod_items = [
                    f'<span class="px-2 py-0.5 rounded-full bg-emerald-900/30 border border-emerald-700/50 text-xs text-emerald-400">{escape(str(m))}</span>'
                    for m in modules[:15]
                ]
                mod_html = f'<div class="flex flex-wrap gap-1.5 mt-2">{"".join(mod_items)}</div>'

            # Suspicious API list
            sus_api_html = ""
            if isinstance(suspicious_apis, list) and suspicious_apis:
                sus_rows = []
                for api in suspicious_apis[:10]:
                    if isinstance(api, dict):
                        api_name = escape(str(api.get("name", "unknown")))
                        api_reason = escape(str(api.get("reason", "")))
                        api_count = api.get("count", 1)
                        sus_rows.append(
                            f'<div class="flex items-center gap-3 px-3 py-2 bg-[#060B14] rounded-lg border border-red-900/30">'
                            f'<i class="fas fa-bug text-xs text-red-500"></i>'
                            f'<span class="text-sm font-mono text-red-400">{api_name}</span>'
                            f'<span class="text-xs text-slate-500">×{api_count}</span>'
                            f'<span class="text-xs text-slate-400 ml-auto">{api_reason}</span></div>'
                        )
                if sus_rows:
                    sus_api_html = (
                        '<div class="mt-4">'
                        '<div class="text-xs font-bold text-red-400 uppercase tracking-wider mb-2"><i class="fas fa-bug mr-1"></i>Suspicious APIs</div>'
                        f'<div class="space-y-1.5">{"".join(sus_rows)}</div></div>'
                    )

            dynamic_html = ""
            if isinstance(dynamic_imports, list) and dynamic_imports:
                dyn_items = []
                for item in dynamic_imports[:24]:
                    if not isinstance(item, dict):
                        continue
                    name = escape(str(item.get("name", "")))
                    if not name:
                        continue
                    dyn_items.append(
                        '<span class="px-2 py-0.5 rounded-full bg-indigo-900/30 border border-indigo-700/50 '
                        'text-xs text-indigo-300 font-mono">'
                        f"{name}</span>"
                    )
                if dyn_items:
                    dynamic_html = (
                        '<div class="mt-4">'
                        '<div class="text-xs font-bold text-indigo-300 uppercase tracking-wider mb-2">'
                        '<i class="fas fa-link mr-1"></i>Dynamically Resolved APIs</div>'
                        f'<div class="flex flex-wrap gap-1.5">{"".join(dyn_items)}</div>'
                        f'<div class="text-[11px] text-slate-500 mt-2">{int(dynamic_total):,} resolved entries</div>'
                        '</div>'
                    )

            cards.append(
                '<div class="bg-[#0B1324] rounded-xl border border-[#131e36] overflow-hidden hover:shadow-[0_0_15px_rgba(0,240,255,0.15)] transition-all duration-200">'
                '<div class="flex items-center gap-3 px-5 py-3 bg-[#060B14] border-b border-[#131e36]">'
                '<div class="w-7 h-7 rounded-lg bg-emerald-900/30 text-emerald-400 flex items-center justify-center flex-shrink-0 text-xs"><i class="fas fa-plug"></i></div>'
                '<h3 class="font-bold text-white text-sm">Win32 API Calls</h3>'
                f'<span class="ml-auto px-2 py-0.5 rounded-full bg-emerald-900/30 text-emerald-400 text-xs font-mono">{api_total:,} calls</span></div>'
                f'<div class="p-5">{mod_html}{sus_api_html}{dynamic_html}</div></div>'
            )

    # ── 5. Network Activity Card ────────────────────────────────────────
    network = qiling.get("network_activity", {})
    if isinstance(network, dict) and network:
        indicators = network.get("indicators", {}) if isinstance(network, dict) else {}
        connections = network.get("connections", [])
        dns_queries = network.get("dns_queries", [])

        net_rows: List[str] = []

        # C2 candidates
        c2 = indicators.get("c2_candidates", []) if isinstance(indicators, dict) else []
        if isinstance(c2, list) and c2:
            c2_items = [
                f'<span class="px-2 py-0.5 rounded-full bg-red-900/30 border border-red-700/50 text-xs text-red-400 font-mono">{escape(str(v))}</span>'
                for v in c2[:15]
            ]
            net_rows.append(
                '<div class="mt-2"><div class="text-xs font-bold text-red-400 uppercase tracking-wider mb-2"><i class="fas fa-satellite-dish mr-1"></i>C2 Candidates</div>'
                f'<div class="flex flex-wrap gap-1.5">{"".join(c2_items)}</div></div>'
            )

        # DNS domains
        dns_domains = indicators.get("dns_domains", []) if isinstance(indicators, dict) else []
        if isinstance(dns_domains, list) and dns_domains:
            dns_items = [
                f'<span class="px-2 py-0.5 rounded-full bg-amber-900/30 border border-amber-700/50 text-xs text-amber-400 font-mono">{escape(str(d))}</span>'
                for d in dns_domains[:15]
            ]
            net_rows.append(
                '<div class="mt-3"><div class="text-xs font-bold text-amber-400 uppercase tracking-wider mb-2"><i class="fas fa-globe mr-1"></i>DNS Domains</div>'
                f'<div class="flex flex-wrap gap-1.5">{"".join(dns_items)}</div></div>'
            )

        # Protocols
        protocols = indicators.get("protocols_used", []) if isinstance(indicators, dict) else []
        if isinstance(protocols, list) and protocols:
            proto_items = [
                f'<span class="px-2 py-0.5 rounded-full bg-blue-900/30 border border-blue-700/50 text-xs text-blue-400">{escape(str(p))}</span>'
                for p in protocols[:10]
            ]
            net_rows.append(
                f'<div class="flex flex-wrap gap-1.5 mt-3">{"".join(proto_items)}</div>'
            )

        # Connection table
        if isinstance(connections, list) and connections:
            conn_rows = []
            for conn in connections[:10]:
                if isinstance(conn, dict):
                    conn_rows.append(
                        f'<tr class="border-b border-[#131e36]">'
                        f'<td class="px-3 py-1.5 text-xs font-mono text-slate-300">{escape(str(conn.get("dst_ip", "?")))}</td>'
                        f'<td class="px-3 py-1.5 text-xs font-mono text-slate-400">{escape(str(conn.get("dst_port", "?")))}</td>'
                        f'<td class="px-3 py-1.5 text-xs text-slate-400">{escape(str(conn.get("protocol", "?")))}</td>'
                        f'<td class="px-3 py-1.5 text-xs text-slate-500">{escape(str(conn.get("type", "")))}</td></tr>'
                    )
            if conn_rows:
                net_rows.append(
                    '<div class="mt-3 overflow-x-auto"><table class="w-full text-left">'
                    '<thead><tr class="border-b border-slate-700">'
                    '<th class="px-3 py-1.5 text-[10px] text-slate-500 uppercase">Destination</th>'
                    '<th class="px-3 py-1.5 text-[10px] text-slate-500 uppercase">Port</th>'
                    '<th class="px-3 py-1.5 text-[10px] text-slate-500 uppercase">Protocol</th>'
                    '<th class="px-3 py-1.5 text-[10px] text-slate-500 uppercase">Type</th>'
                    f'</tr></thead><tbody>{"".join(conn_rows)}</tbody></table></div>'
                )

        if net_rows:
            conn_count = len(connections) if isinstance(connections, list) else 0
            cards.append(
                '<div class="bg-[#0B1324] rounded-xl border border-[#131e36] overflow-hidden hover:shadow-[0_0_15px_rgba(0,240,255,0.15)] transition-all duration-200">'
                '<div class="flex items-center gap-3 px-5 py-3 bg-[#060B14] border-b border-[#131e36]">'
                '<div class="w-7 h-7 rounded-lg bg-red-900/30 text-red-400 flex items-center justify-center flex-shrink-0 text-xs"><i class="fas fa-network-wired"></i></div>'
                '<h3 class="font-bold text-white text-sm">Network Activity</h3>'
                f'<span class="ml-auto px-2 py-0.5 rounded-full bg-red-900/30 text-red-400 text-xs font-mono">{conn_count} connections</span></div>'
                f'<div class="p-5">{"".join(net_rows)}</div></div>'
            )

    # ── 6. Memory Indicators Card ───────────────────────────────────────
    memory = qiling.get("memory_events", {})
    if isinstance(memory, dict) and memory:
        mem_payload = memory.get("memory_events", memory)
        if isinstance(mem_payload, dict):
            indicators = mem_payload.get("indicators", {})
            if isinstance(indicators, dict) and indicators:
                ind_items = []
                for key, val in indicators.items():
                    if isinstance(val, bool):
                        icon = "fa-check text-emerald-400" if val else "fa-times text-slate-600"
                        val_text = "Yes" if val else "No"
                        val_color = "emerald" if val else "slate"
                    elif isinstance(val, (int, float)):
                        icon = "fa-chart-bar text-cyan-400"
                        val_text = f"{val:,}" if isinstance(val, int) else f"{val:.2f}"
                        val_color = "cyan"
                    else:
                        icon = "fa-info-circle text-blue-400"
                        val_text = str(val)
                        val_color = "blue"
                    ind_items.append(
                        f'<div class="flex items-center justify-between px-3 py-2 bg-[#060B14] rounded-lg border border-[#131e36]">'
                        f'<span class="flex items-center gap-2 text-xs text-slate-400"><i class="fas {icon} text-[10px]"></i>{escape(str(key).replace("_", " ").title())}</span>'
                        f'<span class="text-xs font-bold text-{val_color}-400">{escape(str(val_text))}</span></div>'
                    )
                if ind_items:
                    cards.append(
                        '<div class="bg-[#0B1324] rounded-xl border border-[#131e36] overflow-hidden hover:shadow-[0_0_15px_rgba(0,240,255,0.15)] transition-all duration-200">'
                        '<div class="flex items-center gap-3 px-5 py-3 bg-[#060B14] border-b border-[#131e36]">'
                        '<div class="w-7 h-7 rounded-lg bg-amber-900/30 text-amber-400 flex items-center justify-center flex-shrink-0 text-xs"><i class="fas fa-memory"></i></div>'
                        '<h3 class="font-bold text-white text-sm">Memory Indicators</h3></div>'
                        f'<div class="p-5"><div class="grid grid-cols-1 md:grid-cols-2 gap-2">{"".join(ind_items)}</div></div></div>'
                    )

    # ── 7. Evasion Techniques Card ──────────────────────────────────────
    evasion = qiling.get("evasion_techniques", {})
    if isinstance(evasion, dict) and evasion:
        ev_summary = evasion.get("summary", {})
        techniques = evasion.get("techniques", [])

        if isinstance(ev_summary, dict) and ev_summary:
            total_tech = ev_summary.get("total_techniques", 0)
            risk_level = str(ev_summary.get("risk_level", "low"))
            risk_colors = {"critical": "red", "high": "red", "medium": "amber", "low": "emerald"}
            risk_color = risk_colors.get(risk_level.lower(), "slate")

            tech_cards = []
            if isinstance(techniques, list):
                for tech in techniques[:12]:
                    if isinstance(tech, dict):
                        method = escape(str(tech.get("method", "unknown")))
                        mitre_id = escape(str(tech.get("mitre_id", "N/A")))
                        description = escape(str(tech.get("description", "")))
                        category = escape(str(tech.get("category", "")))
                        tech_cards.append(
                            f'<div class="bg-[#060B14] rounded-lg p-3 border border-{risk_color}-900/30">'
                            f'<div class="flex items-center gap-2 mb-1">'
                            f'<span class="text-sm font-bold text-{risk_color}-400">{method}</span>'
                            f'<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-{risk_color}-900/30 text-{risk_color}-400 border border-{risk_color}-700/50">{mitre_id}</span>'
                            f'</div>'
                            f'<div class="text-xs text-slate-400">{description}</div>'
                            f'{"<div class=&quot;text-[10px] text-slate-600 mt-1&quot;>" + category + "</div>" if category else ""}'
                            f'</div>'
                        )

            tech_grid = f'<div class="grid grid-cols-1 md:grid-cols-2 gap-2 mt-3">{"".join(tech_cards)}</div>' if tech_cards else ''

            cards.append(
                '<div class="bg-[#0B1324] rounded-xl border border-[#131e36] overflow-hidden hover:shadow-[0_0_15px_rgba(0,240,255,0.15)] transition-all duration-200">'
                '<div class="flex items-center gap-3 px-5 py-3 bg-[#060B14] border-b border-[#131e36]">'
                '<div class="w-7 h-7 rounded-lg bg-rose-900/30 text-rose-400 flex items-center justify-center flex-shrink-0 text-xs"><i class="fas fa-user-secret"></i></div>'
                '<h3 class="font-bold text-white text-sm">Evasion Techniques</h3>'
                f'<span class="ml-auto flex items-center gap-2">'
                f'<span class="px-2 py-0.5 rounded-full bg-{risk_color}-900/30 text-{risk_color}-400 text-xs font-bold uppercase">{escape(risk_level)} risk</span>'
                f'<span class="px-2 py-0.5 rounded-full bg-rose-900/30 text-rose-400 text-xs font-mono">{total_tech} techniques</span></span></div>'
                f'<div class="p-5">{tech_grid}</div></div>'
            )

    # ── 8. Errors Card (if any) ─────────────────────────────────────────
    errors = qiling.get("errors", [])
    if isinstance(errors, list) and errors:
        err_items = [
            f'<div class="flex items-start gap-2 px-3 py-2 bg-[#060B14] rounded-lg border border-orange-900/30">'
            f'<i class="fas fa-exclamation-triangle text-xs text-orange-500 mt-0.5"></i>'
            f'<span class="text-xs text-orange-400">{escape(str(e))}</span></div>'
            for e in errors[:10]
        ]
        cards.append(
            '<div class="bg-[#0B1324] rounded-xl border border-orange-900/30 overflow-hidden">'
            '<div class="flex items-center gap-3 px-5 py-3 bg-[#060B14] border-b border-orange-900/30">'
            '<div class="w-7 h-7 rounded-lg bg-orange-900/30 text-orange-400 flex items-center justify-center flex-shrink-0 text-xs"><i class="fas fa-exclamation-circle"></i></div>'
            '<h3 class="font-bold text-orange-400 text-sm">Emulation Warnings</h3></div>'
            f'<div class="p-5 space-y-1.5">{"".join(err_items)}</div></div>'
        )

    if not cards:
        return (
            '<div class="bg-[#0B1324] rounded-xl border border-[#131e36] p-8 text-center">'
            '<i class="fas fa-vial text-3xl text-slate-600 mb-3"></i>'
            '<p class="text-sm text-slate-500">Qiling ran but returned no dynamic telemetry.</p></div>'
        )

    return f'<div class="space-y-4">{"".join(cards)}</div>'


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

# APIs that are too generic to be interesting on their own  --  if a function
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
    - The only matched APIs are from the generic-only set (memcpy, memset, ...).
    """
    # Only apply to anonymous / unhelpful function names
    if not re.match(r'^(?:fcn\.|sub_|FUN_)', func_name):
        return False

    # OpenSSL / crypto library internal strings in the code body
    if _OPENSSL_CONTENT_RE.search(code):
        return True

    # Function only matched low-value generic APIs  --  skip it
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
                                        <td>Ghidra: {len(strings_data.get('strings', []))} &middot; R2: {len(r2_strings.get('strings', []))} extracted</td></tr>'''

    has_qiling = bool(qiling_results)
    qiling_section_no = "12" if has_qiling else "11"
    iocs_section_no = "13" if has_qiling else "12"
    recommendations_section_no = "14" if has_qiling else "13"
    conclusion_section_no = "15" if has_qiling else "14"
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


def _pdf_md_to_html(text: str) -> str:
    """Lightweight markdown→HTML for PDF (light-mode, no Tailwind dark: classes)."""
    if not text:
        return ""
    safe = escape(text)

    # Code blocks
    code_blocks: list[str] = []
    def _save_cb(m):
        code_blocks.append(m.group(2))
        return f'\x00CB{len(code_blocks)-1}\x00'
    safe = re.sub(r'```(\w+)?\n(.*?)```', _save_cb, safe, flags=re.DOTALL)

    # Inline code
    inline: list[str] = []
    def _save_ic(m):
        inline.append(m.group(1))
        return f'\x00IC{len(inline)-1}\x00'
    safe = re.sub(r'`(.+?)`', _save_ic, safe)

    # Bold / italic
    safe = re.sub(r'\*\*\*(.+?)\*\*\*', r'<strong><em>\1</em></strong>', safe)
    safe = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', safe)
    safe = re.sub(r'\*(.+?)\*', r'<em>\1</em>', safe)

    # Headers → styled headings
    safe = re.sub(r'####\s+(.+)$', r'<h4 style="font-size:0.8rem;font-weight:700;margin:0.6rem 0 0.2rem;color:#1e293b;">\1</h4>', safe, flags=re.MULTILINE)
    safe = re.sub(r'###\s+(.+)$', r'<h3 style="font-size:0.85rem;font-weight:700;margin:0.6rem 0 0.2rem;color:#1e293b;">\1</h3>', safe, flags=re.MULTILINE)
    safe = re.sub(r'##\s+(.+)$', r'<h2 style="font-size:0.9rem;font-weight:700;margin:0.7rem 0 0.3rem;color:#0f172a;">\1</h2>', safe, flags=re.MULTILINE)

    # Bullet lists
    lines = safe.split('\n')
    out: list[str] = []
    in_ul = False
    for ln in lines:
        s = ln.strip()
        if s.startswith('- ') or s.startswith('* '):
            if not in_ul:
                out.append('<ul style="margin:0.3rem 0;padding-left:1.2rem;list-style:disc;">')
                in_ul = True
            out.append(f'<li style="margin-bottom:0.15rem;font-size:0.72rem;color:#334155;">{s[2:]}</li>')
        else:
            if in_ul and s:
                out.append('</ul>')
                in_ul = False
            out.append(ln)
    if in_ul:
        out.append('</ul>')
    safe = '\n'.join(out)

    # Numbered lists
    lines = safe.split('\n')
    out = []
    in_ol = False
    for ln in lines:
        s = ln.strip()
        m = re.match(r'^(\d+)\.\s+(.+)', s)
        if m and not s.startswith('<'):
            if not in_ol:
                out.append('<ol style="margin:0.3rem 0;padding-left:1.2rem;list-style:decimal;">')
                in_ol = True
            out.append(f'<li style="margin-bottom:0.15rem;font-size:0.72rem;color:#334155;">{m.group(2)}</li>')
        else:
            if in_ol and s:
                out.append('</ol>')
                in_ol = False
            out.append(ln)
    if in_ol:
        out.append('</ol>')
    safe = '\n'.join(out)

    # Paragraphs
    lines = safe.split('\n')
    out = []
    for ln in lines:
        s = ln.strip()
        if s and not s.startswith('<') and '\x00CB' not in s:
            out.append(f'<p style="margin:0.2rem 0;font-size:0.72rem;line-height:1.5;color:#334155;">{s}</p>')
        else:
            out.append(ln)
    safe = '\n'.join(out)

    # Restore code
    for i, blk in enumerate(code_blocks):
        safe = safe.replace(f'\x00CB{i}\x00',
            f'<pre style="background:#f1f5f9;border:1px solid #e2e8f0;border-radius:4px;padding:0.4rem;font-size:0.6rem;line-height:1.35;overflow-x:auto;margin:0.3rem 0;"><code>{blk}</code></pre>')
    for i, ic in enumerate(inline):
        safe = safe.replace(f'\x00IC{i}\x00',
            f'<code style="background:#f1f5f9;color:#dc2626;padding:0.1rem 0.25rem;border-radius:3px;font-size:0.65rem;">{ic}</code>')
    return safe


def _pdf_code_evidence(state: Dict[str, Any]) -> str:
    """Render code evidence for PDF  --  light-mode code blocks."""
    decomp_cache = state.get("decompilation_cache", {})
    r2_decomp_cache = state.get("r2_decompilation_cache", {})
    func_data = state.get("analysis_results", {}).get("functions", {})
    r2_func_data = state.get("r2_analysis_results", {}).get("functions", {})

    addr_map: Dict[str, str] = {}
    for flist in [func_data.get("functions", []), r2_func_data.get("functions", [])]:
        for f in flist:
            addr_map[f.get("name", "")] = f.get("address", "?")

    blocks: list[str] = []
    for source, cache in [("Ghidra", decomp_cache), ("Radare2", r2_decomp_cache)]:
        for func_name, code in cache.items():
            is_lib = is_library_function(func_name)
            api_set = _HIGH_VALUE_APIS if is_lib else (_HIGH_VALUE_APIS | _CONTEXT_APIS)
            found_apis = [api for api in api_set if _API_WORD_RE[api].search(code)]
            if not found_apis:
                continue
            if not is_lib and _is_library_content(func_name, code, found_apis):
                is_lib = True
            if is_lib:
                non_crypto = [a for a in found_apis if a not in _CONTEXT_APIS]
                if not non_crypto:
                    continue
                found_apis = non_crypto

            addr = addr_map.get(func_name, "?")
            interesting: list[str] = []
            for line in code.split("\n"):
                ls = line.strip()
                if any(_API_WORD_RE[api].search(ls) for api in found_apis):
                    interesting.append(line.rstrip())
                    if len(interesting) >= 8:
                        break
            if not interesting:
                continue

            snippet = escape("\n".join(interesting))
            apis_str = ", ".join(sorted(set(found_apis)))
            blocks.append(
                f'<div style="border:1px solid #e2e8f0;border-radius:6px;margin-bottom:0.5rem;overflow:hidden;break-inside:avoid;">'
                f'<div style="background:#f8fafc;padding:0.3rem 0.6rem;border-bottom:1px solid #e2e8f0;display:flex;justify-content:space-between;align-items:center;">'
                f'<span style="font-size:0.6rem;color:#64748b;font-family:monospace;">[{escape(source)}] {escape(func_name)} @ {escape(str(addr))}</span>'
                f'<span style="font-size:0.55rem;color:#dc2626;font-family:monospace;font-weight:600;">{escape(apis_str)}</span></div>'
                f'<pre style="margin:0;padding:0.4rem 0.6rem;font-size:0.55rem;line-height:1.4;background:#fafbfc;overflow-x:auto;"><code>{snippet}</code></pre>'
                f'</div>'
            )
            if len(blocks) >= 10:
                break
        if len(blocks) >= 10:
            break

    if not blocks:
        return '<p style="font-size:0.7rem;color:#94a3b8;font-style:italic;">No suspicious API calls detected.</p>'
    return "\n".join(blocks)


def _build_pdf_html(state: Dict[str, Any]) -> str:
    """Build a clean, white-background professional PDF report HTML.

    This is a self-contained, light-mode HTML document designed *exclusively*
    for Playwright → A4 PDF rendering.  No Tailwind CDN, no JavaScript  --  pure
    inline-CSS to guarantee deterministic output.
    """
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

    # --- Extract LLM sections ---
    exec_summary = _extract_section(summary_text, "Executive Summary")
    if not exec_summary:
        fb = re.sub(r'^#{2,3}\\s+.*$', '', summary_text[:2000], flags=re.MULTILINE).strip()
        exec_summary = fb or summary_text[:2000]

    mitre_md = _extract_section(summary_text, "Threat Intel & MITRE ATT&CK") or _extract_section(summary_text, "MITRE ATT&CK Tactics & Techniques")
    capabilities_md = _extract_section(summary_text, "Malware Capabilities")
    technical_md = _extract_section(summary_text, "Technical Analysis")
    functions_md = _extract_section(summary_text, "Functions Analysis")
    operational_md = _extract_section(summary_text, "Operational Flow")
    evidence_md = _extract_section(summary_text, "Evidence of Malicious Activity")
    conclusion_text = _extract_section(summary_text, "Conclusion")
    evidence_items = _extract_evidence(summary_text)
    recommendations = _extract_recommendations(summary_text)
    ioc_list = _parse_iocs_for_template(iocs)

    # --- Binary metadata ---
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

    gh_funcs = funcs.get("functions", []) or []
    r2_func_list = r2_funcs.get("functions", []) or []
    total_functions = len(gh_funcs) + len(r2_func_list)
    gh_decomp = len(state.get("decompilation_cache", {}))
    r2_decomp = len(state.get("r2_decompilation_cache", {}))
    decompiled_total = gh_decomp + r2_decomp
    total_strings = len(strings_data.get("strings", [])) + len(r2_strings.get("strings", []))
    ioc_total = len(ioc_list)
    chain_total = len(gh_call_graph.get("chains", []) or []) + len(r2_call_graph.get("chains", []) or [])

    # Verdict colors (light-mode)
    _VC = {
        "malicious": ("#dc2626", "#fef2f2", "#991b1b", "MALICIOUS"),
        "suspicious": ("#ea580c", "#fff7ed", "#9a3412", "SUSPICIOUS"),
        "clean": ("#16a34a", "#f0fdf4", "#166534", "CLEAN"),
        "unknown": ("#6b7280", "#f9fafb", "#374151", "UNKNOWN"),
    }
    v_color, v_bg, v_dark, v_label = _VC.get(verdict_class, _VC["unknown"])

    # ---- Render content sections via light-mode markdown ----
    exec_html = _pdf_md_to_html(exec_summary)
    mitre_html = _pdf_md_to_html(mitre_md) if mitre_md else ""
    cap_html = _pdf_md_to_html(capabilities_md) if capabilities_md else ""
    tech_html = _pdf_md_to_html(technical_md) if technical_md else ""
    func_html = _pdf_md_to_html(functions_md) if functions_md else ""
    ops_html = _pdf_md_to_html(operational_md) if operational_md else ""
    evidence_html_md = _pdf_md_to_html(evidence_md) if evidence_md else ""
    code_ev_html = _pdf_code_evidence(state)
    conclusion_html = _pdf_md_to_html(conclusion_text) if conclusion_text else (
        f'<p style="font-size:0.72rem;color:#334155;">This binary has been classified as <strong>{escape(verdict)}</strong> '
        f'with a risk score of {score}/100. Review the technical analysis and IOCs above for detection and response guidance.</p>'
    )

    # ---- IOC rows ----
    ioc_rows = ""
    for ic in ioc_list:
        ioc_rows += f'<tr><td style="padding:0.25rem 0.5rem;font-size:0.65rem;border-bottom:1px solid #f1f5f9;color:#64748b;font-weight:600;">{escape(ic["type"])}</td><td style="padding:0.25rem 0.5rem;font-size:0.65rem;border-bottom:1px solid #f1f5f9;color:#1e293b;font-family:monospace;word-break:break-all;">{escape(ic["value"])}</td></tr>'

    # ---- Evidence items ----
    ev_items_html = ""
    for i, item in enumerate(evidence_items, 1):
        chunks = item.split(' - Evidence:', 1)
        if len(chunks) == 2:
            title, desc = chunks[0].strip(), chunks[1].strip()
        else:
            raw = item.strip()
            dot = raw.find('.')
            if 0 < dot < 80:
                title, desc = raw[:dot], raw[dot+1:].strip()
            else:
                title, desc = raw[:80], raw[80:].strip()
        sev_color = "#dc2626" if i <= 3 else "#ea580c"
        sev_label = "HIGH" if i <= 3 else "MEDIUM"
        desc_part = f'<div style="font-size:0.62rem;color:#64748b;margin-top:0.1rem;">{escape(desc)}</div>' if desc else ''
        ev_items_html += (
            f'<div style="border-left:3px solid {sev_color};padding:0.35rem 0.6rem;margin-bottom:0.35rem;background:#fafbfc;border-radius:0 4px 4px 0;break-inside:avoid;">'
            f'<div style="display:flex;align-items:center;gap:0.4rem;">'
            f'<span style="font-size:0.5rem;font-weight:800;color:{sev_color};letter-spacing:0.05em;">{sev_label}</span>'
            f'<span style="font-size:0.68rem;font-weight:600;color:#1e293b;">{escape(title)}</span>'
            f'</div>{desc_part}</div>'
        )

    # ---- Recommendations ----
    rec_html = ""
    for i, rec in enumerate(recommendations, 1):
        safe = escape(rec)
        safe = re.sub(r'\*\*(.+?)\*\*', r'\1', safe)
        if ':' in safe:
            rtitle, rdesc = safe.split(':', 1)
        else:
            rtitle, rdesc = f'Recommendation {i}', safe
        rec_html += (
            f'<div style="border:1px solid #e2e8f0;border-radius:4px;padding:0.4rem 0.6rem;margin-bottom:0.3rem;break-inside:avoid;">'
            f'<div style="font-size:0.7rem;font-weight:700;color:#1e293b;margin-bottom:0.1rem;">{rtitle.strip()}</div>'
            f'<div style="font-size:0.62rem;color:#475569;">{rdesc.strip()}</div>'
            f'</div>'
        )

    # ---- Call graph summary ----
    cg_parts: list[str] = []
    for src_name, cg in [("Ghidra", gh_call_graph), ("Radare2", r2_call_graph)]:
        if not cg:
            continue
        nodes = cg.get("total_nodes", 0)
        edges = cg.get("total_edges", 0)
        chains = cg.get("chains", []) or []
        if nodes or edges or chains:
            cg_parts.append(
                f'<div style="border:1px solid #e2e8f0;border-radius:4px;padding:0.4rem 0.6rem;margin-bottom:0.3rem;break-inside:avoid;">'
                f'<div style="font-size:0.7rem;font-weight:700;color:#1e293b;margin-bottom:0.15rem;">{src_name} Call Graph</div>'
                f'<div style="font-size:0.62rem;color:#475569;">{nodes} nodes, {edges} edges, {len(chains)} attack chain(s)</div>'
            )
            for ci, chain in enumerate(chains[:5]):
                path = chain.get("path", [])
                if path:
                    arrow_path = " → ".join(escape(str(p)) for p in path)
                    cg_parts.append(f'<div style="font-size:0.55rem;color:#64748b;font-family:monospace;margin-top:0.1rem;">Chain {ci+1}: {arrow_path}</div>')
            cg_parts.append('</div>')
    cg_html = "\n".join(cg_parts) if cg_parts else '<p style="font-size:0.65rem;color:#94a3b8;font-style:italic;">No call graph data available.</p>'

    # ---- Helper: section block ----
    def _sec(num: str, title: str, body: str, subtitle: str = "") -> str:
        if not body:
            return ""
        sub = f'<div style="font-size:0.6rem;color:#94a3b8;margin-bottom:0.3rem;font-style:italic;">{escape(subtitle)}</div>' if subtitle else ''
        return (
            f'<div style="margin-bottom:0.6rem;">'
            f'<div style="display:flex;align-items:baseline;gap:0.4rem;margin-bottom:0.3rem;border-bottom:2px solid #e2e8f0;padding-bottom:0.25rem;">'
            f'<span style="font-size:0.55rem;font-weight:800;color:#94a3b8;letter-spacing:0.1em;">{num}</span>'
            f'<span style="font-size:0.85rem;font-weight:700;color:#0f172a;">{escape(title)}</span>'
            f'</div>'
            f'{sub}'
            f'{body}'
            f'</div>'
        )

    # ---- Pre-build nested HTML fragments (Python 3.11 cannot nest f''' inside f''') ----
    _stripped_val = (
        'Yes' if r2_binary.get('stripped') is True
        else 'No' if r2_binary.get('stripped') is False
        else str(r2_binary.get('stripped', 'unknown'))
    )
    file_metadata_html = (
        '<table>'
        f'<tr style="background:#f8fafc;"><td style="padding:0.25rem 0.5rem;font-size:0.65rem;font-weight:600;color:#64748b;width:25%;border-bottom:1px solid #f1f5f9;">SHA-256</td><td style="padding:0.25rem 0.5rem;font-size:0.6rem;color:#1e293b;font-family:monospace;border-bottom:1px solid #f1f5f9;word-break:break-all;">{escape(program_hash)}</td></tr>'
        f'<tr><td style="padding:0.25rem 0.5rem;font-size:0.65rem;font-weight:600;color:#64748b;border-bottom:1px solid #f1f5f9;">Architecture</td><td style="padding:0.25rem 0.5rem;font-size:0.65rem;color:#1e293b;border-bottom:1px solid #f1f5f9;">{escape(str(arch))} ({bits}-bit)</td></tr>'
        f'<tr style="background:#f8fafc;"><td style="padding:0.25rem 0.5rem;font-size:0.65rem;font-weight:600;color:#64748b;border-bottom:1px solid #f1f5f9;">Format</td><td style="padding:0.25rem 0.5rem;font-size:0.65rem;color:#1e293b;border-bottom:1px solid #f1f5f9;">{escape(fmt_str)}  --  {escape(str(os_name))}</td></tr>'
        f'<tr><td style="padding:0.25rem 0.5rem;font-size:0.65rem;font-weight:600;color:#64748b;border-bottom:1px solid #f1f5f9;">Image Base</td><td style="padding:0.25rem 0.5rem;font-size:0.65rem;color:#1e293b;font-family:monospace;border-bottom:1px solid #f1f5f9;">{escape(str(binary.get("image_base", "unknown")))}</td></tr>'
        f'<tr style="background:#f8fafc;"><td style="padding:0.25rem 0.5rem;font-size:0.65rem;font-weight:600;color:#64748b;border-bottom:1px solid #f1f5f9;">Entry Points</td><td style="padding:0.25rem 0.5rem;font-size:0.6rem;color:#1e293b;font-family:monospace;border-bottom:1px solid #f1f5f9;">{escape(_format_entry_points(binary.get("entry_points", ["unknown"])))}</td></tr>'
        f'<tr><td style="padding:0.25rem 0.5rem;font-size:0.65rem;font-weight:600;color:#64748b;border-bottom:1px solid #f1f5f9;">Compiler</td><td style="padding:0.25rem 0.5rem;font-size:0.65rem;color:#1e293b;border-bottom:1px solid #f1f5f9;">{escape(_sanitize_compiler(binary.get("compiler", r2_binary.get("compiler", "unknown"))))}</td></tr>'
        f'<tr style="background:#f8fafc;"><td style="padding:0.25rem 0.5rem;font-size:0.65rem;font-weight:600;color:#64748b;border-bottom:1px solid #f1f5f9;">Stripped</td><td style="padding:0.25rem 0.5rem;font-size:0.65rem;color:#1e293b;border-bottom:1px solid #f1f5f9;">{_stripped_val}</td></tr>'
        f'<tr><td style="padding:0.25rem 0.5rem;font-size:0.65rem;font-weight:600;color:#64748b;border-bottom:1px solid #f1f5f9;">Endianness</td><td style="padding:0.25rem 0.5rem;font-size:0.65rem;color:#1e293b;border-bottom:1px solid #f1f5f9;">{escape(str(r2_binary.get("endian", "unknown")))}</td></tr>'
        f'<tr style="background:#f8fafc;"><td style="padding:0.25rem 0.5rem;font-size:0.65rem;font-weight:600;color:#64748b;border-bottom:1px solid #f1f5f9;">Imports</td><td style="padding:0.25rem 0.5rem;font-size:0.6rem;color:#1e293b;border-bottom:1px solid #f1f5f9;">{escape(_format_import_export_list(binary.get("imports", [])))}</td></tr>'
        f'<tr><td style="padding:0.25rem 0.5rem;font-size:0.65rem;font-weight:600;color:#64748b;border-bottom:1px solid #f1f5f9;">Exports</td><td style="padding:0.25rem 0.5rem;font-size:0.65rem;color:#1e293b;border-bottom:1px solid #f1f5f9;">{len(binary.get("exports", []))} symbols</td></tr>'
        f'<tr style="background:#f8fafc;"><td style="padding:0.25rem 0.5rem;font-size:0.65rem;font-weight:600;color:#64748b;border-bottom:1px solid #f1f5f9;">Functions</td><td style="padding:0.25rem 0.5rem;font-size:0.65rem;color:#1e293b;border-bottom:1px solid #f1f5f9;">Ghidra: {len(gh_funcs)} ({gh_decomp} decompiled) &middot; R2: {len(r2_func_list)} ({r2_decomp} decompiled)</td></tr>'
        f'<tr><td style="padding:0.25rem 0.5rem;font-size:0.65rem;font-weight:600;color:#64748b;">Strings</td><td style="padding:0.25rem 0.5rem;font-size:0.65rem;color:#1e293b;">Ghidra: {len(strings_data.get("strings", []))} &middot; R2: {len(r2_strings.get("strings", []))} extracted</td></tr>'
        '</table>'
    )

    # ---- Build HTML ----
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  @page {{ size: A4; margin: 0; }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    font-size: 10pt;
    color: #1e293b;
    background: #ffffff;
    line-height: 1.5;
  }}
  .page {{
    max-width: 100%;
    padding: 12mm 14mm;
  }}
  table {{ border-collapse: collapse; width: 100%; }}
  code {{ font-family: 'Consolas', 'Monaco', 'Courier New', monospace; }}
</style>
</head>
<body>
<div class="page">

  <!-- Header -->
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:0.8rem;padding-bottom:0.5rem;border-bottom:3px solid #0f172a;">
    <div>
      <div style="font-size:0.55rem;font-weight:800;letter-spacing:0.15em;text-transform:uppercase;color:#64748b;">Reverse Engineering Intelligence Report</div>
      <div style="font-size:1.4rem;font-weight:800;color:#0f172a;margin-top:0.1rem;">{file_name}</div>
      <div style="font-size:0.6rem;color:#64748b;margin-top:0.15rem;">Ghidra &amp; Radare2 Dual-Engine Analysis</div>
    </div>
    <div style="text-align:right;">
      <div style="display:inline-block;background:{v_bg};border:2px solid {v_color};border-radius:6px;padding:0.3rem 0.8rem;">
        <div style="font-size:0.5rem;font-weight:800;letter-spacing:0.1em;color:{v_color};">VERDICT</div>
        <div style="font-size:1rem;font-weight:800;color:{v_dark};">{v_label}</div>
        <div style="font-size:0.55rem;color:{v_color};">Score: {score}/100</div>
      </div>
    </div>
  </div>

  <!-- Meta strip -->
  <div style="display:flex;gap:0.6rem;flex-wrap:wrap;margin-bottom:0.6rem;font-size:0.6rem;color:#64748b;">
    <span><strong>SHA-256:</strong> <code style="font-size:0.55rem;color:#1e293b;">{escape(program_hash)}</code></span>
    <span>|</span>
    <span><strong>Format:</strong> {escape(fmt_str)} ({bits}-bit)</span>
    <span>|</span>
    <span><strong>Arch:</strong> {escape(str(arch))}</span>
    <span>|</span>
    <span><strong>OS:</strong> {escape(str(os_name))}</span>
    <span>|</span>
    <span><strong>Generated:</strong> {timestamp}</span>
  </div>

  <!-- Stats bar -->
  <div style="display:flex;gap:0.4rem;margin-bottom:0.8rem;">
    <div style="flex:1;background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:0.35rem 0.5rem;text-align:center;">
      <div style="font-size:1rem;font-weight:800;color:#0f172a;">{total_functions}</div>
      <div style="font-size:0.5rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em;">Functions</div>
    </div>
    <div style="flex:1;background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:0.35rem 0.5rem;text-align:center;">
      <div style="font-size:1rem;font-weight:800;color:#0f172a;">{decompiled_total}</div>
      <div style="font-size:0.5rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em;">Decompiled</div>
    </div>
    <div style="flex:1;background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:0.35rem 0.5rem;text-align:center;">
      <div style="font-size:1rem;font-weight:800;color:#0f172a;">{total_strings}</div>
      <div style="font-size:0.5rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em;">Strings</div>
    </div>
    <div style="flex:1;background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:0.35rem 0.5rem;text-align:center;">
      <div style="font-size:1rem;font-weight:800;color:#0f172a;">{chain_total}</div>
      <div style="font-size:0.5rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em;">Attack Chains</div>
    </div>
    <div style="flex:1;background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:0.35rem 0.5rem;text-align:center;">
      <div style="font-size:1rem;font-weight:800;color:#0f172a;">{ioc_total}</div>
      <div style="font-size:0.5rem;color:#94a3b8;text-transform:uppercase;letter-spacing:0.05em;">IOCs</div>
    </div>
  </div>

  <!-- Sections -->

  <!-- Maliciousness Assessment Banner -->
  <div style="margin-bottom:0.7rem;padding:0.6rem 0.8rem;background:{v_bg};border:2px solid {v_color};border-radius:6px;display:flex;justify-content:space-between;align-items:center;break-inside:avoid;">
    <div>
      <div style="font-size:0.5rem;font-weight:800;letter-spacing:0.12em;text-transform:uppercase;color:{v_color};">Maliciousness Assessment</div>
      <div style="font-size:1.1rem;font-weight:800;color:{v_dark};margin-top:0.1rem;">{v_label}</div>
      <div style="font-size:0.6rem;color:{v_color};margin-top:0.1rem;">Confidence: {score}/100</div>
    </div>
    <div style="text-align:right;max-width:55%;">
      {''.join(f'<div style="font-size:0.6rem;color:{v_dark};margin-bottom:0.1rem;">• ' + escape(str(ind)) + '</div>' for ind in (indicators or [])[:6])}
    </div>
  </div>

  {_sec("01", "Executive Summary", exec_html)}

  {_sec("02", "File Metadata", file_metadata_html)}

  {_sec("03", "Threat Intel &amp; MITRE ATT&amp;CK", mitre_html, "Mapped tactics and techniques observed in the binary.")}

  {_sec("04", "Malware Capabilities", cap_html, "Behavioral capabilities identified through code analysis and pattern matching.")}

  {_sec("05", "Technical Analysis", tech_html, "Component-level deep dive with decompiled code insights.")}

  {_sec("06", "Functions Analysis", func_html, "Analysis of interesting, suspicious, and high-priority functions.")}

  {_sec("07", "Evidence of Malicious Activity", ev_items_html or evidence_html_md, "Structured findings for incident response and threat hunting.")}

  {_sec("08", "Code Evidence (Suspicious API Calls)", code_ev_html, "Decompiled lines containing suspicious API invocations.")}

  {_sec("09", "Operational Flow", ops_html, "Timeline from initialization to persistence and C2 communication.")}

  {_sec("10", "Call Graph &amp; Attack Chains", cg_html, "Graph-derived routes from entry points to suspicious sinks.")}

  {_sec("11", "Indicators of Compromise (IOCs)", f'<table><thead><tr><th style="padding:0.25rem 0.5rem;font-size:0.55rem;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;border-bottom:2px solid #e2e8f0;text-align:left;">Type</th><th style="padding:0.25rem 0.5rem;font-size:0.55rem;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;border-bottom:2px solid #e2e8f0;text-align:left;">Value</th></tr></thead><tbody>{ioc_rows}</tbody></table>' if ioc_rows else '<p style="font-size:0.65rem;color:#94a3b8;font-style:italic;">No IOCs extracted.</p>')}

  {_sec("12", "Recommendations", rec_html or '<p style="font-size:0.65rem;color:#94a3b8;font-style:italic;">No specific recommendations available.</p>')}

  {_sec("13", "Conclusion", conclusion_html)}

  <!-- Footer -->
  <div style="margin-top:1rem;padding-top:0.4rem;border-top:2px solid #e2e8f0;display:flex;justify-content:space-between;font-size:0.5rem;color:#94a3b8;">
    <span>Confidential &amp; Proprietary  --  Reverse Engineering Analysis Report</span>
    <span>Generated by Gireng Analysis Agent &mdash; {timestamp}</span>
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

    # Use the dedicated light-mode PDF template (no Tailwind CDN needed)
    html = _build_pdf_html(state)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1100, "height": 900})
        await page.set_content(html, wait_until="load")
        await page.wait_for_timeout(500)

        pdf_bytes = await page.pdf(
            format="A4",
            print_background=True,
            margin={"top": "5mm", "right": "5mm", "bottom": "5mm", "left": "5mm"},
            prefer_css_page_size=False,
            scale=0.82,
        )
        await browser.close()

    return pdf_bytes


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
