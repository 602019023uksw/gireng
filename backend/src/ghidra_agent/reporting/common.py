# -*- coding: utf-8 -*-
"""Shared helpers for report generation."""

import logging
import re
from datetime import datetime, timezone
from html import escape
from typing import Any, Dict, List

from ghidra_agent.function_priority import is_library_function
from ghidra_agent.ioc_extractor import IOCs, calculate_verdict, extract_iocs_from_state

logger = logging.getLogger(__name__)

__all__ = [
    'logger',
    '_set_report_tone',
    '_format_timestamp',
    '_code_color',
    '_MAX_ENTRY_POINTS',
    '_JAVA_TOSTRING_RE',
    '_sanitize_compiler',
    '_format_entry_points',
    '_MAX_IMPORT_EXPORT',
    '_clean_import_name',
    '_format_import_export_list',
    '_extract_section',
    '_markdown_to_html',
    '_parse_iocs_for_template',
    '_extract_recommendations',
    '_extract_evidence',
    '_REC_STYLES',
    '_render_evidence',
    '_render_recommendations',
    '_CAP_ICONS',
    '_TECH_ICONS',
    '_inline_code_html',
    '_render_mitre_cards',
    '_render_capabilities_cards',
    '_render_technical_cards',
    '_render_functions_cards',
    '_render_evidence_cards',
    '_render_operational_flow',
    '_render_iocs',
    '_render_evidence_correlation',
    '_deduplicate_chains',
    '_render_call_graph_section',
    '_render_qiling_dynamic_section',
    '_HIGH_VALUE_APIS',
    '_CONTEXT_APIS',
    '_API_WORD_RE',
    '_GENERIC_ONLY_APIS',
    '_OPENSSL_CONTENT_RE',
    '_is_library_content',
    '_render_code_evidence',
]

# ── Report tone context (set per-build_report_html call) ──
_report_tone: str = "neutral"  # neutral | clean | suspicious | malicious


def _set_report_tone(tone: str) -> None:
    global _report_tone
    _report_tone = tone


def _format_timestamp(iso_string: str) -> str:
    """Convert an ISO-8601 string to a human-readable format."""
    try:
        dt = datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except Exception:
        return iso_string


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
    for decoded in iocs.decoded_strings:
        results.append({"type": "Decoded String", "value": decoded})

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


def _render_evidence_correlation(correlation: Dict[str, Any]) -> str:
    """Render cross-engine evidence correlations."""
    findings = correlation.get("findings", []) if isinstance(correlation, dict) else []
    if not findings:
        return '<div class="text-slate-500 italic">No cross-engine evidence correlations found.</div>'

    cards: List[str] = []
    for finding in findings[:12]:
        engine = escape(str(finding.get("engine", "unknown")).title())
        source = escape(str(finding.get("source", "evidence")).replace("_", " ").title())
        description = escape(str(finding.get("description", "")))
        confidence = int(finding.get("confidence", 0))
        iocs = ", ".join(escape(str(ioc)) for ioc in finding.get("iocs", [])[:4]) or "none"
        functions = ", ".join(escape(str(func)) for func in finding.get("functions", [])[:4]) or "unknown"
        evidence = "; ".join(escape(str(item)) for item in finding.get("evidence", [])[:3])
        cards.append(
            '<div class="rounded-lg border border-slate-700 bg-[#0B1324] p-4">'
            '<div class="flex items-center justify-between gap-3 mb-2">'
            f'<div class="text-sm font-semibold text-slate-100">{engine} · {source}</div>'
            f'<div class="text-xs text-slate-400">{confidence}% confidence</div>'
            '</div>'
            f'<div class="text-sm text-slate-300 mb-2">{description}</div>'
            f'<div class="text-xs text-slate-400"><span class="font-semibold text-slate-300">IOCs:</span> {iocs}</div>'
            f'<div class="text-xs text-slate-400"><span class="font-semibold text-slate-300">Functions:</span> {functions}</div>'
            f'<div class="text-xs text-slate-500 mt-2 break-all">{evidence}</div>'
            '</div>'
        )
    if len(findings) > 12:
        cards.append(f'<div class="text-xs text-slate-500">... and {len(findings) - 12} more correlations</div>')
    return '<div class="grid grid-cols-1 lg:grid-cols-2 gap-4">' + "\n".join(cards) + '</div>'


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
