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


def _render_evidence(evidence: List[str]) -> str:
    """Render evidence items as HTML."""
    if not evidence:
        return '<div class="text-gray-500 italic">Evidence extracted from analysis data. Review summary for details.</div>'

    # Heuristic to detect code-like content (hex addrs, C operators, decompiler output)
    _CODE_RE = re.compile(
        r'(0x[0-9a-fA-F]{4,}|FUN_[0-9a-fA-F]+|->|<<|>>|\bparam_\d+|\buVar\d+|\biVar\d+|\bint \*)',
    )

    html = ''
    for i, item in enumerate(evidence, 1):
        # Split on " - Evidence:" if present
        parts = item.split(' - Evidence:', 1)
        if len(parts) == 2:
            title = parts[0].strip()
            desc = parts[1].strip()
        else:
            title = f'Finding {i}'
            desc = item.strip()

        # Separate code snippets from narrative text
        desc_lines = desc.split('\n') if '\n' in desc else [desc]
        narrative_parts: List[str] = []
        code_parts: List[str] = []
        for line in desc_lines:
            stripped = line.strip()
            if not stripped:
                continue
            if _CODE_RE.search(stripped):
                code_parts.append(stripped)
            else:
                narrative_parts.append(stripped)

        # If the whole desc looks like code (single line with hex/func refs), treat it as code
        if not code_parts and len(narrative_parts) == 1 and _CODE_RE.search(narrative_parts[0]):
            code_parts = narrative_parts
            narrative_parts = []

        block = f'<div class="finding-item"><div class="finding-title">{escape(title)}</div>'
        if narrative_parts:
            block += f'<div class="finding-desc text-sm leading-relaxed pl-4">{escape(" ".join(narrative_parts))}</div>'
        if code_parts:
            snippet = escape("\n".join(code_parts))
            block += (
                f'<pre style="margin:6px 0 0 1rem;padding:10px 14px;background:#f8f9fa;'
                f'border:1px solid #e5e7eb;border-radius:4px;overflow-x:auto;'
                f'font-family:\'Roboto Mono\',monospace;font-size:0.8rem;line-height:1.6;'
                f'color:#374151;white-space:pre-wrap;word-break:break-word;">'
                f'<code>{snippet}</code></pre>'
            )
        block += '</div>'
        html += block
    return html


def _render_recommendations(recommendations: List[str]) -> str:
    """Render recommendations as HTML."""
    if not recommendations:
        return '<div class="text-gray-500 italic">No specific recommendations available.</div>'
    html = ''
    for i, rec in enumerate(recommendations, 1):
        # Convert inline markdown: **bold** and `code`
        safe = escape(rec)
        safe = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', safe)
        safe = re.sub(r'`(.+?)`', r'<code>\1</code>', safe)
        # Clean trailing ### markers from section splitting
        safe = re.sub(r'\s*#{2,3}\s*$', '', safe).strip()
        html += f'<div class="flex gap-4 items-start pb-4 border-b border-dashed border-gray-200 last:border-0"><div class="flex-shrink-0" style="width:24px;height:24px;border-radius:50%;background:#1f2937;color:white;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:bold;">{i}</div><div class="text-sm pt-half text-gray-800">{safe}</div></div>'
    return html


def _render_iocs(iocs: List[Dict[str, str]]) -> str:
    """Render IOCs as table rows."""
    if not iocs:
        return '<tr><td colspan="2" class="text-gray-500 italic">No IOCs extracted.</td></tr>'
    html = ''
    for ioc in iocs:
        html += f'<tr><td class="font-bold text-xs text-gray-500 uppercase">{escape(ioc["type"])}</td><td class="font-mono text-sm break-all">{escape(ioc["value"])}</td></tr>'
    return html


def _render_call_graph_section(source: str, analysis: Dict[str, Any]) -> str:
    """Render call-graph adjacency and attack chains for one analyzer."""
    if not analysis or not analysis.get("ok"):
        return f'<div class="text-gray-500 italic mb-4">{escape(source)}: call graph data not available.</div>'

    stats = analysis.get("stats", {})
    entries = analysis.get("entries", []) or []
    chains = analysis.get("chains", []) or []
    cycles = analysis.get("cycles", []) or []
    adjacency = analysis.get("adjacency", []) or []

    parts = [
        f'<h3>{escape(source)} Call Graph</h3>',
        (
            f'<p class="mb-3"><strong>Nodes:</strong> {stats.get("nodes", 0)} | '
            f'<strong>Edges:</strong> {stats.get("edges", 0)} | '
            f'<strong>Entries:</strong> {escape(", ".join(entries[:10])) or "N/A"} | '
            f'<strong>Attack Chains:</strong> {stats.get("chains", len(chains))}</p>'
        ),
    ]

    if chains:
        parts.append('<h4>Attack Chains</h4>')
        parts.append('<ul class="list-disc pl-6 mb-4">')
        for chain in chains:
            category = escape(str(chain.get("category", "Unknown")))
            path = " &rarr; ".join(escape(str(p)) for p in chain.get("path", []))
            parts.append(f'<li class="mb-2"><strong>[{category}]</strong> {path}</li>')
        parts.append('</ul>')
    else:
        parts.append('<p class="text-gray-500 italic">No sink-reaching attack chains were detected.</p>')

    if adjacency:
        top_adj = adjacency[:10]
        parts.append(f'<h4>Adjacency — Top {len(top_adj)} of {len(adjacency)} Functions</h4>')
        parts.append('<table class="w-full text-left border-collapse">')
        parts.append('<tr><th>Function</th><th>Calls</th></tr>')
        for row in top_adj:
            fn = escape(str(row.get("function", "")))
            calls = row.get("calls", []) or []
            calls_text = escape(", ".join(str(c) for c in calls)) if calls else "-"
            parts.append(f'<tr><td><code>{fn}</code></td><td>{calls_text}</td></tr>')
        parts.append('</table>')

    if cycles:
        top_cycles = cycles[:5]
        cycle_lines = [escape(" -> ".join(str(n) for n in c)) for c in top_cycles]
        parts.append(f'<h4>Detected Cycles — Top {len(top_cycles)} of {len(cycles)}</h4>')
        parts.append('<ul class="list-disc pl-6 mb-4">')
        for c in cycle_lines:
            parts.append(f'<li class="mb-2"><code>{c}</code></li>')
        parts.append('</ul>')

    return "\n".join(parts)


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
                f'<div class="decomp-block" style="margin-bottom:16px;border:1px solid #d1d5db;border-radius:4px;overflow:hidden;">'
                f'<div style="background:#1f2937;color:white;padding:8px 14px;font-family:\'Roboto Mono\',monospace;font-size:0.82rem;">'
                f'<strong>[{escape(source)}]</strong> {escape(func_name)} @ {escape(str(addr))} — '
                f'<span style="color:#fbbf24;">{escape(apis_str)}</span></div>'
                f'<pre style="margin:0;padding:12px;background:#f8f9fa;overflow-x:auto;font-size:0.8rem;line-height:1.5;">'
                f'<code>{snippet}</code></pre></div>'
            )

            if is_lib:
                lib_blocks.append(block)
            else:
                app_blocks.append(block)

    # Application-logic functions first, then library (capped at 5)
    evidence_blocks = app_blocks + lib_blocks[:5]

    if not evidence_blocks:
        return '<div class="text-gray-500 italic">No suspicious API calls detected in decompiled code.</div>'

    return "\n".join(evidence_blocks)


def build_report_html(state: Dict[str, Any]) -> str:
    """Build HTML report matching professional template format."""

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
    gh_call_graph_analysis = analysis_results.get("call_graph_analysis", {})
    r2_call_graph_analysis = r2_results.get("call_graph_analysis", {})

    program_hash = state.get("program_hash", "unknown")
    summary_text = state.get("summary", "")

    logger.info("build_report_html: summary_text length=%d", len(summary_text))

    # Extract executive summary; fallback strips markdown headers to avoid duplicates
    exec_summary = _extract_section(summary_text, "Executive Summary")
    if not exec_summary:
        # Strip any leading markdown headers from the raw text to avoid duplicate headings
        fallback = re.sub(r'^#{2,3}\s+.*$', '', summary_text[:2000], flags=re.MULTILINE).strip()
        exec_summary = fallback or summary_text[:2000]

    report_data = {
        "file_name": escape(state.get("binary_path", "unknown").split("/")[-1]),
        "summary": _markdown_to_html(exec_summary),
        "malware_capabilities": _markdown_to_html(_extract_section(summary_text, "Malware Capabilities")),
        "binary_info": _markdown_to_html(f"""| Property | Value |
|----------|-------|
| SHA256 | {program_hash} |
| Architecture | {binary.get('architecture', 'unknown')} |
| Type | ELF/PE (inferred) |
| Image Base | {binary.get('image_base', 'unknown')} |
| Entry Point | {_format_entry_points(binary.get('entry_points', ['unknown']))} |
| Compiler | {_sanitize_compiler(binary.get('compiler', 'unknown'))} |
| Ghidra Imports | {', '.join(binary.get('imports', [])) or 'N/A'} |
| Ghidra Exports | {', '.join(binary.get('exports', [])) or 'N/A'} |
| Functions (Ghidra) | {len(funcs.get('functions', []))} total ({len(state.get('decompilation_cache', {}))} decompiled) |
| Functions (R2) | {len(r2_funcs.get('functions', []))} total ({len(state.get('r2_decompilation_cache', {}))} decompiled) |
| R2 Architecture | {r2_binary.get('architecture', 'N/A')} ({r2_binary.get('bits', '?')}-bit) |
| R2 OS | {r2_binary.get('os', 'N/A')} |
| R2 Imports | {', '.join(r2_binary.get('imports', [])) or 'N/A'} |
| R2 Exports | {', '.join(r2_binary.get('exports', [])) or 'N/A'} |
| Strings (Ghidra) | {len(strings_data.get('strings', []))} extracted |
| Strings (R2) | {len(r2_strings.get('strings', []))} extracted |"""),
        "technical_analysis": _markdown_to_html(_extract_section(summary_text, "Technical Analysis")),
        "functions_analysis": _markdown_to_html(_extract_section(summary_text, "Functions Analysis")),
        "how_it_works": _markdown_to_html(_extract_section(summary_text, "Operational Flow")),
        "c2_analysis": _markdown_to_html(_extract_section(summary_text, "C2 & Networking")),
        "evidence": _extract_evidence(summary_text),
        "recommendations": _extract_recommendations(summary_text),
        "iocs": _parse_iocs_for_template(iocs),
        "conclusion": _markdown_to_html(_extract_section(summary_text, "Conclusion")),
        "call_graph": (
            _render_call_graph_section("Ghidra", gh_call_graph_analysis)
            + "\n"
            + _render_call_graph_section("Radare2", r2_call_graph_analysis)
        ),
        "code_evidence": _render_code_evidence(state),
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

        <!-- Code Evidence -->
        <div>
            <h2 class="section-header">6b. Code Evidence (Suspicious API Calls)</h2>
            <div class="text-sm text-gray-600 mb-4 italic border-l-2 border-gray-300 pl-3">Exact code locations where suspicious or malicious API calls were found in decompiled functions. Only factual findings from both Ghidra and Radare2.</div>
            <div>{report_data['code_evidence']}</div>
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

        <!-- Call Graph -->
        <div>
            <h2 class="section-header">12. Call Graph &amp; Attack Chains</h2>
            <div class="markdown-content">{report_data['call_graph']}</div>
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
        /* Utility classes used by markdown renderer */
        .w-full { width: 100%; }
        .text-left { text-align: left; }
        .text-sm { font-size: 0.875rem; line-height: 1.25rem; }
        .text-xs { font-size: 0.75rem; line-height: 1rem; }
        .text-gray-500 { color: #6b7280; }
        .text-gray-600 { color: #4b5563; }
        .text-gray-800 { color: #1f2937; }
        .italic { font-style: italic; }
        .font-bold { font-weight: 700; }
        .break-all { word-break: break-all; }
        .list-disc { list-style-type: disc; }
        .pl-4 { padding-left: 1rem; }
        .pl-6 { padding-left: 1.5rem; }
        .pt-half { padding-top: 0.125rem; }
        .pb-4 { padding-bottom: 1rem; }
        .mb-2 { margin-bottom: 0.5rem; }
        .mb-3 { margin-bottom: 0.75rem; }
        .mb-4 { margin-bottom: 1rem; }
        .gap-4 { gap: 1rem; }
        .items-start { align-items: flex-start; }
        .flex { display: flex; }
        .flex-shrink-0 { flex-shrink: 0; }
        .space-y-4 > * + * { margin-top: 1rem; }
        .border-b { border-bottom: 1px solid #e5e7eb; }
        .border-dashed { border-style: dashed; }
        .border-gray-200 { border-color: #e5e7eb; }

        .leading-relaxed { line-height: 1.625; }
        .uppercase { text-transform: uppercase; }
        .border-l-2 { border-left: 2px solid; }
        .border-gray-300 { border-color: #d1d5db; }
        .pl-3 { padding-left: 0.75rem; }
        .border-collapse { border-collapse: collapse; }
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
    <div class="no-print" style="position: fixed; bottom: 32px; right: 32px; z-index: 50;">
        <button onclick="window.print()" style="background: #1f2937; color: white; padding: 12px 24px; border: none; cursor: pointer; font-weight: 500; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.2);">
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
            <div>Generated by Ghidra + Radare2 Analysis Agent</div>
        </div>
    </div>
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
        <tr><td class="prop">Imports</td><td class="mono" style="word-break:break-all">{escape(', '.join(binary.get('imports', [])))}</td></tr>
        <tr><td class="prop">Exports</td><td class="mono" style="word-break:break-all">{escape(', '.join(binary.get('exports', [])))}</td></tr>
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
        <tr><td class="prop">Imports</td><td class="mono" style="word-break:break-all">{escape(', '.join(binary.get('imports', [])))}</td></tr>
        <tr><td class="prop">Exports</td><td class="mono" style="word-break:break-all">{escape(', '.join(binary.get('exports', [])))}</td></tr>
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
            lines.append(f"Imports:      {', '.join(gh_imports)}")
        gh_exports = binary.get("exports", [])
        if gh_exports:
            lines.append(f"Exports:      {', '.join(gh_exports)}")
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
            lines.append(f"Imports:      {', '.join(imports)}")
        exports = r2_binary.get("exports", [])
        if exports:
            lines.append(f"Exports:      {', '.join(exports)}")
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
            lines.append(f"  Entry points: {', '.join(entries[:10])}")
        if chains:
            lines.append("  Attack chains:")
            for chain in chains[:20]:
                path = " -> ".join(chain.get("path", []))
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
