"""Enhanced HTML report generation with professional formatting."""

import json
import re
from datetime import datetime, timezone
from html import escape
from typing import Any, Dict, List

from ghidra_agent.ioc_extractor import extract_iocs_from_state, IOCs, calculate_verdict


def _simple_markdown_to_html(text: str) -> str:
    """Convert simple markdown to HTML."""
    if not text:
        return ""
    
    # Escape HTML first
    text = escape(text)
    
    # Headers
    text = re.sub(r'^#### (.+)$', r'<h4>\1</h4>', text, flags=re.MULTILINE)
    text = re.sub(r'^### (.+)$', r'<h3>\1</h3>', text, flags=re.MULTILINE)
    text = re.sub(r'^## (.+)$', r'<h2>\1</h2>', text, flags=re.MULTILINE)
    text = re.sub(r'^# (.+)$', r'<h1>\1</h1>', text, flags=re.MULTILINE)
    
    # Bold and italic
    text = re.sub(r'\*\*\*(.+?)\*\*\*', r'<strong><em>\1</em></strong>', text)
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)
    
    # Code blocks
    text = re.sub(r'```(\w+)?\n(.*?)```', r'<pre class="code-block"><code>\2</code></pre>', text, flags=re.DOTALL)
    text = re.sub(r'`(.+?)`', r'<code>\1</code>', text)
    
    # Bullet lists
    lines = text.split('\n')
    result = []
    in_list = False
    
    for line in lines:
        if line.strip().startswith('• ') or line.strip().startswith('- '):
            if not in_list:
                result.append('<ul>')
                in_list = True
            item = line.strip()[2:]
            result.append(f'<li>{item}</li>')
        else:
            if in_list:
                result.append('</ul>')
                in_list = False
            result.append(line)
    
    if in_list:
        result.append('</ul>')
    
    text = '\n'.join(result)
    
    # Paragraphs (wrap non-tag lines)
    lines = text.split('\n')
    result = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('<') and not stripped.startswith('---'):
            result.append(f'<p>{stripped}</p>')
        else:
            result.append(line)
    
    return '\n'.join(result)


def _format_iocs_html(iocs: IOCs) -> str:
    """Format IOCs as categorized HTML."""
    sections = []
    
    if iocs.ips:
        items = ''.join([f'<li class="ioc-item"><span class="ioc-type">IP</span>{escape(ip)}</li>' for ip in iocs.ips[:20]])
        sections.append(f'<div class="ioc-category"><h4>IP Addresses & Ports</h4><ul class="ioc-list">{items}</ul></div>')
    
    if iocs.domains:
        items = ''.join([f'<li class="ioc-item"><span class="ioc-type">Domain</span>{escape(d)}</li>' for d in iocs.domains[:15]])
        sections.append(f'<div class="ioc-category"><h4>Domains</h4><ul class="ioc-list">{items}</ul></div>')
    
    if iocs.urls:
        items = ''.join([f'<li class="ioc-item"><span class="ioc-type">URL</span><a href="{escape(url)}" target="_blank">{escape(url[:80])}{"..." if len(url) > 80 else ""}</a></li>' for url in iocs.urls[:10]])
        sections.append(f'<div class="ioc-category"><h4>URLs</h4><ul class="ioc-list">{items}</ul></div>')
    
    if iocs.file_paths:
        items = ''.join([f'<li class="ioc-item"><span class="ioc-type">Path</span><code>{escape(p)}</code></li>' for p in iocs.file_paths[:15]])
        sections.append(f'<div class="ioc-category"><h4>File Paths</h4><ul class="ioc-list">{items}</ul></div>')
    
    if iocs.emails:
        items = ''.join([f'<li class="ioc-item"><span class="ioc-type">Email</span>{escape(e)}</li>' for e in iocs.emails[:10]])
        sections.append(f'<div class="ioc-category"><h4>Email Addresses</h4><ul class="ioc-list">{items}</ul></div>')
    
    if iocs.registry_keys:
        items = ''.join([f'<li class="ioc-item"><span class="ioc-type">Registry</span><code>{escape(r)}</code></li>' for r in iocs.registry_keys[:10]])
        sections.append(f'<div class="ioc-category"><h4>Windows Registry Keys</h4><ul class="ioc-list">{items}</ul></div>')
    
    if iocs.mutexes:
        items = ''.join([f'<li class="ioc-item"><span class="ioc-type">Mutex</span><code>{escape(m)}</code></li>' for m in iocs.mutexes[:10]])
        sections.append(f'<div class="ioc-category"><h4>Mutex/Event Names</h4><ul class="ioc-list">{items}</ul></div>')
    
    if iocs.crypto_materials:
        items = ''.join([f'<li class="ioc-item"><span class="ioc-type">Crypto</span>{escape(c)}</li>' for c in iocs.crypto_materials[:10]])
        sections.append(f'<div class="ioc-category"><h4>Cryptographic Materials</h4><ul class="ioc-list">{items}</ul></div>')
    
    if iocs.suspicious_strings:
        items = ''.join([f'<li class="ioc-item"><span class="ioc-type">Suspicious</span>{escape(s)}</li>' for s in iocs.suspicious_strings[:15]])
        sections.append(f'<div class="ioc-category"><h4>Suspicious Indicators</h4><ul class="ioc-list">{items}</ul></div>')
    
    if not sections:
        return '<p class="no-data">No IOCs extracted.</p>'
    
    return '\n'.join(sections)


def _format_functions_html(functions: List[Dict]) -> str:
    """Format function list as HTML table."""
    if not functions:
        return '<p class="no-data">No function data available.</p>'
    
    sorted_funcs = sorted(functions, key=lambda f: f.get("xrefs", 0), reverse=True)[:10]
    
    rows = []
    for i, f in enumerate(sorted_funcs, 1):
        name = escape(f.get("name", "unknown"))
        addr = escape(f.get("address", "?"))
        xrefs = f.get("xrefs", 0)
        size = f.get("size", 0)
        
        xref_class = "high" if xrefs > 50 else "medium" if xrefs > 10 else "low"
        
        rows.append(
            f'<tr>'
            f'<td>{i}</td>'
            f'<td><code class="func-name">{name}</code></td>'
            f'<td><code>{addr}</code></td>'
            f'<td><span class="badge {xref_class}">{xrefs}</span></td>'
            f'<td>{size:,}</td>'
            f'</tr>'
        )
    
    return (
        '<table class="data-table">'
        '<thead><tr><th>#</th><th>Function Name</th><th>Address</th><th>XRefs</th><th>Size</th></tr></thead>'
        '<tbody>' + '\n'.join(rows) + '</tbody>'
        '</table>'
    )


def _format_code_html(decomp_cache: Dict[str, str]) -> str:
    """Format decompiled code sections."""
    if not decomp_cache:
        return '<p class="no-data">No decompiled code available.</p>'
    
    sections = []
    for func_name, c_code in list(decomp_cache.items())[:5]:
        # Simple syntax highlighting for C code
        highlighted = escape(c_code[:4000])
        
        # Highlight common C keywords
        keywords = ['void', 'int', 'char', 'return', 'if', 'else', 'while', 'for', 'do', 'break', 'continue', 
                   'switch', 'case', 'default', 'struct', 'union', 'typedef', 'static', 'const', 'sizeof']
        for kw in keywords:
            highlighted = re.sub(rf'\b{kw}\b', f'<span class="kw">{kw}</span>', highlighted)
        
        # Highlight function calls
        highlighted = re.sub(r'(\w+)\s*\(', r'<span class="func">\1</span>(', highlighted)
        
        # Highlight strings
        highlighted = re.sub(r'"([^"]*)"', r'<span class="str">"\1"</span>', highlighted)
        
        # Highlight comments
        highlighted = re.sub(r'(/\*.*?\*/)', r'<span class="comment">\1</span>', highlighted, flags=re.DOTALL)
        highlighted = re.sub(r'(//.*?)$', r'<span class="comment">\1</span>', highlighted, flags=re.MULTILINE)
        
        sections.append(
            f'<div class="code-section">'
            f'<div class="code-header">{escape(func_name)}</div>'
            f'<pre class="code-content">{highlighted}</pre>'
            f'</div>'
        )
    
    if len(decomp_cache) > 5:
        sections.append(f'<p class="more">... and {len(decomp_cache) - 5} more decompiled functions</p>')
    
    return '\n'.join(sections)


def build_report_html(state: Dict[str, Any]) -> str:
    """Build professional HTML report."""
    
    iocs = extract_iocs_from_state(state)
    verdict, verdict_class, indicators, score = calculate_verdict(iocs, state)
    
    analysis_results = state.get("analysis_results", {})
    binary = analysis_results.get("binary", {})
    funcs = analysis_results.get("functions", {})
    strings_data = analysis_results.get("strings", {})
    decomp_cache = state.get("decompilation_cache", {})
    
    # Build metadata
    program_hash = state.get("program_hash", "unknown")
    architecture = binary.get("architecture", "unknown")
    compiler = binary.get("compiler", "unknown")
    image_base = binary.get("image_base", "unknown")
    entry_points = binary.get("entry_points", [])
    segments = binary.get("segments", [])
    function_count = len(funcs.get("functions", []))
    string_count = len(strings_data.get("strings", [])) if strings_data.get("ok") else 0
    
    # Build capabilities
    caps = []
    if strings_data.get("ok"):
        strings_vals = " ".join([s.get("value", "").lower() for s in strings_data.get("strings", [])])
        cap_map = [
            ("Network", ["socket", "connect", "recv", "send", "http", "tcp", "udp"]),
            ("Command Exec", ["exec", "system", "popen", "shell", "/bin/sh"]),
            ("Crypto", ["encrypt", "aes", "rsa", "sha", "md5", "cipher"]),
            ("Persistence", ["registry", "startup", "cron", "systemd", "init.d"]),
            ("Anti-Analysis", ["debugger", "vmware", "virtualbox", "sandbox"]),
            ("Info Gathering", ["gethost", "uname", "sysinfo", "cpuinfo", "/proc"]),
        ]
        for name, keywords in cap_map:
            if any(kw in strings_vals for kw in keywords):
                caps.append(name)
    
    cap_badges = ''.join([f'<span class="cap-badge">{c}</span>' for c in caps]) if caps else '<span class="none">None detected</span>'
    
    # Format summary with markdown
    summary_html = _simple_markdown_to_html(state.get("summary", "No summary available."))
    
    # Build indicators text
    indicators_text = '<ul>' + ''.join([f'<li>{escape(ind)}</li>' for ind in indicators[:10]]) + '</ul>' if indicators else '<p>No suspicious indicators detected.</p>'
    
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Analysis Report - {program_hash[:16]}...</title>
    <style>
        :root {{
            --bg: #f8f9fa;
            --card: #ffffff;
            --text: #212529;
            --text-muted: #6c757d;
            --border: #dee2e6;
            --primary: #2563eb;
            --primary-light: #dbeafe;
            --success: #059669;
            --success-light: #d1fae5;
            --warning: #d97706;
            --warning-light: #fef3c7;
            --danger: #dc2626;
            --danger-light: #fee2e2;
            --code-bg: #1e1e2e;
            --code-text: #cdd6f4;
        }}
        
        * {{ box-sizing: border-box; }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            margin: 0;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        header {{
            background: var(--card);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        
        h1 {{
            margin: 0 0 10px 0;
            font-size: 28px;
            font-weight: 700;
        }}
        
        .subtitle {{
            color: var(--text-muted);
            font-size: 14px;
        }}
        
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        
        .card {{
            background: var(--card);
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        
        .card h2 {{
            margin: 0 0 16px 0;
            font-size: 18px;
            font-weight: 600;
            color: var(--text);
            padding-bottom: 8px;
            border-bottom: 2px solid var(--border);
        }}
        
        .card h3 {{
            margin: 20px 0 12px 0;
            font-size: 15px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .verdict {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 18px;
            font-weight: 700;
        }}
        
        .verdict.malicious {{
            background: var(--danger-light);
            color: var(--danger);
        }}
        
        .verdict.suspicious {{
            background: var(--warning-light);
            color: var(--warning);
        }}
        
        .verdict.clean {{
            background: var(--success-light);
            color: var(--success);
        }}
        
        .score {{
            font-size: 14px;
            font-weight: 500;
            color: var(--text-muted);
            margin-top: 8px;
        }}
        
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 12px;
        }}
        
        .meta-item {{
            padding: 12px;
            background: var(--bg);
            border-radius: 8px;
        }}
        
        .meta-label {{
            font-size: 12px;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 4px;
        }}
        
        .meta-value {{
            font-size: 14px;
            font-weight: 500;
            word-break: break-all;
        }}
        
        .stats {{
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
        }}
        
        .stat {{
            text-align: center;
            padding: 16px 24px;
            background: var(--bg);
            border-radius: 8px;
            min-width: 100px;
        }}
        
        .stat-value {{
            font-size: 24px;
            font-weight: 700;
            color: var(--primary);
        }}
        
        .stat-label {{
            font-size: 12px;
            color: var(--text-muted);
            margin-top: 4px;
        }}
        
        .cap-badge {{
            display: inline-block;
            padding: 4px 12px;
            background: var(--primary-light);
            color: var(--primary);
            border-radius: 20px;
            font-size: 12px;
            font-weight: 500;
            margin: 4px;
        }}
        
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }}
        
        .badge.high {{
            background: var(--danger-light);
            color: var(--danger);
        }}
        
        .badge.medium {{
            background: var(--warning-light);
            color: var(--warning);
        }}
        
        .badge.low {{
            background: var(--success-light);
            color: var(--success);
        }}
        
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        
        .data-table th,
        .data-table td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        
        .data-table th {{
            font-weight: 600;
            color: var(--text-muted);
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            background: var(--bg);
        }}
        
        .data-table tr:hover {{
            background: var(--bg);
        }}
        
        .func-name {{
            color: var(--primary);
            font-weight: 500;
        }}
        
        .ioc-category {{
            margin-bottom: 20px;
        }}
        
        .ioc-category h4 {{
            margin: 0 0 12px 0;
            font-size: 14px;
            font-weight: 600;
            color: var(--text-muted);
        }}
        
        .ioc-list {{
            list-style: none;
            padding: 0;
            margin: 0;
        }}
        
        .ioc-item {{
            padding: 8px 12px;
            background: var(--bg);
            border-radius: 6px;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        
        .ioc-type {{
            display: inline-block;
            padding: 2px 8px;
            background: var(--danger-light);
            color: var(--danger);
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            min-width: 60px;
            text-align: center;
        }}
        
        .code-section {{
            margin-bottom: 20px;
            border: 1px solid var(--border);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .code-header {{
            background: var(--code-bg);
            color: var(--code-text);
            padding: 10px 16px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 13px;
            font-weight: 600;
        }}
        
        .code-content {{
            background: var(--code-bg);
            color: var(--code-text);
            padding: 16px;
            margin: 0;
            overflow-x: auto;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 13px;
            line-height: 1.5;
        }}
        
        .code-content .kw {{ color: #c792ea; }}
        .code-content .func {{ color: #82aaff; }}
        .code-content .str {{ color: #c3e88d; }}
        .code-content .comment {{ color: #676e95; font-style: italic; }}
        
        .summary {{
            line-height: 1.8;
        }}
        
        .summary h2 {{
            font-size: 20px;
            margin-top: 24px;
            margin-bottom: 12px;
            color: var(--text);
        }}
        
        .summary h3 {{
            font-size: 16px;
            margin-top: 20px;
            color: var(--text-muted);
        }}
        
        .summary ul {{
            padding-left: 20px;
        }}
        
        .summary li {{
            margin-bottom: 8px;
        }}
        
        .summary code {{
            background: var(--bg);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.9em;
        }}
        
        .no-data {{
            color: var(--text-muted);
            font-style: italic;
            padding: 20px;
            text-align: center;
        }}
        
        .more {{
            color: var(--text-muted);
            font-style: italic;
            text-align: center;
            padding: 10px;
        }}
        
        .download-btn {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 20px;
            background: var(--primary);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            margin-top: 16px;
        }}
        
        .download-btn:hover {{
            background: #1d4ed8;
        }}
        
        @media print {{
            body {{ background: white; }}
            .card {{ box-shadow: none; border: 1px solid var(--border); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Binary Analysis Report</h1>
            <div class="subtitle">Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} • {program_hash}</div>
        </header>
        
        <div class="grid">
            <div class="card">
                <h2>Verdict</h2>
                <div class="verdict {verdict_class}">
                    {'🔴' if verdict_class == 'malicious' else '🟡' if verdict_class == 'suspicious' else '🟢'} {verdict}
                </div>
                <div class="score">Risk Score: {score}/100</div>
            </div>
            
            <div class="card">
                <h2>Binary Information</h2>
                <div class="meta-grid">
                    <div class="meta-item">
                        <div class="meta-label">Architecture</div>
                        <div class="meta-value">{architecture}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Compiler</div>
                        <div class="meta-value">{compiler}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Image Base</div>
                        <div class="meta-value">{image_base}</div>
                    </div>
                    <div class="meta-item">
                        <div class="meta-label">Entry Point</div>
                        <div class="meta-value">{entry_points[0] if entry_points else 'Unknown'}</div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <h2>Statistics</h2>
                <div class="stats">
                    <div class="stat">
                        <div class="stat-value">{function_count:,}</div>
                        <div class="stat-label">Functions</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{string_count:,}</div>
                        <div class="stat-label">Strings</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{len(decomp_cache)}</div>
                        <div class="stat-label">Decompiled</div>
                    </div>
                    <div class="stat">
                        <div class="stat-value">{len(iocs.to_dict())}</div>
                        <div class="stat-label">IOC Categories</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h2>Detected Capabilities</h2>
                {cap_badges}
            </div>
        </div>
        
        <div class="card">
            <h2>Executive Summary</h2>
            <div class="summary">
                {summary_html}
            </div>
        </div>
        
        <div class="card">
            <h2>Indicators of Compromise (IOCs)</h2>
            {_format_iocs_html(iocs)}
        </div>
        
        <div class="card">
            <h2>Top Functions by References</h2>
            {_format_functions_html(funcs.get("functions", []))}
        </div>
        
        <div class="card">
            <h2>Decompiled Code</h2>
            {_format_code_html(decomp_cache)}
        </div>
        
        <div class="card">
            <h2>Suspicious Indicators</h2>
            {indicators_text}
        </div>
    </div>
</body>
</html>'''
    
    return html


def build_report_text(state: Dict[str, Any]) -> str:
    """Build plain text report for download."""
    iocs = extract_iocs_from_state(state)
    verdict, _, indicators, score = calculate_verdict(iocs, state)
    
    analysis_results = state.get("analysis_results", {})
    binary = analysis_results.get("binary", {})
    funcs = analysis_results.get("functions", {})
    
    lines = [
        "=" * 70,
        "GHIDRA BINARY ANALYSIS REPORT",
        "=" * 70,
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"SHA-256: {state.get('program_hash', 'unknown')}",
        "",
        "-" * 70,
        "VERDICT",
        "-" * 70,
        f"Classification: {verdict}",
        f"Risk Score: {score}/100",
        "",
        "-" * 70,
        "BINARY INFORMATION",
        "-" * 70,
        f"Architecture: {binary.get('architecture', 'unknown')}",
        f"Compiler: {binary.get('compiler', 'unknown')}",
        f"Image Base: {binary.get('image_base', 'unknown')}",
        f"Entry Points: {', '.join(binary.get('entry_points', ['unknown']))}",
        f"Segments: {', '.join(binary.get('segments', []))}",
        "",
        "-" * 70,
        "SUMMARY",
        "-" * 70,
        state.get("summary", "No summary available."),
        "",
        "-" * 70,
        "IOCs (INDICATORS OF COMPROMISE)",
        "-" * 70,
    ]
    
    if iocs.ips:
        lines.extend(["", "IP Addresses:"])
        lines.extend([f"  - {ip}" for ip in iocs.ips])
    
    if iocs.domains:
        lines.extend(["", "Domains:"])
        lines.extend([f"  - {d}" for d in iocs.domains])
    
    if iocs.file_paths:
        lines.extend(["", "File Paths:"])
        lines.extend([f"  - {p}" for p in iocs.file_paths])
    
    if not any([iocs.ips, iocs.domains, iocs.file_paths]):
        lines.append("No IOCs extracted.")
    
    lines.extend([
        "",
        "-" * 70,
        "TOP FUNCTIONS",
        "-" * 70,
    ])
    
    sorted_funcs = sorted(funcs.get("functions", []), key=lambda f: f.get("xrefs", 0), reverse=True)[:20]
    for f in sorted_funcs:
        lines.append(f"  {f.get('name', 'unknown'):40s} @ {f.get('address', '?'):12s} ({f.get('xrefs', 0)} refs)")
    
    lines.extend([
        "",
        "-" * 70,
        "DECOMPILED CODE",
        "-" * 70,
    ])
    
    for func_name, c_code in list(state.get("decompilation_cache", {}).items())[:3]:
        lines.extend(["", f"--- {func_name} ---", c_code[:2000], ""])
    
    lines.extend([
        "",
        "=" * 70,
        "END OF REPORT",
        "=" * 70,
    ])
    
    return '\n'.join(lines)
