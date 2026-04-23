# -*- coding: utf-8 -*-
"""PDF report generation."""

from typing import Any, Dict

from ghidra_agent.reporting.common import *

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


