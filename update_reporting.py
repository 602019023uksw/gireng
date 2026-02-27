import os
import re

path = r"c:\git\gireng\backend\src\ghidra_agent\reporting.py"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Insert _render_mitre_cards before _render_capabilities_cards
mitre_func = """
def _render_mitre_cards(md_text: str) -> str:
    \"\"\"Render MITRE ATT&CK as modern cyber cards.\"\"\"
    if not md_text:
        return ''
    
    cards = []
    for line in md_text.split('\\n'):
        # Match - **Tactic**: Technique (ID) - Description
        # Or variations
        m = re.match(r'^[-*]\\s+\\*\*\\[?(.+?)\\]?\\*\\*:\\s*\\[?([^-]+?)(?:\\s+\\((T\\d+)\\))?\\]?\\s*-\\s*(.+)', line.strip())
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

"""
if "def _render_mitre_cards" not in content:
    content = content.replace("def _render_capabilities_cards", mitre_func + "def _render_capabilities_cards")

# 2. Add MITRE ATT&CK extraction to build_report_html
ext_str = """
    mitre_md = _extract_section(summary_text, "Threat Intel & MITRE ATT&CK")
    if not mitre_md:
        mitre_md = _extract_section(summary_text, "MITRE ATT&CK Tactics & Techniques")
"""
if "Threat Intel & MITRE ATT&CK" not in content:
    content = content.replace('capabilities_md = _extract_section(summary_text, "Malware Capabilities")', ext_str + '    capabilities_md = _extract_section(summary_text, "Malware Capabilities")')

# 3. Add MITRE rendering
rend_str = """    mitre_html = _render_mitre_cards(mitre_md)\n"""
if "_render_mitre_cards(mitre_md)" not in content:
    content = content.replace('capabilities_html = _render_capabilities_cards(capabilities_md)', rend_str + '    capabilities_html = _render_capabilities_cards(capabilities_md)')

# 4. Add MITRE section to the HTML payload
section_html = """
                    <!-- MITRE ATT&CK -->
                    {('<section id="mitre-attack" class="scroll-mt-20"><h2 class="text-2xl font-display font-bold text-white mb-6 border-l-4 border-[#00ff41] pl-3 uppercase tracking-wider flex items-center gap-3"><i class="fas fa-spider text-[#00ff41]"></i> Threat Intel &amp; MITRE ATT&amp;CK</h2>' + mitre_html + '</section>') if mitre_html else ''}
"""
if "mitre-attack" not in content:
    content = content.replace('<!-- 2. Malware Capabilities -->', section_html + '\n                    <!-- 2. Malware Capabilities -->')

# 5. Add MITRE Sidebar link
link_html = """<a href="#mitre-attack" class="block px-3 py-2 rounded text-slate-400 hover:text-white hover:bg-[#131e36] hover:shadow-[inset_2px_0_0_#00ff41] transition-all"><i class="fas fa-spider w-5 text-center mr-2"></i> Threat Intel</a>"""
if "#mitre-attack" not in content:
    content = content.replace('<a href="#capabilities"', link_html + '\n            <a href="#capabilities"')

# 6. Apply massive aesthetic styling replaces
tw_old = """        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Inter', 'sans-serif'],
                        mono: ['JetBrains Mono', 'monospace'],
                    },
                    colors: {
                        primary: '#0f2937',
                        accent: '#dc2626',
                    }"""
tw_new = """    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Inter', 'sans-serif'],
                        mono: ['JetBrains Mono', 'monospace'],
                        display: ['Space Grotesk', 'sans-serif'],
                    },
                    colors: {
                        cyber: {
                            900: '#060B14',
                            800: '#0B1324',
                            700: '#131e36',
                            600: '#1b2a47',
                            accent: '#00f0ff',
                            purple: '#b500ff',
                            green: '#00ff41',
                            red: '#ff003c',
                        }
                    },
                    boxShadow: {
                        'neon': '0 0 10px rgba(0, 240, 255, 0.5)',
                        'neon-red': '0 0 10px rgba(255, 0, 60, 0.5)',
                        'neon-purple': '0 0 10px rgba(181, 0, 255, 0.5)',
                    }"""
if "Space Grotesk" not in content:
    content = content.replace(tw_old, tw_new)

# Force default dark mode aesthetic everywhere
content = content.replace('bg-slate-100 text-slate-900 dark:bg-slate-950 dark:text-slate-200', "bg-[#060B14] text-slate-200")
content = content.replace("bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800", "bg-[#0B1324] border-r border-[#131e36]")
content = content.replace("text-slate-800 dark:text-slate-100", "text-white")
content = content.replace("bg-slate-50 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800", "bg-[#060B14] border-b border-[#131e36]")
content = content.replace('bg-white dark:bg-slate-900 rounded-lg shadow-xl border border-slate-200 dark:border-slate-800', 'bg-[#060B14] rounded-xl shadow-[0_0_30px_rgba(0,240,255,0.05)] border border-[#131e36]')

# Headers style update
content = content.replace('text-2xl font-bold text-slate-900 dark:text-white mb-6 section-header-accent', 'text-2xl font-display font-bold text-white mb-6 border-l-4 border-[#00f0ff] pl-3 uppercase tracking-wider')

content = content.replace("text-slate-900 dark:text-white", "text-white")
content = content.replace("text-slate-900", "text-white")

content = content.replace("bg-white dark:bg-slate-800", "bg-[#0B1324]")
content = content.replace("border-slate-200 dark:border-slate-700", "border-[#131e36]")
content = content.replace("bg-slate-50 dark:bg-slate-800/80", "bg-[#060B14]")

# Add grid background to body
content = content.replace('class="bg-[#060B14] text-slate-200 font-sans"', 'class="bg-[#060B14] text-slate-200 font-sans" style="background-image: linear-gradient(rgba(19,30,54,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(19,30,54,0.3) 1px, transparent 1px); background-size: 30px 30px;"')

# Fix sidebar links
content = content.replace('class="block px-3 py-2 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"', 'class="block px-3 py-2 rounded text-slate-400 hover:text-white hover:bg-[#131e36] hover:shadow-[inset_2px_0_0_#00f0ff] transition-all"')

# Header fonts
content = content.replace('class="text-4xl font-bold text-slate-900 dark:text-white mb-2 tracking-tight"', 'class="text-4xl font-display font-bold text-white mb-2 tracking-tight drop-shadow-[0_0_8px_rgba(255,255,255,0.2)]"')
content = content.replace('text-lg font-bold text-slate-800 dark:text-slate-100', 'text-lg font-display font-bold text-white')

# Cards shadow and borders
content = content.replace('hover:shadow-lg', 'hover:shadow-[0_0_15px_rgba(0,240,255,0.15)]')

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print("Updated reporting.py")
