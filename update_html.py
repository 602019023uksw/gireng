import os
import re

path = r"c:\git\gireng\sample-report\sample_report_latest.html"
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

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
content = content.replace('bg-white dark:bg-slate-900 rounded-lg shadow-xl', 'bg-[#060B14] rounded-xl shadow-[0_0_30px_rgba(0,240,255,0.05)]')

# Headers style update
content = content.replace('text-2xl font-bold text-slate-900 dark:text-white mb-6 section-header-accent', 'text-2xl font-display font-bold text-white mb-6 border-l-4 border-[#00f0ff] pl-3 uppercase tracking-wider')

content = content.replace("text-slate-900 dark:text-white", "text-white")
content = content.replace("text-slate-900", "text-white")

content = content.replace("bg-white dark:bg-slate-800", "bg-[#0B1324]")
content = content.replace("border-slate-200 dark:border-slate-700", "border-[#131e36]")
content = content.replace("bg-slate-50 dark:bg-slate-800/80", "bg-[#060B14]")

# Add grid background to body
if "linear-gradient" not in content:
    content = content.replace('class="bg-[#060B14] text-slate-200 font-sans"', 'class="bg-[#060B14] text-slate-200 font-sans" style="background-image: linear-gradient(rgba(19,30,54,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(19,30,54,0.3) 1px, transparent 1px); background-size: 30px 30px;"')
else:
    content = content.replace('class="bg-slate-100 text-slate-900 dark:bg-slate-950 dark:text-slate-200 font-sans"', 'class="bg-[#060B14] text-slate-200 font-sans" style="background-image: linear-gradient(rgba(19,30,54,0.3) 1px, transparent 1px), linear-gradient(90deg, rgba(19,30,54,0.3) 1px, transparent 1px); background-size: 30px 30px;"')

# Fix sidebar links
content = content.replace('class="block px-3 py-2 rounded hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"', 'class="block px-3 py-2 rounded text-slate-400 hover:text-white hover:bg-[#131e36] hover:shadow-[inset_2px_0_0_#00f0ff] transition-all"')

# Header fonts
content = content.replace('class="text-4xl font-bold text-slate-900 dark:text-white mb-2 tracking-tight"', 'class="text-4xl font-display font-bold text-white mb-2 tracking-tight drop-shadow-[0_0_8px_rgba(255,255,255,0.2)]"')
content = content.replace('text-lg font-bold text-slate-800 dark:text-slate-100', 'text-lg font-display font-bold text-white')

# Cards shadow and borders
content = content.replace('hover:shadow-lg', 'hover:shadow-[0_0_15px_rgba(0,240,255,0.15)]')

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print("Updated sample_report_latest.html")
