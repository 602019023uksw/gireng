import json
from datetime import datetime, timezone
from html import escape
from typing import Any, Dict

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Ghidra Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; color: #1f2937; }
    h1, h2, h3 { color: #111827; }
    pre { background: #f3f4f6; padding: 12px; border-radius: 6px; overflow: auto; }
    table { width: 100%; border-collapse: collapse; margin-top: 8px; }
    th, td { border: 1px solid #e5e7eb; padding: 8px; text-align: left; }
    th { background: #f9fafb; }
    .section { margin-bottom: 24px; }
    .tag { display: inline-block; background: #e0f2fe; color: #075985; padding: 2px 8px; border-radius: 12px; margin-right: 6px; }
  </style>
</head>
<body>
  <h1>Ghidra Reverse Engineering Report</h1>
  <div class="section">
    <h2>Summary</h2>
    <p><strong>Hash:</strong> {program_hash}</p>
    <p><strong>Status:</strong> {status}</p>
    <p><strong>Generated:</strong> {generated_at}</p>
  </div>
  <div class="section">
    <h2>Executive Summary</h2>
    <p>{executive_summary}</p>
  </div>
  <div class="section">
    <h2>Static Analysis</h2>
    <pre>{static_analysis}</pre>
  </div>
  <div class="section">
    <h2>Indicators & Notes</h2>
    <pre>{iocs}</pre>
  </div>
  <div class="section">
    <h2>Execution Logs</h2>
    <pre>{execution_logs}</pre>
  </div>
</body>
</html>
"""


def build_report_html(state: Dict[str, Any]) -> str:
    analysis = escape(json.dumps(state.get("analysis_results", {}), indent=2))
    logs = escape("\n".join(state.get("reasoning_trace", [])))
    return HTML_TEMPLATE.format(
        program_hash=escape(state.get("program_hash", "")),
        status=escape(state.get("status", "unknown")),
        generated_at=datetime.now(timezone.utc).isoformat(),
        executive_summary="Ghidra analysis completed.",
        static_analysis=analysis,
        iocs="",
        execution_logs=logs,
    )
