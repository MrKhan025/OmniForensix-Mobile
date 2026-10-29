"""Self-contained offline HTML5 forensic investigative report generator using Jinja2."""

from __future__ import annotations

from pathlib import Path
from jinja2 import Template

from omniforensix.analyzers.exif_carver import MediaForensicFinding
from omniforensix.analyzers.ioc_engine import IoCMatch
from omniforensix.plugins.base import ArtifactRecord
from omniforensix.timeline.builder import TimelineEvent

HTML_TEMPLATE = Template(
    """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Forensic Investigation Report — {{ case_id }}</title>
  <style>
    :root {
      --bg: #0f172a;
      --panel: #1e293b;
      --border: #334155;
      --text: #f8fafc;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --danger: #ef4444;
      --ok: #22c55e;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      margin: 0;
      padding: 24px;
    }
    header {
      border-bottom: 1px solid var(--border);
      padding-bottom: 16px;
      margin-bottom: 24px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
    }
    .card h3 { margin: 0 0 8px 0; font-size: 0.9rem; color: var(--muted); }
    .card .val { font-size: 1.8rem; font-weight: 700; color: var(--accent); }
    .alert { border-left: 4px solid var(--danger); }
    table {
      width: 100%;
      border-collapse: collapse;
      background: var(--panel);
      border-radius: 8px;
      overflow: hidden;
      margin-bottom: 28px;
    }
    th, td {
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
      text-align: left;
      font-size: 0.88rem;
    }
    th { background: #0f172a; color: var(--accent); }
    input[type="search"] {
      width: 100%;
      max-width: 420px;
      padding: 10px;
      margin-bottom: 14px;
      background: var(--panel);
      border: 1px solid var(--border);
      color: var(--text);
      border-radius: 6px;
    }
    .badge-crit {
      background: var(--danger);
      color: #fff;
      padding: 2px 8px;
      border-radius: 4px;
      font-weight: 600;
      font-size: 0.78rem;
    }
  </style>
</head>
<body>
  <header>
    <h1>Mobile Forensic Investigative Report</h1>
    <p>Case ID: <strong>{{ case_id }}</strong> | Case Name: <strong>{{ case_name }}</strong> | Examiner: <strong>{{ examiner }}</strong></p>
  </header>

  <div class="grid">
    <div class="card"><h3>Total Parsed Artifacts</h3><div class="val">{{ records|length }}</div></div>
    <div class="card"><h3>Timeline Events (UTC)</h3><div class="val">{{ timeline|length }}</div></div>
    <div class="card alert"><h3>IoC Threat Matches</h3><div class="val" style="color: var(--danger);">{{ ioc_matches|length }}</div></div>
    <div class="card"><h3>Media & EXIF Findings</h3><div class="val">{{ media_findings|length }}</div></div>
  </div>

  {% if ioc_matches %}
  <h2>Threat Intelligence & IoC Detections</h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>Type</th><th>Indicator</th><th>Plugin</th><th>Source File</th><th>Context</th></tr>
    </thead>
    <tbody>
      {% for hit in ioc_matches %}
      <tr>
        <td><span class="badge-crit">{{ hit.severity }}</span></td>
        <td>{{ hit.ioc_type }}</td>
        <td><code>{{ hit.matched_indicator }}</code></td>
        <td>{{ hit.source_plugin }}</td>
        <td>{{ hit.source_file }}</td>
        <td>{{ hit.context_summary }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% endif %}

  <h2>Normalized Super-Timeline (UTC ISO-8601)</h2>
  <input type="search" id="filterInput" placeholder="Filter timeline events by keyword, number, URL, or package..." onkeyup="filterTable()" />
  <table id="timelineTable">
    <thead>
      <tr><th>UTC Timestamp</th><th>OS</th><th>Category</th><th>Artifact Type</th><th>Summary</th><th>Source File</th></tr>
    </thead>
    <tbody>
      {% for ev in timeline %}
      <tr>
        <td><code>{{ ev.datetime }}</code></td>
        <td>{{ ev.os_type }}</td>
        <td>{{ ev.category }}</td>
        <td>{{ ev.artifact_type }}</td>
        <td>{{ ev.message }}</td>
        <td>{{ ev.source_file }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>

  <script>
    function filterTable() {
      const q = document.getElementById("filterInput").value.toLowerCase();
      const rows = document.querySelectorAll("#timelineTable tbody tr");
      rows.forEach(r => {
        r.style.display = r.innerText.toLowerCase().includes(q) ? "" : "none";
      });
    }
  </script>
</body>
</html>
"""
)


def generate_html_report(
    output_path: Path,
    case_id: str,
    case_name: str,
    examiner: str,
    records: list[ArtifactRecord],
    timeline: list[TimelineEvent],
    ioc_matches: list[IoCMatch],
    media_findings: list[MediaForensicFinding],
) -> Path:
    """Render a standalone, offline HTML5 investigative report."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rendered = HTML_TEMPLATE.render(
        case_id=case_id,
        case_name=case_name,
        examiner=examiner,
        records=records,
        timeline=timeline,
        ioc_matches=ioc_matches,
        media_findings=media_findings,
    )
    output_path.write_text(rendered, encoding="utf-8")
    return output_path
