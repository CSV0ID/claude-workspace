"""
report.py
=========
Report generator for the AI Pentesting / Recon Assistant (roadmap Month 3).

Turns an ``AgentRun`` (from agent.py) into clean, shareable artifacts:

    - a Markdown report (the model's own write-up + an appendix of raw tool runs)
    - a styled, self-contained HTML report (Jinja2, severity-coloured)

The HTML is intentionally single-file (inline CSS, no external assets) so it can
be emailed, dropped in a ticket, or opened straight from disk in a demo.

Public API
----------
    render_markdown(run)        -> str
    render_html(run)            -> str
    write_reports(run, out_dir) -> [md_path, html_path]
"""

from __future__ import annotations

import html
import json
import os
import re
from typing import Any

from jinja2 import Environment, BaseLoader, select_autoescape


# Severity ordering / colours used in the HTML badges.
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
SEVERITY_COLORS = {
    "critical": "#8b0000",
    "high":     "#d9534f",
    "medium":   "#f0ad4e",
    "low":      "#5bc0de",
    "info":     "#5cb85c",
    "unknown":  "#777777",
}


# ---------------------------------------------------------------------------
# Light parsing of the model's Markdown report to count severities
# ---------------------------------------------------------------------------

_SEV_RE = re.compile(r"severity[:\s*]*\**\s*(critical|high|medium|low|info)",
                     re.IGNORECASE)


def count_severities(markdown: str) -> dict[str, int]:
    """Count 'Severity: X' mentions in the model's report (best-effort)."""
    counts = {s: 0 for s in SEVERITY_ORDER if s != "unknown"}
    for m in _SEV_RE.finditer(markdown or ""):
        counts[m.group(1).lower()] += 1
    return counts


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def render_markdown(run: Any) -> str:
    """Build a full Markdown report: the model's write-up + a raw-runs appendix."""
    lines: list[str] = []
    body = (getattr(run, "report", "") or "").strip()
    if not body.lower().startswith("# "):
        lines.append(f"# Security Report: {run.target}\n")
    lines.append(body or "_(no report text produced)_")

    lines.append("\n\n---\n")
    lines.append("## Run Metadata\n")
    lines.append(f"- Target: `{run.target}`")
    lines.append(f"- Provider/Model: `{getattr(run, 'provider', '')}/{getattr(run, 'model', '')}`")
    lines.append(f"- Steps: {getattr(run, 'steps', 0)}")
    lines.append(f"- Tool calls: {len(getattr(run, 'tool_calls', []))}")
    lines.append(f"- Stopped: `{getattr(run, 'stopped_reason', '')}`")

    results = getattr(run, "tool_results", []) or []
    if results:
        lines.append("\n## Appendix — Raw Tool Runs\n")
        for i, r in enumerate(results, 1):
            lines.append(f"### {i}. `{r.get('name','?')}`")
            lines.append(f"Input: `{json.dumps(r.get('input', {}))}`\n")
            out = r.get("output", "")
            snippet = out if len(out) <= 4000 else out[:4000] + "\n…(truncated)"
            lines.append("```json")
            lines.append(snippet)
            lines.append("```")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Report — {{ target }}</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         margin: 0; background: #f5f6f8; color: #1c1e21; }
  .wrap { max-width: 900px; margin: 0 auto; padding: 32px 24px 64px; }
  header { background: #0f1b2d; color: #fff; padding: 28px 24px; border-radius: 10px; }
  header h1 { margin: 0 0 6px; font-size: 22px; }
  header .meta { opacity: .8; font-size: 13px; }
  .badges { margin: 20px 0; display: flex; flex-wrap: wrap; gap: 10px; }
  .badge { color:#fff; padding:6px 12px; border-radius:20px; font-size:13px; font-weight:600; }
  .card { background:#fff; border:1px solid #e3e6ea; border-radius:10px;
          padding:20px 24px; margin:18px 0; }
  pre { background:#0f1b2d; color:#d6e2f0; padding:14px; border-radius:8px;
        overflow:auto; font-size:12.5px; line-height:1.45; }
  code { background:#eef0f3; padding:2px 5px; border-radius:4px; font-size:12.5px; }
  h2 { border-bottom:2px solid #e3e6ea; padding-bottom:6px; margin-top:28px; }
  .report { white-space: pre-wrap; line-height:1.55; }
  .muted { color:#65676b; font-size:13px; }
  footer { text-align:center; color:#9aa0a6; font-size:12px; margin-top:30px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>🛡️ Security Report — {{ target }}</h1>
    <div class="meta">
      {{ provider }}/{{ model }} ·
      {{ steps }} steps · {{ n_calls }} tool calls · stopped: {{ stopped }}
    </div>
  </header>

  <div class="badges">
    {% for sev in sev_order %}
      {% if counts.get(sev, 0) > 0 %}
      <span class="badge" style="background:{{ colors[sev] }}">
        {{ sev|capitalize }}: {{ counts[sev] }}
      </span>
      {% endif %}
    {% endfor %}
    {% if total_findings == 0 %}
      <span class="badge" style="background:{{ colors['info'] }}">No severities parsed</span>
    {% endif %}
  </div>

  <div class="card">
    <div class="report">{{ report }}</div>
  </div>

  {% if results %}
  <h2>Appendix — Raw Tool Runs</h2>
  {% for r in results %}
  <div class="card">
    <strong>{{ loop.index }}. {{ r.name }}</strong>
    <div class="muted">input: <code>{{ r.input }}</code></div>
    <pre>{{ r.output }}</pre>
  </div>
  {% endfor %}
  {% endif %}

  <footer>Generated by the AI Pentesting / Recon Assistant · authorized targets only</footer>
</div>
</body>
</html>
"""


def render_html(run: Any) -> str:
    """Render the run as a self-contained HTML document."""
    env = Environment(loader=BaseLoader(), autoescape=select_autoescape(["html"]))
    template = env.from_string(_HTML_TEMPLATE)

    report_md = (getattr(run, "report", "") or "").strip() or "(no report text produced)"
    counts = count_severities(report_md)
    results = []
    for r in (getattr(run, "tool_results", []) or []):
        out = r.get("output", "")
        results.append({
            "name": r.get("name", "?"),
            "input": json.dumps(r.get("input", {})),
            "output": out if len(out) <= 6000 else out[:6000] + "\n…(truncated)",
        })

    return template.render(
        target=run.target,
        provider=getattr(run, "provider", ""),
        model=getattr(run, "model", ""),
        steps=getattr(run, "steps", 0),
        n_calls=len(getattr(run, "tool_calls", [])),
        stopped=getattr(run, "stopped_reason", ""),
        report=report_md,
        counts=counts,
        total_findings=sum(counts.values()),
        sev_order=SEVERITY_ORDER,
        colors=SEVERITY_COLORS,
        results=results,
    )


# ---------------------------------------------------------------------------
# Disk writing
# ---------------------------------------------------------------------------

def _safe_name(target: str) -> str:
    """Filesystem-safe slug from a target string."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", target) or "report"


def write_reports(run: Any, out_dir: str) -> list[str]:
    """Write Markdown + HTML reports into `out_dir`; return the file paths."""
    os.makedirs(out_dir, exist_ok=True)
    base = _safe_name(run.target)
    md_path = os.path.join(out_dir, f"{base}.md")
    html_path = os.path.join(out_dir, f"{base}.html")

    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(run))
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(render_html(run))
    return [md_path, html_path]
