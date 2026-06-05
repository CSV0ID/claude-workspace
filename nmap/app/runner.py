"""
runner.py
=========
Bridges the API to the existing recon code (nmap/tools). Runs one scan to
completion in a background thread and persists the result.

Two modes:
  - "offline" : offline_recon.run_offline_recon  (no LLM, default — always works)
  - "llm"     : agent.run_agent                  (needs a provider API key)

Both produce a run object that report.py can render, so persistence is uniform.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

# Make the flat tool modules importable (they live in nmap/tools).
_TOOLS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")
if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)

import report  # noqa: E402  (from nmap/tools)

from .db import SessionLocal, Scan


def _persist(scan_id: int, **fields) -> None:
    with SessionLocal() as s:
        row = s.get(Scan, scan_id)
        if row is None:
            return
        for k, v in fields.items():
            setattr(row, k, v)
        s.commit()


def run_scan(scan_id: int) -> None:
    """Execute the scan identified by `scan_id` and persist every outcome.

    Designed to run in a background thread/task. All errors are captured into
    the row (status='failed') — a crashing scan never takes down the server.
    """
    with SessionLocal() as s:
        row = s.get(Scan, scan_id)
        if row is None:
            return
        target = row.target
        mode = row.mode
        provider = row.provider or "anthropic"
        scope = json.loads(row.scope or "null")

    _persist(scan_id, status="running")

    try:
        if mode == "llm":
            import agent  # imported lazily: needs LLM client libs/keys
            run = agent.run_agent(
                target, provider=provider, allowed_scope=scope, verbose=False)
            bundle_json = json.dumps({
                "target": run.target, "provider": run.provider, "model": run.model,
                "steps": run.steps, "stopped_reason": run.stopped_reason,
                "tool_results": run.tool_results,
            }, indent=2)
            stopped = run.stopped_reason
            steps = run.steps
        else:  # offline (default)
            import offline_recon
            bundle = offline_recon.run_offline_recon(
                target, allowed_scope=scope, verbose=False)
            run = bundle
            bundle_json = json.dumps(offline_recon.bundle_to_payload(bundle), indent=2)
            stopped = bundle.stopped_reason
            steps = bundle.steps

        md = report.render_markdown(run)
        html = report.render_html(run)
        counts = report.count_severities(md)

        _persist(
            scan_id,
            status="done",
            stopped_reason=stopped,
            steps=steps,
            report_md=md,
            report_html=html,
            bundle_json=bundle_json,
            sev_counts=json.dumps(counts),
            finished_at=datetime.now(timezone.utc),
        )
    except Exception as exc:  # any failure -> failed row, server stays up
        _persist(
            scan_id,
            status="failed",
            error=f"{type(exc).__name__}: {exc}",
            finished_at=datetime.now(timezone.utc),
        )
