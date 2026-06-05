"""
offline_recon.py
================
Run the recon tools and SAVE the raw results to the filesystem WITHOUT calling
an LLM.

Why this exists
---------------
The LLM "brain" (agent.py) normally decides which tools to run and writes the
report. When the LLM API is unavailable (billing/rate-limit/outage) we still
want to do the actual scanning and keep the evidence. This module:

1. Runs a deterministic, rule-based recon plan (no LLM needed):
     nmap version scan  ->  if web ports open: httpx + whatweb + nuclei
                        ->  nmap vuln-script scan
2. Captures every tool's structured + raw output.
3. Writes a single self-describing JSON "scan bundle" to disk.

That JSON file is exactly the payload we feed to the LLM LATER, once the API is
back, to test the reasoning/report step in isolation:

    payload = json.load(open("runs/127_0_0_1-20260605T101500Z.json"))
    prompt  = payload_to_prompt(payload)
    # ... send `prompt` to the model, compare its report to a human one.

It is intentionally decoupled from llm.py / agent.py, so it imports cleanly and
runs even if the LLM client libraries are not installed at all.

SAFETY: the same code-level scope allow-list every wrapper enforces still
applies here — an out-of-scope target is refused before any binary runs.

Usage
-----
    python offline_recon.py 127.0.0.1
    python offline_recon.py 192.168.56.101 --scope 192.168.56.0/24 --out runs/
    python offline_recon.py juice.lab --severity high,critical --no-vuln
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from nmap_wrapper import (
    DEFAULT_ALLOWED_SCOPE,
    NmapResult,
    ScopeError,
    run_nmap,
)
from tool_wrappers import TOOL_REGISTRY as _WEB_REGISTRY


# ---------------------------------------------------------------------------
# Merged registry (nmap + web tools), mirroring agent.py but llm-free.
# ---------------------------------------------------------------------------

TOOL_REGISTRY: dict[str, Callable[..., Any]] = {
    "run_nmap": run_nmap,
    **{name: func for name, (func, _schema) in _WEB_REGISTRY.items()},
}

# Ports/services that mean "there is a web server here worth probing".
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000}
WEB_SERVICES = {"http", "https", "http-alt", "http-proxy", "https-alt", "ssl/http"}


# ---------------------------------------------------------------------------
# Run record — duck-compatible with report.write_reports / render_markdown.
# ---------------------------------------------------------------------------

@dataclass
class ReconBundle:
    """One offline recon run. Shaped to drop straight into report.py."""

    target: str
    allowed_scope: list[str]
    provider: str = "offline (no LLM)"   # report.py reads these for metadata
    model: str = "-"
    report: str = ""                      # no LLM write-up in offline mode
    steps: int = 0
    stopped_reason: str = "offline_recon"
    started_at: str = ""
    finished_at: str = ""
    plan: list[str] = field(default_factory=list)            # human-readable steps taken
    tool_calls: list[dict] = field(default_factory=list)     # {name, input}
    tool_results: list[dict] = field(default_factory=list)   # {name, input, output(json str)}
    structured: list[dict] = field(default_factory=list)     # rich, for the LLM payload


# ---------------------------------------------------------------------------
# Tool dispatch (local copy — keeps this module independent of agent.py/llm.py)
# ---------------------------------------------------------------------------

def _dispatch(name: str, args: dict, allowed_scope: list[str]):
    """Run one tool, return its result object (or None on hard failure).

    Errors are swallowed into a synthetic failed result so one bad tool never
    aborts the whole recon — the evidence of the failure is kept in the bundle.
    """
    func = TOOL_REGISTRY.get(name)
    if func is None:
        return None, {"error": f"Unknown tool {name!r}."}
    try:
        result = func(allowed_scope=allowed_scope, **args)
        return result, None
    except ScopeError as exc:
        return None, {"error": f"ScopeError: {exc}"}
    except TypeError as exc:
        return None, {"error": f"Bad arguments for {name}: {exc}"}
    except Exception as exc:  # pragma: no cover - defensive
        return None, {"error": f"{name} crashed: {exc}"}


def _record(bundle: ReconBundle, name: str, args: dict, result, err: Optional[dict]) -> None:
    """Append a tool run to the bundle in both report-shaped and rich form."""
    bundle.tool_calls.append({"name": name, "input": args})

    if err is not None:
        output = json.dumps(err)
        bundle.tool_results.append({"name": name, "input": args, "output": output})
        bundle.structured.append({
            "tool": name, "input": args, "success": False,
            "error": err.get("error"), "parsed": [], "summary": err.get("error"),
        })
        return

    output = result.to_json() if hasattr(result, "to_json") else json.dumps(str(result))
    bundle.tool_results.append({"name": name, "input": args, "output": output})

    entry: dict[str, Any] = {
        "tool": name,
        "input": args,
        "success": bool(getattr(result, "success", False)),
        "error": getattr(result, "error", None),
    }
    if isinstance(result, NmapResult):
        entry["summary"] = result.summary()
        entry["hosts"] = result.hosts
    else:  # ToolResult from tool_wrappers
        entry["parsed"] = getattr(result, "parsed", [])
        # Keep a trimmed raw tail so the payload stays sendable to an LLM.
        raw = getattr(result, "raw_stdout", "") or ""
        entry["raw_excerpt"] = raw if len(raw) <= 4000 else raw[:4000] + "\n…(truncated)"
    bundle.structured.append(entry)


# ---------------------------------------------------------------------------
# Rule-based planner (the part the LLM normally does)
# ---------------------------------------------------------------------------

def _open_web_targets(nmap_result: NmapResult, target: str) -> list[str]:
    """Inspect a parsed nmap result; return web URLs worth probing."""
    urls: list[str] = []
    if not isinstance(nmap_result, NmapResult) or not nmap_result.success:
        return urls
    for host in nmap_result.hosts:
        for p in host.get("ports", []):
            if p.get("state") != "open":
                continue
            port = int(p.get("port", 0) or 0)
            svc = (p.get("service") or "").lower()
            if port in WEB_PORTS or svc in WEB_SERVICES:
                scheme = "https" if port in (443, 8443) or "https" in svc or "ssl" in svc else "http"
                default = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
                urls.append(f"{scheme}://{target}" if default else f"{scheme}://{target}:{port}")
    # De-dupe, preserve order.
    seen: set[str] = set()
    return [u for u in urls if not (u in seen or seen.add(u))]


def run_offline_recon(
    target: str,
    *,
    allowed_scope: Optional[list[str]] = None,
    do_web: bool = True,
    do_vuln: bool = True,
    severity: str = "medium,high,critical",
    verbose: bool = True,
) -> ReconBundle:
    """Run the deterministic recon plan against `target` and return the bundle.

    No LLM is involved. The plan branches on real nmap output:
      1. nmap version scan  (open ports + service versions)
      2. for each open web port: httpx, whatweb, nuclei   (if do_web)
      3. nmap vuln NSE scripts                              (if do_vuln)
    """
    allowed_scope = allowed_scope or DEFAULT_ALLOWED_SCOPE
    bundle = ReconBundle(
        target=target,
        allowed_scope=list(allowed_scope),
        started_at=datetime.now(timezone.utc).isoformat(),
    )

    def step(name: str, args: dict, label: str) -> Any:
        bundle.steps += 1
        bundle.plan.append(label)
        if verbose:
            print(f"🔧 [step {bundle.steps}] {label}")
        result, err = _dispatch(name, args, allowed_scope)
        _record(bundle, name, args, result, err)
        return result

    # Scope guard up front: refuse out-of-scope before running anything.
    from nmap_wrapper import is_in_scope
    if not is_in_scope(target, allowed_scope):
        bundle.stopped_reason = "scope_refused"
        bundle.plan.append(f"REFUSED: {target} not in scope {allowed_scope}")
        bundle.finished_at = datetime.now(timezone.utc).isoformat()
        if verbose:
            print(f"❌ {target!r} not in authorized scope {allowed_scope} — nothing run.")
        return bundle

    # 1) Service/version scan.
    nmap_res = step("run_nmap", {"target": target, "scan_type": "version"},
                    "nmap version scan (open ports + service versions)")

    # 2) Web probing on whatever ports actually came back open.
    if do_web and isinstance(nmap_res, NmapResult):
        for url in _open_web_targets(nmap_res, target):
            step("run_httpx", {"target": url}, f"httpx probe {url}")
            step("run_whatweb", {"target": url}, f"whatweb fingerprint {url}")
            step("run_nuclei", {"target": url, "severity": severity},
                 f"nuclei scan {url} (severity={severity})")

    # 3) Deeper nmap vuln scripts.
    if do_vuln:
        step("run_nmap", {"target": target, "scan_type": "vuln"},
             "nmap vuln NSE scripts")

    bundle.finished_at = datetime.now(timezone.utc).isoformat()
    return bundle


# ---------------------------------------------------------------------------
# Persistence — the JSON scan bundle is the file we feed the LLM later.
# ---------------------------------------------------------------------------

def _safe_name(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", target) or "target"


def bundle_to_payload(bundle: ReconBundle) -> dict:
    """The JSON-serialisable scan record. This is the LLM input for later."""
    return {
        "schema": "recon-bundle/v1",
        "target": bundle.target,
        "allowed_scope": bundle.allowed_scope,
        "started_at": bundle.started_at,
        "finished_at": bundle.finished_at,
        "steps": bundle.steps,
        "stopped_reason": bundle.stopped_reason,
        "plan": bundle.plan,
        "results": bundle.structured,
    }


def save_bundle(bundle: ReconBundle, out_dir: str, *, write_report: bool = True) -> dict[str, str]:
    """Write the JSON payload (+ optional MD/HTML) to `out_dir`.

    Returns a dict of {kind: path}. The JSON is always written; MD/HTML are
    best-effort (they need jinja2 and must never break the scan).
    """
    os.makedirs(out_dir, exist_ok=True)
    ts = (bundle.finished_at or bundle.started_at or "").replace(":", "").replace("-", "")
    ts = ts.split(".")[0].replace("+0000", "Z") or "run"
    base = f"{_safe_name(bundle.target)}-{ts}"

    paths: dict[str, str] = {}
    json_path = os.path.join(out_dir, f"{base}.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(bundle_to_payload(bundle), fh, indent=2)
    paths["json"] = json_path

    if write_report:
        try:
            from report import write_reports
            md_path, html_path = write_reports(bundle, out_dir)
            paths["markdown"], paths["html"] = md_path, html_path
        except Exception as exc:  # pragma: no cover - reports optional
            paths["report_error"] = str(exc)
    return paths


# ---------------------------------------------------------------------------
# Bridge: turn a saved bundle into an LLM prompt (used later, when API is back).
# ---------------------------------------------------------------------------

REPORT_INSTRUCTIONS = """\
You are a penetration tester. Below is the raw output of an AUTHORIZED recon run
(saved earlier; no analysis has been done yet). Write a security report.

Format (Markdown):
  # Security Report: <target>
  ## Summary               (2-3 sentences, overall risk)
  ## Findings              (one subsection per finding)
     - Severity: info|low|medium|high|critical
     - Evidence: the concrete tool output that proves it
     - Remediation: how to fix it
  ## Scan Log              (the tools that were run and why)

Base every finding ONLY on the evidence below. Do not invent findings.
"""


def payload_to_prompt(payload: dict) -> str:
    """Render a saved scan bundle as a single prompt string for the LLM.

    Lets us test the reasoning step in isolation once the API is available:
        payload = json.load(open(path)); send(payload_to_prompt(payload))
    """
    parts = [REPORT_INSTRUCTIONS,
             f"\n## Recon data for target: {payload.get('target')}",
             f"Authorized scope: {payload.get('allowed_scope')}",
             f"Plan executed:\n" + "\n".join(f"  - {s}" for s in payload.get("plan", [])),
             "\n## Tool results\n"]
    for i, r in enumerate(payload.get("results", []), 1):
        parts.append(f"### {i}. {r.get('tool')} — input {json.dumps(r.get('input', {}))}")
        parts.append(f"success={r.get('success')} error={r.get('error')}")
        if r.get("summary"):
            parts.append(r["summary"])
        if r.get("parsed"):
            parts.append("parsed: " + json.dumps(r["parsed"])[:3000])
        if r.get("raw_excerpt"):
            parts.append("```\n" + r["raw_excerpt"] + "\n```")
        parts.append("")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline recon: run the tools and save the scan bundle to "
                    "disk (no LLM). AUTHORIZED targets only.",
    )
    parser.add_argument("target", help="Host/IP/domain (must be in scope).")
    parser.add_argument("--scope", action="append", default=None,
                        help="Allowed scope entry (IP/CIDR/host). Repeatable. "
                             "Defaults to localhost + private ranges.")
    parser.add_argument("--out", default="runs", help="Output dir. Default: runs/")
    parser.add_argument("--severity", default="medium,high,critical",
                        help="nuclei severity filter.")
    parser.add_argument("--no-web", action="store_true", help="Skip web tools.")
    parser.add_argument("--no-vuln", action="store_true", help="Skip nmap vuln scripts.")
    parser.add_argument("--no-report", action="store_true",
                        help="Write only the JSON bundle (skip MD/HTML).")
    parser.add_argument("--quiet", action="store_true", help="Hide step output.")
    args = parser.parse_args(argv)

    bundle = run_offline_recon(
        args.target,
        allowed_scope=args.scope,
        do_web=not args.no_web,
        do_vuln=not args.no_vuln,
        severity=args.severity,
        verbose=not args.quiet,
    )

    paths = save_bundle(bundle, args.out, write_report=not args.no_report)

    print("\n" + "=" * 70)
    print(f"Offline recon finished: {bundle.steps} tool runs "
          f"(stopped: {bundle.stopped_reason}).")
    print("=" * 70)
    for kind, path in paths.items():
        print(f"  {kind:>13}: {path}")
    print(f"\nFeed the JSON to the LLM later with payload_to_prompt(json.load(...)).")
    return 0 if bundle.stopped_reason != "scope_refused" else 2


if __name__ == "__main__":
    raise SystemExit(_main())
