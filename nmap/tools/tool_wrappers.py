"""
tool_wrappers.py
================
Wrappers for the rest of the recon toolset used by the AI Pentesting Assistant:

    - subfinder  : passive subdomain enumeration
    - httpx      : probe which hosts are alive over HTTP/S
    - whatweb    : web technology fingerprinting
    - nuclei     : template-based vulnerability scanner
    - gobuster   : directory / path brute-forcing

Each wrapper follows the SAME contract so the LLM agent can treat them uniformly:

    run_<tool>(...) -> ToolResult

and each exposes a `*_TOOL_SCHEMA` dict for LLM function-calling.

SAFETY: every wrapper that hits a network target goes through the same scope
guard (`is_in_scope`) imported from nmap_wrapper. Only scan authorized hosts.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Optional

from nmap_wrapper import (
    DEFAULT_ALLOWED_SCOPE,
    ScopeError,
    is_in_scope,
)


# ---------------------------------------------------------------------------
# Shared result container
# ---------------------------------------------------------------------------

@dataclass
class ToolResult:
    tool: str
    target: str
    command: list[str]
    success: bool
    parsed: list[dict] = field(default_factory=list)  # structured findings
    raw_stdout: str = ""
    raw_stderr: str = ""
    error: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _check_installed(binary: str) -> Optional[str]:
    """Return an error string if the binary is missing, else None."""
    if shutil.which(binary) is None:
        return f"{binary} is not installed or not on PATH."
    return None


def _guard_scope(target: str, allowed_scope: list[str]) -> None:
    """Raise ScopeError if target is out of scope.

    For tools that take a domain (subfinder), we also allow the bare domain to
    be matched as an exact string in the scope list.
    """
    if not is_in_scope(target, allowed_scope):
        raise ScopeError(
            f"Target {target!r} is not in the authorized scope. "
            f"Allowed: {allowed_scope}"
        )


def _run(cmd: list[str], timeout: int) -> tuple[bool, str, str, Optional[str]]:
    """Execute a command, returning (success, stdout, stderr, error)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
        err = None if proc.returncode == 0 else (proc.stderr.strip() or "non-zero exit")
        return proc.returncode == 0, proc.stdout, proc.stderr, err
    except subprocess.TimeoutExpired:
        return False, "", "", f"Timed out after {timeout}s."
    except Exception as exc:  # pragma: no cover - defensive
        return False, "", "", f"Failed to run command: {exc}"


def _parse_jsonl(text: str) -> list[dict]:
    """Parse newline-delimited JSON (many tools support -json output)."""
    out: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


# ---------------------------------------------------------------------------
# subfinder — passive subdomain enumeration
# ---------------------------------------------------------------------------

def run_subfinder(
    domain: str,
    *,
    allowed_scope: Optional[list[str]] = None,
    timeout: int = 300,
) -> ToolResult:
    """Enumerate subdomains of `domain` passively."""
    allowed_scope = allowed_scope or DEFAULT_ALLOWED_SCOPE
    if err := _check_installed("subfinder"):
        return ToolResult("subfinder", domain, [], False, error=err)
    _guard_scope(domain, allowed_scope)

    # -silent: only subdomains; -oJ -: JSONL to stdout.
    cmd = ["subfinder", "-d", domain, "-silent", "-oJ"]
    ok, out, errout, error = _run(cmd, timeout)
    parsed = _parse_jsonl(out)
    return ToolResult(
        "subfinder", domain, cmd, ok,
        parsed=parsed, raw_stdout=out, raw_stderr=errout, error=error,
    )


# ---------------------------------------------------------------------------
# httpx — probe live HTTP/S hosts
# ---------------------------------------------------------------------------

def run_httpx(
    target: str,
    *,
    allowed_scope: Optional[list[str]] = None,
    timeout: int = 180,
) -> ToolResult:
    """Probe a host/URL for a live HTTP/S service; grab status, title, tech."""
    allowed_scope = allowed_scope or DEFAULT_ALLOWED_SCOPE
    if err := _check_installed("httpx"):
        return ToolResult("httpx", target, [], False, error=err)
    _guard_scope(_host_only(target), allowed_scope)

    # -json: structured output; -title -status-code -tech-detect: useful fields.
    cmd = [
        "httpx", "-u", target, "-json",
        "-title", "-status-code", "-tech-detect", "-silent",
    ]
    ok, out, errout, error = _run(cmd, timeout)
    parsed = _parse_jsonl(out)
    return ToolResult(
        "httpx", target, cmd, ok,
        parsed=parsed, raw_stdout=out, raw_stderr=errout, error=error,
    )


# ---------------------------------------------------------------------------
# whatweb — web technology fingerprinting
# ---------------------------------------------------------------------------

def run_whatweb(
    target: str,
    *,
    allowed_scope: Optional[list[str]] = None,
    timeout: int = 180,
) -> ToolResult:
    """Fingerprint the web technologies running on `target`."""
    allowed_scope = allowed_scope or DEFAULT_ALLOWED_SCOPE
    if err := _check_installed("whatweb"):
        return ToolResult("whatweb", target, [], False, error=err)
    _guard_scope(_host_only(target), allowed_scope)

    # --log-json -: emit JSON to stdout; --no-errors: quieter.
    cmd = ["whatweb", "--log-json=-", "--no-errors", target]
    ok, out, errout, error = _run(cmd, timeout)
    parsed = _parse_jsonl(out)
    return ToolResult(
        "whatweb", target, cmd, ok,
        parsed=parsed, raw_stdout=out, raw_stderr=errout, error=error,
    )


# ---------------------------------------------------------------------------
# nuclei — template-based vulnerability scanner (the big one)
# ---------------------------------------------------------------------------

def run_nuclei(
    target: str,
    *,
    severity: str = "medium,high,critical",
    allowed_scope: Optional[list[str]] = None,
    timeout: int = 900,
) -> ToolResult:
    """Run nuclei against `target`, filtering by severity.

    `severity` is a comma list among: info, low, medium, high, critical.
    """
    allowed_scope = allowed_scope or DEFAULT_ALLOWED_SCOPE
    if err := _check_installed("nuclei"):
        return ToolResult("nuclei", target, [], False, error=err)
    _guard_scope(_host_only(target), allowed_scope)

    valid = {"info", "low", "medium", "high", "critical"}
    sevs = [s.strip() for s in severity.split(",") if s.strip()]
    bad = [s for s in sevs if s not in valid]
    if bad:
        return ToolResult(
            "nuclei", target, [], False,
            error=f"Invalid severities {bad}. Allowed: {sorted(valid)}.",
        )

    # -jsonl: structured; -severity: filter; -silent: no banner noise.
    cmd = [
        "nuclei", "-u", target,
        "-severity", ",".join(sevs),
        "-jsonl", "-silent",
    ]
    ok, out, errout, error = _run(cmd, timeout)
    parsed = _parse_jsonl(out)
    return ToolResult(
        "nuclei", target, cmd, ok,
        parsed=parsed, raw_stdout=out, raw_stderr=errout, error=error,
    )


# ---------------------------------------------------------------------------
# gobuster — directory / path brute-forcing
# ---------------------------------------------------------------------------

def run_gobuster(
    target: str,
    wordlist: str,
    *,
    extensions: Optional[str] = None,
    allowed_scope: Optional[list[str]] = None,
    timeout: int = 600,
) -> ToolResult:
    """Brute-force directories/files on a web target using `wordlist`."""
    allowed_scope = allowed_scope or DEFAULT_ALLOWED_SCOPE
    if err := _check_installed("gobuster"):
        return ToolResult("gobuster", target, [], False, error=err)
    _guard_scope(_host_only(target), allowed_scope)

    cmd = ["gobuster", "dir", "-u", target, "-w", wordlist, "-q", "-z"]
    if extensions:
        cmd += ["-x", extensions]
    ok, out, errout, error = _run(cmd, timeout)

    # gobuster -q prints "  /admin (Status: 200) [Size: 1234]" lines.
    parsed = [{"line": ln.strip()} for ln in out.splitlines() if ln.strip()]
    return ToolResult(
        "gobuster", target, cmd, ok,
        parsed=parsed, raw_stdout=out, raw_stderr=errout, error=error,
    )


# ---------------------------------------------------------------------------
# small util
# ---------------------------------------------------------------------------

def _host_only(target: str) -> str:
    """Strip scheme/path so scope checks see just the host.

    'http://192.168.1.5:8080/path' -> '192.168.1.5'
    """
    t = target.split("://", 1)[-1]      # drop scheme
    t = t.split("/", 1)[0]              # drop path
    t = t.split(":", 1)[0]             # drop port
    return t


# ---------------------------------------------------------------------------
# LLM function-calling schemas
# ---------------------------------------------------------------------------

SUBFINDER_TOOL_SCHEMA = {
    "name": "run_subfinder",
    "description": "Passively enumerate subdomains of an authorized domain.",
    "input_schema": {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Root domain to enumerate."},
        },
        "required": ["domain"],
    },
}

HTTPX_TOOL_SCHEMA = {
    "name": "run_httpx",
    "description": "Probe a host/URL for a live HTTP/S service; returns status, title, detected tech.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host or URL to probe."},
        },
        "required": ["target"],
    },
}

WHATWEB_TOOL_SCHEMA = {
    "name": "run_whatweb",
    "description": "Fingerprint web technologies (CMS, frameworks, servers) on a target URL.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "URL to fingerprint."},
        },
        "required": ["target"],
    },
}

NUCLEI_TOOL_SCHEMA = {
    "name": "run_nuclei",
    "description": "Scan a target for known vulnerabilities using nuclei templates, filtered by severity.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Host or URL to scan."},
            "severity": {
                "type": "string",
                "description": "Comma list among info,low,medium,high,critical.",
            },
        },
        "required": ["target"],
    },
}

GOBUSTER_TOOL_SCHEMA = {
    "name": "run_gobuster",
    "description": "Brute-force hidden directories/files on a web target using a wordlist.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Base URL, e.g. http://host."},
            "wordlist": {"type": "string", "description": "Path to a wordlist file."},
            "extensions": {"type": "string", "description": "Optional, e.g. 'php,html'."},
        },
        "required": ["target", "wordlist"],
    },
}


# Registry: name -> (callable, schema). The agent loop iterates over this.
TOOL_REGISTRY = {
    "run_subfinder": (run_subfinder, SUBFINDER_TOOL_SCHEMA),
    "run_httpx":     (run_httpx, HTTPX_TOOL_SCHEMA),
    "run_whatweb":   (run_whatweb, WHATWEB_TOOL_SCHEMA),
    "run_nuclei":    (run_nuclei, NUCLEI_TOOL_SCHEMA),
    "run_gobuster":  (run_gobuster, GOBUSTER_TOOL_SCHEMA),
}


if __name__ == "__main__":
    # Quick smoke test: report which tools are installed on this machine.
    for name in ["subfinder", "httpx", "whatweb", "nuclei", "gobuster"]:
        status = "FOUND" if shutil.which(name) else "missing"
        print(f"{name:12} {status}")
