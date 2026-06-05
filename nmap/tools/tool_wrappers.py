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
    _guard_scope(domain, allowed_scope)
    if err := _check_installed("subfinder"):
        return ToolResult("subfinder", domain, [], False, error=err)

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
    _guard_scope(_host_only(target), allowed_scope)
    if err := _check_installed("httpx"):
        return ToolResult("httpx", target, [], False, error=err)

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
    _guard_scope(_host_only(target), allowed_scope)
    if err := _check_installed("whatweb"):
        return ToolResult("whatweb", target, [], False, error=err)

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
    _guard_scope(_host_only(target), allowed_scope)
    if err := _check_installed("nuclei"):
        return ToolResult("nuclei", target, [], False, error=err)

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
    _guard_scope(_host_only(target), allowed_scope)
    if err := _check_installed("gobuster"):
        return ToolResult("gobuster", target, [], False, error=err)

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
# nikto — classic web server vulnerability scanner
# ---------------------------------------------------------------------------

def run_nikto(
    target: str,
    *,
    allowed_scope: Optional[list[str]] = None,
    timeout: int = 900,
) -> ToolResult:
    """Scan a web server for known issues / misconfigurations with nikto."""
    allowed_scope = allowed_scope or DEFAULT_ALLOWED_SCOPE
    _guard_scope(_host_only(target), allowed_scope)
    if err := _check_installed("nikto"):
        return ToolResult("nikto", target, [], False, error=err)

    # -Format json -output -: emit JSON to stdout; -ask no: never prompt.
    cmd = ["nikto", "-h", target, "-Format", "json", "-output", "-", "-ask", "no"]
    ok, out, errout, error = _run(cmd, timeout)
    parsed = _parse_nikto(out)
    return ToolResult(
        "nikto", target, cmd, ok,
        parsed=parsed, raw_stdout=out, raw_stderr=errout, error=error,
    )


def _parse_nikto(text: str) -> list[dict]:
    """Pull the vulnerability items out of nikto's JSON output."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    # nikto may emit a list of host objects or a single object.
    hosts = data if isinstance(data, list) else [data]
    findings: list[dict] = []
    for h in hosts:
        for v in (h.get("vulnerabilities") or []):
            findings.append({
                "id": v.get("id", ""),
                "method": v.get("method", ""),
                "url": v.get("url", ""),
                "msg": v.get("msg", ""),
            })
    return findings


# ---------------------------------------------------------------------------
# sslscan — TLS/SSL configuration & certificate auditing
# ---------------------------------------------------------------------------

def run_sslscan(
    target: str,
    *,
    allowed_scope: Optional[list[str]] = None,
    timeout: int = 180,
) -> ToolResult:
    """Audit a host's TLS configuration (protocols, ciphers, cert) with sslscan."""
    allowed_scope = allowed_scope or DEFAULT_ALLOWED_SCOPE
    host = _host_only(target)
    _guard_scope(host, allowed_scope)
    if err := _check_installed("sslscan"):
        return ToolResult("sslscan", target, [], False, error=err)

    # --no-colour keeps stdout clean for parsing.
    cmd = ["sslscan", "--no-colour", target]
    ok, out, errout, error = _run(cmd, timeout)
    # Flag weak/deprecated protocols if present in the text output.
    weak = [p for p in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1") if f"{p}   enabled" in out or f"{p}  enabled" in out]
    parsed = [{"weak_protocols": weak}] if weak else []
    return ToolResult(
        "sslscan", target, cmd, ok,
        parsed=parsed, raw_stdout=out, raw_stderr=errout, error=error,
    )


# ---------------------------------------------------------------------------
# wafw00f — detect & fingerprint Web Application Firewalls
# ---------------------------------------------------------------------------

def run_wafw00f(
    target: str,
    *,
    allowed_scope: Optional[list[str]] = None,
    timeout: int = 120,
) -> ToolResult:
    """Detect whether a WAF sits in front of a web target."""
    allowed_scope = allowed_scope or DEFAULT_ALLOWED_SCOPE
    _guard_scope(_host_only(target), allowed_scope)
    if err := _check_installed("wafw00f"):
        return ToolResult("wafw00f", target, [], False, error=err)

    # -o - -f json: JSON report to stdout.
    cmd = ["wafw00f", target, "-o", "-", "-f", "json"]
    ok, out, errout, error = _run(cmd, timeout)
    parsed = []
    try:
        data = json.loads(out)
        parsed = data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        pass
    return ToolResult(
        "wafw00f", target, cmd, ok,
        parsed=parsed, raw_stdout=out, raw_stderr=errout, error=error,
    )


# ---------------------------------------------------------------------------
# dnsx — fast DNS resolution / record enumeration
# ---------------------------------------------------------------------------

def run_dnsx(
    domain: str,
    *,
    record_types: str = "a,aaaa,cname,mx,ns,txt",
    allowed_scope: Optional[list[str]] = None,
    timeout: int = 180,
) -> ToolResult:
    """Resolve DNS records for a domain with dnsx (JSONL output)."""
    allowed_scope = allowed_scope or DEFAULT_ALLOWED_SCOPE
    _guard_scope(domain, allowed_scope)
    if err := _check_installed("dnsx"):
        return ToolResult("dnsx", domain, [], False, error=err)

    types = [t.strip() for t in record_types.split(",") if t.strip()]
    cmd = ["dnsx", "-silent", "-json", "-d", domain]
    for t in types:
        cmd.append(f"-{t}")
    ok, out, errout, error = _run(cmd, timeout)
    parsed = _parse_jsonl(out)
    return ToolResult(
        "dnsx", domain, cmd, ok,
        parsed=parsed, raw_stdout=out, raw_stderr=errout, error=error,
    )


# ---------------------------------------------------------------------------
# ffuf — fast web fuzzer (directories, vhosts, params)
# ---------------------------------------------------------------------------

def run_ffuf(
    target: str,
    wordlist: str,
    *,
    extensions: Optional[str] = None,
    allowed_scope: Optional[list[str]] = None,
    timeout: int = 600,
) -> ToolResult:
    """Fuzz a web target with ffuf. `target` must contain the FUZZ keyword,
    e.g. 'http://host/FUZZ'. If it doesn't, '/FUZZ' is appended."""
    allowed_scope = allowed_scope or DEFAULT_ALLOWED_SCOPE
    _guard_scope(_host_only(target), allowed_scope)
    if err := _check_installed("ffuf"):
        return ToolResult("ffuf", target, [], False, error=err)

    url = target if "FUZZ" in target else target.rstrip("/") + "/FUZZ"
    # -of json -o -: JSON report to stdout; -s: silent.
    cmd = ["ffuf", "-u", url, "-w", wordlist, "-of", "json", "-o", "-", "-s"]
    if extensions:
        cmd += ["-e", extensions]
    ok, out, errout, error = _run(cmd, timeout)
    parsed = _parse_ffuf(out)
    return ToolResult(
        "ffuf", target, cmd, ok,
        parsed=parsed, raw_stdout=out, raw_stderr=errout, error=error,
    )


def _parse_ffuf(text: str) -> list[dict]:
    """Extract the result rows from ffuf's JSON report."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    for r in (data.get("results") or []):
        out.append({
            "url": r.get("url", ""),
            "status": r.get("status", 0),
            "length": r.get("length", 0),
            "words": r.get("words", 0),
        })
    return out


# ---------------------------------------------------------------------------
# katana — fast web crawler (endpoint/URL discovery)
# ---------------------------------------------------------------------------

def run_katana(
    target: str,
    *,
    depth: int = 2,
    allowed_scope: Optional[list[str]] = None,
    timeout: int = 300,
) -> ToolResult:
    """Crawl a web target with katana to enumerate URLs/endpoints."""
    allowed_scope = allowed_scope or DEFAULT_ALLOWED_SCOPE
    _guard_scope(_host_only(target), allowed_scope)
    if err := _check_installed("katana"):
        return ToolResult("katana", target, [], False, error=err)

    if not 1 <= depth <= 10:
        return ToolResult("katana", target, [], False,
                          error=f"Invalid depth {depth!r}; use 1-10.")
    # -jsonl: structured per-URL output; -silent: no banner.
    cmd = ["katana", "-u", target, "-d", str(depth), "-jsonl", "-silent"]
    ok, out, errout, error = _run(cmd, timeout)
    parsed = _parse_jsonl(out)
    return ToolResult(
        "katana", target, cmd, ok,
        parsed=parsed, raw_stdout=out, raw_stderr=errout, error=error,
    )


# ---------------------------------------------------------------------------
# wpscan — WordPress vulnerability scanner
# ---------------------------------------------------------------------------

def run_wpscan(
    target: str,
    *,
    allowed_scope: Optional[list[str]] = None,
    timeout: int = 900,
) -> ToolResult:
    """Scan a WordPress site for vulnerable core/plugins/themes with wpscan."""
    allowed_scope = allowed_scope or DEFAULT_ALLOWED_SCOPE
    _guard_scope(_host_only(target), allowed_scope)
    if err := _check_installed("wpscan"):
        return ToolResult("wpscan", target, [], False, error=err)

    # -f json -o -: JSON to stdout; --no-banner: quiet; -e vp: vulnerable plugins.
    cmd = ["wpscan", "--url", target, "-f", "json", "-o", "-",
           "--no-banner", "-e", "vp"]
    ok, out, errout, error = _run(cmd, timeout)
    parsed = []
    try:
        data = json.loads(out)
        parsed = [data] if isinstance(data, dict) else data
    except json.JSONDecodeError:
        pass
    return ToolResult(
        "wpscan", target, cmd, ok,
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

NIKTO_TOOL_SCHEMA = {
    "name": "run_nikto",
    "description": "Scan a web server for known vulnerabilities and misconfigurations (nikto).",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Web server URL or host."},
        },
        "required": ["target"],
    },
}

SSLSCAN_TOOL_SCHEMA = {
    "name": "run_sslscan",
    "description": "Audit a host's TLS/SSL configuration, protocols, ciphers and certificate.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "host or host:port (e.g. host:443)."},
        },
        "required": ["target"],
    },
}

WAFW00F_TOOL_SCHEMA = {
    "name": "run_wafw00f",
    "description": "Detect and fingerprint a Web Application Firewall in front of a target.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Web URL or host to test."},
        },
        "required": ["target"],
    },
}

DNSX_TOOL_SCHEMA = {
    "name": "run_dnsx",
    "description": "Resolve DNS records (A/AAAA/CNAME/MX/NS/TXT) for a domain.",
    "input_schema": {
        "type": "object",
        "properties": {
            "domain": {"type": "string", "description": "Domain to resolve."},
            "record_types": {"type": "string", "description": "Comma list, e.g. 'a,mx,txt'."},
        },
        "required": ["domain"],
    },
}

FFUF_TOOL_SCHEMA = {
    "name": "run_ffuf",
    "description": "Fast web fuzzer for directories/files. Use FUZZ keyword in the URL.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "URL with FUZZ, e.g. http://host/FUZZ."},
            "wordlist": {"type": "string", "description": "Path to a wordlist file."},
            "extensions": {"type": "string", "description": "Optional, e.g. '.php,.html'."},
        },
        "required": ["target", "wordlist"],
    },
}

KATANA_TOOL_SCHEMA = {
    "name": "run_katana",
    "description": "Crawl a web target to enumerate URLs/endpoints up to a given depth.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "Base URL to crawl."},
            "depth": {"type": "integer", "description": "Crawl depth 1-10 (default 2)."},
        },
        "required": ["target"],
    },
}

WPSCAN_TOOL_SCHEMA = {
    "name": "run_wpscan",
    "description": "Scan a WordPress site for vulnerable core, plugins and themes.",
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "WordPress site URL."},
        },
        "required": ["target"],
    },
}


# Registry: name -> (callable, schema). The agent loop iterates over this.
TOOL_REGISTRY = {
    "run_subfinder": (run_subfinder, SUBFINDER_TOOL_SCHEMA),
    "run_httpx":     (run_httpx, HTTPX_TOOL_SCHEMA),
    "run_whatweb":   (run_whatweb, WHATWEB_TOOL_SCHEMA),
    "run_nuclei":    (run_nuclei, NUCLEI_TOOL_SCHEMA),
    "run_gobuster":  (run_gobuster, GOBUSTER_TOOL_SCHEMA),
    "run_nikto":     (run_nikto, NIKTO_TOOL_SCHEMA),
    "run_sslscan":   (run_sslscan, SSLSCAN_TOOL_SCHEMA),
    "run_wafw00f":   (run_wafw00f, WAFW00F_TOOL_SCHEMA),
    "run_dnsx":      (run_dnsx, DNSX_TOOL_SCHEMA),
    "run_ffuf":      (run_ffuf, FFUF_TOOL_SCHEMA),
    "run_katana":    (run_katana, KATANA_TOOL_SCHEMA),
    "run_wpscan":    (run_wpscan, WPSCAN_TOOL_SCHEMA),
}


if __name__ == "__main__":
    # Quick smoke test: report which tools are installed on this machine.
    bins = ["subfinder", "httpx", "whatweb", "nuclei", "gobuster", "nikto",
            "sslscan", "wafw00f", "dnsx", "ffuf", "katana", "wpscan"]
    for name in bins:
        status = "FOUND" if shutil.which(name) else "missing"
        print(f"{name:12} {status}")
