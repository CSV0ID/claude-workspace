"""
nmap_wrapper.py
================
A smart, LLM-friendly wrapper around nmap for the AI Pentesting / Recon Assistant.

Design goal
-----------
Instead of exposing dozens of raw nmap flags to the LLM, we expose ONE function,
`run_nmap(...)`, with a small set of high-level, well-described parameters. The
LLM chooses *what* it wants (a version scan, a vuln-script scan, a full-port
scan, etc.) and this module translates that intent into a correct, safe nmap
command line.

Key features
------------
- Builds the nmap command from structured arguments (no shell string injection).
- Parses nmap's XML output (-oX) into clean Python dicts / JSON.
- Enforces a scope allow-list so the agent can only scan authorized targets.
- Sensible timeouts so a scan can't hang the agent forever.

SAFETY: Only scan hosts you own or are explicitly authorized to test.
        The `ScopeError` guard exists to enforce that at the code level.
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from typing import Optional


# ---------------------------------------------------------------------------
# Scope control — the legal/safety guardrail
# ---------------------------------------------------------------------------

class ScopeError(Exception):
    """Raised when a target is not inside the authorized scope."""


# Edit this to match YOUR lab. Supports exact hostnames, IPs, and CIDR ranges.
# Defaults to localhost + common private lab ranges only.
DEFAULT_ALLOWED_SCOPE = [
    "127.0.0.1",
    "localhost",
    "10.0.0.0/8",
    "192.168.0.0/16",
    "172.16.0.0/12",
]


def is_in_scope(target: str, allowed_scope: list[str]) -> bool:
    """Return True if `target` is covered by the allow-list.

    Matches by exact string (hostnames) or by IP/CIDR membership.
    """
    target = target.strip().lower()

    # Exact hostname / string match (e.g. "localhost", "scanme.nmap.org")
    for entry in allowed_scope:
        if target == entry.strip().lower():
            return True

    # IP / CIDR match
    try:
        target_ip = ipaddress.ip_address(target)
    except ValueError:
        # Not a literal IP (it's a hostname). Only allow if exact-matched above.
        return False

    for entry in allowed_scope:
        try:
            if target_ip in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


# ---------------------------------------------------------------------------
# Scan profiles — the high-level "intents" the LLM can pick from
# ---------------------------------------------------------------------------
#
# Each profile maps to a set of nmap flags. This is what keeps the interface
# small for the LLM: it picks a profile name, not raw flags.

SCAN_PROFILES: dict[str, list[str]] = {
    # Is the host even up? (host discovery only, no port scan)
    "ping":        ["-sn"],

    # Fast scan of the most common 1000 ports.
    "quick":       ["-T4", "--top-ports", "1000"],

    # Service + version detection on common ports.
    "version":     ["-sV", "-T4"],

    # Everything: all 65535 ports + version detection.
    "full":        ["-p-", "-sV", "-T4"],

    # Default safe scripts + version detection (-sC == --script=default).
    "default":     ["-sC", "-sV", "-T4"],

    # Aggressive: OS detect + version + default scripts + traceroute.
    "aggressive":  ["-A", "-T4"],

    # UDP scan (slow — keep the port set small).
    "udp":         ["-sU", "-T4", "--top-ports", "50"],
}

# Allow-listed NSE script categories the agent may request.
# Note: "exploit" and "brute" are intentionally EXCLUDED by default because
# they are intrusive. Add them only for labs you own.
ALLOWED_SCRIPT_CATEGORIES = {
    "default", "safe", "discovery", "version", "vuln", "auth", "malware",
}

# Validates an nmap port spec like "80", "1-1000", "22,80,443", "U:53,T:80".
_PORT_RE = re.compile(r"^[UT]?:?[0-9,\-]+(,[UT]?:?[0-9,\-]+)*$")


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class NmapResult:
    target: str
    command: list[str]
    success: bool
    hosts: list[dict] = field(default_factory=list)
    raw_stdout: str = ""
    raw_stderr: str = ""
    error: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)

    def summary(self) -> str:
        """A short text summary — handy to feed straight into the LLM."""
        if not self.success:
            return f"Scan of {self.target} failed: {self.error}"
        lines = [f"Scan of {self.target}:"]
        for host in self.hosts:
            lines.append(f"  Host {host['address']} ({host['state']}):")
            for p in host.get("ports", []):
                svc = p.get("service", "")
                ver = p.get("version", "")
                lines.append(
                    f"    {p['port']}/{p['protocol']} {p['state']} "
                    f"{svc} {ver}".rstrip()
                )
            if not host.get("ports"):
                lines.append("    (no open ports found)")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# The main entry point the LLM agent calls
# ---------------------------------------------------------------------------

def run_nmap(
    target: str,
    scan_type: str = "default",
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
    *,
    allowed_scope: Optional[list[str]] = None,
    timeout: int = 600,
    extra_args: Optional[list[str]] = None,
) -> NmapResult:
    """Run an nmap scan and return a structured result.

    Parameters
    ----------
    target : str
        Host or IP to scan. MUST be inside `allowed_scope`.
    scan_type : str
        One of SCAN_PROFILES keys ("ping", "quick", "version", "full",
        "default", "aggressive", "udp"). This is the LLM's main lever.
    ports : str, optional
        Explicit port spec, e.g. "80,443" or "1-1000". Overrides the
        profile's port selection when given.
    scripts : str, optional
        Comma-separated NSE script *categories* (e.g. "vuln,auth"). Each must
        be in ALLOWED_SCRIPT_CATEGORIES. Translated to --script=...
    allowed_scope : list[str], optional
        Override the default scope allow-list.
    timeout : int
        Hard wall-clock limit in seconds for the scan.
    extra_args : list[str], optional
        Escape hatch for advanced flags. Use sparingly.

    Returns
    -------
    NmapResult
    """
    allowed_scope = allowed_scope or DEFAULT_ALLOWED_SCOPE

    # 1) nmap must be installed.
    if shutil.which("nmap") is None:
        return NmapResult(
            target=target, command=[], success=False,
            error="nmap is not installed or not on PATH.",
        )

    # 2) Scope guard — refuse out-of-scope targets.
    if not is_in_scope(target, allowed_scope):
        raise ScopeError(
            f"Target {target!r} is not in the authorized scope. "
            f"Allowed: {allowed_scope}"
        )

    # 3) Validate scan_type.
    if scan_type not in SCAN_PROFILES:
        return NmapResult(
            target=target, command=[], success=False,
            error=f"Unknown scan_type {scan_type!r}. "
                  f"Choose from {sorted(SCAN_PROFILES)}.",
        )

    # 4) Build the command.
    cmd: list[str] = ["nmap"]
    cmd += SCAN_PROFILES[scan_type]

    # Explicit ports override the profile.
    if ports:
        if not _PORT_RE.match(ports):
            return NmapResult(
                target=target, command=[], success=False,
                error=f"Invalid port spec {ports!r}.",
            )
        cmd += ["-p", ports]

    # NSE script categories (validated against the allow-list).
    if scripts:
        cats = [c.strip() for c in scripts.split(",") if c.strip()]
        bad = [c for c in cats if c not in ALLOWED_SCRIPT_CATEGORIES]
        if bad:
            return NmapResult(
                target=target, command=[], success=False,
                error=f"Disallowed script categories: {bad}. "
                      f"Allowed: {sorted(ALLOWED_SCRIPT_CATEGORIES)}.",
            )
        cmd += [f"--script={','.join(cats)}"]

    if extra_args:
        cmd += extra_args

    # Always emit XML to stdout so we can parse it reliably.
    cmd += ["-oX", "-", target]

    # 5) Execute.
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return NmapResult(
            target=target, command=cmd, success=False,
            error=f"nmap timed out after {timeout}s.",
        )
    except Exception as exc:  # pragma: no cover - defensive
        return NmapResult(
            target=target, command=cmd, success=False,
            error=f"Failed to run nmap: {exc}",
        )

    # 6) Parse the XML.
    hosts = _parse_nmap_xml(proc.stdout)
    return NmapResult(
        target=target,
        command=cmd,
        success=proc.returncode == 0,
        hosts=hosts,
        raw_stdout=proc.stdout,
        raw_stderr=proc.stderr,
        error=None if proc.returncode == 0 else proc.stderr.strip(),
    )


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------

def _parse_nmap_xml(xml_text: str) -> list[dict]:
    """Turn nmap's -oX output into a list of host dicts."""
    if not xml_text.strip():
        return []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []

    hosts: list[dict] = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        state = status_el.get("state") if status_el is not None else "unknown"

        addr = ""
        addr_el = host_el.find("address")
        if addr_el is not None:
            addr = addr_el.get("addr", "")

        ports: list[dict] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                p_state_el = port_el.find("state")
                svc_el = port_el.find("service")
                # Collect any NSE script output attached to this port.
                scripts_out = {
                    s.get("id"): s.get("output", "")
                    for s in port_el.findall("script")
                }
                ports.append({
                    "port": int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol", ""),
                    "state": p_state_el.get("state") if p_state_el is not None else "",
                    "service": svc_el.get("name", "") if svc_el is not None else "",
                    "product": svc_el.get("product", "") if svc_el is not None else "",
                    "version": svc_el.get("version", "") if svc_el is not None else "",
                    "scripts": scripts_out,
                })

        hosts.append({
            "address": addr,
            "state": state,
            "ports": ports,
        })
    return hosts


# ---------------------------------------------------------------------------
# Tool schema for LLM function-calling
# ---------------------------------------------------------------------------
# Drop this straight into your Claude/OpenAI tool definitions.

NMAP_TOOL_SCHEMA = {
    "name": "run_nmap",
    "description": (
        "Scan an authorized host with nmap. Use scan_type to pick the intent: "
        "'ping' (is host up), 'quick' (top 1000 ports), 'version' (service "
        "versions), 'full' (all 65535 ports), 'default' (safe scripts + "
        "versions), 'aggressive' (OS + scripts + traceroute), 'udp'. "
        "Optionally pass NSE script categories via 'scripts' (e.g. 'vuln')."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "description": "Host or IP to scan (must be in authorized scope).",
            },
            "scan_type": {
                "type": "string",
                "enum": list(SCAN_PROFILES.keys()),
                "description": "The scan intent / profile.",
            },
            "ports": {
                "type": "string",
                "description": "Optional port spec, e.g. '80,443' or '1-1000'.",
            },
            "scripts": {
                "type": "string",
                "description": (
                    "Optional comma-separated NSE categories. Allowed: "
                    + ", ".join(sorted(ALLOWED_SCRIPT_CATEGORIES))
                ),
            },
        },
        "required": ["target", "scan_type"],
    },
}


# ---------------------------------------------------------------------------
# Manual test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Scans localhost — always in scope. Safe to run on your own machine.
    result = run_nmap("127.0.0.1", scan_type="quick")
    print(result.summary())
    print("\n--- JSON ---")
    print(result.to_json())
