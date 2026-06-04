# AI Pentesting / Recon Assistant

An AI agent that takes an **authorized** target, runs recon/vuln tools, and uses
an LLM to reason over the output and write a security report. Think of it as a
tireless junior pentester that does the boring recon and drafts the report.

> ⚠️ **Legal:** Only scan machines you own or have **written permission** to test
> (your own VMs, localhost, or intentionally vulnerable labs like DVWA, OWASP
> Juice Shop, Metasploitable, HackTheBox, TryHackMe). The code enforces a scope
> allow-list — keep it tight.

## Layout

```
nmap/
├── README.md              # this file
├── requirements.txt
├── docs/
│   └── chat-log.md        # full planning transcript + roadmap
└── tools/
    ├── nmap_wrapper.py     # smart nmap wrapper (one function, many profiles)
    ├── tool_wrappers.py    # subfinder / httpx / whatweb / nuclei / gobuster
    └── agent.py            # LLM tool-calling loop that drives all the wrappers
```

## The wrappers

Every tool is exposed to the LLM as a single function plus a JSON schema, so
adding a tool = writing one wrapper. The LLM picks the *intent* (e.g. nmap
`scan_type="vuln"`) and the wrapper builds a correct, safe command line and
parses the output into clean JSON.

- `run_nmap(target, scan_type, ports, scripts)` — profiles: ping, quick,
  version, full, default, aggressive, udp; optional NSE script categories.
- `run_subfinder(domain)` — passive subdomain enum.
- `run_httpx(target)` — live HTTP/S probing (status, title, tech).
- `run_whatweb(target)` — web tech fingerprinting.
- `run_nuclei(target, severity)` — template-based vuln scanning.
- `run_gobuster(target, wordlist)` — directory brute-forcing.

`tool_wrappers.TOOL_REGISTRY` maps name → (callable, schema) for the agent loop.

## The agent

`agent.py` is the autonomous brain (Month 2). Give it an authorized target and it
drives Claude through a tool-calling loop: Claude picks an *intent* (a tool +
args), the wrapper runs it and returns clean JSON, Claude reasons over the output
and decides the next tool — broad → deep — then writes a Markdown security
report. Every tool call still passes through the in-code scope guard, so an
out-of-scope request is refused even if the model asks for it.

```bash
export ANTHROPIC_API_KEY=sk-...
cd nmap/tools
python agent.py 127.0.0.1                              # localhost, always in scope
python agent.py 192.168.56.101 --scope 192.168.56.0/24 --max-steps 12
```

`agent.TOOL_REGISTRY` merges `run_nmap` with the five web tools — the full set the
agent can call.

## Quick test

```bash
cd nmap/tools
python nmap_wrapper.py        # scans 127.0.0.1 (always in scope)
python tool_wrappers.py       # prints which external tools are installed
```

## Roadmap

See `docs/chat-log.md` for the full 4-month plan. The wrappers and the agent loop
are done; next up: report generator (Jinja2 → HTML/PDF) and the FastAPI backend.
