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
    ├── nmap_wrapper.py     # smart nmap wrapper (one function, 14 profiles)
    ├── tool_wrappers.py    # 12 recon/vuln tool wrappers + TOOL_REGISTRY
    ├── llm.py              # multi-provider LLM layer (anthropic/openai/openrouter/gemini)
    ├── agent.py            # vendor-neutral tool-calling agent loop
    ├── report.py           # Markdown + HTML report generator (Jinja2)
    └── tests/
        └── test_suite.py   # pytest suite (44 tests, no binaries/network needed)
```

## The wrappers

Every tool is exposed to the LLM as a single function plus a JSON schema, so
adding a tool = writing one wrapper. The LLM picks the *intent* (e.g. nmap
`scan_type="vuln"`) and the wrapper builds a correct, safe command line and
parses the output into clean JSON.

- `run_nmap(target, scan_type, ports, scripts, ...)` — 14 profiles: ping,
  discovery, fast, quick, version, full, default, aggressive, os, udp, udp_tcp,
  vuln, web, stealth; plus `skip_ping`, `os_detect`, `top_ports`, NSE categories.
- `run_subfinder(domain)` — passive subdomain enum.
- `run_httpx(target)` — live HTTP/S probing (status, title, tech).
- `run_whatweb(target)` — web tech fingerprinting.
- `run_nuclei(target, severity)` — template-based vuln scanning.
- `run_gobuster(target, wordlist)` — directory brute-forcing.
- `run_nikto(target)` — web server vuln/misconfig scan.
- `run_sslscan(target)` — TLS/SSL config & cert audit.
- `run_wafw00f(target)` — WAF detection/fingerprint.
- `run_dnsx(domain)` — DNS record enumeration.
- `run_ffuf(target, wordlist)` — fast web fuzzer (FUZZ keyword).
- `run_katana(target)` — web crawler / endpoint discovery.
- `run_wpscan(target)` — WordPress vuln scan.

`tool_wrappers.TOOL_REGISTRY` maps name → (callable, schema). `agent.TOOL_REGISTRY`
merges in `run_nmap` for the full 13-tool set the agent can call.

## Pick your LLM

The agent is vendor-neutral via `llm.py`. Choose with `--provider`:

| Provider | Endpoint | API key env |
|----------|----------|-------------|
| `anthropic` | Claude (native) | `ANTHROPIC_API_KEY` |
| `openai` | OpenAI | `OPENAI_API_KEY` |
| `openrouter` | OpenRouter (any model) | `OPENROUTER_API_KEY` |
| `gemini` | Google Gemini | `GEMINI_API_KEY` |

OpenAI/OpenRouter/Gemini share one OpenAI-compatible adapter; Anthropic uses its
native Messages API. Same agent code drives all of them.

## The agent

`agent.py` is the autonomous brain (Month 2). Give it an authorized target and it
drives the chosen LLM through a tool-calling loop: the model picks an *intent* (a
tool + args), the wrapper runs it and returns clean JSON, the model reasons over
the output and decides the next tool — broad → deep — then writes a Markdown
security report. `--report-dir` also emits a styled HTML report. Every tool call
passes through the in-code scope guard, so an out-of-scope request is refused even
if the model asks for it.

```bash
export ANTHROPIC_API_KEY=sk-...                        # or OPENAI/OPENROUTER/GEMINI key
cd nmap/tools
python agent.py 127.0.0.1                              # localhost, always in scope
python agent.py 192.168.56.101 --provider gemini --scope 192.168.56.0/24 --report-dir out
python agent.py 10.0.0.5 --provider openrouter --model anthropic/claude-3.5-sonnet
```

## Tests

```bash
cd nmap/tools
python -m pytest tests/ -q     # 44 tests; no scanner binaries or network needed
```

## Quick test

```bash
cd nmap/tools
python nmap_wrapper.py        # scans 127.0.0.1 (always in scope)
python tool_wrappers.py       # prints which external tools are installed
```

## Roadmap

See `docs/chat-log.md` for the full 4-month plan. Done: wrappers, multi-LLM agent
loop, report generator, test suite. Next: FastAPI backend + job queue (Month 3),
then dashboard UI + demo (Month 4).
