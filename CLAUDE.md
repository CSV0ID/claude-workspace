# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An **AI Pentesting / Recon Assistant**: an LLM agent that takes an *authorized*
target, autonomously runs recon/vuln tools (nmap + 12 web tools), reasons over
the output via a tool-calling loop, and writes a Markdown/HTML security report.
All code lives under `nmap/tools/`. There is no build step — it's a Python CLI.

## Commands

```bash
cd nmap/tools                    # everything runs from here (flat module imports)

# Tests — no scanner binaries or network needed (parsers fed captured samples,
# agent driven by a FakeProvider). This MUST stay true for new tests.
python -m pytest tests/ -q
python -m pytest tests/test_suite.py::TestOfflineRecon -q          # one class
python -m pytest "tests/test_suite.py::TestScope::test_localhost_in_scope" -q  # one test

# Run the LLM agent (needs an API key for the chosen provider)
export ANTHROPIC_API_KEY=sk-...  # or OPENAI_/OPENROUTER_/GEMINI_API_KEY
python agent.py 127.0.0.1
python agent.py 192.168.56.101 --provider gemini --scope 192.168.56.0/24 --report-dir out

# Run recon WITHOUT an LLM (when the API is down) — saves a scan bundle to disk
python offline_recon.py 127.0.0.1 --out runs/

# Smoke checks
python nmap_wrapper.py           # scans 127.0.0.1
python tool_wrappers.py          # prints which external tool binaries are installed
```

Dependencies: `pip install -r nmap/requirements.txt`. The recon **tools
themselves** (nmap, subfinder, httpx, whatweb, nuclei, gobuster, …) are external
binaries installed via the OS/Go — they are NOT pip packages. Wrappers degrade
gracefully when a binary is missing (return a failed result, never crash).

## Architecture

Layered, each layer vendor- or tool-neutral so adding a provider or tool is one
edit:

- **`nmap_wrapper.py`** — `run_nmap(target, scan_type, ports, scripts, ...)`.
  One function exposes 14 nmap profiles (ping/discovery/fast/quick/version/full/
  default/aggressive/os/udp/udp_tcp/vuln/web/stealth). Returns a parsed
  `NmapResult` (hosts → ports/service/OS/hostscripts). Owns the scope primitives
  (`is_in_scope`, `ScopeError`, `DEFAULT_ALLOWED_SCOPE`) and the NSE category
  allow-list (`ALLOWED_SCRIPT_CATEGORIES`).
- **`tool_wrappers.py`** — 12 web/recon wrappers (subfinder, httpx, whatweb,
  nuclei, gobuster, nikto, sslscan, wafw00f, dnsx, ffuf, katana, wpscan), each
  returning a `ToolResult`. Exports `TOOL_REGISTRY: name -> (callable, schema)`.
  Deliberately excludes nmap.
- **`llm.py`** — vendor-neutral LLM layer. `AnthropicProvider` (native Messages
  API) + `OpenAICompatProvider` (one adapter shared by openai/openrouter/gemini).
  Normalised types `Turn` / `ToolCall` / `LLMReply`; `make_provider`,
  `PROVIDERS`, `DEFAULT_MODELS`, `has_api_key`/`env_key_for`.
- **`agent.py`** — the autonomous loop. Merges nmap into the full registry
  (`TOOL_REGISTRY = {"run_nmap": ..., **web}`), feeds tool schemas to the model,
  dispatches each requested tool, echoes results back as tool turns, loops
  broad→deep until the model stops, then captures its report. `run_agent()`
  accepts a provider *instance* (used by tests' `FakeProvider`).
- **`offline_recon.py`** — LLM-free fallback. A rule-based planner replaces the
  model's tool-picking (nmap version scan → branch on open web ports → httpx/
  whatweb/nuclei → nmap vuln scripts). Saves a `recon-bundle/v1` JSON to disk;
  `payload_to_prompt(json.load(...))` turns a saved bundle back into an LLM
  prompt so the reasoning step can be tested in isolation later. Intentionally
  imports neither `agent` nor `llm` so it runs with LLM libs absent.
- **`report.py`** — duck-typed on any run object with `target/provider/model/
  steps/tool_calls/tool_results/report/stopped_reason` (both `AgentRun` and
  `ReconBundle` qualify). Emits Markdown + self-contained HTML (inline-CSS,
  severity badges via Jinja2 autoescape).

Data flow: `run_agent`/`run_offline_recon` → run object → `report.write_reports`.

## Critical invariants

- **Scope guard runs FIRST.** In every wrapper, the `is_in_scope` check happens
  *before* the binary-installed check and *before* building any command line —
  an out-of-scope target is refused even if the model/planner asks for it, and
  even if the binary is absent. Preserve this ordering in any new wrapper.
  `agent._dispatch_tool` and `offline_recon._dispatch` inject `allowed_scope`
  into every call; never bypass it.
- **Tests run offline.** No new test may require a scanner binary or network.
  Feed parsers captured sample output; drive the agent with a fake provider.
- **Adding a tool** = one wrapper returning `ToolResult` + an entry in
  `tool_wrappers.TOOL_REGISTRY` (it flows into `agent` and `offline_recon`
  automatically). **Adding a provider** = a new `LLMProvider` subclass wired into
  `make_provider`/`PROVIDERS`/`DEFAULT_MODELS`.
- NSE scripts are restricted to `ALLOWED_SCRIPT_CATEGORIES`; `--script-args` and
  ffuf/gobuster inputs are sanitised. Keep untrusted values off the command line.

## Roadmap context

4-month plan in `nmap/docs/chat-log.md`. Done: all wrappers, multi-LLM agent
loop, offline recon, report generator, test suite. Next (Month 3): FastAPI
backend + async job queue + result persistence; then (Month 4) dashboard UI +
demo. Target audience: interview/investor demo, so favour working end-to-end
features over breadth.

## Legal

Scan only owned machines, intentionally vulnerable labs (DVWA, Juice Shop,
Metasploitable, HTB/THM), or written-permission targets. The scope allow-list
enforces this in code — keep `DEFAULT_ALLOWED_SCOPE` tight (localhost + private
ranges) and require explicit `--scope` for anything else.
