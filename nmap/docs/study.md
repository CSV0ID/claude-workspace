# Study — what you need to know to build/use this project

> Everything you'd need to learn to build this from scratch (or defend it in an
> interview), plus extra context that helps. Ordered roughly easy → hard.
> ⭐ = used heavily in this codebase, learn it first.

---

## 0. The 10-minute mental model

This project is **3 layers**:

```
  React dashboard  ──HTTP──▶  FastAPI backend  ──calls──▶  Python recon core
   (launch scans,              (job queue +                (agent loop OR
    read reports)               SQLite store)               offline planner
                                                            → wraps real tools
                                                            → writes report)
```

The "AI" is one idea: an **LLM tool-calling loop**. You give the model a list of
functions (recon tools). It says "call nmap". You run nmap, give it the result.
It says "now call nuclei on port 80". Repeat until it says "done, here's the
report." Everything else is plumbing and safety around that loop.

---

## 1. Foundations (must-have) ⭐

| Topic | Why you need it | Where it shows up |
|-------|-----------------|-------------------|
| **Python 3.10+** | whole core | everywhere; uses `from __future__ import annotations`, `X | None` types |
| **`dataclasses`** ⭐ | every result type | `NmapResult`, `ToolResult`, `AgentRun`, `ReconBundle` |
| **`subprocess`** ⭐ | running external CLI tools safely | every wrapper shells out to nmap/nuclei/etc. |
| **`argparse`** | the CLIs | `agent.py`, `offline_recon.py` |
| **`json`** ⭐ | tool results, bundles, API bodies | everywhere |
| **type hints / `typing`** | readability + tool schemas | all modules |
| **exceptions & `try/except`** ⭐ | graceful degradation | wrappers never crash the loop |
| **virtualenv + pip** | deps | `requirements.txt` |
| **pytest** ⭐ | the test suite | `tests/test_suite.py`, `app/tests/` |

**Extra that helps:** `pathlib`, `enum`, f-strings, `subprocess.run(timeout=...)`,
list/dict comprehensions, `getattr`/`hasattr` (the report layer is duck-typed).

---

## 2. The LLM / agent part (the "AI") ⭐

This is the heart. Understand it deeply.

- **What an LLM tool/function call is.** The model returns structured "I want to
  call function X with args {...}" instead of text. You execute it and feed the
  result back as a "tool result" message. Read the
  [Anthropic tool use docs](https://docs.anthropic.com/en/docs/build-with-claude/tool-use)
  and OpenAI "function calling" docs — same idea, different JSON.
- **JSON Schema** — how you *describe* each tool to the model (name, params,
  types). Each wrapper ships a schema. Learn enough JSON Schema to write one.
- **The agent loop** — see `agent.py:run_agent`. Pseudocode:
  ```
  turns = [user: "recon this target"]
  loop up to max_steps:
      reply = model.chat(system, tools, turns)
      if reply has no tool calls: return reply.text   # the report
      append assistant turn
      for each tool call: run it, append a tool-result turn
  ```
- **System prompt design** — `agent.py:SYSTEM_PROMPT` tells the model to go
  broad→deep, never invent findings, prefer non-intrusive scans, and the exact
  report format. Prompt = behavior spec. Study how specific it is.
- **Provider abstraction** — `llm.py`. Two concrete providers: native Anthropic
  Messages API, and one OpenAI-compatible adapter reused for OpenAI/OpenRouter/
  Gemini. Normalized types: `Turn`, `ToolCall`, `LLMReply`. Lesson: **normalize
  vendor differences into your own types at the boundary.**
- **Why an offline planner exists** — `offline_recon.py` replaces the model's
  tool-picking with hand-written `if` rules (version scan → if web port open →
  httpx/whatweb/nuclei → vuln scripts). Lets you run + test the pipeline with no
  LLM. Lesson: **separate "what to do next" from "how to do it" so either a model
  or rules can drive.**

**Extra that helps:** prompt-injection awareness, token/cost basics, why you cap
`max_steps` (runaway loops cost money), structured-output / schema validation,
the idea of "agent" vs "single completion".

---

## 3. The security / recon domain ⭐

You don't need to be a pentester, but know what each tool *does* and *when* the
agent reaches for it.

### The methodology the agent follows (learn this order)
1. **Host discovery** — is it up? (`nmap -sn`)
2. **Port + service scan** — what's running and which versions? (`nmap -sV`)
3. **Web probing** — for any web port: is it live, what tech? (httpx, whatweb)
4. **Targeted vuln checks** — based on what was found (nuclei, nmap NSE `vuln`,
   wpscan if WordPress, etc.)
5. **Report** — severity, evidence, remediation.

### The tools (know one sentence each)
| Tool | Does | When |
|------|------|------|
| **nmap** ⭐ | port/service/OS scan, NSE scripts | always, first |
| subfinder | passive subdomain enum | domain targets |
| httpx | probe which hosts/ports serve HTTP/S | after port scan |
| whatweb | fingerprint web tech (CMS, server) | on live web |
| nuclei ⭐ | template-based known-vuln scan | core vuln step |
| gobuster / ffuf | dir & content brute-force / fuzz | content discovery |
| nikto | web server misconfig/vuln scan | web servers |
| sslscan | TLS/cert audit | HTTPS ports |
| wafw00f | detect a WAF | before noisy scans |
| dnsx | DNS record enum | domains |
| katana | crawl/spider endpoints | mapping a web app |
| wpscan | WordPress-specific vuln scan | if WordPress found |

### Concepts to understand
- **Ports & services** — TCP/UDP, common ports (22 SSH, 80/443 HTTP(S), etc.).
- **Severity scale** — info / low / medium / high / critical (and roughly CVSS).
- **Finding structure** — *what* + *evidence* + *remediation*. The whole report
  is built on this triple.
- **NSE (nmap scripting engine)** — scripts grouped by category (`vuln`, `safe`,
  `discovery`...). This project **allow-lists** categories — know why (some NSE
  scripts are intrusive/dangerous).

**Extra that helps:** the OWASP Top 10, CVE/CVSS basics, the difference between
*passive* (subfinder, whatweb) and *active* (nmap, nuclei) recon, what makes a
scan "intrusive", basic networking (IP, CIDR, DNS).

---

## 4. Safety engineering (the differentiator) ⭐

This is what makes it defensible. Study how it's done in code.

- **Scope allow-list** — `nmap_wrapper.py` owns `is_in_scope`, `ScopeError`,
  `DEFAULT_ALLOWED_SCOPE`. The **invariant**: in *every* wrapper the scope check
  runs **first** — before the binary-installed check, before building any command
  line. Out-of-scope = refused no matter what.
- **CIDR / IP matching** — how `is_in_scope` decides if a target is inside an
  allowed range. Learn Python's `ipaddress` module.
- **Command injection defense** ⭐ — untrusted values (target, wordlists,
  `--script-args`, ffuf/gobuster inputs) must never be concatenated naively onto
  a shell line. This project sanitises them and restricts NSE categories. Learn:
  pass args as a **list** to `subprocess` (no `shell=True`), validate/whitelist
  inputs.
- **Graceful failure** — missing binary → return a failed `ToolResult`, don't
  raise. The agent adapts.

**Extra that helps:** the general principle "*never trust LLM output as
authority*" — the model is an *advisor*, the code is the *guard*. Sandboxing
ideas (containers, network namespaces) for running scanners safely.

---

## 5. The backend (FastAPI) — Month 3

- **FastAPI** ⭐ — routing, `pydantic` request models (`ScanRequest`), query
  params with validation, `HTTPException`, response types (HTML/JSON/Plain).
  See `app/main.py`.
- **Background tasks / async job queue** — scans take minutes, so `POST /scans`
  queues work via `BackgroundTasks` and returns immediately; client **polls**
  `GET /scans/{id}` for `queued → running → done|failed`. See `app/runner.py`.
- **SQLite + SQLAlchemy** ⭐ — `app/db.py`: `Scan` and `Finding` models, a
  one-to-many with **cascade delete**, `SessionLocal`. Persisting results so the
  dashboard can list/read them.
- **Findings extraction** — `extract_findings()` turns nuclei / nmap NSE output
  into `Finding` rows in the DB.
- **REST design** — resource-oriented routes, status codes (201 created, 204 no
  content, 404, 409 conflict when not finished). Read the endpoint list at the
  top of `app/main.py`.

**Extra that helps:** `uvicorn` (the ASGI server), what "async" buys you, why you
poll instead of block, idempotency, pagination (`limit`/`offset`), DB migrations
(not used here but you'd need them in prod).

---

## 6. The frontend (React/Vite) — Month 4

- **React basics** ⭐ — components, `useState`, `useEffect`, props. See `src/`.
- **Vite** — dev server + build tool; the **dev proxy** forwards `/api` to the
  backend (CORS-free local dev). See `vite.config.js`.
- **Polling UI** — `ScanList` re-fetches every 3s to show live status. `useEffect`
  + `setInterval`.
- **axios client** — `src/api.js`, one place wrapping all backend calls; uses the
  Vite proxy in dev and `VITE_API_BASE` in prod.
- **Rendering an untrusted report** — the HTML report is shown in a **sandboxed
  iframe** (don't `dangerouslySetInnerHTML` attacker-influenced HTML).

**Extra that helps:** the request/response cycle end-to-end, env vars at build
time vs runtime, why a sandboxed iframe, basic CSS (severity badge colors).

---

## 7. Reporting

- **Jinja2** ⭐ — templating the Markdown + self-contained HTML. **Autoescape on**
  to prevent injection from tool output into the HTML. See `report.py`.
- **Duck typing** — `write_reports` works on *any* object with the right fields
  (`target/steps/tool_results/report/...`), so both `AgentRun` and `ReconBundle`
  feed it. Lesson: program to a *shape*, not a class.
- **Self-contained HTML** — inline CSS so the report is one portable file.

---

## 8. Tooling / workflow / ops

- **git** ⭐ — branches, commits. This repo saves work to incrementing `tN`
  branches (`git-save-workflow` memory).
- **pytest patterns** ⭐ — fixtures, captured-output samples, a **`FakeProvider`**
  that scripts LLM replies so the agent is testable offline. The rule: *no test
  needs a binary or network.* This is a strong interview talking point.
- **External binary management** — recon tools are installed via OS/Go, **not**
  pip. Know the difference (`pip install -r requirements.txt` gets the Python
  libs; nmap/nuclei/etc. are separate).
- **Environment / API keys** — `ANTHROPIC_API_KEY` etc.; `has_api_key` /
  `env_key_for` gate the LLM path.

**Extra that helps:** Docker (sandbox the scanners + reproducible env), a Makefile
or task runner, CI (GitHub Actions running the offline tests), `.env` files,
logging.

---

## 9. How to actually run it (cheat sheet)

```bash
# --- core recon, NO LLM (works anywhere, no key) ---
cd nmap/tools
python offline_recon.py 127.0.0.1 --out runs/

# --- the LLM agent (needs a key) ---
export ANTHROPIC_API_KEY=sk-...          # or OPENAI_/OPENROUTER_/GEMINI_API_KEY
python agent.py 127.0.0.1
python agent.py 192.168.56.101 --provider gemini --scope 192.168.56.0/24 --report-dir out

# --- backend ---
cd nmap && pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000      # http://localhost:8000/docs

# --- dashboard ---
cd nmap && npm install && npm run dev          # http://localhost:5173

# --- tests (all offline) ---
cd nmap/tools && python -m pytest tests/ -q    # 50 tool tests
cd nmap       && python -m pytest app/tests/ -q # 11 API tests

# --- smoke checks ---
python nmap_wrapper.py        # scans 127.0.0.1
python tool_wrappers.py       # prints which tool binaries are installed
```

---

## 10. If you were rebuilding from scratch — order of attack

1. Write **one** tool wrapper (nmap) returning a clean dataclass. Get `subprocess`
   + parsing + a test with captured output working.
2. Add the **scope guard** and make it run first. Test the refusal.
3. Add the **LLM layer** for one provider. Get a single tool call round-tripping.
4. Build the **agent loop**. Add `max_steps`. Drive it with a `FakeProvider` test.
5. Add the **other 12 tools** (now it's copy-the-pattern).
6. Add the **report generator** (Jinja2, autoescape).
7. Add the **offline planner** so it runs with no LLM.
8. Add **FastAPI + SQLite** (queue, persist, poll).
9. Add the **React dashboard**.
10. Make the **second/third/fourth LLM provider** work via the adapter.

Each step is demoable on its own — that's the point.

---

## 11. Quick glossary

- **Agent loop** — model picks a tool → you run it → feed result back → repeat.
- **Tool/function calling** — model emits a structured call instead of text.
- **Recon** — reconnaissance; information-gathering phase of a pentest.
- **NSE** — Nmap Scripting Engine; pluggable scripts grouped by category.
- **Scope** — the set of targets you're authorized to scan.
- **Finding** — one issue: what + evidence + severity + remediation.
- **Provider** — an LLM vendor (Anthropic/OpenAI/OpenRouter/Gemini).
- **Bundle** — saved JSON of a recon run, replayable into the report layer.
- **Graceful degradation** — fail cleanly (missing tool/API) instead of crashing.
- **Idempotent / poll** — client asks repeatedly for status of a long job.
