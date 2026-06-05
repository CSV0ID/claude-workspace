# Session Archive — Demo Branch

> Full extract of the working session that produced Month 3 (findings persistence
> + scan-management API) and Month 4 (React/Vite dashboard) of the AI Pentesting /
> Recon Assistant. Captures the assistant's operating instructions, the chat
> history, project memory, repo data, and the latest pushed code.
>
> Generated 2026-06-05. Latest code branch: **t6** (this `demo` branch is cut from it).

---

## 1. Assistant instructions (operating context)

### 1.1 Role / harness
- **Agent:** Claude Code (Anthropic's official CLI), model Opus 4.8 (1M context).
- Interactive software-engineering agent. Outputs GitHub-flavored markdown to a terminal.
- Tools run behind a user-selected permission mode. Prefers dedicated file/search
  tools over shell. Confirms hard-to-reverse / outward-facing actions. Reports
  outcomes faithfully (failing tests stated as such).
- Persistent file memory under `.claude/.../memory/` — one fact per file with
  frontmatter; `MEMORY.md` is the loaded index.

### 1.2 Project instructions (`CLAUDE.md`, checked into repo)
The repo is an **AI Pentesting / Recon Assistant**: an LLM agent that takes an
*authorized* target, runs recon/vuln tools (nmap + 12 web tools), reasons over the
output via a tool-calling loop, and writes a Markdown/HTML report. Key invariants:

- **Scope guard runs FIRST** in every wrapper — before the binary-installed check
  and before building any command line. Out-of-scope target is always refused.
- **Tests run offline** — no test may require a scanner binary or network (parsers
  fed captured samples; agent driven by a `FakeProvider`).
- **Adding a tool** = one wrapper returning `ToolResult` + a `TOOL_REGISTRY` entry.
  **Adding a provider** = an `LLMProvider` subclass wired into `make_provider`.
- NSE scripts restricted to `ALLOWED_SCRIPT_CATEGORIES`; ffuf/gobuster/`--script-args`
  inputs sanitised. Keep untrusted values off the command line.
- Legal: scan only owned machines, intentionally vulnerable labs, or
  written-permission targets. `DEFAULT_ALLOWED_SCOPE` stays tight (localhost +
  private ranges); anything else needs explicit `--scope`.

### 1.3 Active session hook — Caveman mode
A `SessionStart` hook activated **CAVEMAN MODE (full)**: terse, fragment output,
drop articles/filler/pleasantries/hedging — but **code, commits, PRs, and security
warnings written normally**. Persists until "stop caveman" / "normal mode".

### 1.4 Working-style instructions (from memory)
Do exactly what is asked — no more, no less. Execute immediately, no preamble. No
unrequested features/refactors/tests. Ask only on a true blocker (one question max).
File ops without confirmation. Show result/final file only.

---

## 2. Chat history (this session)

| # | User | Assistant action |
|---|------|------------------|
| 1 | "hi" | Greeted; noted modified files + new `ERRORS.md`. |
| 2 | "see our past chat and check what we have done and anything left" | Read `docs/chat-log.md` (4-month roadmap), inspected uncommitted diffs, ran tests (50 tool + 11 API green). Reported: Months 1–3 done + uncommitted Month-3 polish; Month-4 dashboard not started (empty `package.json` shell). |
| 3 | "both" (commit Month-3 work + scaffold dashboard) | **Save 1 (t5):** committed findings persistence, scan-management endpoints, docs. **Save 2 (t6):** scaffolded + built the React/Vite dashboard, verified end-to-end via Vite proxy against a live backend, pushed. Bumped memory to last `tN`=t6. |
| 4 | "extract all your instructions, chat history, data and memory and latest push and push it to branch demo" | Wrote this archive, cut `demo` branch from t6, pushed. |

### Work delivered
- **t5 — `0a1a1bf`** "Add findings persistence, scan management endpoints, docs":
  `Finding` model + cascade, `extract_findings()` (nuclei/nmap NSE → DB),
  `GET /scans/{id}/findings`, `DELETE /scans/{id}`, list pagination + status
  filter, 4 new API tests, `ERRORS.md`, `RUN.md` backend/verify sections.
- **t6 — `cdccabb`** "Add Month 4 React/Vite dashboard":
  SPA under `nmap/` (`index.html`, `vite.config.js`, `src/`). Components:
  `ScanForm`, `ScanList` (live 3s poll), `ScanDetail` (severity counts, findings
  tab, sandboxed HTML report iframe, .md download, delete), `FindingsTable`.
  `api.js` axios client (Vite proxy in dev, `VITE_API_BASE` in prod). RUN.md
  dashboard + Vercel steps; `.gitignore` for node_modules/dist.
  Verified: `npm run build` clean (88 modules); dev proxy round-trips health +
  scan create/poll/findings against a live backend.

---

## 3. Repo data / state

- **Repo:** `CSV0ID/claude-workspace` (origin `https://github.com/CSV0ID/claude-workspace.git`).
- **Branch lineage:** `main` → `t4` (FastAPI backend, offline recon, docs) →
  `t5` (Month-3 polish) → `t6` (Month-4 dashboard) → `demo` (this archive).
- **Tests:** 50 tool tests (`nmap/tools/tests/`) + 11 API tests (`nmap/app/tests/`),
  all green, fully offline.
- **Layout:** `nmap/tools/` (CLI + agent + wrappers), `nmap/app/` (FastAPI),
  `nmap/src/` + `nmap/index.html` (dashboard), `nmap/docs/` (roadmap + this archive).
- **Roadmap status:** Months 1–4 code complete. Remaining (non-code): demo video,
  pitch deck — both outlined in `docs/chat-log.md`.

---

## 4. Memory (project knowledge base)

### 4.1 `MEMORY.md` (index)
- AI Pentest Assistant Project — main 4-month project, stack, code location, next step
- User Profile — CS diploma student, Python, into hacking/security, demo/investor-ready
- Git Save Workflow — save chats to `nmap/`, commit + push to incrementing `tN` branches
- Working Style Instructions — do exactly what's asked, immediate, terse, no extras

### 4.2 user-profile
CS diploma student. Knows Python. Into hacking/security. Wants working/demo-able
projects impressive enough for interviews and investors.

### 4.3 ai-pentest-assistant-project
Main project (chosen 2026-06-03, ~4-month timeline). LLM agent that takes an
authorized target, runs recon/vuln tools (nmap, subfinder, httpx, whatweb, nuclei,
gobuster), reasons over output with an LLM, writes a report — an "autonomous junior
pentester". Stack: Python, Claude/OpenAI tool-calling, FastAPI, React/Streamlit UI,
Jinja2 reports. Lab targets only. Code in `nmap/tools/`. Scope guard runs BEFORE
binary/arg checks in every wrapper.

### 4.4 git-save-workflow
Save every chat + artifact under `nmap/`; after each save, commit and push to a new
incrementing `tN` branch (last used: **t6**). Repo `CSV0ID/claude-workspace`.

### 4.5 working-style-instructions
Do exactly what is asked — no more, no less. Immediate, terse, no unrequested
extras, no "are you sure?" prompts, overwrite on conflict, show final result only.

---

## 5. How to run the latest push

```bash
# backend
cd nmap && pip install -r requirements.txt
uvicorn app.main:app --port 8000

# dashboard (separate shell)
cd nmap && npm install && npm run dev      # http://localhost:5173

# tests
cd nmap/tools && python -m pytest tests/ -q     # 50 tool tests
cd nmap       && python -m pytest app/tests/ -q # 11 API tests
```
