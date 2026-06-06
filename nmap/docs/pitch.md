# Pitch — AI Pentesting / Recon Assistant

> Your talking-points bible. Topics you can pitch, the full pitch (3 lengths),
> demo script, and the common questions + answers. Read top-to-bottom once, then
> keep §2 (the one-liner) and §6 (Q&A) in your head for live demos.
>
> File named `pitch.md` (you said "pinch" — same thing, your elevator pitch).

---

## 1. Topics you can pitch (the menu)

Pick from these depending on who you talk to. Each is a thread you can pull on.

### Product / value
- **What it is** — an AI agent that does autonomous recon on an *authorized*
  target and writes a first-draft security report (severity, evidence, fix).
- **The "junior pentester" framing** — it does the boring recon + drafting so
  humans focus on fixing, not finding.
- **Time saved** — companies wait weeks for a pentest report; this drafts one in
  minutes.
- **First-draft, not replacement** — positions it as a force-multiplier for a
  security team, not a magic auto-hacker (honest = credible).

### Technical depth (for engineers / technical interviewers)
- **Tool-calling agent loop** — LLM decides *which* tool to run next from the
  output of the last one (broad → deep). The "AI magic".
- **Vendor-neutral LLM layer** — one adapter, 4 providers (Anthropic / OpenAI /
  OpenRouter / Gemini). Swap with a `--provider` flag.
- **13 real recon tools wrapped** — nmap (14 profiles) + 12 web tools
  (subfinder, httpx, whatweb, nuclei, gobuster, nikto, sslscan, wafw00f, dnsx,
  ffuf, katana, wpscan).
- **One-wrapper-to-add-a-tool design** — extensibility as an architecture story.
- **Offline fallback** — a rule-based planner runs the same recon with *no* LLM
  (when the API is down or you have no key). Same report pipeline.
- **Graceful degradation** — every wrapper returns a clean failed result when a
  binary is missing; never crashes.

### Safety / legal (the differentiator vs "just a scanner")
- **Scope guard runs FIRST** — out-of-scope target refused in code, before the
  tool even runs, even if the LLM asks for it. Safety is not a prompt, it's an
  invariant.
- **Input sanitisation** — NSE scripts restricted to an allow-list; ffuf/gobuster
  / `--script-args` sanitised so untrusted values never hit the command line.
- **Legal-by-design** — default scope is localhost + private ranges; anything
  else needs an explicit `--scope`. "Scope control is part of the pitch."

### Engineering / process (for interviews)
- **Full-stack** — Python CLI + FastAPI backend (async job queue, SQLite
  persistence) + React/Vite dashboard.
- **61 tests, fully offline** — parsers fed captured samples, agent driven by a
  `FakeProvider`. No binaries, no network in CI.
- **Layered architecture** — each layer vendor/tool-neutral; adding a provider or
  tool is a one-file change.
- **Market context** — same category as funded startups (XBOW, Horizon3.ai),
  shows you read the space.

---

## 2. The one-liner (memorize this)

> "It's an AI agent that acts like a tireless junior pentester: you give it an
> authorized target, it autonomously runs the recon tools, reasons over the
> output with an LLM, and writes a security report in minutes instead of weeks."

---

## 3. The full pitch

### 30-second (investor / recruiter)
> Pentesting is expensive and slow — companies wait weeks for a security report.
> My tool uses an AI agent to automate the recon and generate a first-draft
> report in minutes, so security teams spend their time fixing instead of
> finding. You give it an authorized target; it decides which tools to run —
> nmap, nuclei, a dozen others — reasons over what it finds, and writes a report
> with severity, evidence, and remediation. It's like a tireless junior
> pentester. Same category as funded startups like XBOW and Horizon3 — but I
> built the core loop end-to-end.

### 2-minute (technical interview)
> The product is an autonomous recon assistant. The core is a **tool-calling
> agent loop**: I hand an LLM the JSON schemas for 13 recon tools, it picks one,
> I run it, feed the parsed result back, and it loops — starting broad (is the
> host up, what ports are open) and going deep (probe the web service, fingerprint
> the tech, run targeted vuln checks). When it has enough, it stops and writes a
> Markdown/HTML report.
>
> Three things I'm proud of architecturally:
>
> 1. **Vendor-neutral LLM layer.** One adapter abstracts Anthropic, OpenAI,
>    OpenRouter, and Gemini behind normalized `Turn`/`ToolCall` types. Adding a
>    provider is a single subclass.
> 2. **Safety as an invariant, not a prompt.** Every tool wrapper checks the
>    scope allow-list *first* — before it even checks the binary is installed.
>    So even if the model asks to scan something out of scope, the call is
>    refused in code. NSE scripts are allow-listed; fuzzer inputs are sanitised.
> 3. **It degrades gracefully.** There's an LLM-free rule-based planner that runs
>    the same recon flow when the API is down, and every wrapper returns a clean
>    failure if a tool binary is missing — it never crashes.
>
> Around the core I built a FastAPI backend with an async job queue and SQLite
> persistence, and a React dashboard to launch scans and read reports. 61 tests,
> all offline — parsers are fed captured tool output and the agent runs against a
> fake LLM provider, so CI needs no scanners and no network.

### 5-minute (deep dive — walk the architecture)
Add to the 2-minute version:
> The codebase is layered so each layer is tool- or vendor-neutral:
> - `nmap_wrapper.py` — one `run_nmap()` exposing 14 scan profiles and owning the
>   scope primitives + NSE category allow-list.
> - `tool_wrappers.py` — 12 web tools, each a wrapper returning a `ToolResult`,
>   registered in a `TOOL_REGISTRY`.
> - `llm.py` — the provider abstraction.
> - `agent.py` — merges nmap + web tools into the full registry and runs the loop.
> - `offline_recon.py` — the LLM-free planner; saves a JSON "recon bundle" you can
>   replay into the report generator later.
> - `report.py` — duck-typed on any run object, emits Markdown + self-contained
>   HTML with severity badges.
>
> The design rule is: *don't expose all of nmap as 50 tools; expose a few smart
> functions and let the LLM fill in the arguments.* One wrapper, infinite
> combinations. The data flow is one line: `run_agent` → run object →
> `report.write_reports`. Same run object works for the offline path, so the
> report layer doesn't know or care whether an LLM was involved.

---

## 4. Live demo script (5 min)

1. **Frame it (15s):** "Authorized recon only — I'm scanning localhost / a lab
   VM. The scope is enforced in code."
2. **Show the refusal (30s):** try an out-of-scope target → it's refused before
   anything runs. *This is the money shot — safety is real, not a promise.*
3. **Run offline recon (1m):** `python offline_recon.py 127.0.0.1 --out runs/` —
   no API key needed, works on any laptop. Show the JSON bundle.
4. **Run the agent (2m):** `python agent.py 127.0.0.1` — narrate the loop as it
   prints: "host up → open ports → saw port 80 → probing web → fingerprinting →
   targeted vuln check." Point out the LLM is *choosing* each step.
5. **Show the report (1m):** open the HTML report — severity badges, evidence,
   remediation. "This is the first draft a human would otherwise spend hours on."
6. **Show the dashboard (30s):** launch a scan from the UI, watch it poll
   queued→running→done, open the report inline.

**Fallback if no network/API:** the whole offline path + dashboard + tests run
with zero external dependencies. Lead with those.

---

## 5. Numbers to drop

- **13** recon tools wrapped (nmap + 12 web).
- **14** nmap scan profiles behind one function.
- **4** LLM providers, swappable with a flag.
- **61** tests, **100% offline** (50 tool + 11 API).
- **Minutes vs weeks** — report turnaround.
- Full stack: **CLI + FastAPI + React**.

---

## 6. Common questions & answers

**Q: Isn't this illegal / a hacking tool?**
A: It only scans what you're authorized to. The scope allow-list is enforced in
code and runs before any tool executes — default is localhost and private ranges,
anything else needs an explicit opt-in. It's built for owned machines, lab VMs
(DVWA, Juice Shop, Metasploitable, HTB/THM), and written-permission engagements.
Scope control is a feature, not an afterthought.

**Q: How is this different from just running nmap / nuclei myself?**
A: Two things. First, the LLM *orchestrates* — it decides which tool to run next
based on what the last one found, so you don't have to know the methodology.
Second, it *interprets* — instead of raw scanner output you get a report with
severity, the evidence that proves each finding, and remediation. It turns tool
output into a decision a human can act on.

**Q: Does the AI actually hack things, or just scan?**
A: Recon and non-intrusive vuln checks only — it's explicitly told to prefer
non-intrusive options and not to request brute-force or exploit scripts. It finds
and explains; a human verifies and exploits. That's the honest, responsible
scope, and it's also what keeps it legal.

**Q: What if the LLM hallucinates a vulnerability?**
A: The system prompt forbids inventing findings — every finding must cite real
tool output as evidence. And the report shows that evidence, so a human can
verify. It's a *first draft*, reviewed by a person, not an autonomous authority.

**Q: What if the LLM asks to scan something it shouldn't?**
A: It can't. The scope check is in the wrapper, not the prompt. The model can ask
for anything; the code refuses out-of-scope calls before building a command line.
Safety doesn't depend on the model behaving.

**Q: Which LLM does it use? What if I don't want to pay for one?**
A: Any of four — Anthropic, OpenAI, OpenRouter, or Gemini — picked with a flag.
And there's a fully LLM-free mode: a rule-based planner runs the same recon flow
with no API key at all. So it works even with the API down or no budget.

**Q: What happens if a tool isn't installed?**
A: Every wrapper degrades gracefully — it returns a clean "failed" result instead
of crashing. The agent reads that and moves on. The recon tools are external
binaries (nmap, nuclei, etc.), not Python packages, so this matters.

**Q: How do you test something that depends on network scanners?**
A: All 61 tests run offline. Parsers are fed captured real tool output as
fixtures, and the agent runs against a `FakeProvider` that scripts the LLM's
responses. No binaries, no network — CI is fast and deterministic.

**Q: How hard is it to add a new tool or provider?**
A: A tool is one wrapper function returning a `ToolResult` plus one registry
entry — it then flows into both the agent and the offline planner automatically.
A provider is one `LLMProvider` subclass wired into the factory. The whole
architecture is built so extension is a one-file change.

**Q: Is this production-ready / who's the customer?**
A: It's a working end-to-end prototype aimed at a demo, not a hardened product.
The realistic customer is an internal security/AppSec team or an MSSP that wants
to cut the recon-and-first-draft time on routine engagements. Productionizing
would mean auth, multi-tenant isolation, a hardened sandbox for the scanners, and
rate/cost controls.

**Q: What's the market? Anyone else doing this?**
A: Yes — and that validates it. XBOW, Horizon3.ai and others are funded in the
"AI + offensive security" space. The category is real; I built the core agent
loop and full stack to show I can execute in it.

**Q: What was the hardest part?**
A: Making safety structural instead of relying on the model. It's tempting to put
"don't scan out of scope" in the prompt — but prompts can be jailbroken. Moving
the check into every wrapper, before the command line is even built, and keeping
that invariant as I added 13 tools, was the real engineering discipline.

**Q: What would you build next?**
A: Authentication + multi-user on the backend, a proper sandbox (containers) for
running the scanners, cost/rate controls on the LLM, and richer report exports.
Then a demo video and pitch deck — the code is done through Month 4 of the plan.

---

## 7. Pitfalls — don't oversell

- Don't call it "autonomous hacking" or "replaces a pentester" — say *first-draft
  recon assistant*. Overclaiming gets picked apart by anyone technical.
- Don't claim it finds zero-days — it runs known tools with known templates.
- Don't demo against a live internet host — always localhost / a lab VM, and say
  so. The legal posture *is* part of the pitch.
- If asked something you didn't build, say so plainly — "that's future work."
  Honesty reads as competence.
