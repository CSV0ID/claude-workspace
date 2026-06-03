# AI Pentesting / Recon Assistant — Full Chat Log

> Saved transcript of the planning conversation that led to this project.
> Date: 2026-06-03

---

## Context: who & what

- **User:** CS diploma student, knows Python, likes hacking/security.
- **Timeline:** 4 months.
- **Goal:** A working project, demo-able in interviews and to investors.

---

## Idea selection

Out of five AI + security project ideas, the user chose **Project 4**:

> ### AI-Powered Automated Pentesting / Recon Assistant
> An AI agent that takes a target, runs recon (nmap, subdomain enum, etc.),
> and uses an LLM to summarize vulnerabilities & suggest exploits, then writes
> a clean security report.

**Why it's a good fit:** combines AI agents + real security tooling + automation —
exactly the category several funded startups (XBOW, Horizon3, etc.) are in.

---

## The one legal rule

Only ever scan/test:
- Machines you **own** (your own VM, localhost),
- **Intentionally vulnerable labs** (HackTheBox, TryHackMe, VulnHub, DVWA,
  Metasploitable, OWASP Juice Shop),
- Or targets with **written permission**.

Scanning random internet hosts is illegal in most countries. For a portfolio
project, vulnerable labs are perfect. "Scope control" is part of the pitch.

---

## What the project does

1. **Recon** → runs tools (nmap, subdomain enum, tech detection)
2. **Parses** the raw tool output
3. **Reasons** with an LLM → explains risk + how to verify
4. **Reports** → human-readable security report (severity, evidence, remediation)

It is an autonomous "junior pentester" that does boring recon and writes the
first draft of the report.

---

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   User /    │────▶│   Orchestr-  │────▶│  Security   │
│   Web UI    │     │   ator       │     │  Tools      │
│  (target)   │◀────│  (Python)    │◀────│ nmap, etc.  │
└─────────────┘     └──────┬───────┘     └─────────────┘
                           │
                    ┌──────▼───────┐
                    │   LLM Agent  │  ← reasons over output,
                    │ (Claude API) │    decides next step,
                    └──────────────┘    writes the report
```

---

## Tech stack

| Layer | Tool |
|-------|------|
| Language | Python |
| LLM | Claude API (opus/sonnet) or OpenAI |
| Agent framework | Raw function-calling first, then LangChain/custom |
| Recon tools | nmap, subfinder/amass, httpx, whatweb, nuclei |
| Orchestration | Python subprocess to run tools, parse output |
| Backend API | FastAPI |
| Frontend | Streamlit (fast) or React (impressive) |
| Reports | Jinja2 → HTML/PDF |
| Lab targets | DVWA, Juice Shop, Metasploitable, HTB |

---

## 4-month roadmap

### Month 1 — Foundations
- Learn LLM function/tool calling (core skill).
- Build a CLI that runs nmap via Python and prints results.
- Set up a safe lab (Docker: Juice Shop, DVWA; or Metasploitable VM).
- Mini-goal: *Python script → runs nmap on my lab → returns clean JSON.*

### Month 2 — The AI brain
- Connect the LLM: feed it raw nmap output → it explains findings.
- Implement tool-calling agent: LLM decides which tool to run next.
- Add 2–3 more tools (subdomain enum, http probing, tech fingerprinting).
- Mini-goal: *Give it a target → autonomous recon → summary.*

### Month 3 — Make it a product
- Build the report generator (severity, evidence, fixes).
- Add FastAPI backend + job queue (scans take time).
- Add scope guardrails (whitelist of allowed targets).
- Mini-goal: *Clean PDF/HTML report out the other end.*

### Month 4 — Polish + Demo + Pitch
- Build dashboard UI (live progress, findings, report download).
- Record a demo video scanning the lab.
- Write the pitch: problem, solution, market, demo.
- Mini-goal: *5-minute demo that wows.*

---

## Tools the agent can orchestrate

### Phase 1: Discovery / Recon
nmap, masscan, subfinder, amass, assetfinder, dnsx, whois, theHarvester

### Phase 2: Web probing / fingerprinting
httpx, whatweb, wappalyzer, gobuster/ffuf/dirsearch, waybackurls/gau

### Phase 3: Vulnerability scanning
nuclei (the big one), nikto, sslscan/testssl.sh, wpscan

### Phase 4: Analysis / reporting
The LLM itself.

### Recommended starter set (5–7 tools)
1. nmap (ports + services)
2. subfinder (subdomains)
3. httpx (live web hosts)
4. whatweb (tech detection)
5. nuclei (vulnerabilities) ← huge wow factor
6. gobuster or ffuf (hidden paths)

Each tool is just a function the LLM can call → adding a tool = one wrapper.

---

## Nmap is "many tools in one"

### Scan types
| Flag | Scan |
|------|------|
| `-sS` | SYN / stealth (default, fast) |
| `-sT` | Full TCP connect |
| `-sU` | UDP |
| `-sV` | Service & version detection |
| `-O` | OS detection |
| `-sn` | Ping sweep (host discovery) |
| `-Pn` | Skip ping |
| `-p-` | All 65535 ports |
| `-A` | Aggressive (version+OS+scripts+traceroute) |
| `-T0`–`-T5` | Timing (T4 typical for labs) |

### NSE — Nmap Scripting Engine (~600+ scripts)
| Category | Use | Command |
|----------|-----|---------|
| default | safe common checks | `-sC` |
| vuln | known vuln checks | `--script=vuln` |
| auth | auth bypass / default creds | `--script=auth` |
| brute | brute-force logins | `--script=brute` |
| discovery | extra service info | `--script=discovery` |
| safe | non-intrusive | `--script=safe` |
| exploit | attempt exploits | `--script=exploit` |
| malware | detect backdoors | `--script=malware` |

List scripts:
```bash
ls /usr/share/nmap/scripts/
nmap --script-help "vuln"
```

### Adaptive agent example
```
User: "scan my lab box"
Agent reasoning:
  → nmap -sn (is host up?)
  → nmap -sV -p- (what's running?)
  → saw port 80 → nmap --script=http-enum
  → saw FTP → nmap --script=ftp-anon
```
The LLM picks the right nmap mode for the situation — that's the "AI" magic.

---

## Design principle

Don't expose all of nmap as separate tools. Expose a few smart functions and
let the LLM fill in the arguments:

```python
run_nmap(target, scan_type="version", ports=None, scripts="vuln")
run_nuclei(target, severity="high,critical")
run_subfinder(domain)
```

One wrapper, infinite combinations.

---

## Pitch (investors / interview)

> "Pentesting is expensive and slow — companies wait weeks for a report. My tool
> uses an AI agent to automate recon and generate a first-draft security report
> in minutes, so security teams focus on fixing instead of finding. It's like a
> tireless junior pentester."
