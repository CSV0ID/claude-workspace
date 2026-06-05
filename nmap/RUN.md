# RUN — Setup & Run on Any System

How to install and run the AI Pentesting / Recon Assistant on Linux, Windows,
macOS, and how hosting works (Vercel + backend).

> ⚠️ Scan only owned machines, vulnerable labs (DVWA, Juice Shop, Metasploitable,
> HTB/THM), or written-permission targets. Scope allow-list is enforced in code.

---

## 0. Three kinds of dependencies

| Kind | What | Installed by |
|------|------|--------------|
| Python libs | anthropic, openai, fastapi, jinja2, pytest… | `pip` (`requirements.txt`) |
| Scanner binaries | nmap, httpx, nuclei, subfinder, gobuster… | OS package manager + Go |
| Node libs | React/Vite dashboard (Month 4) | `npm` (`package.json`) |

The scanner binaries are **NOT** pip/npm packages. Wrappers degrade gracefully:
a missing binary returns a failed result, never crashes.

---

## 1. Python (all systems)

Need Python 3.10+.

```bash
# from repo root
python -m venv .venv

# activate:
source .venv/bin/activate          # Linux / macOS
.venv\Scripts\activate             # Windows PowerShell/CMD

pip install -r nmap/requirements.txt
```

Set the API key for the LLM provider you use (skip for offline mode):

```bash
# Linux / macOS
export ANTHROPIC_API_KEY=sk-...        # or OPENAI_/OPENROUTER_/GEMINI_API_KEY

# Windows PowerShell
$env:ANTHROPIC_API_KEY="sk-..."
```

---

## 2. Scanner binaries

### Linux (Debian/Ubuntu/Kali)
```bash
sudo apt update
sudo apt install -y nmap nikto whatweb sslscan wafw00f   # apt-provided
# Go-based tools (install Go first: sudo apt install -y golang-go):
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/ffuf/ffuf/v2@latest
# wpscan (Ruby): sudo gem install wpscan
export PATH="$PATH:$HOME/go/bin"     # add Go bins to PATH
```

### macOS (Homebrew)
```bash
brew install nmap nikto sslscan go
brew install projectdiscovery/tap/httpx projectdiscovery/tap/nuclei \
             projectdiscovery/tap/subfinder projectdiscovery/tap/dnsx \
             projectdiscovery/tap/katana
brew install gobuster ffuf
# whatweb/wafw00f/wpscan: brew install whatweb wafw00f ; gem install wpscan
export PATH="$PATH:$HOME/go/bin"
```

### Windows
Use **Scoop** or **Chocolatey** (run as admin for choco):
```powershell
# Scoop
scoop install nmap go gobuster ffuf
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# add %USERPROFILE%\go\bin to PATH
```
nmap on Windows also has a GUI installer (nmap.org/download). nikto/whatweb/
wpscan are easiest under WSL2 — for full coverage on Windows, run everything in
**WSL2 (Ubuntu)** and follow the Linux steps.

### Check what's installed
```bash
cd nmap/tools
python tool_wrappers.py     # prints installed/missing for each tool
```

---

## 3. Run

```bash
cd nmap/tools

# Offline recon (NO LLM, no API key) — saves scan bundle JSON to disk
python offline_recon.py 127.0.0.1 --out runs/
python offline_recon.py 192.168.56.101 --scope 192.168.56.0/24

# Full LLM agent (needs API key)
python agent.py 127.0.0.1
python agent.py 192.168.56.101 --provider gemini --scope 192.168.56.0/24 --report-dir out

# Tests (no binaries/network needed)
python -m pytest tests/ -q
```

Windows: same commands, `python` (or `py`) from the activated venv.

### Backend API (FastAPI)
```bash
cd nmap
uvicorn app.main:app --reload --port 8000     # http://localhost:8000
# docs UI: http://localhost:8000/docs
```
DB file defaults to `nmap/app/scans.db` (override with `RECON_DB_URL`).

Endpoints:
| Method | Path | What |
|--------|------|------|
| GET  | `/health` | liveness |
| POST | `/scans` | queue a scan; body `{"target","scope?","mode":"offline\|llm","provider?"}` |
| GET  | `/scans?limit=&offset=&status=` | list scans (newest first) |
| GET  | `/scans/{id}` | scan detail + severity counts |
| GET  | `/scans/{id}/findings` | structured findings |
| GET  | `/scans/{id}/report?format=html\|md` | rendered report |
| GET  | `/scans/{id}/bundle` | raw recon JSON |
| DELETE | `/scans/{id}` | delete scan + findings |

```bash
# example: queue an offline scan and read it back
curl -X POST localhost:8000/scans -H 'content-type: application/json' \
     -d '{"target":"127.0.0.1","mode":"offline"}'
curl localhost:8000/scans/1                       # poll: queued->running->done
curl "localhost:8000/scans/1/report?format=md"
```

---

## 4. Verify everything works

Run top-to-bottom; each line should succeed.

```bash
# 1. Python deps present
python -c "import anthropic, openai, fastapi, sqlalchemy, jinja2; print('py deps ok')"

# 2. Which scanner binaries are installed (missing ones just degrade)
cd nmap/tools && python tool_wrappers.py

# 3. All tests green (tools + API)
cd nmap/tools && python -m pytest tests/ -q          # 50 tests
cd nmap     && python -m pytest app/tests/ -q        # 11 tests

# 4. Offline recon writes a bundle (works with NO binaries/API)
cd nmap/tools && python offline_recon.py 127.0.0.1 --out /tmp/runs
ls /tmp/runs/*.json                                  # bundle exists

# 5. Scope guard refuses out-of-scope (must print "not in scope", 0 tools)
python offline_recon.py 8.8.8.8 --out /tmp/runs

# 6. Backend up + scan round-trip
cd nmap && uvicorn app.main:app --port 8000 &        # then, in another shell:
curl localhost:8000/health                           # {"status":"ok"}
curl -X POST localhost:8000/scans -H 'content-type: application/json' \
     -d '{"target":"127.0.0.1"}'                      # {"id":1,"status":"queued"}
curl localhost:8000/scans/1                           # status -> "done"

# 7. LLM mode (only if an API key is set)
export ANTHROPIC_API_KEY=sk-...
cd nmap/tools && python agent.py 127.0.0.1
```

If a step fails, see `ERRORS.md`.

---

## 4b. Dashboard UI (Month 4)

A React + Vite single-page app (`nmap/index.html` + `nmap/src/`) that drives the
backend: queue scans, watch status live, browse findings, view/download reports.

```bash
cd nmap
npm install
# 1. start the backend (separate shell):  uvicorn app.main:app --port 8000
npm run dev                # dev server on http://localhost:5173
```

The Vite dev server proxies `/scans` and `/health` to the backend on `:8000`
(see `vite.config.js`), so no CORS setup is needed. Override the backend with
`VITE_API_TARGET=http://host:port npm run dev`.

Build a static bundle for hosting:
```bash
npm run build              # outputs dist/
npm run preview            # serve the build locally
```

In production the app talks to the backend via `VITE_API_BASE` (the public
backend URL); leave it unset in dev to use the proxy.

---

## 5. Hosting

### Important: Vercel cannot run the scanners
Vercel = serverless functions, no system packages, 10–60 s timeout, no long-lived
processes. nmap/nuclei/etc. **cannot** run there, and scans take minutes. So:

- **Frontend (Month-4 dashboard) → Vercel.** Static React/Vite build. Set env
  `VITE_API_URL` to the backend URL.
- **Backend (FastAPI + scanners) → a real VM/container**, not Vercel. Options:
  a Linux VPS (DigitalOcean/Hetzner/EC2), Fly.io, Railway, or Render with a
  Docker image that `apt install`s the scanner binaries.

### Backend on a VM (once Month-3 FastAPI exists)
```bash
pip install -r nmap/requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000   # path TBD when backend is built
```

### Docker (recommended for the backend)
A Dockerfile should start from a Linux base, `apt install` the apt tools, `go
install` the Go tools, `pip install -r requirements.txt`, then run uvicorn.
This bakes every scanner into the image so the host needs nothing.

### Frontend on Vercel
```bash
cd nmap                 # dashboard root (index.html + src/)
npm install
npm run build           # static bundle -> dist/
# deploy: import the repo in Vercel, set root to nmap/, build cmd `npm run build`,
# output dir `dist`, and env VITE_API_BASE to the backend's public URL.
```

---

## 6. Quick reference

| Goal | Command |
|------|---------|
| Install Python deps | `pip install -r nmap/requirements.txt` |
| Install Node deps | `cd dashboard && npm install` |
| See installed scanners | `python nmap/tools/tool_wrappers.py` |
| Recon, no LLM | `python nmap/tools/offline_recon.py <target>` |
| Recon, with LLM | `python nmap/tools/agent.py <target>` |
| Run tool tests | `cd nmap/tools && python -m pytest tests/ -q` |
| Run API tests | `cd nmap && python -m pytest app/tests/ -q` |
| Start backend | `cd nmap && uvicorn app.main:app --port 8000` |
