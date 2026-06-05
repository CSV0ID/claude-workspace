# ERRORS — Common Problems & Fixes

Quick lookup for the errors you'll actually hit. Grouped by area.

---

## Python / install

**`No module named anthropic` (or fastapi / sqlalchemy / jinja2 / pytest)**
Deps not installed, or wrong interpreter/venv.
```bash
pip install -r nmap/requirements.txt
# make sure the venv is active:  source .venv/bin/activate  (Win: .venv\Scripts\activate)
which python && python -c "import sys; print(sys.prefix)"
```

**`No module named pip` / `No module named ensurepip`**
Python built without pip.
```bash
python -m ensurepip --upgrade        # if available
# else bootstrap:
curl -sS https://bootstrap.pypa.io/get-pip.py | python
```

**`command not found: python`**
Use `python3` (Linux/macOS) or `py` (Windows). Optionally alias.

**`externally-managed-environment` (PEP 668, Debian/Kali)**
Use a venv (preferred) or `pip install --user`. Avoid `--break-system-packages`.

---

## Scanner binaries

**`<tool> is not installed or not on PATH.`** (in a tool's result `error`)
Expected when the binary isn't installed — the wrapper degrades, never crashes.
Install it (see `RUN.md` §2). Go tools land in `~/go/bin`:
```bash
export PATH="$PATH:$HOME/go/bin"     # add to ~/.bashrc / ~/.zshrc
python nmap/tools/tool_wrappers.py   # re-check installed/missing
```

**`go: command not found`** — install Go first (`apt install golang-go` / `brew install go`), then re-run `go install ...`.

**nmap: `You requested a scan type which requires root privileges` / `-sS` fails**
SYN scan needs root. Run with `sudo`, or the wrapper's non-root profiles use
`-sT` (TCP connect) which needs no root.

**nmap on Windows: missing Npcap** — install Npcap (bundled with the nmap
Windows installer) or run everything under WSL2.

**`nuclei` first run is slow / "templates not found"**
nuclei downloads its template DB on first run:
```bash
nuclei -update-templates
```

---

## Scope guard (by design — not a bug)

**`ScopeError: Target '<x>' is not in the authorized scope.`**
The target is outside the allow-list. This is intentional safety.
```bash
# localhost + private ranges are allowed by default. For a lab subnet:
python offline_recon.py 192.168.56.101 --scope 192.168.56.0/24
# agent:  python agent.py 10.0.0.5 --scope 10.0.0.0/8
```
Offline mode records this as `stopped_reason="scope_refused"`, 0 tools run.

**`stopped_reason: scope_refused` in a scan, `steps: 0`** — same cause; pass the
right `scope` in the POST body: `{"target":"...","scope":["192.168.56.0/24"]}`.

---

## LLM agent (mode=llm)

**`ERROR: set ANTHROPIC_API_KEY ... in your environment`**
No API key for the chosen provider. Export the matching key:
| provider | env var |
|----------|---------|
| anthropic | `ANTHROPIC_API_KEY` |
| openai | `OPENAI_API_KEY` |
| openrouter | `OPENROUTER_API_KEY` |
| gemini | `GEMINI_API_KEY` |

**`401 Unauthorized` / `invalid x-api-key`** — wrong/expired key.

**`429 Too Many Requests` / rate limit / `insufficient_quota`** — out of credit
or rate-limited. Use `--provider` to switch, or run `offline_recon.py` / a scan
with `mode=offline` (no LLM) and feed the saved bundle to the model later with
`payload_to_prompt()`.

**Agent stops with `(Agent hit the N-step limit...)`** — raise the cap:
`agent.py <target> --max-steps 20`.

---

## Backend (FastAPI)

**`sqlalchemy ... no such table: scans`**
Tables not created. They're made on startup (`lifespan`) or by `init_db()`. In
tests/scripts call `from app.db import init_db; init_db()` before using the DB.
Run uvicorn from the `nmap/` dir so `app` is importable.

**`ModuleNotFoundError: No module named 'app'`**
Wrong working dir. `cd nmap` first, then `uvicorn app.main:app`.

**`ModuleNotFoundError: No module named 'report'` (or nmap_wrapper / offline_recon)**
The backend adds `nmap/tools` to `sys.path` in `runner.py`. If you moved files,
keep `app/` and `tools/` siblings under `nmap/`.

**`409 Conflict` on `GET /scans/{id}/report`**
Scan not finished. Poll `GET /scans/{id}` until `status: "done"`, then fetch.

**`address already in use` (port 8000)**
Another process holds the port.
```bash
uvicorn app.main:app --port 8001        # use another port
# or free it:  lsof -ti:8000 | xargs kill   (Linux/macOS)
```

**`findings` empty `[]` on a finished scan**
No scanner produced parsable findings (binaries missing, or nothing found).
Check `GET /scans/{id}/bundle` for the raw tool output and install the binaries.

---

## Hosting

**Scanners "don't work on Vercel" / function timeout**
Vercel is serverless — no system packages, short timeouts. nmap/nuclei can't run
there. Host the **backend on a VM/Docker**, put only the **frontend** on Vercel.
See `RUN.md` §5.

---

## Git

**`remote: Repository not found` / `fatal: repository '.../your-repo.git' not found`**
Origin points at a placeholder. Set the real URL:
```bash
git remote set-url origin https://github.com/CSV0ID/claude-workspace.git
git push -u origin <branch>
```

**`Permission denied` / `Authentication failed` on push** — token expired or
lacks `repo` scope. Generate a new PAT and update the remote URL/credential.

---

## Tests

**Tests want a network or a scanner binary** — they shouldn't. Suite is designed
offline (parsers fed samples, agent driven by a fake provider). If you added a
test that needs a binary/network, mock it instead.

**Run one test:**
```bash
python -m pytest "tools/tests/test_suite.py::TestScope::test_localhost_in_scope" -q
```
