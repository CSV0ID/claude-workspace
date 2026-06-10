"""
main.py
=======
FastAPI backend for the AI Pentesting / Recon Assistant (Month 3).

Endpoints:
    POST   /scans                 queue a scan, returns {id, status}
    GET    /scans                 list scans (newest first)
    GET    /scans/{id}            scan detail + severity counts
    GET    /scans/{id}/report     report (?format=html|md, default html)
    GET    /scans/{id}/bundle     raw recon bundle JSON
    GET    /health                liveness

Scans run in the background (they take minutes); poll GET /scans/{id} for status:
queued -> running -> done|failed.

Run:  cd nmap && uvicorn app.main:app --reload --port 8000
"""

from __future__ import annotations

import json

from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from .db import SessionLocal, Scan, Finding, init_db
from .runner import run_scan


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="AI Pentesting / Recon Assistant", version="0.1.0",
              lifespan=lifespan)

# CORS — temporary wildcard until Vercel URL is known.
# After deploying frontend, replace "*" with your Vercel URL:
#   allow_origins=["https://your-app.vercel.app"]
# and set allow_credentials=True, then redeploy Railway.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,   # must be False when allow_origins=["*"]
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: str = Field(..., description="Host/IP/domain. Must be in scope.")
    scope: list[str] | None = Field(None, description="Allowed scope; defaults to localhost+private.")
    mode: str = Field("offline", pattern="^(offline|llm)$")
    provider: str = Field("anthropic", description="LLM provider (mode=llm only).")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/scans", status_code=201)
def create_scan(req: ScanRequest, background: BackgroundTasks) -> dict:
    with SessionLocal() as s:
        row = Scan(
            target=req.target,
            scope=json.dumps(req.scope) if req.scope is not None else "",
            mode=req.mode,
            provider=req.provider if req.mode == "llm" else "",
            status="queued",
        )
        s.add(row)
        s.commit()
        scan_id = row.id

    background.add_task(run_scan, scan_id)
    return {"id": scan_id, "status": "queued"}


@app.get("/scans")
def list_scans(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    status: str | None = Query(None, pattern="^(queued|running|done|failed)$"),
) -> list[dict]:
    with SessionLocal() as s:
        q = s.query(Scan)
        if status:
            q = q.filter(Scan.status == status)
        rows = q.order_by(Scan.id.desc()).offset(offset).limit(limit).all()
        return [r.summary() for r in rows]


def _get(scan_id: int) -> Scan:
    with SessionLocal() as s:
        row = s.get(Scan, scan_id)
        if row is None:
            raise HTTPException(404, f"scan {scan_id} not found")
        return row


@app.get("/scans/{scan_id}")
def get_scan(scan_id: int) -> dict:
    return _get(scan_id).summary()


@app.get("/scans/{scan_id}/findings")
def get_findings(scan_id: int) -> list[dict]:
    _get(scan_id)  # 404 if missing
    with SessionLocal() as s:
        rows = (s.query(Finding)
                .filter(Finding.scan_id == scan_id)
                .order_by(Finding.id.asc()).all())
        return [f.to_dict() for f in rows]


@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: int):
    with SessionLocal() as s:
        row = s.get(Scan, scan_id)
        if row is None:
            raise HTTPException(404, f"scan {scan_id} not found")
        s.delete(row)  # cascade removes findings
        s.commit()
    return None


@app.get("/scans/{scan_id}/report")
def get_report(scan_id: int, format: str = Query("html", pattern="^(html|md)$")):
    row = _get(scan_id)
    if row.status != "done":
        raise HTTPException(409, f"scan {scan_id} not finished (status={row.status})")
    if format == "md":
        return PlainTextResponse(row.report_md, media_type="text/markdown")
    return HTMLResponse(row.report_html)


@app.get("/scans/{scan_id}/bundle")
def get_bundle(scan_id: int):
    row = _get(scan_id)
    if not row.bundle_json:
        raise HTTPException(409, f"scan {scan_id} has no bundle yet (status={row.status})")
    return JSONResponse(json.loads(row.bundle_json))