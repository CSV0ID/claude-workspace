"""
API tests for the FastAPI backend.

No network or scanner binaries needed: offline mode runs the wrappers, which
degrade to failed results when a binary is absent, so a scan still completes
end-to-end. The DB is a throwaway temp SQLite file per test session.
"""

from __future__ import annotations

import os
import sys
import tempfile

import pytest

# Isolated temp DB BEFORE importing the app (db.py reads RECON_DB_URL at import).
_TMP_DB = os.path.join(tempfile.mkdtemp(), "test_scans.db")
os.environ["RECON_DB_URL"] = f"sqlite:///{_TMP_DB}"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fastapi.testclient import TestClient  # noqa: E402
from app.db import init_db  # noqa: E402
from app.main import app  # noqa: E402

init_db()  # ensure tables exist for the module-level client
client = TestClient(app)


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_create_offline_scan_runs_to_done():
    # TestClient runs BackgroundTasks synchronously, so the scan is finished
    # by the time the POST returns.
    r = client.post("/scans", json={"target": "127.0.0.1", "mode": "offline"})
    assert r.status_code == 201
    scan_id = r.json()["id"]

    detail = client.get(f"/scans/{scan_id}").json()
    assert detail["status"] == "done"
    assert detail["target"] == "127.0.0.1"
    assert detail["stopped_reason"] == "offline_recon"


def test_out_of_scope_scan_refused_but_recorded():
    r = client.post("/scans", json={"target": "8.8.8.8", "mode": "offline"})
    scan_id = r.json()["id"]
    detail = client.get(f"/scans/{scan_id}").json()
    assert detail["status"] == "done"
    assert detail["stopped_reason"] == "scope_refused"
    assert detail["steps"] == 0


def test_report_and_bundle_endpoints():
    scan_id = client.post("/scans", json={"target": "127.0.0.1"}).json()["id"]

    html = client.get(f"/scans/{scan_id}/report")
    assert html.status_code == 200
    assert "Security Report" in html.text

    md = client.get(f"/scans/{scan_id}/report", params={"format": "md"})
    assert md.status_code == 200
    assert "127.0.0.1" in md.text

    bundle = client.get(f"/scans/{scan_id}/bundle").json()
    assert bundle["schema"] == "recon-bundle/v1"
    assert bundle["target"] == "127.0.0.1"


def test_list_scans():
    client.post("/scans", json={"target": "127.0.0.1"})
    rows = client.get("/scans").json()
    assert isinstance(rows, list) and len(rows) >= 1
    assert {"id", "target", "status"} <= set(rows[0].keys())


def test_missing_scan_404():
    assert client.get("/scans/999999").status_code == 404


def test_report_before_done_conflicts(monkeypatch):
    # Queue a row but don't run it: report should 409.
    from app.db import SessionLocal, Scan
    with SessionLocal() as s:
        row = Scan(target="127.0.0.1", mode="offline", status="queued")
        s.add(row); s.commit(); sid = row.id
    assert client.get(f"/scans/{sid}/report").status_code == 409
