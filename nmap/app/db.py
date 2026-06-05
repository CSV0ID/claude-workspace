"""
db.py
=====
SQLite persistence for the AI Pentesting / Recon Assistant backend (Month 3).

A scan is slow and async, so the API stores its lifecycle here: queued -> running
-> done/failed, plus the produced report (Markdown + HTML) and the raw recon
bundle JSON. One row per scan; severity counts denormalised for cheap listing.

SQLAlchemy 2.0 style. The DB file defaults to nmap/app/scans.db (override with
$RECON_DB_URL).
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy import String, Integer, Text, DateTime, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


def _default_db_url() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return f"sqlite:///{os.path.join(here, 'scans.db')}"


DB_URL = os.environ.get("RECON_DB_URL", _default_db_url())

# check_same_thread=False: background scan threads touch the same SQLite file.
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target: Mapped[str] = mapped_column(String(255), index=True)
    scope: Mapped[str] = mapped_column(Text, default="")          # JSON list as string
    mode: Mapped[str] = mapped_column(String(16), default="offline")  # offline | llm
    provider: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    stopped_reason: Mapped[str] = mapped_column(String(64), default="")
    error: Mapped[str] = mapped_column(Text, default="")

    steps: Mapped[int] = mapped_column(Integer, default=0)
    sev_counts: Mapped[str] = mapped_column(Text, default="{}")   # JSON dict as string

    report_md: Mapped[str] = mapped_column(Text, default="")
    report_html: Mapped[str] = mapped_column(Text, default="")
    bundle_json: Mapped[str] = mapped_column(Text, default="")    # full recon payload

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=lambda: datetime.now(timezone.utc))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def summary(self) -> dict:
        """Lightweight dict for list endpoints (no big report/bundle blobs)."""
        import json
        return {
            "id": self.id,
            "target": self.target,
            "mode": self.mode,
            "provider": self.provider,
            "status": self.status,
            "stopped_reason": self.stopped_reason,
            "error": self.error,
            "steps": self.steps,
            "sev_counts": json.loads(self.sev_counts or "{}"),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }


def init_db() -> None:
    """Create tables if absent. Safe to call on every startup."""
    Base.metadata.create_all(engine)
