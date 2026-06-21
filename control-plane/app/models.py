from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base

DEMO_ORG_ID = "org-demo"


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Org(Base):
    __tablename__ = "org"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    name: Mapped[str] = mapped_column(String, default="demo")
    plan: Mapped[str] = mapped_column(String, default="free")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Agent(Base):
    __tablename__ = "agent"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("org.id"), default=DEMO_ORG_ID)
    secret: Mapped[str] = mapped_column(String, unique=True, index=True)
    hostname: Mapped[str] = mapped_column(String, default="")
    os: Mapped[str] = mapped_column(String, default="")
    arch: Mapped[str] = mapped_column(String, default="")
    version: Mapped[str] = mapped_column(String, default="")
    status: Mapped[str] = mapped_column(String, default="idle")
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # cycle bookkeeping so heartbeat does not infinitely re-issue jobs
    last_discover_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_scan_issued_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Asset(Base):
    __tablename__ = "asset"
    __table_args__ = (UniqueConstraint("org_id", "host", "port", name="uq_asset_host_port"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("org.id"), default=DEMO_ORG_ID)
    agent_id: Mapped[str | None] = mapped_column(String, ForeignKey("agent.id"), nullable=True)
    host: Mapped[str] = mapped_column(String, index=True)
    port: Mapped[int] = mapped_column(Integer)
    service: Mapped[str] = mapped_column(String, default="")
    product: Mapped[str | None] = mapped_column(String, nullable=True)
    version: Mapped[str | None] = mapped_column(String, nullable=True)
    exposure: Mapped[str] = mapped_column(String, default="internal")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Detection(Base):
    __tablename__ = "detection"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    title: Mapped[str] = mapped_column(String, default="")
    cve: Mapped[str | None] = mapped_column(String, nullable=True)
    severity: Mapped[str] = mapped_column(String, default="info")
    category: Mapped[str] = mapped_column(String, default="self-hosted")
    engine: Mapped[str] = mapped_column(String, default="nuclei")
    match_service: Mapped[str] = mapped_column(String, default="")
    match_versions: Mapped[str] = mapped_column(String, default="")
    spec: Mapped[dict] = mapped_column(JSON, default=dict)  # full Detection shape
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    signature: Mapped[str] = mapped_column(String, default="stub")


class Scan(Base):
    __tablename__ = "scan"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("org.id"), default=DEMO_ORG_ID)
    agent_id: Mapped[str | None] = mapped_column(String, ForeignKey("agent.id"), nullable=True)
    status: Mapped[str] = mapped_column(String, default="issued")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    assets_count: Mapped[int] = mapped_column(Integer, default=0)


class Finding(Base):
    __tablename__ = "finding"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("org.id"), default=DEMO_ORG_ID)
    asset_id: Mapped[str] = mapped_column(String, ForeignKey("asset.id"))
    detection_id: Mapped[str] = mapped_column(String, ForeignKey("detection.id"))
    scan_id: Mapped[str | None] = mapped_column(String, nullable=True)
    severity: Mapped[str] = mapped_column(String, default="info")
    status: Mapped[str] = mapped_column(String, default="open")  # open|resolved|muted|regressed
    fingerprint: Mapped[str] = mapped_column(String, unique=True, index=True)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    mute_reason: Mapped[str | None] = mapped_column(String, nullable=True)
    mute_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    triage_priority: Mapped[str | None] = mapped_column(String, nullable=True)
    triage_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    triage_rationale: Mapped[str | None] = mapped_column(String, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=_now)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_now)
