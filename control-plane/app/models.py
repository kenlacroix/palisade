from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
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

# Membership roles, ordered most→least privileged. require_role checks against
# these; owner/admin can manage channels/rules, member can mute, viewer reads.
ROLES = ("owner", "admin", "member", "viewer")


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


# --- multi-tenancy (M1) ---
class User(Base):
    __tablename__ = "app_user"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    name: Mapped[str] = mapped_column(String, default="")
    # pbkdf2_hmac hash, stored as "pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>".
    password_hash: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Membership(Base):
    __tablename__ = "membership"
    __table_args__ = (UniqueConstraint("user_id", "org_id", name="uq_membership_user_org"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("app_user.id"), index=True)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("org.id"), index=True)
    role: Mapped[str] = mapped_column(String, default="viewer")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class UserSession(Base):
    __tablename__ = "user_session"

    # token is the primary key; presented as a bearer token by the web UI.
    token: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("app_user.id"), index=True)
    # active org for this session; switchable across the user's memberships.
    org_id: Mapped[str] = mapped_column(String, ForeignKey("org.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=_now)


class EnrollToken(Base):
    __tablename__ = "enroll_token"

    # Single-use: a token may mint exactly one agent. used_at/agent_id record it.
    token: Mapped[str] = mapped_column(String, primary_key=True)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("org.id"), default=DEMO_ORG_ID)
    label: Mapped[str] = mapped_column(String, default="")
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    agent_id: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


# --- alerting (M3) ---
class AlertChannel(Base):
    __tablename__ = "alert_channel"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("org.id"), default=DEMO_ORG_ID, index=True)
    type: Mapped[str] = mapped_column(String)  # telegram|email|webhook
    name: Mapped[str] = mapped_column(String, default="")
    # type-specific delivery config, e.g. {"bot_token","chat_id"} / {"url"} /
    # {"smtp_host","smtp_port","username","password","from","to"}.
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class AlertRule(Base):
    __tablename__ = "alert_rule"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("org.id"), default=DEMO_ORG_ID, index=True)
    name: Mapped[str] = mapped_column(String, default="")
    # Fire when a finding's severity is at least this rank. See SEVERITY_RANK.
    min_severity: Mapped[str] = mapped_column(String, default="high")
    # Which lifecycle events fire the rule, e.g. ["new","regressed"].
    on_events: Mapped[list] = mapped_column(JSON, default=lambda: ["new", "regressed"])
    channel_id: Mapped[str] = mapped_column(String, ForeignKey("alert_channel.id"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


class Alert(Base):
    __tablename__ = "alert"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("org.id"), default=DEMO_ORG_ID, index=True)
    finding_id: Mapped[str] = mapped_column(String, ForeignKey("finding.id"))
    rule_id: Mapped[str | None] = mapped_column(String, nullable=True)
    channel_id: Mapped[str | None] = mapped_column(String, nullable=True)
    event: Mapped[str] = mapped_column(String, default="new")  # new|regressed
    severity: Mapped[str] = mapped_column(String, default="info")
    status: Mapped[str] = mapped_column(String, default="pending")  # pending|sent|failed
    error: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


# --- posture trends (real history) ---
class PostureSnapshot(Base):
    __tablename__ = "posture_snapshot"
    __table_args__ = (UniqueConstraint("org_id", "day", name="uq_snapshot_org_day"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("org.id"), default=DEMO_ORG_ID, index=True)
    # UTC calendar day, "YYYY-MM-DD"; one snapshot per org per day (upserted).
    day: Mapped[str] = mapped_column(String, index=True)
    captured_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    score: Mapped[int] = mapped_column(Integer, default=100)
    critical: Mapped[int] = mapped_column(Integer, default=0)
    high: Mapped[int] = mapped_column(Integer, default=0)
    medium: Mapped[int] = mapped_column(Integer, default=0)
    assets_count: Mapped[int] = mapped_column(Integer, default=0)
