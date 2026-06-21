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
    LargeBinary,
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
    # mTLS identity issued at enroll: sha256 fingerprint (hex) of the client
    # cert's DER and its expiry. Null for agents enrolled before mTLS / bearer-only.
    cert_fingerprint: Mapped[str | None] = mapped_column(String, index=True, nullable=True)
    cert_not_after: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
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
    # Scan target manifest: [{"asset_id", "detection_ids":[...]}]. Records exactly
    # what was scanned so findings ingest can resolve precisely — an unreported
    # (asset, detection) that WAS in the manifest is resolved; one that was not is
    # left untouched (not scanned this cycle, not "absent").
    targets: Mapped[list] = mapped_column(JSON, default=list)


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
    # Evidence sealed at rest (AES-256-GCM, nonce||ciphertext) under the org's
    # data key. Populated only when a KEK is configured; then `evidence` is empty
    # and reads go through encryption.open_evidence. See app/encryption.py.
    evidence_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
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
    # Quiet hours: when both bounds are set, alerts matched during the window are
    # held until it ends ("defer") or dropped ("suppress"). Bounds are local
    # "HH:MM" in quiet_hours_tz (IANA name). Windows may wrap past midnight.
    quiet_hours_start: Mapped[str | None] = mapped_column(String, nullable=True)
    quiet_hours_end: Mapped[str | None] = mapped_column(String, nullable=True)
    quiet_hours_tz: Mapped[str] = mapped_column(String, default="UTC")
    quiet_hours_mode: Mapped[str] = mapped_column(String, default="defer")  # defer|suppress
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
    # pending|sent|failed|deferred|suppressed. deferred alerts are released to
    # pending once deferred_until passes (see alerting.release_due_deferred).
    status: Mapped[str] = mapped_column(String, default="pending")
    error: Mapped[str | None] = mapped_column(String, nullable=True)
    deferred_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


# --- posture trends (real history) ---
class PostureSnapshot(Base):
    __tablename__ = "posture_snapshot"
    __table_args__ = (UniqueConstraint("org_id", "day", name="uq_snapshot_org_day"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("org.id"), default=DEMO_ORG_ID, index=True)
    # UTC calendar day, "YYYY-MM-DD"; one snapshot per org per day (upserted).
    # No standalone index: reads filter by org_id or the (org_id, day) unique.
    day: Mapped[str] = mapped_column(String)
    captured_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
    score: Mapped[int] = mapped_column(Integer, default=100)
    critical: Mapped[int] = mapped_column(Integer, default=0)
    high: Mapped[int] = mapped_column(Integer, default=0)
    medium: Mapped[int] = mapped_column(Integer, default=0)
    assets_count: Mapped[int] = mapped_column(Integer, default=0)


# --- evidence-at-rest: per-org data key, wrapped by the master KEK ---
class OrgEncryptionKey(Base):
    __tablename__ = "org_encryption_key"
    __table_args__ = (UniqueConstraint("org_id", name="uq_org_encryption_key_org"),)

    id: Mapped[str] = mapped_column(String, primary_key=True, default=_uuid)
    org_id: Mapped[str] = mapped_column(String, ForeignKey("org.id"), index=True)
    # 32-byte per-org data key, wrapped (AES-256-GCM nonce||ciphertext) with the
    # master KEK from config. The plaintext data key is never stored. Not under
    # RLS: lookups filter by org_id in code, and background workers (triage,
    # delivery) read it without the per-request org GUC.
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)


# --- mTLS: internal certificate authority (single platform-wide row) ---
class CertAuthority(Base):
    __tablename__ = "cert_authority"

    id: Mapped[str] = mapped_column(String, primary_key=True, default="default")
    cert_pem: Mapped[str] = mapped_column(String)
    key_pem: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_now)
