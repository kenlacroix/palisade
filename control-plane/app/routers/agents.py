from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import require_agent
from .. import mtls
from ..db import get_db
from ..models import Agent, Asset, Detection, EnrollToken, Scan
from ..version_match import service_matches
from ..schemas import (
    AssetsRequest,
    AssetsResponse,
    EnrollRequest,
    EnrollResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    Job,
)

router = APIRouter(prefix="/v1/agents", tags=["agents"])

HEARTBEAT_INTERVAL_S = 30
# If inventory is older than this, re-issue a discover job.
INVENTORY_STALE_S = 3600


def _now() -> datetime:
    return datetime.now(timezone.utc)


@router.post("/enroll", response_model=EnrollResponse)
def enroll(req: EnrollRequest, db: Session = Depends(get_db)) -> EnrollResponse:
    # Enroll tokens are single-use: a token mints exactly one agent and joins it
    # to the token's org. Seeded at bootstrap from PALISADE_ENROLL_TOKENS.
    token = db.get(EnrollToken, req.enroll_token)
    if token is None or token.used_at is not None:
        raise HTTPException(status_code=401, detail="invalid or used enroll token")
    agent = Agent(
        id=str(uuid.uuid4()),
        org_id=token.org_id,
        secret=secrets.token_urlsafe(32),
        hostname=req.host.hostname,
        os=req.host.os,
        arch=req.host.arch,
        version=req.host.agent_version,
        status="idle",
        last_seen=_now(),
    )
    db.add(agent)
    token.used_at = _now()
    token.agent_id = agent.id
    db.commit()

    # Issue an mTLS client cert bound to this agent. Bearer agent_secret is still
    # returned as the dev/plaintext fallback.
    cert = mtls.issue_client_cert(db, agent.id, agent.org_id)
    agent.cert_fingerprint = cert["fingerprint"]
    agent.cert_not_after = cert["not_after"]
    db.commit()

    return EnrollResponse(
        agent_id=agent.id,
        agent_secret=agent.secret,
        heartbeat_interval_s=HEARTBEAT_INTERVAL_S,
        client_cert_pem=cert["client_cert_pem"],
        client_key_pem=cert["client_key_pem"],
        ca_cert_pem=cert["ca_cert_pem"],
    )


def _agent_or_403(agent: Agent, agent_id: str) -> None:
    if agent.id != agent_id:
        raise HTTPException(status_code=403, detail="agent id mismatch")


@router.post("/{agent_id}/heartbeat", response_model=HeartbeatResponse)
def heartbeat(
    req: HeartbeatRequest,
    agent_id: str = Path(...),
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
) -> HeartbeatResponse:
    _agent_or_403(agent, agent_id)
    agent.version = req.agent_version
    agent.status = req.status
    agent.last_seen = _now()

    jobs: list[Job] = []

    assets = db.execute(
        select(Asset).where(Asset.org_id == agent.org_id)
    ).scalars().all()

    inventory_stale = (
        agent.last_discover_at is None
        or (_now() - _ensure_aware(agent.last_discover_at)).total_seconds() > INVENTORY_STALE_S
    )

    if not assets and inventory_stale:
        # No inventory yet -> discover.
        agent.last_discover_at = _now()
        jobs.append(
            Job(
                job_id=str(uuid.uuid4()),
                type="discover",
                payload={"scope": {"subnets": ["10.0.0.0/24", "192.168.1.0/24"]}},
            )
        )
        db.commit()
        return HeartbeatResponse(jobs=jobs)

    # Have assets: issue a scan once per cycle for assets with applicable
    # detections. Guard with last_scan_issued_at to avoid infinite re-issue.
    scan_recent = (
        agent.last_scan_issued_at is not None
        and (_now() - _ensure_aware(agent.last_scan_issued_at)).total_seconds()
        < HEARTBEAT_INTERVAL_S
    )
    if assets and not scan_recent:
        detections = db.execute(select(Detection)).scalars().all()
        targets = []
        for asset in assets:
            det_ids = [
                det.id for det in detections
                if det.match_service == asset.service
                and service_matches(asset.version, det.match_versions)
            ]
            if det_ids:
                targets.append({"asset_id": asset.id, "detection_ids": det_ids})

        if targets:
            scan = Scan(
                id=str(uuid.uuid4()),
                org_id=agent.org_id,
                agent_id=agent.id,
                status="issued",
                assets_count=len(targets),
            )
            db.add(scan)
            agent.last_scan_issued_at = _now()
            jobs.append(
                Job(
                    job_id=str(uuid.uuid4()),
                    type="scan",
                    payload={"scan_id": scan.id, "targets": targets},
                )
            )

    db.commit()
    return HeartbeatResponse(jobs=jobs)


@router.post("/{agent_id}/assets", response_model=AssetsResponse)
def upsert_assets(
    req: AssetsRequest,
    agent_id: str = Path(...),
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
) -> AssetsResponse:
    _agent_or_403(agent, agent_id)
    out: dict[str, str] = {}
    for a in req.assets:
        existing = db.execute(
            select(Asset).where(
                Asset.org_id == agent.org_id,
                Asset.host == a.host,
                Asset.port == a.port,
            )
        ).scalar_one_or_none()
        if existing:
            existing.service = a.service
            existing.product = a.product
            existing.version = a.version
            existing.exposure = a.exposure
            existing.last_seen = _now()
            existing.agent_id = agent.id
            asset = existing
        else:
            asset = Asset(
                id=str(uuid.uuid4()),
                org_id=agent.org_id,
                agent_id=agent.id,
                host=a.host,
                port=a.port,
                service=a.service,
                product=a.product,
                version=a.version,
                exposure=a.exposure,
            )
            db.add(asset)
            db.flush()
        out[f"{a.host}:{a.port}"] = asset.id
    db.commit()
    return AssetsResponse(asset_ids=out)


def _ensure_aware(dt: datetime) -> datetime:
    # SQLite returns naive datetimes; treat stored values as UTC.
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
