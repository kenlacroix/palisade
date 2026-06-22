from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .. import audit, encryption, snapshots
from ..db import get_db
from ..models import Agent, Asset, AuditLog, Detection, Finding, Org, User
from ..tenancy import current_org, current_user, require_role
from ..schemas import (
    AgentRow,
    AgentsList,
    AssetRow,
    AssetsList,
    AuditEntryRow,
    AuditLogList,
    DetectionRow,
    DetectionsList,
    FindingRow,
    FindingsList,
    MuteRequest,
    PostureCounts,
    PostureSummary,
    RescanResponse,
)

# UI BFF read APIs: authenticated with a user session bearer, scoped to the
# session's active org (current_org).
router = APIRouter(prefix="/v1", tags=["read"])

SEVERITY_WEIGHTS = {"critical": 20, "high": 10, "medium": 4, "low": 1, "info": 0}
ACTIVE_STATUSES = ("open", "regressed")
# An agent is "online" if it heartbeat within ~3 intervals (heartbeat is 30s).
ONLINE_WINDOW_S = 90


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


def _finding_row(db: Session, f: Finding) -> FindingRow:
    asset = db.get(Asset, f.asset_id)
    det = db.get(Detection, f.detection_id)
    spec = det.spec if det and isinstance(det.spec, dict) else {}
    return FindingRow(
        id=f.id,
        detection_id=f.detection_id,
        asset_id=f.asset_id,
        host=asset.host if asset else "",
        port=asset.port if asset else 0,
        title=det.title if det else f.detection_id,
        cve=det.cve if det else None,
        severity=f.severity,
        status=f.status,
        fingerprint=f.fingerprint,
        evidence=encryption.open_evidence(db, f),
        remediation=spec.get("remediation") or None,
        references=list(spec.get("references") or []),
        first_seen=_iso(f.first_seen),
        last_seen=_iso(f.last_seen),
        triage_priority=f.triage_priority,
        triage_score=f.triage_score,
        triage_rationale=f.triage_rationale,
    )


@router.get("/assets", response_model=AssetsList)
def list_assets(
    org: Org = Depends(current_org), db: Session = Depends(get_db)
) -> AssetsList:
    assets = db.execute(select(Asset).where(Asset.org_id == org.id)).scalars().all()
    rows: list[AssetRow] = []
    for a in assets:
        findings = db.execute(
            select(Finding).where(Finding.asset_id == a.id)
        ).scalars().all()
        crit = sum(1 for f in findings if f.severity == "critical" and f.status in ACTIVE_STATUSES)
        high = sum(1 for f in findings if f.severity == "high" and f.status in ACTIVE_STATUSES)
        open_count = sum(1 for f in findings if f.status in ACTIVE_STATUSES)
        rows.append(
            AssetRow(
                id=a.id,
                host=a.host,
                port=a.port,
                service=a.service,
                product=a.product,
                version=a.version,
                exposure=a.exposure,
                scheme=a.scheme,
                findings_critical=crit,
                findings_high=high,
                findings_open=open_count,
                last_seen=_iso(a.last_seen),
            )
        )
    return AssetsList(assets=rows)


@router.get("/findings", response_model=FindingsList)
def list_findings(
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    org: Org = Depends(current_org),
    db: Session = Depends(get_db),
) -> FindingsList:
    stmt = select(Finding).where(Finding.org_id == org.id)
    if status:
        stmt = stmt.where(Finding.status == status)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    findings = db.execute(stmt).scalars().all()

    rows = [_finding_row(db, f) for f in findings]
    return FindingsList(findings=rows)


@router.post("/findings/{finding_id}/mute", response_model=FindingRow)
def mute_finding(
    body: MuteRequest,
    finding_id: str = Path(...),
    org: Org = Depends(current_org),
    user: User = Depends(current_user),
    _: str = Depends(require_role("member")),
    db: Session = Depends(get_db),
) -> FindingRow:
    f = db.get(Finding, finding_id)
    if f is None or f.org_id != org.id:
        raise HTTPException(status_code=404, detail="finding not found")
    f.status = "muted"
    f.mute_reason = body.reason
    f.mute_until = datetime.now(timezone.utc) + timedelta(seconds=body.ttl_s)
    audit.record(db, org_id=org.id, actor=user.email, action="finding.mute", target=finding_id)
    db.commit()
    return _finding_row(db, f)


@router.post("/rescan", response_model=RescanResponse)
def rescan(
    org: Org = Depends(current_org),
    _: str = Depends(require_role("member")),
    db: Session = Depends(get_db),
) -> RescanResponse:
    # UI-initiated rescan: clear each agent's per-cycle guards so the next
    # heartbeat re-issues discover/scan jobs. Agents pull on their own cadence,
    # so this is a nudge, not an immediate scan.
    agents = db.execute(
        select(Agent).where(Agent.org_id == org.id)
    ).scalars().all()
    for a in agents:
        a.last_scan_issued_at = None
        a.last_discover_at = None
    db.commit()
    return RescanResponse(agents_nudged=len(agents))


@router.get("/posture/summary", response_model=PostureSummary)
def posture_summary(
    org: Org = Depends(current_org), db: Session = Depends(get_db)
) -> PostureSummary:
    findings = db.execute(
        select(Finding).where(
            Finding.org_id == org.id,
            Finding.status.in_(ACTIVE_STATUSES),
        )
    ).scalars().all()

    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    med = sum(1 for f in findings if f.severity == "medium")
    assets_count = db.execute(
        select(func.count()).select_from(Asset).where(Asset.org_id == org.id)
    ).scalar_one()

    penalty = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    score = max(0, min(100, 100 - penalty))

    snapshots.capture_snapshot(db, org.id)
    trend = snapshots.trend30d(db, org.id, score)

    return PostureSummary(
        score=score,
        counts=PostureCounts(critical=crit, high=high, medium=med, assets=assets_count),
        trend30d=trend,
    )


@router.get("/detections", response_model=DetectionsList)
def list_detections(
    org: Org = Depends(current_org), db: Session = Depends(get_db)
) -> DetectionsList:
    # Detections are a global catalog (not org-scoped); login is still required.
    detections = db.execute(select(Detection)).scalars().all()

    # tenants_total / tenants_hit are platform-wide metrics. On Postgres, RLS
    # (migration 0003) clips `org`/`finding` to the caller's org, so the inline
    # aggregate would only ever see the current org. The SECURITY DEFINER
    # functions from 0004 run as the migration owner and bypass RLS to see all
    # tenants. SQLite has no RLS, so it keeps the plain inline aggregate.
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        tenants_total = db.execute(text("SELECT palisade_org_count()")).scalar_one()
        hit_rows = db.execute(
            text("SELECT detection_id, n_orgs FROM palisade_detection_tenant_hits()")
        ).all()
    else:
        tenants_total = db.execute(select(func.count()).select_from(Org)).scalar_one()
        # tenants_hit: distinct orgs with an active finding for each detection.
        hit_rows = db.execute(
            select(Finding.detection_id, func.count(func.distinct(Finding.org_id)))
            .where(Finding.status.in_(ACTIVE_STATUSES))
            .group_by(Finding.detection_id)
        ).all()
    hits = {det_id: n for det_id, n in hit_rows}

    rows = [
        DetectionRow(
            slug=d.id,
            title=d.title,
            severity=d.severity,
            category=d.category,
            tenants_hit=hits.get(d.id, 0),
            tenants_total=tenants_total,
            version=d.version,
            cvss=d.cvss,
        )
        for d in detections
    ]
    return DetectionsList(detections=rows)


@router.get("/agents", response_model=AgentsList)
def list_agents(
    org: Org = Depends(current_org), db: Session = Depends(get_db)
) -> AgentsList:
    agents = db.execute(
        select(Agent).where(Agent.org_id == org.id)
    ).scalars().all()
    now = datetime.now(timezone.utc)
    rows: list[AgentRow] = []
    for a in agents:
        last = None if a.last_seen is None else (
            a.last_seen if a.last_seen.tzinfo else a.last_seen.replace(tzinfo=timezone.utc)
        )
        online = last is not None and (now - last).total_seconds() <= ONLINE_WINDOW_S
        rows.append(
            AgentRow(
                id=a.id,
                name=a.hostname or a.id[:8],
                status=a.status,
                online=online,
                last_seen=_iso(a.last_seen),
            )
        )
    return AgentsList(agents=rows)


@router.get("/audit", response_model=AuditLogList)
def list_audit(
    limit: int = Query(default=100, ge=1, le=500),
    org: Org = Depends(current_org),
    _: str = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> AuditLogList:
    # Admin-only view of the org's privileged-action trail, newest first. RLS
    # (migration 0010) also clips this to current_org on Postgres.
    entries = db.execute(
        select(AuditLog)
        .where(AuditLog.org_id == org.id)
        .order_by(AuditLog.at.desc())
        .limit(limit)
    ).scalars().all()
    return AuditLogList(
        entries=[
            AuditEntryRow(id=e.id, actor=e.actor, action=e.action, target=e.target, at=_iso(e.at))
            for e in entries
        ]
    )
