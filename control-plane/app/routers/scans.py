from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, Path, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import alerting, config
from ..auth import require_agent
from ..db import SessionLocal, get_db
from ..models import Agent, Asset, Detection, Finding
from ..schemas import FindingsRequest
from ..triage import triage_finding

router = APIRouter(prefix="/v1/scans", tags=["scans"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _triage_findings(finding_ids: list[str]) -> None:
    """Background AI triage off the request path. Own session; never raises."""
    db = SessionLocal()
    try:
        for fid in finding_ids:
            try:
                f = db.get(Finding, fid)
                if f is None:
                    continue
                det = db.get(Detection, f.detection_id)
                asset = db.get(Asset, f.asset_id)
                evidence = f.evidence if isinstance(f.evidence, dict) else {}
                result = triage_finding(
                    title=det.title if det else f.detection_id,
                    severity=f.severity,
                    cve=det.cve if det else None,
                    cvss=det.cvss if det else None,
                    host=asset.host if asset else "",
                    service=asset.service if asset else "",
                    evidence_note=str(evidence.get("note", "")),
                )
                if result:
                    f.triage_priority = result["triage_priority"]
                    f.triage_score = result["triage_score"]
                    f.triage_rationale = result["triage_rationale"]
                    db.commit()
            except Exception:
                db.rollback()
    finally:
        db.close()


@router.post("/{scan_id}/findings", status_code=202)
def ingest_findings(
    req: FindingsRequest,
    background: BackgroundTasks,
    scan_id: str = Path(...),
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
) -> Response:
    reported_keys: set[tuple[str, str]] = set()
    # (finding_id, event) pairs to evaluate against alert rules after commit.
    alert_events: list[tuple[str, str]] = []
    new_finding_ids: list[str] = []

    for fr in req.findings:
        reported_keys.add((fr.asset_id, fr.detection_id))
        det = db.get(Detection, fr.detection_id)
        severity = fr.severity or (det.severity if det else "info")

        existing = db.execute(
            select(Finding).where(Finding.fingerprint == fr.fingerprint)
        ).scalar_one_or_none()

        if existing is None:
            # Unseen fingerprint -> open. AI triage is offloaded post-commit.
            finding = Finding(
                org_id=agent.org_id,
                asset_id=fr.asset_id,
                detection_id=fr.detection_id,
                scan_id=scan_id,
                severity=severity,
                status="open",
                fingerprint=fr.fingerprint,
                evidence=fr.evidence.model_dump(),
            )
            db.add(finding)
            db.flush()  # assign id for triage + alerting
            new_finding_ids.append(finding.id)
            alert_events.append((finding.id, "new"))
        else:
            # Seen and still reported -> bump last_seen.
            existing.last_seen = _now()
            existing.scan_id = scan_id
            existing.evidence = fr.evidence.model_dump()
            if existing.status == "resolved":
                # resolved -> regressed on reappearance.
                existing.status = "regressed"
                alert_events.append((existing.id, "regressed"))

    # open -> resolved when a later scan of the same asset+detection does NOT
    # report it. Best effort: scope to assets touched in this scan's targets.
    # TODO(prod): track scan target manifest to resolve precisely; here we
    #             resolve open findings for (asset,detection) pairs that share
    #             an asset reported in this batch but were not re-reported.
    touched_assets = {asset_id for asset_id, _ in reported_keys}
    if touched_assets:
        open_findings = db.execute(
            select(Finding).where(
                Finding.asset_id.in_(touched_assets),
                Finding.status.in_(["open", "regressed"]),
            )
        ).scalars().all()
        for f in open_findings:
            if (f.asset_id, f.detection_id) not in reported_keys:
                f.status = "resolved"
                f.last_seen = _now()

    db.commit()

    # Offload AI triage so it never blocks the request. No-op without a key.
    if config.ANTHROPIC_API_KEY and new_finding_ids:
        background.add_task(_triage_findings, new_finding_ids)

    # Evaluate alert rules and enqueue, then deliver in the background.
    alert_ids: list[str] = []
    for fid, event in alert_events:
        f = db.get(Finding, fid)
        if f is None:
            continue
        alert_ids.extend(alerting.evaluate_and_enqueue(db, agent.org_id, f, event))
    if alert_ids:
        db.commit()
        background.add_task(alerting.deliver_pending, alert_ids)

    return Response(status_code=202)
