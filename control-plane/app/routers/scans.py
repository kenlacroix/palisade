from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, Path, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import alerting, config, encryption, queue
from ..auth import require_agent
from ..db import get_db
from ..models import Agent, Detection, Finding
from ..schemas import FindingsRequest
from ..tasks import triage_findings

router = APIRouter(prefix="/v1/scans", tags=["scans"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


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

        evidence_json, evidence_enc = encryption.seal(
            db, agent.org_id, fr.evidence.model_dump()
        )
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
                evidence=evidence_json,
                evidence_enc=evidence_enc,
            )
            db.add(finding)
            db.flush()  # assign id for triage + alerting
            new_finding_ids.append(finding.id)
            alert_events.append((finding.id, "new"))
        else:
            # Seen and still reported -> bump last_seen.
            existing.last_seen = _now()
            existing.scan_id = scan_id
            existing.evidence = evidence_json
            existing.evidence_enc = evidence_enc
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
        queue.enqueue(background, "triage_findings", triage_findings, new_finding_ids)

    # Evaluate alert rules and enqueue, then deliver in the background.
    alert_ids: list[str] = []
    for fid, event in alert_events:
        f = db.get(Finding, fid)
        if f is None:
            continue
        alert_ids.extend(alerting.evaluate_and_enqueue(db, agent.org_id, f, event))
    if alert_ids:
        db.commit()
        queue.enqueue(background, "deliver_alerts", alerting.deliver_pending, alert_ids)

    return Response(status_code=202)
