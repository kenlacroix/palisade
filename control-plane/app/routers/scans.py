from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Path, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from ..auth import require_agent
from ..db import get_db
from ..models import Agent, Asset, Detection, Finding
from ..schemas import FindingsRequest
from ..triage import triage_finding

router = APIRouter(prefix="/v1/scans", tags=["scans"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


@router.post("/{scan_id}/findings", status_code=202)
def ingest_findings(
    req: FindingsRequest,
    scan_id: str = Path(...),
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
) -> Response:
    reported_keys: set[tuple[str, str]] = set()

    for fr in req.findings:
        reported_keys.add((fr.asset_id, fr.detection_id))
        det = db.get(Detection, fr.detection_id)
        severity = fr.severity or (det.severity if det else "info")

        existing = db.execute(
            select(Finding).where(Finding.fingerprint == fr.fingerprint)
        ).scalar_one_or_none()

        if existing is None:
            # Unseen fingerprint -> open.
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
            # Best-effort inline AI triage. Never blocks or raises the request.
            # TODO(prod): offload to a queue/worker instead of inline.
            if config.ANTHROPIC_API_KEY:
                try:
                    asset = db.get(Asset, fr.asset_id)
                    result = triage_finding(
                        title=det.title if det else fr.detection_id,
                        severity=severity,
                        cve=det.cve if det else None,
                        cvss=det.cvss if det else None,
                        host=asset.host if asset else "",
                        service=asset.service if asset else "",
                        evidence_note=fr.evidence.note,
                    )
                    if result:
                        finding.triage_priority = result["triage_priority"]
                        finding.triage_score = result["triage_score"]
                        finding.triage_rationale = result["triage_rationale"]
                except Exception:
                    pass
            db.add(finding)
        else:
            # Seen and still reported -> bump last_seen.
            existing.last_seen = _now()
            existing.scan_id = scan_id
            existing.evidence = fr.evidence.model_dump()
            if existing.status == "resolved":
                # resolved -> regressed on reappearance.
                existing.status = "regressed"

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
    return Response(status_code=202)
