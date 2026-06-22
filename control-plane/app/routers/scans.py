from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Path, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import alerting, config, queue
from ..auth import require_agent
from ..db import get_db
from ..ingest import Report, ingest_reports
from ..models import Agent, Asset, Finding, Org, Scan
from ..schemas import ExternalScanResponse, FindingsRequest
from ..tasks import scan_external_assets, triage_findings
from ..tenancy import _set_rls_org, current_org, require_role

router = APIRouter(prefix="/v1/scans", tags=["scans"])


@router.post("/external", response_model=ExternalScanResponse)
def trigger_external_scan(
    background: BackgroundTasks,
    org: Org = Depends(current_org),
    _: str = Depends(require_role("member")),
    db: Session = Depends(get_db),
) -> ExternalScanResponse:
    """Kick a control-plane perimeter scan of the org's external-exposure assets
    (attacker's-eye view). Durably enqueued; runs in the worker (or inline
    without Redis). Returns immediately."""
    n = db.execute(
        select(func.count())
        .select_from(Asset)
        .where(Asset.org_id == org.id, Asset.exposure == "external")
    ).scalar_one()
    queue.enqueue(background, "scan_external_assets", scan_external_assets, org.id)
    return ExternalScanResponse(enqueued=True, external_assets=n)


@router.post("/{scan_id}/findings", status_code=202)
def ingest_findings(
    req: FindingsRequest,
    background: BackgroundTasks,
    scan_id: str = Path(...),
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
) -> Response:
    # The agent only authenticates itself; the scan_id and asset_ids in the body
    # are attacker-controllable. Bind both to the agent's org so a compromised
    # agent can't attach findings to another tenant's scan or assets. (RLS backs
    # this on Postgres; the explicit checks also cover the SQLite path.)
    scan = db.get(Scan, scan_id)
    if scan is None or scan.org_id != agent.org_id:
        raise HTTPException(status_code=404, detail="scan not found")
    asset_ids = {fr.asset_id for fr in req.findings}
    if asset_ids:
        owned = set(
            db.execute(
                select(Asset.id).where(
                    Asset.org_id == agent.org_id, Asset.id.in_(asset_ids)
                )
            ).scalars().all()
        )
        if asset_ids - owned:
            raise HTTPException(status_code=400, detail="unknown asset for this org")

    reports = [
        Report(
            asset_id=fr.asset_id,
            detection_id=fr.detection_id,
            severity=fr.severity,
            fingerprint=fr.fingerprint,
            evidence=fr.evidence.model_dump(),
        )
        for fr in req.findings
    ]
    new_finding_ids, alert_events = ingest_reports(db, agent.org_id, scan_id, reports)
    db.commit()
    # commit() ended the transaction, dropping the SET LOCAL ROLE + org GUC set
    # by require_agent. Re-scope before the post-commit alert writes below, which
    # INSERT into the RLS-protected alert table.
    _set_rls_org(db, agent.org_id)

    # Offload AI triage so it never blocks the request. No-op without a key.
    if config.ANTHROPIC_API_KEY and new_finding_ids:
        queue.enqueue(background, "triage_findings", triage_findings, agent.org_id, new_finding_ids)

    # Evaluate alert rules and enqueue, then deliver in the background.
    alert_ids: list[str] = []
    for fid, event in alert_events:
        f = db.get(Finding, fid)
        if f is None:
            continue
        alert_ids.extend(alerting.evaluate_and_enqueue(db, agent.org_id, f, event))
    # Release any deferred alerts whose quiet window has since closed.
    alert_ids.extend(alerting.release_due_deferred(db, agent.org_id))
    if alert_ids:
        db.commit()
        queue.enqueue(background, "deliver_alerts", alerting.deliver_pending, agent.org_id, alert_ids)

    return Response(status_code=202)
