"""Background work bodies, transport-agnostic. Each opens its own session and
never raises, so it runs identically under an Arq worker (REDIS_URL set) or an
in-process FastAPI BackgroundTask (the fallback). See queue.enqueue."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from . import alerting, config, encryption, perimeter
from .db import SessionLocal
from .fingerprint import finding_fingerprint
from .ingest import Report, ingest_reports
from .models import Asset, Detection, Finding, Scan
from .tenancy import _set_rls_org
from .triage import triage_finding
from .version_match import service_matches

log = logging.getLogger(__name__)


def triage_findings(finding_ids: list[str]) -> None:
    """AI-triage newly opened findings off the request path. No-op without a key."""
    db = SessionLocal()
    try:
        for fid in finding_ids:
            try:
                f = db.get(Finding, fid)
                if f is None:
                    continue
                det = db.get(Detection, f.detection_id)
                asset = db.get(Asset, f.asset_id)
                evidence = encryption.open_evidence(db, f)
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


def scan_external_assets(org_id: str) -> None:
    """Control-plane perimeter scan: probe the org's external-exposure assets
    from the control plane and ingest findings through the shared pipeline.
    Background-safe: own session, never raises out. Module-engine detections are
    skipped (their compiled logic lives in the agent)."""
    new_ids: list[str] = []
    alert_ids: list[str] = []
    db = SessionLocal()
    try:
        _set_rls_org(db, org_id)
        assets = db.execute(
            select(Asset).where(Asset.org_id == org_id, Asset.exposure == "external")
        ).scalars().all()
        if not assets:
            return
        detections = db.execute(select(Detection)).scalars().all()

        targets: list[dict] = []
        reports: list[Report] = []
        for asset in assets:
            base = perimeter.base_url(asset.host, asset.port)
            det_ids: list[str] = []
            for det in detections:
                if det.engine != "nuclei":
                    continue
                if det.match_service != asset.service:
                    continue
                if not service_matches(asset.version, det.match_versions):
                    continue
                det_ids.append(det.id)
                spec = det.spec if isinstance(det.spec, dict) else {}
                hit = perimeter.run_detection(base, spec)
                if hit is not None:
                    evidence, key = hit
                    fp = finding_fingerprint(asset.id, det.id, key)
                    reports.append(Report(asset.id, det.id, det.severity, fp, evidence))
            if det_ids:
                targets.append({"asset_id": asset.id, "detection_ids": det_ids})

        scan = Scan(
            id=str(uuid.uuid4()),
            org_id=org_id,
            agent_id=None,  # control-plane origin
            status="finished",
            finished_at=datetime.now(timezone.utc),
            assets_count=len(targets),
            targets=targets,
        )
        db.add(scan)
        db.flush()
        new_ids, alert_events = ingest_reports(db, org_id, scan.id, reports)

        for fid, event in alert_events:
            f = db.get(Finding, fid)
            if f is not None:
                alert_ids.extend(alerting.evaluate_and_enqueue(db, org_id, f, event))
        alert_ids.extend(alerting.release_due_deferred(db, org_id))
        db.commit()
    except Exception:
        db.rollback()
        log.exception("perimeter scan failed for org %s", org_id)
        return
    finally:
        db.close()

    # triage + delivery open their own sessions; run inline (already background).
    if config.ANTHROPIC_API_KEY and new_ids:
        triage_findings(new_ids)
    if alert_ids:
        alerting.deliver_pending(alert_ids)
