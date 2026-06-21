"""Background work bodies, transport-agnostic. Each opens its own session and
never raises, so it runs identically under an Arq worker (REDIS_URL set) or an
in-process FastAPI BackgroundTask (the fallback). See queue.enqueue."""
from __future__ import annotations

from . import encryption
from .db import SessionLocal
from .models import Asset, Detection, Finding
from .triage import triage_finding


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
