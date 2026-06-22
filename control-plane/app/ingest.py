"""Shared findings-ingest core. Both the agent findings endpoint and the
control-plane perimeter scan worker funnel reports through ingest_reports so
fingerprint dedupe, evidence sealing, regression detection, and manifest-based
resolution behave identically regardless of who scanned. The caller owns the
transaction (commit) and any post-commit triage/alert work.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import encryption
from .models import Detection, Finding, Scan


@dataclass
class Report:
    asset_id: str
    detection_id: str
    severity: str  # "" -> default to the detection's severity
    fingerprint: str
    evidence: dict


def _now() -> datetime:
    return datetime.now(timezone.utc)


def ingest_reports(
    db: Session, org_id: str, scan_id: str, reports: list[Report]
) -> tuple[list[str], list[tuple[str, str]]]:
    """Upsert reports, resolve absent findings against the scan manifest, and
    return (new_finding_ids, [(finding_id, event)]) for post-commit triage and
    alerting. Does not commit."""
    reported_keys: set[tuple[str, str]] = set()
    alert_events: list[tuple[str, str]] = []
    new_finding_ids: list[str] = []

    for r in reports:
        reported_keys.add((r.asset_id, r.detection_id))
        det = db.get(Detection, r.detection_id)
        severity = r.severity or (det.severity if det else "info")

        # Dedupe within the org only. A bare fingerprint match would let a
        # report collide with — and overwrite — another tenant's finding that
        # happens to share a fingerprint (now also blocked at the DB by the
        # per-org unique index, migration 0011).
        existing = db.execute(
            select(Finding).where(
                Finding.org_id == org_id, Finding.fingerprint == r.fingerprint
            )
        ).scalar_one_or_none()

        evidence_json, evidence_enc = encryption.seal(db, org_id, r.evidence)
        if existing is None:
            finding = Finding(
                org_id=org_id,
                asset_id=r.asset_id,
                detection_id=r.detection_id,
                scan_id=scan_id,
                severity=severity,
                status="open",
                fingerprint=r.fingerprint,
                evidence=evidence_json,
                evidence_enc=evidence_enc,
            )
            db.add(finding)
            db.flush()  # assign id for triage + alerting
            new_finding_ids.append(finding.id)
            alert_events.append((finding.id, "new"))
        else:
            existing.last_seen = _now()
            existing.scan_id = scan_id
            existing.evidence = evidence_json
            existing.evidence_enc = evidence_enc
            if existing.status == "resolved":
                existing.status = "regressed"
                alert_events.append((existing.id, "regressed"))

    # open -> resolved when a scan that covered the (asset, detection) pair does
    # NOT report it. The scan's stored target manifest makes this precise: only
    # pairs we actually scanned can be resolved; a pair absent from the manifest
    # was not scanned this cycle and is left untouched (not "absent").
    scan = db.get(Scan, scan_id)
    manifest: set[tuple[str, str]] = set()
    if scan is not None:
        for t in scan.targets or []:
            aid = t.get("asset_id")
            for did in t.get("detection_ids") or []:
                manifest.add((aid, did))

    if manifest:
        scanned_assets = {aid for aid, _ in manifest}
        open_findings = db.execute(
            select(Finding).where(
                Finding.asset_id.in_(scanned_assets),
                Finding.status.in_(["open", "regressed"]),
            )
        ).scalars().all()
        for f in open_findings:
            key = (f.asset_id, f.detection_id)
            if key in manifest and key not in reported_keys:
                f.status = "resolved"
                f.last_seen = _now()
    else:
        # Legacy/manifest-less scan: best-effort by asset touched in this batch.
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

    return new_finding_ids, alert_events
