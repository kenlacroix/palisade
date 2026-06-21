"""DB-aware alert evaluation and delivery. evaluate_and_enqueue runs inside the
ingest request's transaction (caller commits); deliver_pending runs in a
BackgroundTask with its own session so network I/O never touches the request.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import encryption, notify
from .db import SessionLocal
from .models import Alert, AlertChannel, AlertRule, Asset, Detection, Finding

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
# Keys whose values are secrets; the router redacts these on read.
SECRET_KEYS = {"bot_token", "password", "username"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def evaluate_and_enqueue(db: Session, org_id: str, finding: Finding, event: str) -> list[str]:
    """Create a pending Alert per matching enabled rule. Caller commits."""
    rules = db.execute(
        select(AlertRule).where(AlertRule.org_id == org_id, AlertRule.enabled == True)  # noqa: E712
    ).scalars().all()

    finding_rank = SEVERITY_RANK.get(finding.severity, 0)
    new_ids: list[str] = []
    for rule in rules:
        if event not in (rule.on_events or []):
            continue
        if finding_rank < SEVERITY_RANK.get(rule.min_severity, 0):
            continue
        alert = Alert(
            org_id=org_id,
            finding_id=finding.id,
            rule_id=rule.id,
            channel_id=rule.channel_id,
            event=event,
            severity=finding.severity,
            status="pending",
        )
        db.add(alert)
        db.flush()  # assign id
        new_ids.append(alert.id)
    return new_ids


def deliver_pending(alert_ids: list[str]) -> None:
    """Background-safe delivery: own session, one dispatch per alert."""
    if not alert_ids:
        return
    db = SessionLocal()
    try:
        for alert_id in alert_ids:
            alert = db.get(Alert, alert_id)
            if alert is None:
                continue
            channel = db.get(AlertChannel, alert.channel_id) if alert.channel_id else None
            if channel is None or not channel.enabled:
                alert.status = "failed"
                alert.error = "channel missing or disabled"
                continue

            finding = db.get(Finding, alert.finding_id)
            asset = db.get(Asset, finding.asset_id) if finding else None
            det = db.get(Detection, finding.detection_id) if finding else None

            title = det.title if det else (finding.detection_id if finding else alert.finding_id)
            evidence = encryption.open_evidence(db, finding) if finding else {}
            subject, text = notify.render_alert_text(
                title=title,
                severity=alert.severity,
                host=asset.host if asset else "",
                port=asset.port if asset else 0,
                cve=det.cve if det else None,
                event=alert.event,
                evidence_note=str(evidence.get("note", "")),
            )
            payload = {
                "title": title,
                "severity": alert.severity,
                "event": alert.event,
                "host": asset.host if asset else "",
                "port": asset.port if asset else 0,
                "cve": det.cve if det else None,
                "finding_id": alert.finding_id,
            }
            ok, error = notify.dispatch(
                channel.type, channel.config or {}, subject=subject, text=text, payload=payload
            )
            alert.status = "sent" if ok else "failed"
            alert.error = error
            alert.sent_at = _now() if ok else None
        db.commit()
    finally:
        db.close()
