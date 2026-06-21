"""DB-aware alert evaluation and delivery. evaluate_and_enqueue runs inside the
ingest request's transaction (caller commits); deliver_pending runs in a
BackgroundTask with its own session so network I/O never touches the request.
"""
from __future__ import annotations

import zoneinfo
from datetime import datetime, time, timedelta, timezone

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


def _parse_hhmm(s: str | None) -> time | None:
    if not s:
        return None
    try:
        h, m = s.split(":")
        return time(int(h), int(m))
    except (ValueError, AttributeError):
        return None


def _quiet_window(rule: AlertRule) -> tuple[time, time, zoneinfo.ZoneInfo] | None:
    start = _parse_hhmm(rule.quiet_hours_start)
    end = _parse_hhmm(rule.quiet_hours_end)
    if start is None or end is None or start == end:
        return None
    try:
        tz = zoneinfo.ZoneInfo(rule.quiet_hours_tz or "UTC")
    except Exception:
        tz = zoneinfo.ZoneInfo("UTC")
    return start, end, tz


def in_quiet_hours(rule: AlertRule, now_utc: datetime) -> bool:
    win = _quiet_window(rule)
    if win is None:
        return False
    start, end, tz = win
    lt = now_utc.astimezone(tz).time()
    if start < end:
        return start <= lt < end
    return lt >= start or lt < end  # wraps past midnight


def quiet_end_utc(rule: AlertRule, now_utc: datetime) -> datetime | None:
    """The next moment the rule's quiet window ends, as a UTC datetime."""
    win = _quiet_window(rule)
    if win is None:
        return None
    start, end, tz = win
    local = now_utc.astimezone(tz)
    end_today = local.replace(hour=end.hour, minute=end.minute, second=0, microsecond=0)
    if start < end:
        cand = end_today  # same-day window; end is later today
    elif local.time() < end:
        cand = end_today  # overnight window, early-morning tail ends today
    else:
        cand = end_today + timedelta(days=1)  # evening; ends tomorrow morning
    return cand.astimezone(timezone.utc)


def evaluate_and_enqueue(db: Session, org_id: str, finding: Finding, event: str) -> list[str]:
    """Create an Alert per matching enabled rule and return the ids to deliver
    now. Rules in quiet hours record an alert but withhold delivery: "suppress"
    drops it (status=suppressed); "defer" holds it (status=deferred) until
    release_due_deferred picks it up after the window ends. Caller commits."""
    rules = db.execute(
        select(AlertRule).where(AlertRule.org_id == org_id, AlertRule.enabled == True)  # noqa: E712
    ).scalars().all()

    finding_rank = SEVERITY_RANK.get(finding.severity, 0)
    now = _now()
    new_ids: list[str] = []
    for rule in rules:
        if event not in (rule.on_events or []):
            continue
        if finding_rank < SEVERITY_RANK.get(rule.min_severity, 0):
            continue

        status, deferred_until = "pending", None
        if in_quiet_hours(rule, now):
            if rule.quiet_hours_mode == "suppress":
                status = "suppressed"
            else:
                status, deferred_until = "deferred", quiet_end_utc(rule, now)

        alert = Alert(
            org_id=org_id,
            finding_id=finding.id,
            rule_id=rule.id,
            channel_id=rule.channel_id,
            event=event,
            severity=finding.severity,
            status=status,
            deferred_until=deferred_until,
        )
        db.add(alert)
        db.flush()  # assign id
        if status == "pending":
            new_ids.append(alert.id)
    return new_ids


def release_due_deferred(db: Session, org_id: str) -> list[str]:
    """Flip deferred alerts whose window has ended back to pending and return
    their ids for delivery. Runs on each ingest/scan cycle, so deferred alerts
    go out on the first cycle after their quiet window closes. Caller commits."""
    now = _now()
    rows = db.execute(
        select(Alert).where(
            Alert.org_id == org_id,
            Alert.status == "deferred",
            Alert.deferred_until <= now,
        )
    ).scalars().all()
    ids: list[str] = []
    for a in rows:
        a.status = "pending"
        ids.append(a.id)
    return ids


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
