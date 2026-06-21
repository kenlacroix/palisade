from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import alerting, notify
from ..db import get_db
from ..models import Alert, AlertChannel, AlertRule, Asset, Detection, Finding, Org
from ..tenancy import current_org, require_role
from ..schemas import (
    AlertChannelCreate,
    AlertChannelRow,
    AlertChannelsList,
    AlertRow,
    AlertRuleCreate,
    AlertRuleRow,
    AlertRulesList,
    AlertsList,
    ChannelTestResponse,
)

# Alerting BFF: org-scoped via current_org; mutations require admin.
router = APIRouter(prefix="/v1", tags=["alerts"])


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


def _redact(config: dict[str, Any]) -> dict[str, Any]:
    return {k: ("***" if k in alerting.SECRET_KEYS and v else v) for k, v in config.items()}


def _channel_row(c: AlertChannel) -> AlertChannelRow:
    return AlertChannelRow(
        id=c.id,
        type=c.type,
        name=c.name,
        config=_redact(c.config or {}),
        enabled=c.enabled,
        created_at=_iso(c.created_at),
    )


def _rule_row(r: AlertRule, channel_name: str) -> AlertRuleRow:
    return AlertRuleRow(
        id=r.id,
        name=r.name,
        min_severity=r.min_severity,
        on_events=list(r.on_events or []),
        channel_id=r.channel_id,
        channel_name=channel_name,
        enabled=r.enabled,
        created_at=_iso(r.created_at),
    )


def _get_channel(db: Session, org_id: str, channel_id: str) -> AlertChannel:
    c = db.get(AlertChannel, channel_id)
    if c is None or c.org_id != org_id:
        raise HTTPException(status_code=404, detail="channel not found")
    return c


def _get_rule(db: Session, org_id: str, rule_id: str) -> AlertRule:
    r = db.get(AlertRule, rule_id)
    if r is None or r.org_id != org_id:
        raise HTTPException(status_code=404, detail="rule not found")
    return r


@router.get("/alerts", response_model=AlertsList)
def list_alerts(org: Org = Depends(current_org), db: Session = Depends(get_db)) -> AlertsList:
    alerts = db.execute(
        select(Alert).where(Alert.org_id == org.id).order_by(Alert.created_at.desc())
    ).scalars().all()
    rows: list[AlertRow] = []
    for a in alerts:
        finding = db.get(Finding, a.finding_id)
        asset = db.get(Asset, finding.asset_id) if finding else None
        det = db.get(Detection, finding.detection_id) if finding else None
        channel = db.get(AlertChannel, a.channel_id) if a.channel_id else None
        rows.append(
            AlertRow(
                id=a.id,
                finding_id=a.finding_id,
                title=det.title if det else a.finding_id,
                host=asset.host if asset else "",
                severity=a.severity,
                event=a.event,
                status=a.status,
                error=a.error,
                channel_name=channel.name if channel else None,
                created_at=_iso(a.created_at),
                sent_at=_iso(a.sent_at),
            )
        )
    return AlertsList(alerts=rows)


@router.get("/alert-channels", response_model=AlertChannelsList)
def list_channels(org: Org = Depends(current_org), db: Session = Depends(get_db)) -> AlertChannelsList:
    channels = db.execute(
        select(AlertChannel).where(AlertChannel.org_id == org.id).order_by(AlertChannel.created_at.desc())
    ).scalars().all()
    return AlertChannelsList(channels=[_channel_row(c) for c in channels])


@router.post("/alert-channels", response_model=AlertChannelRow)
def create_channel(
    body: AlertChannelCreate,
    org: Org = Depends(current_org),
    _: str = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> AlertChannelRow:
    c = AlertChannel(
        org_id=org.id,
        type=body.type,
        name=body.name,
        config=body.config,
        enabled=body.enabled,
    )
    db.add(c)
    db.commit()
    return _channel_row(c)


@router.patch("/alert-channels/{channel_id}", response_model=AlertChannelRow)
def update_channel(
    channel_id: str = Path(...),
    body: dict[str, Any] = Body(...),
    org: Org = Depends(current_org),
    _: str = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> AlertChannelRow:
    c = _get_channel(db, org.id, channel_id)
    if "name" in body:
        c.name = body["name"]
    if "enabled" in body:
        c.enabled = bool(body["enabled"])
    if "config" in body and isinstance(body["config"], dict):
        # Merge so omitted secret keys keep their stored value.
        c.config = {**(c.config or {}), **body["config"]}
    db.commit()
    return _channel_row(c)


@router.delete("/alert-channels/{channel_id}", status_code=204)
def delete_channel(
    channel_id: str = Path(...),
    org: Org = Depends(current_org),
    _: str = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> Response:
    c = _get_channel(db, org.id, channel_id)
    # Cascade-delete dependent rules so no rule dangles on a missing channel.
    rules = db.execute(
        select(AlertRule).where(AlertRule.org_id == org.id, AlertRule.channel_id == channel_id)
    ).scalars().all()
    for r in rules:
        db.delete(r)
    db.delete(c)
    db.commit()
    return Response(status_code=204)


@router.post("/alert-channels/{channel_id}/test", response_model=ChannelTestResponse)
def test_channel(
    channel_id: str = Path(...),
    org: Org = Depends(current_org),
    _: str = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> ChannelTestResponse:
    c = _get_channel(db, org.id, channel_id)
    subject, text = notify.render_alert_text(
        title="Palisade test alert",
        severity="info",
        host="palisade.local",
        port=0,
        cve=None,
        event="test",
        evidence_note="This is a synthetic test message.",
    )
    ok, error = notify.dispatch(
        c.type,
        c.config or {},
        subject=subject,
        text=text,
        payload={"test": True, "channel": c.name},
    )
    return ChannelTestResponse(ok=ok, error=error)


@router.get("/alert-rules", response_model=AlertRulesList)
def list_rules(org: Org = Depends(current_org), db: Session = Depends(get_db)) -> AlertRulesList:
    rules = db.execute(
        select(AlertRule).where(AlertRule.org_id == org.id).order_by(AlertRule.created_at.desc())
    ).scalars().all()
    rows: list[AlertRuleRow] = []
    for r in rules:
        channel = db.get(AlertChannel, r.channel_id)
        rows.append(_rule_row(r, channel.name if channel else ""))
    return AlertRulesList(rules=rows)


@router.post("/alert-rules", response_model=AlertRuleRow)
def create_rule(
    body: AlertRuleCreate,
    org: Org = Depends(current_org),
    _: str = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> AlertRuleRow:
    channel = db.get(AlertChannel, body.channel_id)
    if channel is None or channel.org_id != org.id:
        raise HTTPException(status_code=400, detail="channel_id not in this org")
    r = AlertRule(
        org_id=org.id,
        name=body.name,
        min_severity=body.min_severity,
        on_events=body.on_events,
        channel_id=body.channel_id,
        enabled=body.enabled,
    )
    db.add(r)
    db.commit()
    return _rule_row(r, channel.name)


@router.patch("/alert-rules/{rule_id}", response_model=AlertRuleRow)
def update_rule(
    rule_id: str = Path(...),
    body: dict[str, Any] = Body(...),
    org: Org = Depends(current_org),
    _: str = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> AlertRuleRow:
    r = _get_rule(db, org.id, rule_id)
    if "name" in body:
        r.name = body["name"]
    if "min_severity" in body:
        r.min_severity = body["min_severity"]
    if "on_events" in body and isinstance(body["on_events"], list):
        r.on_events = body["on_events"]
    if "enabled" in body:
        r.enabled = bool(body["enabled"])
    if "channel_id" in body:
        channel = db.get(AlertChannel, body["channel_id"])
        if channel is None or channel.org_id != org.id:
            raise HTTPException(status_code=400, detail="channel_id not in this org")
        r.channel_id = body["channel_id"]
    db.commit()
    channel = db.get(AlertChannel, r.channel_id)
    return _rule_row(r, channel.name if channel else "")


@router.delete("/alert-rules/{rule_id}", status_code=204)
def delete_rule(
    rule_id: str = Path(...),
    org: Org = Depends(current_org),
    _: str = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> Response:
    r = _get_rule(db, org.id, rule_id)
    db.delete(r)
    db.commit()
    return Response(status_code=204)
