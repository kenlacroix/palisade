"""Audit trail: one row per privileged action (SPEC section 6 / 11).

`record` stages an AuditLog row on the caller's session without committing, so
the entry lands in the same transaction as the action it describes — either
both persist or neither does.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from .models import AuditLog


def record(db: Session, *, org_id: str, actor: str, action: str, target: str | None = None) -> None:
    db.add(AuditLog(org_id=org_id, actor=actor, action=action, target=target))
