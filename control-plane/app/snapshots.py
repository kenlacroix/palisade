from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Asset, Finding, PostureSnapshot

# Mirror of read.py's scoring so snapshots and live posture agree.
SEVERITY_WEIGHTS = {"critical": 20, "high": 10, "medium": 4, "low": 1, "info": 0}
ACTIVE_STATUSES = ("open", "regressed")


def _score(penalty: int) -> int:
    return max(0, min(100, 100 - penalty))


def _today() -> str:
    return datetime.now(UTC).date().isoformat()


def capture_snapshot(db: Session, org_id: str) -> PostureSnapshot:
    """Upsert today's (UTC) PostureSnapshot for an org from live active findings.

    Idempotent within a day: re-running overwrites the same (org_id, day) row.
    Commits internally; callers need not commit on its behalf.
    """
    findings = (
        db.execute(
            select(Finding).where(
                Finding.org_id == org_id,
                Finding.status.in_(ACTIVE_STATUSES),
            )
        )
        .scalars()
        .all()
    )

    crit = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    med = sum(1 for f in findings if f.severity == "medium")
    assets_count = db.execute(select(Asset).where(Asset.org_id == org_id)).scalars().all()
    assets_n = len(assets_count)
    score = _score(sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings))

    day = _today()
    snap = db.execute(
        select(PostureSnapshot).where(
            PostureSnapshot.org_id == org_id,
            PostureSnapshot.day == day,
        )
    ).scalar_one_or_none()
    if snap is None:
        snap = PostureSnapshot(org_id=org_id, day=day)
        db.add(snap)
    snap.captured_at = datetime.now(UTC)
    snap.score = score
    snap.critical = crit
    snap.high = high
    snap.medium = med
    snap.assets_count = assets_n
    db.commit()
    return snap


def _day_score(db: Session, org_id: str, d: date) -> int:
    """Reconstruct a score for a past day with no snapshot, from finding history.

    A finding counts as active on day D if it first appeared on/before D and was
    still open through D (either currently active or last seen on/after D).
    """
    findings = db.execute(select(Finding).where(Finding.org_id == org_id)).scalars().all()
    penalty = 0
    for f in findings:
        first = (f.first_seen or datetime.now(UTC)).date()
        last = (f.last_seen or f.first_seen or datetime.now(UTC)).date()
        if first <= d and (f.status in ACTIVE_STATUSES or last >= d):
            penalty += SEVERITY_WEIGHTS.get(f.severity, 0)
    return _score(penalty)


def trend30d(db: Session, org_id: str, today_score: int) -> list[int]:
    """30-element score series, oldest (day-29) .. newest (today).

    Prefers a stored PostureSnapshot per day; reconstructs from finding history
    for days predating this feature. Today reflects the live score.
    """
    today = datetime.now(UTC).date()
    snaps = (
        db.execute(select(PostureSnapshot).where(PostureSnapshot.org_id == org_id)).scalars().all()
    )
    by_day = {s.day: s.score for s in snaps}

    trend: list[int] = []
    for i in range(30):
        d = today - timedelta(days=29 - i)
        if d == today:
            trend.append(today_score)
        elif d.isoformat() in by_day:
            trend.append(by_day[d.isoformat()])
        else:
            trend.append(_day_score(db, org_id, d))
    return trend
