"""Cron-like per-org scheduler (SPEC §177): the Arq worker enqueues per-asset
scan jobs on a per-org cadence, releases quiet-hours deferred alerts promptly,
and captures a daily posture snapshot.

These cron jobs only fire when the Arq worker is running (REDIS_URL set). In the
dev/SQLite/in-process fallback there is no scheduler — that's expected and
mirrors how the durable queue already degrades (see app/queue.py).

RLS correctness: in prod the worker runs as a NON-OWNER Postgres role, so
Row-Level Security clips queries to the org named by the `app.current_org_id`
GUC. The `org` table is NOT RLS-protected, so we enumerate orgs without a GUC.
Each tenant-table unit of work sets the GUC via `_set_rls_org` and `SET LOCAL`
is per-transaction, so we re-set it after every commit (mirrors
tasks.py::triage_findings). `scan_external_assets` is the exception: it manages
its own session + RLS internally, so we only enumerate orgs and invoke it.

Cron bodies are async (arq jobs) and push blocking DB/SDK work into a thread via
asyncio.to_thread; the real sync logic lives in plain helpers so it's importable
and testable.
"""
from __future__ import annotations

import asyncio
import logging

from sqlalchemy import select

from . import alerting, snapshots, tasks
from .db import SessionLocal
from .models import Org
from .tenancy import _set_rls_org

log = logging.getLogger(__name__)


def _org_ids() -> list[str]:
    # The org table is not RLS-protected, so a plain session enumerates all orgs.
    db = SessionLocal()
    try:
        return list(db.execute(select(Org.id)).scalars().all())
    finally:
        db.close()


def run_perimeter_scans() -> None:
    """Per org, run a control-plane external scan. scan_external_assets manages
    its own session + RLS + triage + delivery, so we just enumerate and invoke."""
    for org_id in _org_ids():
        try:
            tasks.scan_external_assets(org_id)
        except Exception:
            log.exception("scheduled perimeter scan failed for org %s", org_id)


def run_deferred_release() -> None:
    """Per org, flip due deferred alerts back to pending and deliver them, so a
    quiet-hours alert goes out promptly after its window closes."""
    for org_id in _org_ids():
        db = SessionLocal()
        try:
            _set_rls_org(db, org_id)
            alert_ids = alerting.release_due_deferred(db, org_id)
            db.commit()
            if alert_ids:
                # deliver_pending opens its own session + sets RLS itself.
                alerting.deliver_pending(org_id, alert_ids)
        except Exception:
            db.rollback()
            log.exception("scheduled deferred-release failed for org %s", org_id)
        finally:
            db.close()


def run_daily_snapshots() -> None:
    """Per org, capture today's posture snapshot (idempotent within a UTC day)."""
    for org_id in _org_ids():
        db = SessionLocal()
        try:
            _set_rls_org(db, org_id)
            snapshots.capture_snapshot(db, org_id)  # commits internally
        except Exception:
            db.rollback()
            log.exception("scheduled posture snapshot failed for org %s", org_id)
        finally:
            db.close()


async def perimeter_scan_cron(ctx) -> None:
    await asyncio.to_thread(run_perimeter_scans)


async def deferred_release_cron(ctx) -> None:
    await asyncio.to_thread(run_deferred_release)


async def daily_snapshot_cron(ctx) -> None:
    await asyncio.to_thread(run_daily_snapshots)


if __name__ == "__main__":
    # Self-check: helpers enumerate orgs and set RLS per org without a worker.
    logging.basicConfig(level=logging.INFO)
    ids = _org_ids()
    log.info("scheduler self-check: %d org(s) enumerated", len(ids))
    run_deferred_release()
    run_daily_snapshots()
    run_perimeter_scans()
    log.info("scheduler self-check: helpers ran without raising")
