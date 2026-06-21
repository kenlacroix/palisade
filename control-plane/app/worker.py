"""Arq worker: `arq app.worker.WorkerSettings`. Runs the same task bodies the
API would otherwise run inline, but durably and with retries. Bodies are sync
(sync SQLAlchemy + SDK), so they run in a thread to keep the worker loop free.
"""
from __future__ import annotations

import asyncio

from arq import cron
from arq.connections import RedisSettings

from . import alerting, config, scheduler, tasks


async def triage_findings(ctx, org_id: str, finding_ids: list[str]) -> None:
    await asyncio.to_thread(tasks.triage_findings, org_id, finding_ids)


async def deliver_alerts(ctx, org_id: str, alert_ids: list[str]) -> None:
    await asyncio.to_thread(alerting.deliver_pending, org_id, alert_ids)


async def scan_external_assets(ctx, org_id: str) -> None:
    await asyncio.to_thread(tasks.scan_external_assets, org_id)


# Translate config cadence knobs into arq cron() minute/hour sets (SPEC §177).
# Perimeter scan: minute 0 of every Nth hour. Deferred release: every N minutes
# of every hour (minutes-of-hour set, may be uneven if N doesn't divide 60).
# Snapshot: once/day at a fixed UTC hour.
_SCAN_HOURS = set(range(0, 24, config.SCAN_EVERY_HOURS))
_RELEASE_MINUTES = set(range(0, 60, config.DEFERRED_RELEASE_EVERY_MIN))


class WorkerSettings:
    functions = [triage_findings, deliver_alerts, scan_external_assets]
    cron_jobs = [
        cron(scheduler.perimeter_scan_cron, hour=_SCAN_HOURS, minute=0),
        cron(scheduler.deferred_release_cron, minute=_RELEASE_MINUTES, run_at_startup=True),
        cron(scheduler.daily_snapshot_cron, hour=config.SNAPSHOT_UTC_HOUR, minute=0),
    ]
    redis_settings = RedisSettings.from_dsn(config.REDIS_URL or "redis://localhost:6379")
    max_tries = 3
    keep_result = 3600
