"""Arq worker: `arq app.worker.WorkerSettings`. Runs the same task bodies the
API would otherwise run inline, but durably and with retries. Bodies are sync
(sync SQLAlchemy + SDK), so they run in a thread to keep the worker loop free.
"""
from __future__ import annotations

import asyncio

from arq.connections import RedisSettings

from . import alerting, config, tasks


async def triage_findings(ctx, finding_ids: list[str]) -> None:
    await asyncio.to_thread(tasks.triage_findings, finding_ids)


async def deliver_alerts(ctx, alert_ids: list[str]) -> None:
    await asyncio.to_thread(alerting.deliver_pending, alert_ids)


async def scan_external_assets(ctx, org_id: str) -> None:
    await asyncio.to_thread(tasks.scan_external_assets, org_id)


class WorkerSettings:
    functions = [triage_findings, deliver_alerts, scan_external_assets]
    redis_settings = RedisSettings.from_dsn(config.REDIS_URL or "redis://localhost:6379")
    max_tries = 3
    keep_result = 3600
