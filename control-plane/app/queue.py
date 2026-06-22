"""One enqueue() call site, two transports. With REDIS_URL set, work is pushed
to a durable Arq queue (survives restarts, retried by the worker, lets the API
scale horizontally). Without it, work runs in an in-process BackgroundTask so
dev/SQLite needs no Redis. If a Redis enqueue fails, we fall back rather than
drop the work — at-least-once, never zero.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

from . import config

log = logging.getLogger(__name__)

# The Arq pool and the loop it lives on. Sync route handlers run in a threadpool,
# so they hand coroutines back to this loop via run_coroutine_threadsafe.
_pool: Any = None
_loop: asyncio.AbstractEventLoop | None = None


async def init_pool() -> None:
    """Create the Arq redis pool. Called from the app lifespan; no-op without URL."""
    global _pool, _loop
    if not config.REDIS_URL:
        return
    from arq import create_pool
    from arq.connections import RedisSettings

    _pool = await create_pool(RedisSettings.from_dsn(config.REDIS_URL))
    _loop = asyncio.get_running_loop()


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def enqueue(background: Any, fn_name: str, fallback: Callable[..., Any], *args: Any) -> None:
    """Durably enqueue fn_name(*args) via Arq, else run fallback(*args) in a
    BackgroundTask. fn_name must match a function in worker.WorkerSettings."""
    if _pool is not None and _loop is not None:
        try:
            fut = asyncio.run_coroutine_threadsafe(_pool.enqueue_job(fn_name, *args), _loop)
            fut.result(timeout=5)
            return
        except Exception:
            log.exception("arq enqueue %s failed; running inline", fn_name)
    background.add_task(fallback, *args)
