from __future__ import annotations

import json
import logging
import sys
import time
import uuid
from contextvars import ContextVar
from typing import Any

from fastapi import FastAPI, Request, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    Counter,
    Histogram,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Match

from . import config

# Per-request id, set by RequestContextMiddleware and read by the log formatter.
_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)

_LATENCY_BUCKETS = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
)


def _get_or_create_counter(name: str, doc: str, labels: tuple[str, ...]) -> Counter:
    existing = REGISTRY._names_to_collectors.get(name)  # type: ignore[attr-defined]
    if existing is not None:
        return existing  # type: ignore[return-value]
    return Counter(name, doc, labels)


def _get_or_create_histogram(
    name: str, doc: str, labels: tuple[str, ...], buckets: tuple[float, ...]
) -> Histogram:
    existing = REGISTRY._names_to_collectors.get(name)  # type: ignore[attr-defined]
    if existing is not None:
        return existing  # type: ignore[return-value]
    return Histogram(name, doc, labels, buckets=buckets)


# Import-safe registration: uvicorn --reload re-imports this module, so reuse any
# collector already registered instead of raising a duplicate-timeseries error.
REQUESTS_TOTAL = _get_or_create_counter(
    "palisade_http_requests_total",
    "Total HTTP requests processed.",
    ("method", "path", "status"),
)
REQUEST_LATENCY = _get_or_create_histogram(
    "palisade_http_request_duration_seconds",
    "HTTP request latency in seconds.",
    ("method", "path"),
    _LATENCY_BUCKETS,
)


def _route_template(request: Request) -> str:
    # Use the matched route template (e.g. /v1/findings/{finding_id}/mute) rather
    # than the raw path, so per-id paths collapse to one low-cardinality label.
    for route in request.app.router.routes:
        match, _ = route.matches(request.scope)
        if match == Match.FULL:
            return getattr(route, "path", request.url.path)
    return "__unmatched__"


class JsonFormatter(logging.Formatter):
    """One-line JSON logs (timestamp, level, logger, message + request context)
    so Loki/promtail can parse them without a regex pipeline."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        rid = _request_id.get()
        if rid is not None:
            payload["request_id"] = rid
        for key in ("method", "path", "status", "duration_ms"):
            if key in record.__dict__:
                payload[key] = record.__dict__[key]
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    if config.LOG_FORMAT == "text":
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
    else:
        handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(config.LOG_LEVEL)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers[:] = []
        lg.propagate = True


_access_log = logging.getLogger("palisade.access")


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns/propagates X-Request-ID, records request metrics, and emits a
    structured access log line per request."""

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        token = _request_id.set(rid)
        start = time.perf_counter()
        status = 500
        response: Response | None = None
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["X-Request-ID"] = rid
            return response
        finally:
            duration = time.perf_counter() - start
            template = _route_template(request)
            if config.metrics_enabled() and template != "/metrics":
                REQUESTS_TOTAL.labels(request.method, template, str(status)).inc()
                REQUEST_LATENCY.labels(request.method, template).observe(duration)
            _access_log.info(
                "request",
                extra={
                    "method": request.method,
                    "path": template,
                    "status": status,
                    "duration_ms": round(duration * 1000, 2),
                },
            )
            _request_id.reset(token)


def _metrics_endpoint() -> Response:
    return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


def install(app: FastAPI) -> None:
    # Future OTel tracing would hook here: wrap the ASGI app with
    # FastAPIInstrumentor or add an OTel middleware alongside this one.
    setup_logging()
    app.add_middleware(RequestContextMiddleware)
    if config.metrics_enabled():
        app.add_api_route("/metrics", _metrics_endpoint, include_in_schema=False)
