"""Control-plane-side external scanning. Mirrors the agent's nuclei executor
(status / word / duration-DSL matchers, ANDed) in Python so internet-exposed
assets can be probed from the control plane for an attacker's-eye view
(SPEC §97) without an agent on the host.

Safe-check posture (SPEC §428 — responsible scanning): no destructive payloads,
redirects are not followed, the matched body is capped, and every request has a
timeout. Outbound probes are rate-limited per host and the total probe count per
scan burst is hard-capped, so a scan never hammers a target or fans out runaway.
Targets are checked against an operator-confirmed scope allowlist before any
request leaves the box. Module-engine detections are skipped here — their
multi-step logic lives in the compiled agent, not the control plane.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from urllib.parse import urlsplit

import httpx

from . import config

log = logging.getLogger(__name__)

_MAX_BODY = 1 << 20  # 1 MiB, matches the agent's cap
_TIMEOUT_S = 30.0  # must exceed the longest duration-DSL check (sleep payloads)


def base_url(host: str, port: int) -> str:
    scheme = "https" if port in (443, 8443) else "http"
    return f"{scheme}://{host}:{port}"


class RateLimiter:
    """Per-host fixed-interval throttle plus a global per-scan request budget.

    Library-free: a lock + last-probe timestamps. The scan budget resets after
    an idle gap longer than _idle_reset so each contiguous scan burst (the
    tasks.scan_external_assets loop) gets a fresh cap without the caller having
    to signal scan boundaries — which it can't, since run_detection is called
    positionally. rps<=0 disables pacing (no-op); budget<=0 disables the cap."""

    def __init__(self, rps: float, min_interval_s: float, max_requests: int):
        if min_interval_s > 0:
            self._interval = min_interval_s
        elif rps > 0:
            self._interval = 1.0 / rps
        else:
            self._interval = 0.0
        self._max_requests = max_requests
        self._idle_reset = _TIMEOUT_S * 2  # gap implying a new scan burst
        self._lock = threading.Lock()
        self._last_host: dict[str, float] = {}
        self._budget_used = 0
        self._last_any = 0.0

    def acquire(self, host: str) -> bool:
        """Block to honor the per-host interval, then claim one budget slot.
        Returns False (and does not sleep) when the per-scan cap is exhausted."""
        with self._lock:
            now = time.monotonic()
            if self._last_any and (now - self._last_any) > self._idle_reset:
                self._budget_used = 0  # new contiguous scan burst
            self._last_any = now
            if self._max_requests > 0 and self._budget_used >= self._max_requests:
                return False
            self._budget_used += 1
            wait = 0.0
            if self._interval > 0:
                last = self._last_host.get(host, 0.0)
                wait = self._interval - (now - last)
                self._last_host[host] = now + max(wait, 0.0)
        if wait > 0:
            time.sleep(wait)
        return True


_LIMITER = RateLimiter(
    config.PERIMETER_RATE_LIMIT_RPS,
    config.PERIMETER_MIN_INTERVAL_S,
    config.PERIMETER_MAX_REQUESTS_PER_SCAN,
)


def _host_of(base: str) -> str:
    return urlsplit(base).hostname or base


def host_in_scope(host: str) -> bool:
    """True when host is operator-confirmed in scope. An empty allowlist is
    deny-all in production (config.is_production()) so a misconfigured prod never
    probes an unconfirmed target, and allow-all for dev/demo so the SQLite path
    and the existing back-compat flow keep working. With entries, match by exact
    host, parent-domain suffix, or CIDR membership."""
    allow = config.perimeter_scope_allowlist()
    if not allow:
        return not config.is_production()
    host = (host or "").strip().lower()
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    for entry in allow:
        entry = entry.lower()
        if "/" in entry and ip is not None:
            try:
                if ip in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                continue
            continue
        if host == entry or host.endswith("." + entry):
            return True
    return False


def run_detection(
    base: str, spec: dict, timeout: float = _TIMEOUT_S, limiter: RateLimiter | None = None
) -> tuple[dict, str] | None:
    """Run a nuclei-engine detection's http steps against base. On the first
    step whose matchers all pass, return (evidence, fingerprint_key); else None.
    The key is the stable matcher key (not the timing note) so fingerprints stay
    constant across rescans.

    Responsible-scanning guards (SPEC §428): out-of-scope targets are skipped
    (logged, not raised); each probe is paced by limiter (defaults to the
    config-driven module limiter); the per-scan request cap aborts the detection
    when exhausted. The signature stays positional-compatible with the caller in
    tasks.scan_external_assets — limiter is an optional keyword."""
    host = _host_of(base)
    if not host_in_scope(host):
        log.warning("perimeter: skipping out-of-scope target %s", host)
        return None
    if not config.perimeter_scope_allowlist():
        log.warning("perimeter: empty scope allowlist (dev allow-all) — probing %s", host)
    limiter = limiter or _LIMITER
    for step in spec.get("http") or []:
        method = (step.get("method") or "GET").upper()
        path = step.get("path") or ""
        url = base.rstrip("/") + path
        body = step.get("body")
        headers = {"Content-Type": "application/json"} if body else {}
        if not limiter.acquire(host):
            log.warning("perimeter: per-scan request cap reached, skipping %s %s", method, url)
            return None
        start = time.monotonic()
        try:
            resp = httpx.request(
                method,
                url,
                content=body,
                headers=headers,
                timeout=timeout,
                follow_redirects=False,
            )
        except Exception as exc:  # network/TLS/timeout — try the next step
            log.info("perimeter: %s %s: %s", method, url, exc)
            continue
        elapsed = time.monotonic() - start
        text = (resp.text or "")[:_MAX_BODY]
        matched, key = _eval_matchers(step.get("matchers") or [], resp.status_code, text, elapsed)
        if matched:
            evidence = {
                "request": f"{method} {path}",
                "note": f"matched {key} in {elapsed:.3f}s (control-plane scan)",
            }
            return evidence, key
    return None


def _eval_matchers(matchers: list, status: int, body: str, elapsed: float) -> tuple[bool, str]:
    if not matchers:
        return False, ""
    first_key = ""
    for m in matchers:
        ok, key = _eval_matcher(m, status, body, elapsed)
        if not ok:
            return False, ""
        if not first_key:
            first_key = key
    return True, first_key


def _eval_matcher(m: dict, status: int, body: str, elapsed: float) -> tuple[bool, str]:
    mtype = m.get("type")
    if mtype == "dsl":
        exprs = m.get("dsl") or []
        for expr in exprs:
            if not _eval_dsl(expr, elapsed):
                return False, ""
        return True, "dsl:" + ",".join(exprs)
    if mtype == "word":
        words = m.get("words") or []
        for w in words:
            if w not in body:
                return False, ""
        return True, "word:" + ",".join(words)
    if mtype == "status":
        for code in m.get("status") or []:
            if code == status:
                return True, f"status:{status}"
        return False, ""
    log.warning("perimeter: unknown matcher type %r, treating as no-match", mtype)
    return False, ""


def _eval_dsl(expr: str, elapsed: float) -> bool:
    """duration{>=,>,<=,<,==}N seconds. Anything else fails closed, matching the
    agent's evalDSL safety posture."""
    expr = expr.replace(" ", "")
    if not expr.startswith("duration"):
        return False
    rest = expr[len("duration") :]
    op = next((o for o in (">=", "<=", "==", ">", "<") if rest.startswith(o)), "")
    if not op:
        return False
    try:
        want = float(rest[len(op) :])
    except ValueError:
        return False
    got = elapsed
    return {
        ">=": got >= want,
        "<=": got <= want,
        "==": got == want,
        ">": got > want,
        "<": got < want,
    }[op]
