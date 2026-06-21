"""Control-plane-side external scanning. Mirrors the agent's nuclei executor
(status / word / duration-DSL matchers, ANDed) in Python so internet-exposed
assets can be probed from the control plane for an attacker's-eye view
(SPEC §97) without an agent on the host.

Safe-check posture: no destructive payloads, redirects are not followed, the
matched body is capped, and every request has a timeout. Module-engine
detections are skipped here — their multi-step logic lives in the compiled
agent, not the control plane.
"""
from __future__ import annotations

import logging
import time

import httpx

log = logging.getLogger(__name__)

_MAX_BODY = 1 << 20  # 1 MiB, matches the agent's cap
_TIMEOUT_S = 30.0  # must exceed the longest duration-DSL check (sleep payloads)


def base_url(host: str, port: int) -> str:
    scheme = "https" if port in (443, 8443) else "http"
    return f"{scheme}://{host}:{port}"


def run_detection(
    base: str, spec: dict, timeout: float = _TIMEOUT_S
) -> tuple[dict, str] | None:
    """Run a nuclei-engine detection's http steps against base. On the first
    step whose matchers all pass, return (evidence, fingerprint_key); else None.
    The key is the stable matcher key (not the timing note) so fingerprints stay
    constant across rescans."""
    for step in spec.get("http") or []:
        method = (step.get("method") or "GET").upper()
        path = step.get("path") or ""
        url = base.rstrip("/") + path
        body = step.get("body")
        headers = {"Content-Type": "application/json"} if body else {}
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
    rest = expr[len("duration"):]
    op = next((o for o in (">=", "<=", "==", ">", "<") if rest.startswith(o)), "")
    if not op:
        return False
    try:
        want = float(rest[len(op):])
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
