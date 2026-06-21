from __future__ import annotations

import json

from . import config

SYSTEM = """You are a vulnerability triage analyst. Given one finding, rank how \
urgently the operator should act. Weigh severity, CVSS, exploit maturity, and \
exposure. Reply with STRICT JSON only, no prose:
{"priority": "act-now"|"schedule"|"monitor", "score": <int 0-100>, "rationale": "<=160 chars"}"""

_PRIORITIES = {"act-now", "schedule", "monitor"}


def _extract_json(text: str) -> dict | None:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except Exception:
        return None


def triage_finding(
    *,
    title: str,
    severity: str,
    cve: str | None,
    cvss: float | None,
    host: str,
    service: str,
    evidence_note: str,
) -> dict | None:
    """Best-effort AI triage of one finding. Returns None on missing key or any error."""
    if not config.ANTHROPIC_API_KEY:
        return None
    try:
        import anthropic

        client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
        prompt = (
            f"Title: {title}\nSeverity: {severity}\nCVE: {cve or 'n/a'}\n"
            f"CVSS: {cvss if cvss is not None else 'n/a'}\nHost: {host}\n"
            f"Service: {service}\nEvidence: {evidence_note}"
        )
        resp = client.messages.create(
            model=config.TRIAGE_MODEL,
            max_tokens=256,
            system=SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        text = "".join(b.text for b in resp.content if b.type == "text")
        data = _extract_json(text)
        if not data:
            return None
        priority = data.get("priority")
        if priority not in _PRIORITIES:
            return None
        score = int(data.get("score"))
        return {
            "triage_priority": priority,
            "triage_score": max(0, min(100, score)),
            "triage_rationale": str(data.get("rationale", ""))[:160],
        }
    except Exception:
        return None
