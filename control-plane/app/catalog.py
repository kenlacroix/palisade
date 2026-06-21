from __future__ import annotations

import os
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import DETECTIONS_DIR
from .models import Detection

# Inline fallback in the EXACT Detection wire shape (used when the detections
# directory does not exist). Seed CVEs to support the end-to-end loop.
INLINE_DETECTIONS: list[dict[str, Any]] = [
    {
        "id": "litellm-proxy-preauth-sqli",
        "title": "LiteLLM proxy pre-auth SQLi",
        "cve": "CVE-2026-42208",
        "severity": "critical",
        "category": "ai-infra",
        "engine": "nuclei",
        "match": {"service": "litellm", "versions": "<1.40.2"},
        "http": [
            {
                "method": "POST",
                "path": "/key/info",
                "body": '{"key":"1\' OR sleep(5)-- -"}',
                "matchers": [{"type": "dsl", "dsl": ["duration>=5"]}],
            }
        ],
        "remediation": (
            "Upgrade LiteLLM to >=1.40.2. Restrict /key/* to authenticated admin."
        ),
        "references": ["https://github.com/BerriAI/litellm/security/advisories"],
        "signature": "stub",
        "cvss": 9.8,
    },
    {
        "id": "audiobookshelf-authbypass",
        "title": "Audiobookshelf authentication bypass",
        "cve": "CVE-2025-25205",
        "severity": "critical",
        "category": "self-hosted",
        "engine": "nuclei",
        "match": {"service": "audiobookshelf", "versions": "<2.17.0"},
        "http": [
            {
                "method": "GET",
                "path": "/api/users",
                "matchers": [
                    {"type": "status", "status": [200]},
                    {"type": "word", "words": ["\"username\"", "\"isActive\""]},
                ],
            }
        ],
        "remediation": "Upgrade Audiobookshelf to >=2.17.0. Require auth on /api/*.",
        "references": ["https://github.com/advplyr/audiobookshelf/security/advisories"],
        "signature": "stub",
        "cvss": 9.1,
    },
]


def _normalize(raw: dict[str, Any]) -> dict[str, Any]:
    """Coerce a loaded YAML/inline detection into the wire Detection shape."""
    match = raw.get("match") or {}
    out: dict[str, Any] = {
        "id": raw["id"],
        "title": raw.get("title", ""),
        "cve": raw.get("cve"),
        "severity": raw.get("severity", "info"),
        "category": raw.get("category", "self-hosted"),
        "engine": raw.get("engine", "nuclei"),
        "match": {
            "service": str(match.get("service", "")),
            "versions": str(match.get("versions", "")),
        },
        "remediation": raw.get("remediation", ""),
        "references": list(raw.get("references", []) or []),
        "signature": raw.get("signature") or "stub",
        "cvss": raw.get("cvss"),
    }
    if out["engine"] == "module":
        out["spec_ref"] = raw.get("spec_ref", "")
    else:
        out["http"] = raw.get("http", [])
    return out


def load_detection_specs() -> list[dict[str, Any]]:
    """Load every *.yaml from the detections dir, else the inline fallback."""
    if os.path.isdir(DETECTIONS_DIR):
        try:
            import yaml  # pyyaml
        except ImportError:
            return [_normalize(d) for d in INLINE_DETECTIONS]
        specs: list[dict[str, Any]] = []
        for name in sorted(os.listdir(DETECTIONS_DIR)):
            if not name.endswith((".yaml", ".yml")):
                continue
            with open(os.path.join(DETECTIONS_DIR, name)) as fh:
                doc = yaml.safe_load(fh)
            if isinstance(doc, dict) and doc.get("id"):
                specs.append(_normalize(doc))
        if specs:
            return specs
    return [_normalize(d) for d in INLINE_DETECTIONS]


def seed_detections(db: Session) -> None:
    for spec in load_detection_specs():
        existing = db.get(Detection, spec["id"])
        if existing:
            continue
        db.add(
            Detection(
                id=spec["id"],
                title=spec["title"],
                cve=spec.get("cve"),
                severity=spec["severity"],
                category=spec["category"],
                engine=spec["engine"],
                match_service=spec["match"]["service"],
                match_versions=spec["match"]["versions"],
                spec=spec,
                cvss=spec.get("cvss"),
                version=1,
                signature=spec["signature"],
            )
        )
    db.commit()


def bundle_version(db: Session) -> int:
    rows = db.execute(select(Detection.version)).scalars().all()
    return max(rows) if rows else 1
