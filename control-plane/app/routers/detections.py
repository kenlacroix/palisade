from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..catalog import bundle_version
from ..config import ANTHROPIC_API_KEY, DRAFT_MODEL
from ..db import get_db
from ..models import Detection, User
from ..tenancy import current_user, require_role
from ..schemas import (
    AcceptDetectionRequest,
    AcceptDetectionResponse,
    DraftDetection,
    DraftRequest,
    DraftResponse,
)

router = APIRouter(prefix="/v1/detections", tags=["detections"])

SYSTEM = """You are a security detection engineer for Palisade, an attack-surface \
monitor for self-hosted and AI-infra services. From a CVE advisory you draft ONE \
detection in Palisade's wire shape.

Rules:
- Only assert a `cve` id that actually appears in the source; otherwise leave it null.
- `match.service` is the lowercase product/service slug an agent fingerprints by \
(e.g. "litellm", "audiobookshelf"); `match.versions` is an affected-range expression \
(e.g. "<1.40.2").
- Prefer a single safe `nuclei`-engine HTTP probe with conservative matchers. Time-based \
checks use a dsl matcher like {"type":"dsl","dsl":["duration>=5"]}; presence checks use \
status/word matchers. Do NOT include destructive payloads.
- `remediation` is one or two sentences: the fix plus how to reduce exposure.
- This draft is unsigned and a human reviews it before it ships — be accurate, not creative."""


def _fetch(url: str) -> str:
    try:
        r = httpx.get(url, timeout=10, follow_redirects=True, headers={"User-Agent": "palisade-draft/0.1"})
        r.raise_for_status()
        return r.text[:20000]
    except Exception:
        return ""


@router.post("/draft", response_model=DraftResponse)
def draft_from_cve_url(
    body: DraftRequest, user: User = Depends(current_user)
) -> DraftResponse:
    if not ANTHROPIC_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="AI drafting is not configured. Set ANTHROPIC_API_KEY on the control plane.",
        )

    page = _fetch(body.cve_url)
    prompt = (
        f"Draft a Palisade detection from this CVE advisory.\n\nURL: {body.cve_url}\n\n"
        + (f"Page content:\n{page}" if page else "(Could not fetch the page; use the URL and your knowledge.)")
    )

    try:
        import anthropic

        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        resp = client.messages.parse(
            model=DRAFT_MODEL,
            max_tokens=2048,
            system=SYSTEM,
            messages=[{"role": "user", "content": prompt}],
            output_format=DraftDetection,
        )
    except Exception as exc:  # network / API / validation
        raise HTTPException(status_code=502, detail=f"drafting failed: {exc}") from exc

    detection = resp.parsed_output
    if detection is None:
        raise HTTPException(status_code=502, detail="model did not return a valid detection draft")

    return DraftResponse(detection=detection, source_url=body.cve_url, model=DRAFT_MODEL)


@router.post("", response_model=AcceptDetectionResponse)
def accept_detection(
    body: AcceptDetectionRequest,
    user: User = Depends(current_user),
    _: str = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> AcceptDetectionResponse:
    # Reviewer UI persists an approved draft. Admin/owner only.
    spec: dict = {
        "id": body.id,
        "title": body.title,
        "cve": body.cve,
        "severity": body.severity,
        "category": body.category,
        "engine": body.engine,
        "match": {"service": body.match.service, "versions": body.match.versions},
        "remediation": body.remediation,
        "references": list(body.references),
        "signature": "stub",  # bundle-level signing happens at /v1/catalog/bundle
        "cvss": body.cvss,
    }
    if body.engine == "module":
        spec["spec_ref"] = body.spec_ref
    else:
        spec["http"] = [s.model_dump() for s in (body.http or [])]

    new_version = bundle_version(db) + 1

    existing = db.get(Detection, body.id)
    if existing:
        existing.title = body.title
        existing.cve = body.cve
        existing.severity = body.severity
        existing.category = body.category
        existing.engine = body.engine
        existing.match_service = body.match.service
        existing.match_versions = body.match.versions
        existing.spec = spec
        existing.cvss = body.cvss
        existing.version = new_version
    else:
        db.add(
            Detection(
                id=body.id,
                title=body.title,
                cve=body.cve,
                severity=body.severity,
                category=body.category,
                engine=body.engine,
                match_service=body.match.service,
                match_versions=body.match.versions,
                spec=spec,
                cvss=body.cvss,
                version=new_version,
            )
        )

    db.commit()
    return AcceptDetectionResponse(id=body.id, version=new_version)
