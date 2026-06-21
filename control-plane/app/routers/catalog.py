from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import require_agent
from ..catalog import bundle_version
from ..db import get_db
from ..models import Agent, Detection
from ..schemas import CatalogBundle, Detection as DetectionSchema
from ..signing import sign_bundle

router = APIRouter(prefix="/v1/catalog", tags=["catalog"])


@router.get("/bundle", response_model=CatalogBundle)
def get_bundle(
    since: int = Query(default=0),
    agent: Agent = Depends(require_agent),
    db: Session = Depends(get_db),
) -> CatalogBundle:
    version = bundle_version(db)
    rows = db.execute(select(Detection).where(Detection.version > since)).scalars().all()
    detections = [DetectionSchema(**r.spec) for r in rows]
    dets = [r.spec for r in rows]
    signature = sign_bundle(version, dets)
    return CatalogBundle(version=version, detections=detections, signature=signature)
