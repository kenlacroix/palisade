from __future__ import annotations

from fastapi import Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import enroll_tokens
from .db import get_db
from .models import Agent

__all__ = ["enroll_tokens", "require_agent"]


# TODO(prod): replace bearer-token auth with mTLS client certs (SPEC: enroll
#             returns an mTLS cert). Not implemented in this scaffold.
def require_agent(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Agent:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    secret = authorization.split(" ", 1)[1].strip()
    agent = db.execute(select(Agent).where(Agent.secret == secret)).scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=401, detail="invalid agent secret")
    return agent
