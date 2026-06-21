from __future__ import annotations

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import config, mtls
from .db import get_db
from .models import Agent
from .tenancy import _set_rls_org

__all__ = ["require_agent"]


def require_agent(
    request: Request,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Agent:
    # mTLS path: a TLS-terminating proxy forwards the client cert PEM in the
    # configured header. Verify it against the internal CA and map the
    # fingerprint to its Agent.
    cert_pem = request.headers.get(config.MTLS_CERT_HEADER)
    if cert_pem:
        fingerprint = mtls.verify_client_cert(db, cert_pem)
        if fingerprint is None:
            raise HTTPException(status_code=401, detail="invalid client certificate")
        agent = db.execute(
            select(Agent).where(Agent.cert_fingerprint == fingerprint)
        ).scalar_one_or_none()
        if agent is None:
            raise HTTPException(status_code=401, detail="invalid client certificate")
        _set_rls_org(db, agent.org_id)
        return agent

    if config.require_mtls():
        raise HTTPException(status_code=401, detail="client certificate required")

    # Bearer-secret fallback (dev/plaintext).
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    secret = authorization.split(" ", 1)[1].strip()
    agent = db.execute(select(Agent).where(Agent.secret == secret)).scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=401, detail="invalid agent secret")
    # Scope Postgres RLS to the agent's org for the rest of this request.
    _set_rls_org(db, agent.org_id)
    return agent
