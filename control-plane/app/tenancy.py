"""Multi-tenancy primitives: password hashing, sessions, and the per-request
org-scoping dependencies every BFF/read endpoint depends on.

The web UI authenticates with `Authorization: Bearer <session-token>` (distinct
from agent secrets, which live on the /v1/agents and /v1/scans routers). A
request's active org comes from its session; `current_org` resolves it and, on
Postgres, sets the `app.current_org_id` GUC so Row-Level Security (migration
0003) enforces isolation at the database layer too.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Cookie, Depends, Header, HTTPException, Request
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from . import config
from .db import get_db
from .models import DEMO_ORG_ID, ROLES, Membership, Org, User, UserSession

_PBKDF2_ITERATIONS = 240_000
_MUTATING_METHODS = ("POST", "PATCH", "PUT", "DELETE")
# Postgres role identifiers we'll inject into SET LOCAL ROLE must be plain
# identifiers (no quoting/injection); anything else is ignored.
_ROLE_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


# --- password hashing (stdlib pbkdf2, no extra deps) ---
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = encoded.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def create_session(db: Session, user: User, org_id: str) -> UserSession:
    sess = UserSession(
        token=secrets.token_urlsafe(32),
        user_id=user.id,
        org_id=org_id,
        expires_at=_now() + timedelta(seconds=config.SESSION_TTL_S),
    )
    db.add(sess)
    return sess


def _bearer_token(authorization: str | None, cookie: str | None) -> str:
    # Header takes precedence; fall back to the httpOnly session cookie so the
    # web UI no longer needs JS-readable token storage.
    if authorization and authorization.lower().startswith("bearer "):
        return authorization.split(" ", 1)[1].strip()
    if cookie:
        return cookie
    raise HTTPException(status_code=401, detail="missing bearer token")


def current_session(
    authorization: str | None = Header(default=None),
    palisade_session: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
) -> UserSession:
    token = _bearer_token(authorization, palisade_session)
    sess = db.get(UserSession, token)
    if sess is None:
        raise HTTPException(status_code=401, detail="invalid session")
    if _aware(sess.expires_at) < _now():
        db.delete(sess)
        db.commit()
        raise HTTPException(status_code=401, detail="session expired")
    sess.last_seen = _now()
    return sess


def current_user(sess: UserSession = Depends(current_session), db: Session = Depends(get_db)) -> User:
    user = db.get(User, sess.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="user not found")
    return user


def _set_rls_org(db: Session, org_id: str) -> None:
    # On Postgres, scope RLS to this org for the rest of the request's
    # transaction. No-op on SQLite (RLS is enforced by query filters there).
    if db.bind is None or db.bind.dialect.name != "postgresql":
        return
    # Drop to the non-superuser app role (migration 0012) for this transaction
    # so RLS actually binds — the connecting role is usually the superuser/owner,
    # which RLS (even FORCEd) does not constrain. SET LOCAL resets at commit, so
    # this is re-applied per transaction alongside the org GUC.
    role = config.db_app_role()
    if role and _ROLE_IDENT.match(role):
        db.execute(text(f"SET LOCAL ROLE {role}"))
    db.execute(text("SELECT set_config('app.current_org_id', :org, true)"), {"org": org_id})


def current_org(
    request: Request,
    sess: UserSession = Depends(current_session),
    db: Session = Depends(get_db),
) -> Org:
    org = db.get(Org, sess.org_id)
    if org is None:
        raise HTTPException(status_code=401, detail="org not found")
    membership = db.execute(
        select(Membership).where(
            Membership.user_id == sess.user_id, Membership.org_id == sess.org_id
        )
    ).scalar_one_or_none()
    if membership is None:
        raise HTTPException(status_code=403, detail="no membership for active org")
    # Public read-only demo: reject user-session mutations on the demo org. Every
    # user-session mutating endpoint depends on current_org, while agent
    # endpoints authenticate via require_agent and never reach here — so the live
    # demo loop (enroll/heartbeat/assets/findings) keeps writing.
    if (
        config.demo_mode()
        and org.id == DEMO_ORG_ID
        and request.method in _MUTATING_METHODS
    ):
        raise HTTPException(status_code=403, detail="demo is read-only")
    _set_rls_org(db, org.id)
    return org


def current_role(sess: UserSession = Depends(current_session), db: Session = Depends(get_db)) -> str:
    membership = db.execute(
        select(Membership).where(
            Membership.user_id == sess.user_id, Membership.org_id == sess.org_id
        )
    ).scalar_one_or_none()
    if membership is None:
        raise HTTPException(status_code=403, detail="no membership for active org")
    return membership.role


def require_role(*allowed: str):
    """Dependency factory: 403 unless the caller's role is in `allowed`.

    Roles are ordered in models.ROLES; pass the minimum-privileged role that may
    act and any more-privileged role is accepted too.
    """
    min_rank = min(ROLES.index(r) for r in allowed)

    def _dep(role: str = Depends(current_role)) -> str:
        if ROLES.index(role) > min_rank:
            raise HTTPException(status_code=403, detail="insufficient role")
        return role

    return _dep
