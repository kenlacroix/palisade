from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit, config
from ..db import get_db
from ..models import Membership, Org, User, UserSession
from ..schemas import (
    LoginRequest,
    MembershipRow,
    MeResponse,
    SessionInfo,
    SwitchOrgRequest,
    UserInfo,
)
from ..tenancy import (
    _set_rls_org,
    create_session,
    current_session,
    current_user,
    verify_password,
)

router = APIRouter(prefix="/v1/auth", tags=["auth"])

SESSION_COOKIE = "palisade_session"


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=config.SESSION_TTL_S,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )


def _memberships(db: Session, user_id: str) -> list[MembershipRow]:
    rows = db.execute(
        select(Membership, Org)
        .join(Org, Org.id == Membership.org_id)
        .where(Membership.user_id == user_id)
    ).all()
    return [MembershipRow(org_id=o.id, org_name=o.name, role=m.role) for m, o in rows]


def _role_for(db: Session, user_id: str, org_id: str) -> str:
    m = db.execute(
        select(Membership).where(
            Membership.user_id == user_id, Membership.org_id == org_id
        )
    ).scalar_one_or_none()
    if m is None:
        raise HTTPException(status_code=403, detail="not a member of this org")
    return m.role


@router.post("/login", response_model=SessionInfo)
def login(body: LoginRequest, response: Response, db: Session = Depends(get_db)) -> SessionInfo:
    user = db.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="invalid email or password")

    memberships = _memberships(db, user.id)
    if not memberships:
        raise HTTPException(status_code=403, detail="user has no org membership")
    active = memberships[0]

    sess = create_session(db, user, active.org_id)
    # Audit the session under the active org. No request org context exists yet,
    # so set the RLS GUC explicitly for the WITH CHECK insert policy (Postgres).
    _set_rls_org(db, active.org_id)
    audit.record(db, org_id=active.org_id, actor=user.email, action="session.create", target=active.org_name)
    db.commit()
    _set_session_cookie(response, sess.token)
    return SessionInfo(
        token=sess.token,
        user=UserInfo(id=user.id, email=user.email, name=user.name),
        org_id=active.org_id,
        org_name=active.org_name,
        role=active.role,
        memberships=memberships,
        demo_mode=config.demo_mode(),
    )


@router.post("/logout", status_code=204)
def logout(
    sess: UserSession = Depends(current_session), db: Session = Depends(get_db)
) -> Response:
    db.delete(sess)
    db.commit()
    resp = Response(status_code=204)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


@router.get("/me", response_model=MeResponse)
def me(
    user: User = Depends(current_user),
    sess: UserSession = Depends(current_session),
    db: Session = Depends(get_db),
) -> MeResponse:
    memberships = _memberships(db, user.id)
    role = _role_for(db, user.id, sess.org_id)
    org = db.get(Org, sess.org_id)
    return MeResponse(
        user=UserInfo(id=user.id, email=user.email, name=user.name),
        org_id=sess.org_id,
        org_name=org.name if org else "",
        role=role,
        memberships=memberships,
        demo_mode=config.demo_mode(),
    )


@router.post("/switch-org", response_model=MeResponse)
def switch_org(
    body: SwitchOrgRequest,
    user: User = Depends(current_user),
    sess: UserSession = Depends(current_session),
    db: Session = Depends(get_db),
) -> MeResponse:
    role = _role_for(db, user.id, body.org_id)  # 403 if not a member
    sess.org_id = body.org_id
    db.commit()
    org = db.get(Org, body.org_id)
    return MeResponse(
        user=UserInfo(id=user.id, email=user.email, name=user.name),
        org_id=body.org_id,
        org_name=org.name if org else "",
        role=role,
        memberships=_memberships(db, user.id),
        demo_mode=config.demo_mode(),
    )
