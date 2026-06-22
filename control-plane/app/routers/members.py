from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Path, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..models import Membership, Org, User
from ..schemas import MemberCreate, MemberRoleUpdate, MemberRow, MembersList
from ..tenancy import current_org, current_user, require_role

# Org membership admin BFF: org-scoped via current_org; all mutations require
# admin/owner. Each role grant/change/revoke writes an audit_log row.
router = APIRouter(prefix="/v1/members", tags=["members"])


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=UTC)).isoformat()


def _member_row(m: Membership, u: User) -> MemberRow:
    return MemberRow(
        user_id=u.id, email=u.email, name=u.name, role=m.role, created_at=_iso(m.created_at)
    )


def _get_membership(db: Session, org_id: str, user_id: str) -> Membership:
    m = db.execute(
        select(Membership).where(Membership.user_id == user_id, Membership.org_id == org_id)
    ).scalar_one_or_none()
    if m is None:
        raise HTTPException(status_code=404, detail="member not found")
    return m


def _owner_count(db: Session, org_id: str) -> int:
    return db.execute(
        select(func.count())
        .select_from(Membership)
        .where(Membership.org_id == org_id, Membership.role == "owner")
    ).scalar_one()


@router.get("", response_model=MembersList)
def list_members(
    org: Org = Depends(current_org),
    _: str = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> MembersList:
    rows = db.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.org_id == org.id)
        .order_by(Membership.created_at)
    ).all()
    return MembersList(members=[_member_row(m, u) for m, u in rows])


@router.post("", response_model=MemberRow)
def add_member(
    body: MemberCreate,
    org: Org = Depends(current_org),
    actor: User = Depends(current_user),
    _: str = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> MemberRow:
    # Attach an existing user to this org. Account creation (signup/invite) is a
    # separate flow; here we only grant org access to a known user.
    user = db.execute(select(User).where(User.email == body.email)).scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="no user with that email")
    if (
        db.execute(
            select(Membership).where(Membership.user_id == user.id, Membership.org_id == org.id)
        ).scalar_one_or_none()
        is not None
    ):
        raise HTTPException(status_code=409, detail="already a member of this org")
    m = Membership(user_id=user.id, org_id=org.id, role=body.role)
    db.add(m)
    db.flush()
    audit.record(
        db,
        org_id=org.id,
        actor=actor.email,
        action="membership.create",
        target=f"{user.email}:{body.role}",
    )
    db.commit()
    return _member_row(m, user)


@router.patch("/{user_id}", response_model=MemberRow)
def update_member_role(
    body: MemberRoleUpdate,
    user_id: str = Path(...),
    org: Org = Depends(current_org),
    actor: User = Depends(current_user),
    _: str = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> MemberRow:
    m = _get_membership(db, org.id, user_id)
    # Don't strand an org with no owner: block demoting its last owner.
    if m.role == "owner" and body.role != "owner" and _owner_count(db, org.id) == 1:
        raise HTTPException(status_code=400, detail="cannot demote the last owner")
    m.role = body.role
    user = db.get(User, user_id)
    audit.record(
        db,
        org_id=org.id,
        actor=actor.email,
        action="membership.update",
        target=f"{user.email if user else user_id}:{body.role}",
    )
    db.commit()
    return _member_row(m, user)


@router.delete("/{user_id}", status_code=204)
def remove_member(
    user_id: str = Path(...),
    org: Org = Depends(current_org),
    actor: User = Depends(current_user),
    _: str = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> Response:
    m = _get_membership(db, org.id, user_id)
    if m.role == "owner" and _owner_count(db, org.id) == 1:
        raise HTTPException(status_code=400, detail="cannot remove the last owner")
    user = db.get(User, user_id)
    db.delete(m)
    audit.record(
        db,
        org_id=org.id,
        actor=actor.email,
        action="membership.delete",
        target=user.email if user else user_id,
    )
    db.commit()
    return Response(status_code=204)
