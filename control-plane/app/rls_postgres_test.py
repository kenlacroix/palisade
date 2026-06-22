"""Postgres-only proof that Row-Level Security is actually ENFORCED for the
application's own database role.

Migration 0003 only ENABLEd RLS, which Postgres does not apply to a table's
owner — and the app connects as the owner — so isolation rode entirely on the
Python query filters. Migration 0011 adds FORCE ROW LEVEL SECURITY. This test
proves the difference: connected as the app role, with the app.current_org_id
GUC set to org A, rows belonging to org B are invisible and unwritable.

Skipped unless PALISADE_TEST_DATABASE_URL points at Postgres (CI's
integration-postgres job sets it). SQLite has no RLS, so there's nothing to
assert there. Run:  python -m app.rls_postgres_test
"""
from __future__ import annotations

import os
import uuid

_PG_URL = os.environ.get("PALISADE_TEST_DATABASE_URL", "")
_IS_PG = _PG_URL.startswith("postgresql")


def _skip(msg: str):
    try:
        import pytest

        pytest.skip(msg)
    except ImportError:
        print(f"SKIP: {msg}")


def test_force_rls_isolates_app_role():
    if not _IS_PG:
        _skip("PALISADE_TEST_DATABASE_URL not Postgres; RLS is a no-op on SQLite")
        return

    # Point the app's engine at the test Postgres and migrate to head (idempotent).
    os.environ["DATABASE_URL"] = _PG_URL
    from alembic import command
    from alembic.config import Config
    from sqlalchemy import create_engine, func, select, text

    from app import config as config_module
    from app import db as db_module

    config_module.DATABASE_URL = _PG_URL
    db_module.DATABASE_URL = _PG_URL
    engine = create_engine(_PG_URL, future=True)
    db_module.engine = engine
    db_module.SessionLocal.configure(bind=engine)

    cfg = Config("alembic.ini")
    command.upgrade(cfg, "head")

    from app.models import Agent, Asset, Detection, Finding, Org
    from app.tenancy import _set_rls_org

    org_a = f"rls-a-{uuid.uuid4().hex[:8]}"
    org_b = f"rls-b-{uuid.uuid4().hex[:8]}"
    secret_a = f"sec-a-{uuid.uuid4().hex}"
    secret_b = f"sec-b-{uuid.uuid4().hex}"

    # org table is not RLS-protected, so create both tenants without a GUC.
    with db_module.SessionLocal() as db:
        db.add(Org(id=org_a, name="a"))
        db.add(Org(id=org_b, name="b"))
        db.commit()

    # Each agent insert needs the GUC matching its org (FORCE WITH CHECK).
    with db_module.SessionLocal() as db:
        _set_rls_org(db, org_a)
        db.add(Agent(org_id=org_a, secret=secret_a, hostname="a"))
        db.commit()
    with db_module.SessionLocal() as db:
        _set_rls_org(db, org_b)
        db.add(Agent(org_id=org_b, secret=secret_b, hostname="b"))
        db.commit()

    # Scoped to org A: A's agent is visible, B's is not — even though we query
    # with no org_id filter at all. This is the database enforcing isolation.
    with db_module.SessionLocal() as db:
        _set_rls_org(db, org_a)
        visible = set(db.execute(select(Agent.secret)).scalars().all())
        assert secret_a in visible, "own-org row must be visible"
        assert secret_b not in visible, "FORCE RLS must hide the other org's row"

        # A cross-org UPDATE touches zero rows (WITH CHECK / USING both bind).
        affected = db.execute(
            text("UPDATE agent SET hostname='pwned' WHERE org_id=:b"), {"b": org_b}
        ).rowcount
        assert affected == 0, f"cross-org UPDATE must affect 0 rows, got {affected}"
        db.rollback()

    # With the GUC set to an unrelated org, NOTHING is visible — the owner role
    # gets no implicit bypass.
    with db_module.SessionLocal() as db:
        _set_rls_org(db, "no-such-org")
        n = db.execute(
            select(func.count()).select_from(Agent).where(Agent.secret.in_([secret_a, secret_b]))
        ).scalar_one()
        assert n == 0, f"no GUC match must hide all rows, saw {n}"

    # Catalog-aggregate carve-out: under FORCE, the SECURITY DEFINER metric
    # function must still see findings across BOTH orgs (via its function-scoped
    # app.aggregate_bypass), even though the caller is scoped to org A.
    det_id = f"det-{uuid.uuid4().hex[:8]}"
    with db_module.SessionLocal() as db:
        db.add(Detection(id=det_id, title="t", severity="high"))
        db.commit()
    for org in (org_a, org_b):
        with db_module.SessionLocal() as db:
            _set_rls_org(db, org)
            asset = Asset(org_id=org, host="h", port=1, service="x")
            db.add(asset)
            db.flush()
            db.add(Finding(
                org_id=org, asset_id=asset.id, detection_id=det_id,
                fingerprint=f"fp-{uuid.uuid4().hex}", status="open",
            ))
            db.commit()
    with db_module.SessionLocal() as db:
        _set_rls_org(db, org_a)  # caller scoped to A only
        rows = db.execute(
            text("SELECT detection_id, n_orgs FROM palisade_detection_tenant_hits()")
        ).all()
        hits = {d: n for d, n in rows}
        assert hits.get(det_id) == 2, f"aggregate must span both orgs, got {hits}"

    print("RLS OK: FORCE isolates the app role; catalog aggregate still spans orgs")


if __name__ == "__main__":
    if not _IS_PG:
        print("SKIP: PALISADE_TEST_DATABASE_URL not Postgres; RLS is a no-op on SQLite")
    else:
        test_force_rls_isolates_app_role()
