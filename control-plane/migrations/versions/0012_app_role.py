"""Non-superuser application role so RLS actually binds

Revision ID: 0012_app_role
Revises: 0011_force_rls_org_fingerprint
Create Date: 2026-06-22

FORCE ROW LEVEL SECURITY (0011) still does NOT constrain a Postgres superuser or
a BYPASSRLS role — and the bundled deployment connects as `palisade`, the
cluster superuser, so RLS was bypassed regardless. The control plane now drops
to this NOLOGIN, NOSUPERUSER, NOBYPASSRLS role via `SET LOCAL ROLE` before
touching tenant data (see tenancy._set_rls_org), which is the role the policies
finally apply to. It is NOLOGIN (no password, can't be connected to directly);
the connecting role assumes it with SET ROLE.

Granted plain DML on existing + future tables and EXECUTE on the catalog-metric
functions. Those functions are SECURITY DEFINER owned by the (superuser) migrator,
so they keep their cross-tenant view even when invoked under this role.

Postgres-only; on SQLite there is no RLS and nothing to do.
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0012_app_role"
down_revision: Union[str, None] = "0011_force_rls_org_fingerprint"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_ROLE = "palisade_app"


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    op.execute(
        f"""
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{_ROLE}') THEN
            CREATE ROLE {_ROLE} NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
          END IF;
        END
        $$
        """
    )
    # Let the current (connecting) role assume it via SET ROLE. A superuser does
    # not need this, but it keeps the drop working for non-superuser owners too.
    op.execute(f"GRANT {_ROLE} TO CURRENT_USER")
    op.execute(f"GRANT USAGE ON SCHEMA public TO {_ROLE}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {_ROLE}")
    op.execute(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {_ROLE}")
    op.execute(f"GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO {_ROLE}")
    # Future objects created by the migrating role are usable without re-granting.
    op.execute(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {_ROLE}"
    )
    op.execute(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {_ROLE}"
    )
    op.execute(
        f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO {_ROLE}"
    )


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    # Strip privileges + default-ACL entries so the role can be dropped.
    op.execute(f"DROP OWNED BY {_ROLE}")
    op.execute(f"DROP ROLE IF EXISTS {_ROLE}")
