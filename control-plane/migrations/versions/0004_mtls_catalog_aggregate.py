"""agent mTLS identity, internal CA, and RLS-bypassing catalog aggregate

Revision ID: 0004_mtls_catalog_aggregate
Revises: 0003_tenancy_alerts_trends
Create Date: 2026-06-21

Adds the agent client-cert identity columns and the single-row internal CA
table backing mTLS enrollment, plus two Postgres SECURITY DEFINER functions
that compute the catalog's cross-tenant `tenants_hit`/`tenants_total` metric
without being clipped by Row-Level Security (0003 scopes `finding`/`org` to the
caller's org; these functions run as the migration owner to see all tenants).
The functions are Postgres-only; on SQLite the read router keeps its inline
aggregate (no RLS there).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0004_mtls_catalog_aggregate"
down_revision: Union[str, None] = "0003_tenancy_alerts_trends"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_ORG_COUNT_FN = """
CREATE OR REPLACE FUNCTION palisade_org_count()
RETURNS bigint
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$ SELECT count(*) FROM org $$
"""

_TENANT_HITS_FN = """
CREATE OR REPLACE FUNCTION palisade_detection_tenant_hits()
RETURNS TABLE(detection_id text, n_orgs bigint)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT f.detection_id, count(DISTINCT f.org_id)
    FROM finding f
    WHERE f.status IN ('open', 'regressed')
    GROUP BY f.detection_id
$$
"""


def upgrade() -> None:
    op.add_column("agent", sa.Column("cert_fingerprint", sa.String(), nullable=True))
    op.add_column("agent", sa.Column("cert_not_after", sa.DateTime(), nullable=True))
    op.create_index("ix_agent_cert_fingerprint", "agent", ["cert_fingerprint"])

    op.create_table(
        "cert_authority",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("cert_pem", sa.String(), nullable=False),
        sa.Column("key_pem", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )

    if op.get_bind().dialect.name == "postgresql":
        op.execute(_ORG_COUNT_FN)
        op.execute(_TENANT_HITS_FN)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP FUNCTION IF EXISTS palisade_detection_tenant_hits()")
        op.execute("DROP FUNCTION IF EXISTS palisade_org_count()")

    op.drop_table("cert_authority")
    op.drop_index("ix_agent_cert_fingerprint", table_name="agent")
    op.drop_column("agent", "cert_not_after")
    op.drop_column("agent", "cert_fingerprint")
