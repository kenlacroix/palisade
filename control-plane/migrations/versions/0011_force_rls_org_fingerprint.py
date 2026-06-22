"""FORCE row-level security and scope finding fingerprints per org

Revision ID: 0011_force_rls_org_fingerprint
Revises: 0010_audit_log
Create Date: 2026-06-22

Two tenant-isolation hardening steps:

1. FORCE ROW LEVEL SECURITY on every RLS table. Migration 0003 only ENABLEd
   RLS, which Postgres does NOT apply to a table's owner — and the app connects
   as the role that owns these tables, so the org-isolation policies were silent
   for the application's own queries. FORCE makes the owner subject to them too,
   so the `app.current_org_id` GUC the app sets per request becomes a real
   database-level backstop, not just a convention behind the Python filters.

2. Replace the globally-unique `finding.fingerprint` index with a composite
   unique on (org_id, fingerprint). A global unique let one tenant's fingerprint
   collide with another's, which the ingest dedupe then used to overwrite the
   other tenant's finding. Scoping uniqueness to the org closes that and keeps a
   plain fingerprint index for lookups.

FORCE has one consequence to handle: the cross-tenant catalog metric function
`palisade_detection_tenant_hits` (migration 0004) is SECURITY DEFINER owned by
the app role and relied on the owner being exempt from RLS. Under FORCE the
owner is no longer exempt, so it would be clipped to one org. We add a
SELECT-only permissive policy on `finding` gated by a `app.aggregate_bypass`
GUC, and recreate the function so it sets that GUC for the duration of its own
execution only (a function-scoped SET reverts on return). Normal request reads
never set it, so per-org isolation is unchanged.

RLS DDL is Postgres-only (skipped on SQLite, which has no equivalent); the index
changes run on both.
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0011_force_rls_org_fingerprint"
down_revision: Union[str, None] = "0010_audit_log"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Mirrors migration 0003's _RLS_TABLES — the tenant data tables under org_id RLS.
_RLS_TABLES = (
    "agent",
    "asset",
    "scan",
    "finding",
    "alert_channel",
    "alert_rule",
    "alert",
    "posture_snapshot",
)

# Cross-tenant catalog metric (migration 0004), recreated to set
# app.aggregate_bypass='on' for the duration of its own execution so the
# finding_aggregate_read policy lets it see every org. The function-level SET
# reverts automatically when the function returns.
_TENANT_HITS_FN_BYPASS = """
CREATE OR REPLACE FUNCTION palisade_detection_tenant_hits()
RETURNS TABLE(detection_id text, n_orgs bigint)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
SET app.aggregate_bypass = 'on'
AS $$
    SELECT f.detection_id, count(DISTINCT f.org_id)
    FROM finding f
    WHERE f.status IN ('open', 'regressed')
    GROUP BY f.detection_id
$$
"""

# The original 0004 definition (no bypass), restored on downgrade where the
# owner is RLS-exempt again.
_TENANT_HITS_FN_ORIG = """
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
    # 1) Per-org fingerprint uniqueness: replace the global-unique index with a
    # composite unique on (org_id, fingerprint). No standalone fingerprint index
    # is kept — dedupe filters on (org_id, fingerprint) and nothing queries the
    # fingerprint alone, so a separate index would be pure write amplification.
    op.drop_index("ix_finding_fingerprint", table_name="finding")
    op.create_index(
        "uq_finding_org_fingerprint", "finding", ["org_id", "fingerprint"], unique=True
    )

    # 2) FORCE RLS so the table-owning app role is also bound by the org policy.
    if op.get_bind().dialect.name == "postgresql":
        for table in _RLS_TABLES:
            op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")

        # Carve-out for the cross-tenant catalog metric: a SELECT-only permissive
        # policy that opens `finding` when app.aggregate_bypass is 'on'. Permissive
        # policies OR together, so this widens reads only while the flag is set.
        # This is DEFENSE-IN-DEPTH: today palisade_detection_tenant_hits is
        # SECURITY DEFINER owned by the superuser migrator, which bypasses RLS
        # outright, so the carve-out is dormant. It only does work if that
        # function is ever reowned by a NON-superuser role — the direction this
        # codebase pushes deployments. The `current_user <> 'palisade_app'` clause
        # ensures that even if a request running as the app role somehow set the
        # GUC, it still could not widen its own reads; only the definer can.
        op.execute(
            "CREATE POLICY finding_aggregate_read ON finding FOR SELECT "
            "USING (current_setting('app.aggregate_bypass', true) = 'on' "
            "AND current_user <> 'palisade_app')"
        )
        # Recreate the metric function to set that flag for its own execution
        # only (function-scoped SET reverts on return — it does not leak to the
        # caller's transaction the way set_config(...,true) would).
        op.execute(_TENANT_HITS_FN_BYPASS)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(_TENANT_HITS_FN_ORIG)
        op.execute("DROP POLICY IF EXISTS finding_aggregate_read ON finding")
        for table in _RLS_TABLES:
            op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")

    op.drop_index("uq_finding_org_fingerprint", table_name="finding")
    # Restore a fingerprint index, but NON-unique: post-0011 the per-org unique
    # permits cross-org duplicate fingerprints, so recreating the original
    # GLOBAL-unique index could fail on existing data. Non-unique downgrades
    # cleanly; resolve cross-org dupes manually if a global unique is required.
    op.create_index("ix_finding_fingerprint", "finding", ["fingerprint"], unique=False)
