"""audit_log table

Revision ID: 0010_audit_log
Revises: 0009_enroll_token_expiry
Create Date: 2026-06-21

Adds the audit_log table (SPEC section 6): one row per privileged action,
keyed on org_id. On Postgres it enables Row-Level Security on the same
`app.current_org_id` GUC the other tenant tables use (migration 0003); skipped
on SQLite.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0010_audit_log"
down_revision: Union[str, None] = "0009_enroll_token_expiry"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_log",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_id", sa.String(), sa.ForeignKey("org.id"), nullable=False),
        sa.Column("actor", sa.String(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=True),
        sa.Column("at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_audit_log_org_id", "audit_log", ["org_id"])

    if op.get_bind().dialect.name == "postgresql":
        op.execute("ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY")
        op.execute(
            "CREATE POLICY org_isolation ON audit_log "
            "USING (org_id = current_setting('app.current_org_id', true)) "
            "WITH CHECK (org_id = current_setting('app.current_org_id', true))"
        )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP POLICY IF EXISTS org_isolation ON audit_log")
        op.execute("ALTER TABLE audit_log DISABLE ROW LEVEL SECURITY")

    op.drop_index("ix_audit_log_org_id", table_name="audit_log")
    op.drop_table("audit_log")
