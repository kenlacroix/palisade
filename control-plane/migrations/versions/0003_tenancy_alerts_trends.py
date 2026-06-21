"""multi-tenancy, alerting, and posture-snapshot tables

Revision ID: 0003_tenancy_alerts_trends
Revises: 0002_cvss_triage
Create Date: 2026-06-21

Adds the M1 (users/sessions/memberships, single-use enroll tokens), M3
(alert channels/rules/history), and real posture-trend (daily snapshots)
schema. On Postgres it also enables Row-Level Security on the tenant data
tables, keyed on the `app.current_org_id` session GUC the app sets per request
(SPEC section 6). RLS DDL is skipped on SQLite, which has no equivalent.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0003_tenancy_alerts_trends"
down_revision: Union[str, None] = "0002_cvss_triage"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Tenant data tables that get Postgres RLS keyed on org_id.
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


def upgrade() -> None:
    op.create_table(
        "app_user",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("email", sa.String(), nullable=False, unique=True),
        sa.Column("name", sa.String(), nullable=False, server_default=""),
        sa.Column("password_hash", sa.String(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_app_user_email", "app_user", ["email"], unique=True)

    op.create_table(
        "membership",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("app_user.id"), nullable=False),
        sa.Column("org_id", sa.String(), sa.ForeignKey("org.id"), nullable=False),
        sa.Column("role", sa.String(), nullable=False, server_default="viewer"),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("user_id", "org_id", name="uq_membership_user_org"),
    )
    op.create_index("ix_membership_user_id", "membership", ["user_id"])
    op.create_index("ix_membership_org_id", "membership", ["org_id"])

    op.create_table(
        "user_session",
        sa.Column("token", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("app_user.id"), nullable=False),
        sa.Column("org_id", sa.String(), sa.ForeignKey("org.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_user_session_user_id", "user_session", ["user_id"])

    op.create_table(
        "enroll_token",
        sa.Column("token", sa.String(), primary_key=True),
        sa.Column("org_id", sa.String(), sa.ForeignKey("org.id"), nullable=False),
        sa.Column("label", sa.String(), nullable=False, server_default=""),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.Column("agent_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "alert_channel",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_id", sa.String(), sa.ForeignKey("org.id"), nullable=False),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False, server_default=""),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_alert_channel_org_id", "alert_channel", ["org_id"])

    op.create_table(
        "alert_rule",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_id", sa.String(), sa.ForeignKey("org.id"), nullable=False),
        sa.Column("name", sa.String(), nullable=False, server_default=""),
        sa.Column("min_severity", sa.String(), nullable=False, server_default="high"),
        sa.Column("on_events", sa.JSON(), nullable=False),
        sa.Column("channel_id", sa.String(), sa.ForeignKey("alert_channel.id"), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_alert_rule_org_id", "alert_rule", ["org_id"])

    op.create_table(
        "alert",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_id", sa.String(), sa.ForeignKey("org.id"), nullable=False),
        sa.Column("finding_id", sa.String(), sa.ForeignKey("finding.id"), nullable=False),
        sa.Column("rule_id", sa.String(), nullable=True),
        sa.Column("channel_id", sa.String(), nullable=True),
        sa.Column("event", sa.String(), nullable=False, server_default="new"),
        sa.Column("severity", sa.String(), nullable=False, server_default="info"),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("error", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("sent_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_alert_org_id", "alert", ["org_id"])

    op.create_table(
        "posture_snapshot",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_id", sa.String(), sa.ForeignKey("org.id"), nullable=False),
        sa.Column("day", sa.String(), nullable=False),
        sa.Column("captured_at", sa.DateTime(), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("critical", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("high", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("medium", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("assets_count", sa.Integer(), nullable=False, server_default="0"),
        sa.UniqueConstraint("org_id", "day", name="uq_snapshot_org_day"),
    )
    op.create_index("ix_posture_snapshot_org_id", "posture_snapshot", ["org_id"])

    if op.get_bind().dialect.name == "postgresql":
        for table in _RLS_TABLES:
            op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
            op.execute(
                f"CREATE POLICY org_isolation ON {table} "
                "USING (org_id = current_setting('app.current_org_id', true)) "
                "WITH CHECK (org_id = current_setting('app.current_org_id', true))"
            )


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        for table in _RLS_TABLES:
            op.execute(f"DROP POLICY IF EXISTS org_isolation ON {table}")
            op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    op.drop_table("posture_snapshot")
    op.drop_table("alert")
    op.drop_table("alert_rule")
    op.drop_table("alert_channel")
    op.drop_table("enroll_token")
    op.drop_table("user_session")
    op.drop_table("membership")
    op.drop_index("ix_app_user_email", table_name="app_user")
    op.drop_table("app_user")
