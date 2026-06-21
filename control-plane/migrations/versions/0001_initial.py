"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-06-21
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "org",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("plan", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "agent",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_id", sa.String(), sa.ForeignKey("org.id"), nullable=False),
        sa.Column("secret", sa.String(), nullable=False),
        sa.Column("hostname", sa.String(), nullable=False),
        sa.Column("os", sa.String(), nullable=False),
        sa.Column("arch", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("last_discover_at", sa.DateTime(), nullable=True),
        sa.Column("last_scan_issued_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_agent_secret", "agent", ["secret"], unique=True)

    op.create_table(
        "asset",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_id", sa.String(), sa.ForeignKey("org.id"), nullable=False),
        sa.Column("agent_id", sa.String(), sa.ForeignKey("agent.id"), nullable=True),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("service", sa.String(), nullable=False),
        sa.Column("product", sa.String(), nullable=True),
        sa.Column("version", sa.String(), nullable=True),
        sa.Column("exposure", sa.String(), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("org_id", "host", "port", name="uq_asset_host_port"),
    )
    op.create_index("ix_asset_host", "asset", ["host"], unique=False)

    op.create_table(
        "detection",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("cve", sa.String(), nullable=True),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=False),
        sa.Column("engine", sa.String(), nullable=False),
        sa.Column("match_service", sa.String(), nullable=False),
        sa.Column("match_versions", sa.String(), nullable=False),
        sa.Column("spec", sa.JSON(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("signature", sa.String(), nullable=False),
    )

    op.create_table(
        "scan",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_id", sa.String(), sa.ForeignKey("org.id"), nullable=False),
        sa.Column("agent_id", sa.String(), sa.ForeignKey("agent.id"), nullable=True),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("assets_count", sa.Integer(), nullable=False),
    )

    op.create_table(
        "finding",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_id", sa.String(), sa.ForeignKey("org.id"), nullable=False),
        sa.Column("asset_id", sa.String(), sa.ForeignKey("asset.id"), nullable=False),
        sa.Column("detection_id", sa.String(), sa.ForeignKey("detection.id"), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=True),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("mute_reason", sa.String(), nullable=True),
        sa.Column("mute_until", sa.DateTime(), nullable=True),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_finding_fingerprint", "finding", ["fingerprint"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_finding_fingerprint", table_name="finding")
    op.drop_table("finding")
    op.drop_table("scan")
    op.drop_table("detection")
    op.drop_index("ix_asset_host", table_name="asset")
    op.drop_table("asset")
    op.drop_index("ix_agent_secret", table_name="agent")
    op.drop_table("agent")
    op.drop_table("org")
