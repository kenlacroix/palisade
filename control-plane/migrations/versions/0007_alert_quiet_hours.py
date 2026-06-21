"""alert quiet hours

Revision ID: 0007_alert_quiet_hours
Revises: 0006_scan_target_manifest
Create Date: 2026-06-21

Adds timezone-aware quiet-hours config to alert_rule (local HH:MM bounds, IANA
tz, and a defer|suppress mode) and alert.deferred_until. Alerts matched during a
rule's quiet window are recorded but withheld: "suppress" drops them, "defer"
holds them until the window ends, when release_due_deferred flips them back to
pending on the next ingest/scan cycle. Existing rows default to no quiet hours.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0007_alert_quiet_hours"
down_revision: Union[str, None] = "0006_scan_target_manifest"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("alert_rule", sa.Column("quiet_hours_start", sa.String(), nullable=True))
    op.add_column("alert_rule", sa.Column("quiet_hours_end", sa.String(), nullable=True))
    op.add_column(
        "alert_rule",
        sa.Column("quiet_hours_tz", sa.String(), nullable=False, server_default="UTC"),
    )
    op.add_column(
        "alert_rule",
        sa.Column("quiet_hours_mode", sa.String(), nullable=False, server_default="defer"),
    )
    op.add_column("alert", sa.Column("deferred_until", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("alert", "deferred_until")
    op.drop_column("alert_rule", "quiet_hours_mode")
    op.drop_column("alert_rule", "quiet_hours_tz")
    op.drop_column("alert_rule", "quiet_hours_end")
    op.drop_column("alert_rule", "quiet_hours_start")
