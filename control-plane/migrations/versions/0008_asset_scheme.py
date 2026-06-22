"""asset scheme

Revision ID: 0008_asset_scheme
Revises: 0007_alert_quiet_hours
Create Date: 2026-06-21

Adds an optional URL scheme ("http"|"https") to asset, set by the agent when a
service's transport is known and null otherwise. Existing rows default to null.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0008_asset_scheme"
down_revision: Union[str, None] = "0007_alert_quiet_hours"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("asset", sa.Column("scheme", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("asset", "scheme")
