"""enroll token expiry

Revision ID: 0009_enroll_token_expiry
Revises: 0008_asset_scheme
Create Date: 2026-06-21

Adds an optional expires_at to enroll_token so admin-minted tokens bound the
enrollment window (default 15 min). Existing and env-seeded bootstrap tokens
default to null and never expire.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0009_enroll_token_expiry"
down_revision: Union[str, None] = "0008_asset_scheme"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("enroll_token", sa.Column("expires_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    op.drop_column("enroll_token", "expires_at")
