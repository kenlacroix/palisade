"""cvss and triage columns

Revision ID: 0002_cvss_triage
Revises: 0001_initial
Create Date: 2026-06-21
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0002_cvss_triage"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("detection", sa.Column("cvss", sa.Float(), nullable=True))
    op.add_column("finding", sa.Column("triage_priority", sa.String(), nullable=True))
    op.add_column("finding", sa.Column("triage_score", sa.Integer(), nullable=True))
    op.add_column("finding", sa.Column("triage_rationale", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("finding", "triage_rationale")
    op.drop_column("finding", "triage_score")
    op.drop_column("finding", "triage_priority")
    op.drop_column("detection", "cvss")
