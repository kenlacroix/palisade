"""scan target manifest for precise finding resolution

Revision ID: 0006_scan_target_manifest
Revises: 0005_evidence_encryption
Create Date: 2026-06-21

Adds scan.targets, the [{asset_id, detection_ids}] manifest of exactly what a
scan covered. Findings ingest resolves open findings only for (asset, detection)
pairs present in the manifest but not re-reported; pairs absent from the manifest
were not scanned and are left untouched. Existing rows default to an empty
manifest and fall back to the previous best-effort by-asset resolution.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0006_scan_target_manifest"
down_revision: Union[str, None] = "0005_evidence_encryption"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scan",
        sa.Column("targets", sa.JSON(), nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("scan", "targets")
