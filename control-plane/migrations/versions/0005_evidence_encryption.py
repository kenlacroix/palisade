"""evidence-at-rest encryption: per-org wrapped data key + sealed evidence

Revision ID: 0005_evidence_encryption
Revises: 0004_mtls_catalog_aggregate
Create Date: 2026-06-21

Adds the org_encryption_key table (one wrapped data key per org) and the
finding.evidence_enc column holding evidence sealed with AES-256-GCM under that
key. Encryption is opt-in via PALISADE_EVIDENCE_KEK; with no key configured the
columns stay null/empty and evidence remains plaintext JSON. org_encryption_key
is intentionally NOT under Row-Level Security: lookups filter by org_id in code
and background workers read it without the per-request org GUC.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0005_evidence_encryption"
down_revision: Union[str, None] = "0004_mtls_catalog_aggregate"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "org_encryption_key",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("org_id", sa.String(), sa.ForeignKey("org.id"), nullable=False),
        sa.Column("wrapped_dek", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("org_id", name="uq_org_encryption_key_org"),
    )
    op.create_index(
        "ix_org_encryption_key_org_id", "org_encryption_key", ["org_id"]
    )
    op.add_column("finding", sa.Column("evidence_enc", sa.LargeBinary(), nullable=True))


def downgrade() -> None:
    op.drop_column("finding", "evidence_enc")
    op.drop_index("ix_org_encryption_key_org_id", table_name="org_encryption_key")
    op.drop_table("org_encryption_key")
