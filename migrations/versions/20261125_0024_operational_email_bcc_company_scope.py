"""Mark circuit-filtered BCC-only Operational Email copies.

Revision ID: 20261125_0024
Revises: 20261123_0023
Create Date: 2026-11-25
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261125_0024"
down_revision = "20261123_0023"
branch_labels = None
depends_on = None


def upgrade():
    """Add an additive flag for message snapshots addressed only through BCC."""
    bind = op.get_bind()
    if not inspect(bind).has_table("operational_emails"):
        return
    columns = {column["name"] for column in inspect(bind).get_columns("operational_emails")}
    if "bcc_copy_only" not in columns:
        op.add_column(
            "operational_emails",
            sa.Column("bcc_copy_only", sa.Boolean(), nullable=False, server_default=sa.false()),
        )


def downgrade():
    """Preserve delivery history; restore a verified backup to reverse this revision."""
    raise RuntimeError(
        "This Operational Email migration is forward-only; restore a verified backup instead."
    )
