"""Add grouping metadata for company-specific Operational Email deliveries.

Revision ID: 20261120_0022
Revises: 20261120_0021
Create Date: 2026-11-20
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261120_0022"
down_revision = "20261120_0021"
branch_labels = None
depends_on = None


def upgrade():
    """Add nullable group metadata without changing existing email snapshots."""
    bind = op.get_bind()
    inspector = inspect(bind)
    if not inspector.has_table("operational_emails"):
        return
    columns = {column["name"] for column in inspector.get_columns("operational_emails")}
    if "group_id" not in columns:
        op.add_column("operational_emails", sa.Column("group_id", sa.String(length=36), nullable=True))
    if "group_company" not in columns:
        op.add_column("operational_emails", sa.Column("group_company", sa.String(length=200), nullable=True))
    indexes = {index["name"] for index in inspect(bind).get_indexes("operational_emails")}
    if "ix_operational_emails_group_id" not in indexes:
        op.create_index("ix_operational_emails_group_id", "operational_emails", ["group_id"])


def downgrade():
    """Reject downgrade because group membership identifies saved delivery history."""
    raise RuntimeError(
        "This Operational Email migration is forward-only; restore a verified backup instead."
    )
