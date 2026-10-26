"""Track successful on-page delivery per active SolarWinds node incident.

Revision ID: 20261013_0005
Revises: 20261005_0004
Create Date: 2026-10-13
"""
from alembic import op
from sqlalchemy import Column, DateTime, inspect


revision = "20261013_0005"
down_revision = "20261005_0004"
branch_labels = None
depends_on = None


def upgrade():
    """Add nullable per-incident on-page delivery time when the column is absent."""
    bind = op.get_bind()
    if "onpage_sent_at" not in {
        column["name"] for column in inspect(bind).get_columns("solarwinds_alerts")
    }:
        op.add_column(
            "solarwinds_alerts",
            Column("onpage_sent_at", DateTime(), nullable=True),
        )


def downgrade():
    """Reject downgrade so successful page-delivery history is not lost."""
    raise RuntimeError(
        "This operational-state migration is forward-only; restore a verified backup instead."
    )
