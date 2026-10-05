"""Persist the operator-selected needs-dispatch state on active alerts.

Revision ID: 20261005_0003
Revises: 20261002_0002
Create Date: 2026-10-05
"""
from alembic import op
from sqlalchemy import Boolean, Column, inspect, text


revision = "20261005_0003"
down_revision = "20261002_0002"
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if "needs_dispatch" not in {
        column["name"] for column in inspect(bind).get_columns("solarwinds_alerts")
    }:
        op.add_column(
            "solarwinds_alerts",
            Column(
                "needs_dispatch",
                Boolean(),
                nullable=False,
                server_default=text("0"),
            ),
        )


def downgrade():
    raise RuntimeError(
        "This operational-state migration is forward-only; restore a verified backup instead."
    )
