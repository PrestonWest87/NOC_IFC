"""Add associated circuit/network-order IDs to the Settings directory.

Revision ID: 20261118_0020
Revises: 20261117_0019
Create Date: 2026-11-18
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261118_0020"
down_revision = "20261117_0019"
branch_labels = None
depends_on = None


def upgrade():
    """Add an empty association list to existing circuit records."""
    bind = op.get_bind()
    inspector = inspect(bind)
    if not inspector.has_table("network_order_circuits"):
        return
    columns = {column["name"] for column in inspector.get_columns("network_order_circuits")}
    if "associated_circuit_network_order_ids" not in columns:
        op.add_column(
            "network_order_circuits",
            sa.Column(
                "associated_circuit_network_order_ids",
                sa.JSON(),
                nullable=False,
                server_default=sa.text("'[]'"),
            ),
        )


def downgrade():
    """Reject downgrade rather than discard administrator-maintained associations."""
    raise RuntimeError(
        "This network-order association migration is forward-only; restore a verified backup instead."
    )
