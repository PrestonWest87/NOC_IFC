"""Add administrator-managed email contact and network-order directories.

Revision ID: 20261111_0011
Revises: 20261110_0010
Create Date: 2026-11-11
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261111_0011"
down_revision = "20261110_0010"
branch_labels = None
depends_on = None


def upgrade():
    """Create additive, ordered reference tables without altering existing records."""
    bind = op.get_bind()
    inspector = inspect(bind)
    if not inspector.has_table("fiber_email_contacts"):
        op.create_table(
            "fiber_email_contacts",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("company", sa.String(length=200), nullable=False),
            sa.Column("email", sa.String(length=254), nullable=False),
            sa.Column("phone", sa.String(length=64), nullable=True),
            sa.Column("sort_order", sa.Integer(), server_default=sa.text("0"), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
    if not inspector.has_table("onpage_email_contacts"):
        op.create_table(
            "onpage_email_contacts",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("department", sa.String(length=128), nullable=False),
            sa.Column("email", sa.String(length=254), nullable=False),
            sa.Column("sort_order", sa.Integer(), server_default=sa.text("0"), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )
    if not inspector.has_table("network_order_circuits"):
        op.create_table(
            "network_order_circuits",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("a_location", sa.String(length=250), nullable=False),
            sa.Column("z_location", sa.String(length=250), nullable=False),
            sa.Column("circuit_network_order_id", sa.String(length=200), nullable=False),
            sa.Column("company", sa.String(length=200), nullable=False),
            sa.Column("sort_order", sa.Integer(), server_default=sa.text("0"), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )

    for table_name in ("fiber_email_contacts", "onpage_email_contacts", "network_order_circuits"):
        existing = {index["name"] for index in inspect(bind).get_indexes(table_name)}
        index_name = f"ix_{table_name}_id"
        if index_name not in existing:
            op.create_index(index_name, table_name, ["id"], unique=True)


def downgrade():
    """Reject downgrade because it would discard administrator-maintained references."""
    raise RuntimeError(
        "This settings-reference migration is forward-only; restore a verified backup instead."
    )
