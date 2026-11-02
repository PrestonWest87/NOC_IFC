"""Add administrator-managed contacts for monitored locations.

Revision ID: 20261102_0006
Revises: 20261013_0005
Create Date: 2026-11-02
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261102_0006"
down_revision = "20261013_0005"
branch_labels = None
depends_on = None


def upgrade():
    """Create the optional one-to-many site-contact table and its lookup index."""
    bind = op.get_bind()
    inspector = inspect(bind)
    if not inspector.has_table("monitored_location_contacts"):
        op.create_table(
            "monitored_location_contacts",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("monitored_location_id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(length=128), nullable=True),
            sa.Column("phone", sa.String(length=64), nullable=True),
            sa.Column("email", sa.String(length=254), nullable=True),
            sa.Column("sort_order", sa.Integer(), server_default=sa.text("0"), nullable=False),
            sa.ForeignKeyConstraint(
                ["monitored_location_id"],
                ["monitored_locations.id"],
                ondelete="CASCADE",
            ),
            sa.PrimaryKeyConstraint("id"),
        )

    index_names = {
        index["name"] for index in inspect(bind).get_indexes("monitored_location_contacts")
    }
    if "ix_monitored_location_contacts_monitored_location_id" not in index_names:
        op.create_index(
            "ix_monitored_location_contacts_monitored_location_id",
            "monitored_location_contacts",
            ["monitored_location_id"],
        )


def downgrade():
    """Reject downgrade because it would discard site contact records."""
    raise RuntimeError(
        "This operational-state migration is forward-only; restore a verified backup instead."
    )
