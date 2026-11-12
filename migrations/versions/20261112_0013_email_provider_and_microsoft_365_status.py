"""Add the Gmail sender profile and Microsoft 365 public-status metadata.

Revision ID: 20261112_0013
Revises: 20261111_0012
Create Date: 2026-11-12
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261112_0013"
down_revision = "20261111_0012"
branch_labels = None
depends_on = None


def _add_missing_columns(table_name, columns):
    """Add absent columns to known tables, including supported partial upgrades."""
    bind = op.get_bind()
    inspector = inspect(bind)
    if not inspector.has_table(table_name):
        return
    present = {column["name"] for column in inspector.get_columns(table_name)}
    for column in columns:
        if column.name not in present:
            op.add_column(table_name, column)


def upgrade():
    """Preserve the existing SMTP sender while adding a selectable Gmail profile."""
    _add_missing_columns(
        "system_config",
        [
            sa.Column("active_smtp_provider", sa.String(length=16), nullable=False, server_default="smtp"),
            sa.Column("gmail_smtp_username", sa.String(length=254), nullable=True),
            sa.Column("gmail_smtp_password", sa.Text(), nullable=True),
            sa.Column("gmail_smtp_sender", sa.String(length=254), nullable=True),
            sa.Column("gmail_smtp_enabled", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        ],
    )
    _add_missing_columns(
        "operational_email_deliveries",
        [sa.Column("smtp_provider", sa.String(length=16), nullable=True)],
    )
    _add_missing_columns(
        "cloud_outages",
        [
            sa.Column("external_id", sa.String(length=255), nullable=True),
            sa.Column("status_code", sa.String(length=64), nullable=True),
        ],
    )

    bind = op.get_bind()
    inspector = inspect(bind)
    if inspector.has_table("cloud_outages"):
        indexes = {index["name"] for index in inspector.get_indexes("cloud_outages")}
        if "uq_cloud_outages_provider_external_id" not in indexes:
            op.create_index(
                "uq_cloud_outages_provider_external_id",
                "cloud_outages",
                ["provider", "external_id"],
                unique=True,
            )

    if not inspect(bind).has_table("microsoft_365_status_state"):
        op.create_table(
            "microsoft_365_status_state",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("last_attempt_at", sa.DateTime(), nullable=True),
            sa.Column("last_success_at", sa.DateTime(), nullable=True),
            sa.Column("last_duration_ms", sa.Integer(), nullable=True),
            sa.Column("last_http_status", sa.Integer(), nullable=True),
            sa.Column("last_error", sa.String(length=500), nullable=True),
            sa.PrimaryKeyConstraint("id"),
        )


def downgrade():
    """Reject downgrade because it would discard sender settings and health history."""
    raise RuntimeError(
        "This email/status migration is forward-only; restore a verified backup instead."
    )
