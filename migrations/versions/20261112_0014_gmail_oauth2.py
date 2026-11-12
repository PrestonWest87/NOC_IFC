"""Replace Gmail App Password settings with OAuth2 refresh-token credentials.

Revision ID: 20261112_0014
Revises: 20261112_0013
Create Date: 2026-11-12
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261112_0014"
down_revision = "20261112_0013"
branch_labels = None
depends_on = None


def upgrade():
    """Add Gmail OAuth fields and clear the now-unused legacy App Password."""
    bind = op.get_bind()
    inspector = inspect(bind)
    if not inspector.has_table("system_config"):
        return

    present = {column["name"] for column in inspector.get_columns("system_config")}
    for column in (
        sa.Column("gmail_smtp_client_id", sa.String(length=255), nullable=True),
        sa.Column("gmail_smtp_client_secret", sa.Text(), nullable=True),
        sa.Column("gmail_smtp_refresh_token", sa.Text(), nullable=True),
    ):
        if column.name not in present:
            op.add_column("system_config", column)

    present = {column["name"] for column in inspect(bind).get_columns("system_config")}
    if "gmail_smtp_password" in present:
        bind.execute(sa.text(
            "UPDATE system_config SET active_smtp_provider = 'smtp' "
            "WHERE active_smtp_provider = 'gmail' AND gmail_smtp_password IS NOT NULL "
            "AND (gmail_smtp_client_id IS NULL OR gmail_smtp_client_id = '' "
            "OR gmail_smtp_client_secret IS NULL OR gmail_smtp_client_secret = '' "
            "OR gmail_smtp_refresh_token IS NULL OR gmail_smtp_refresh_token = '')"
        ))
        bind.execute(sa.text("UPDATE system_config SET gmail_smtp_password = NULL"))


def downgrade():
    """Reject downgrade because it would discard OAuth credentials and restore passwords."""
    raise RuntimeError(
        "This Gmail OAuth migration is forward-only; restore a verified backup instead."
    )
