"""Add editable operational integration settings and an explicit LLM provider.

Revision ID: 20261105_0008
Revises: 20261103_0007
Create Date: 2026-11-05
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261105_0008"
down_revision = "20261103_0007"
branch_labels = None
depends_on = None


def _add_missing_columns(table_name, columns):
    """Add only absent columns so partially adopted legacy SQLite schemas upgrade."""
    bind = op.get_bind()
    inspector = inspect(bind)
    if not inspector.has_table(table_name):
        return
    present = {column["name"] for column in inspector.get_columns(table_name)}
    for column in columns:
        if column.name not in present:
            op.add_column(table_name, column)


def upgrade():
    """Add nullable environment overrides and preserve legacy LLM behavior."""
    _add_missing_columns(
        "system_config",
        [
            sa.Column(
                "llm_provider", sa.String(length=32), nullable=False,
                server_default="openai_compatible",
            ),
            sa.Column("risk_alert_recipients", sa.Text(), nullable=True),
            sa.Column("remedyforce_ticket_email", sa.Text(), nullable=True),
            sa.Column("noc_notify_email", sa.Text(), nullable=True),
            sa.Column("noc_onpage_email", sa.Text(), nullable=True),
            sa.Column("itnetwork_onpage_email", sa.Text(), nullable=True),
            sa.Column("elastic_url", sa.Text(), nullable=True),
            sa.Column("elastic_api_key", sa.Text(), nullable=True),
            sa.Column("elastic_verify_certs", sa.Boolean(), nullable=True),
            sa.Column("elastic_ca_certs", sa.Text(), nullable=True),
            sa.Column("elastic_request_timeout", sa.Float(), nullable=True),
            sa.Column("elastic_max_results", sa.Integer(), nullable=True),
            sa.Column("crime_alert_sms", sa.Text(), nullable=True),
            sa.Column("crime_alert_email", sa.Text(), nullable=True),
        ],
    )


def downgrade():
    """Reject downgrade because it would discard configured provider destinations and credentials."""
    raise RuntimeError(
        "This operational configuration migration is forward-only; restore a verified backup instead."
    )
