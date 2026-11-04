"""Track NWS fetch health and alert lifecycle metadata.

Revision ID: 20261103_0007
Revises: 20261102_0006
Create Date: 2026-11-03
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261103_0007"
down_revision = "20261102_0006"
branch_labels = None
depends_on = None


def _add_missing_columns(table_name, columns):
    """Add only absent fields so partially adopted legacy databases can upgrade."""
    bind = op.get_bind()
    inspector = inspect(bind)
    if not inspector.has_table(table_name):
        return
    present = {column["name"] for column in inspector.get_columns(table_name)}
    for column in columns:
        if column.name not in present:
            op.add_column(table_name, column)


def upgrade():
    """Add provider freshness fields and NWS CAP alert lifecycle columns."""
    _add_missing_columns(
        "geojson_cache",
        [
            sa.Column("last_attempt_at", sa.DateTime(), nullable=True),
            sa.Column("last_success_at", sa.DateTime(), nullable=True),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("last_http_status", sa.Integer(), nullable=True),
            sa.Column("last_duration_ms", sa.Integer(), nullable=True),
            sa.Column("retry_after_at", sa.DateTime(), nullable=True),
            sa.Column("etag", sa.String(length=512), nullable=True),
            sa.Column("last_modified", sa.String(length=128), nullable=True),
            sa.Column("feature_count", sa.Integer(), nullable=True),
            sa.Column("coverage_summary", sa.JSON(), nullable=True),
        ],
    )
    _add_missing_columns(
        "regional_hazards",
        [
            sa.Column("last_seen_at", sa.DateTime(), nullable=True),
            sa.Column("status", sa.String(length=24), nullable=False, server_default="unknown"),
            sa.Column("sent_at", sa.DateTime(), nullable=True),
            sa.Column("effective_at", sa.DateTime(), nullable=True),
            sa.Column("onset_at", sa.DateTime(), nullable=True),
            sa.Column("expires_at", sa.DateTime(), nullable=True),
            sa.Column("event_ending_at", sa.DateTime(), nullable=True),
            sa.Column("message_type", sa.String(length=16), nullable=True),
            sa.Column("references_json", sa.JSON(), nullable=True),
            sa.Column("coverage_scope", sa.String(length=24), nullable=True),
            sa.Column("coverage_precision", sa.String(length=32), nullable=True),
        ],
    )

    bind = op.get_bind()
    inspector = inspect(bind)
    if inspector.has_table("regional_hazards"):
        indexes = {index["name"] for index in inspector.get_indexes("regional_hazards")}
        for index_name, columns in (
            ("ix_regional_hazards_last_seen_at", ["last_seen_at"]),
            ("ix_regional_hazards_status", ["status"]),
            ("ix_regional_hazards_expires_at", ["expires_at"]),
            ("ix_regional_hazards_status_expires_at", ["status", "expires_at"]),
        ):
            if index_name not in indexes:
                op.create_index(index_name, "regional_hazards", columns)


def downgrade():
    """Reject downgrade because alert lifecycle state is operational evidence."""
    raise RuntimeError(
        "This operational-state migration is forward-only; restore a verified backup instead."
    )
