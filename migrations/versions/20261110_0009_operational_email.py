"""Persist operational email templates, messages, attachments, and delivery attempts.

Revision ID: 20261110_0009
Revises: 20261105_0008
Create Date: 2026-11-10
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261110_0009"
down_revision = "20261105_0008"
branch_labels = None
depends_on = None


def upgrade():
    """Create the additive operational-email tables and due/history indexes."""
    bind = op.get_bind()
    inspector = inspect(bind)

    if not inspector.has_table("operational_email_templates"):
        op.create_table(
            "operational_email_templates",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("template_key", sa.String(length=64), nullable=False),
            sa.Column("label", sa.String(length=128), nullable=False),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("default_subject", sa.String(length=500), nullable=False),
            sa.Column("default_body", sa.Text(), nullable=False),
            sa.Column("default_to", sa.Text(), nullable=False),
            sa.Column("default_cc", sa.Text(), nullable=False),
            sa.Column("default_bcc", sa.Text(), nullable=False),
            sa.Column("updated_by_user_id", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["updated_by_user_id"], ["users.id"]),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("template_key"),
        )

    if not inspector.has_table("operational_emails"):
        op.create_table(
            "operational_emails",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("template_key", sa.String(length=64), nullable=False),
            sa.Column("created_by_user_id", sa.Integer(), nullable=True),
            sa.Column("parent_email_id", sa.Integer(), nullable=True),
            sa.Column("subject", sa.String(length=500), nullable=False),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("fields_json", sa.JSON(), nullable=False),
            sa.Column("to_recipients", sa.JSON(), nullable=False),
            sa.Column("cc_recipients", sa.JSON(), nullable=False),
            sa.Column("bcc_recipients", sa.JSON(), nullable=False),
            sa.Column("schedule_type", sa.String(length=16), nullable=False),
            sa.Column("timezone", sa.String(length=64), nullable=False),
            sa.Column("scheduled_at", sa.DateTime(), nullable=True),
            sa.Column("recurrence_time", sa.String(length=5), nullable=True),
            sa.Column("recurrence_weekday", sa.Integer(), nullable=True),
            sa.Column("next_run_at", sa.DateTime(), nullable=True),
            sa.Column("processing_started_at", sa.DateTime(), nullable=True),
            sa.Column("status", sa.String(length=24), nullable=False),
            sa.Column("last_sent_at", sa.DateTime(), nullable=True),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"]),
            sa.ForeignKeyConstraint(["parent_email_id"], ["operational_emails.id"]),
            sa.PrimaryKeyConstraint("id"),
        )

    if not inspector.has_table("operational_email_attachments"):
        op.create_table(
            "operational_email_attachments",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("operational_email_id", sa.Integer(), nullable=False),
            sa.Column("filename", sa.String(length=120), nullable=False),
            sa.Column("content_type", sa.String(length=100), nullable=False),
            sa.Column("content", sa.LargeBinary(), nullable=False),
            sa.Column("size_bytes", sa.Integer(), nullable=False),
            sa.ForeignKeyConstraint(
                ["operational_email_id"], ["operational_emails.id"], ondelete="CASCADE"
            ),
            sa.PrimaryKeyConstraint("id"),
        )

    if not inspector.has_table("operational_email_deliveries"):
        op.create_table(
            "operational_email_deliveries",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("operational_email_id", sa.Integer(), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False),
            sa.Column("sender_address", sa.String(length=254), nullable=True),
            sa.Column("to_recipients", sa.JSON(), nullable=False),
            sa.Column("cc_recipients", sa.JSON(), nullable=False),
            sa.Column("bcc_recipients", sa.JSON(), nullable=False),
            sa.Column("subject", sa.String(length=500), nullable=False),
            sa.Column("body", sa.Text(), nullable=False),
            sa.Column("fields_json", sa.JSON(), nullable=False),
            sa.Column("attachment_names", sa.JSON(), nullable=False),
            sa.Column("attempted_at", sa.DateTime(), nullable=False),
            sa.Column("sent_at", sa.DateTime(), nullable=True),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.ForeignKeyConstraint(
                ["operational_email_id"], ["operational_emails.id"], ondelete="CASCADE"
            ),
            sa.PrimaryKeyConstraint("id"),
        )

    inspector = inspect(bind)
    index_definitions = {
        "operational_email_templates": [
            ("ix_operational_email_templates_id", ["id"], True),
            ("ix_operational_email_templates_template_key", ["template_key"], True),
        ],
        "operational_emails": [
            ("ix_operational_emails_id", ["id"], True),
            ("ix_operational_emails_template_key", ["template_key"], False),
            ("ix_operational_emails_created_by_user_id", ["created_by_user_id"], False),
            ("ix_operational_emails_parent_email_id", ["parent_email_id"], False),
            ("ix_operational_emails_schedule_type", ["schedule_type"], False),
            ("ix_operational_emails_next_run_at", ["next_run_at"], False),
            ("ix_operational_emails_status", ["status"], False),
            ("ix_operational_emails_created_at", ["created_at"], False),
            ("ix_operational_emails_due", ["status", "next_run_at"], False),
        ],
        "operational_email_attachments": [
            ("ix_operational_email_attachments_id", ["id"], True),
            ("ix_operational_email_attachments_operational_email_id", ["operational_email_id"], False),
        ],
        "operational_email_deliveries": [
            ("ix_operational_email_deliveries_id", ["id"], True),
            ("ix_operational_email_deliveries_operational_email_id", ["operational_email_id"], False),
            ("ix_operational_email_deliveries_status", ["status"], False),
            ("ix_operational_email_deliveries_attempted_at", ["attempted_at"], False),
            ("ix_operational_email_deliveries_sent_at", ["sent_at"], False),
        ],
    }
    for table_name, definitions in index_definitions.items():
        if not inspector.has_table(table_name):
            continue
        existing = {index["name"] for index in inspector.get_indexes(table_name)}
        for index_name, columns, unique in definitions:
            if index_name not in existing:
                op.create_index(index_name, table_name, columns, unique=unique)


def downgrade():
    """Reject downgrade because sent-email history is operational evidence."""
    raise RuntimeError(
        "This operational-email migration is forward-only; restore a verified backup instead."
    )
