"""Add signatures and refresh untouched Operational Email template defaults.

Revision ID: 20261110_0010
Revises: 20261110_0009
Create Date: 2026-11-10
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261110_0010"
down_revision = "20261110_0009"
branch_labels = None
depends_on = None


def _add_signature_columns(table_name, columns):
    """Add nullable signature columns/FK with SQLite batch recreation and retry safety."""
    bind = op.get_bind()
    inspector = inspect(bind)
    if not inspector.has_table(table_name):
        return
    present = {column["name"] for column in inspector.get_columns(table_name)}
    has_signature_fk = any(
        foreign_key.get("constrained_columns") == ["signature_id"]
        and foreign_key.get("referred_table") == "operational_email_signatures"
        for foreign_key in inspector.get_foreign_keys(table_name)
    )
    missing_columns = [column for column in columns if column[0] not in present]
    if not missing_columns and has_signature_fk:
        return
    with op.batch_alter_table(table_name, recreate="always") as batch_op:
        for column_name, column_type in missing_columns:
            batch_op.add_column(sa.Column(column_name, column_type, nullable=True))
        if not has_signature_fk:
            batch_op.create_foreign_key(
                f"fk_{table_name}_signature_id",
                "operational_email_signatures",
                ["signature_id"],
                ["id"],
            )


def _refresh_unedited_default(template_key, *, old_subject=None, new_subject=None, old_body=None, new_body=None):
    """Refresh only exact shipped defaults; administrator-customized text remains intact."""
    bind = op.get_bind()
    inspector = inspect(bind)
    if not inspector.has_table("operational_email_templates"):
        return
    if old_subject is not None:
        bind.execute(
            sa.text(
                "UPDATE operational_email_templates SET default_subject = :new_value, updated_at = CURRENT_TIMESTAMP "
                "WHERE template_key = :template_key AND default_subject = :old_value"
            ),
            {"template_key": template_key, "old_value": old_subject, "new_value": new_subject},
        )
    if old_body is not None:
        bind.execute(
            sa.text(
                "UPDATE operational_email_templates SET default_body = :new_value, updated_at = CURRENT_TIMESTAMP "
                "WHERE template_key = :template_key AND default_body = :old_value"
            ),
            {"template_key": template_key, "old_value": old_body, "new_value": new_body},
        )


def upgrade():
    """Add administrator-managed signatures and safe default-template refreshes."""
    bind = op.get_bind()
    inspector = inspect(bind)
    if not inspector.has_table("operational_email_signatures"):
        op.create_table(
            "operational_email_signatures",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("name", sa.String(length=100), nullable=False),
            sa.Column("content", sa.Text(), nullable=False),
            sa.Column("is_active", sa.Boolean(), nullable=False),
            sa.Column("is_default", sa.Boolean(), nullable=False),
            sa.Column("created_by_user_id", sa.Integer(), nullable=True),
            sa.Column("updated_by_user_id", sa.Integer(), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["created_by_user_id"], ["users.id"]),
            sa.ForeignKeyConstraint(["updated_by_user_id"], ["users.id"]),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("name"),
        )

    _add_signature_columns(
        "operational_emails",
        [
            ("signature_id", sa.Integer()),
            ("signature_name", sa.String(length=100)),
            ("signature_content", sa.Text()),
        ],
    )
    _add_signature_columns(
        "operational_email_deliveries",
        [
            ("signature_id", sa.Integer()),
            ("signature_name", sa.String(length=100)),
        ],
    )

    inspector = inspect(bind)
    index_definitions = {
        "operational_email_signatures": [
            ("ix_operational_email_signatures_id", ["id"], True),
            ("ix_operational_email_signatures_name", ["name"], True),
            ("ix_operational_email_signatures_is_active", ["is_active"], False),
            ("ix_operational_email_signatures_is_default", ["is_default"], False),
        ],
        "operational_emails": [
            ("ix_operational_emails_signature_id", ["signature_id"], False),
        ],
        "operational_email_deliveries": [
            ("ix_operational_email_deliveries_signature_id", ["signature_id"], False),
        ],
    }
    for table_name, definitions in index_definitions.items():
        if not inspector.has_table(table_name):
            continue
        existing = {index["name"] for index in inspector.get_indexes(table_name)}
        for index_name, columns, unique in definitions:
            if index_name not in existing:
                op.create_index(index_name, table_name, columns, unique=unique)

    _refresh_unedited_default(
        "maintenance_notice",
        old_body=(
            "PLANNED MAINTENANCE NOTIFICATION\n\n"
            "Site / service: {{site}}\n"
            "Planned work: {{work_scope}}\n"
            "Maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Expected impact: {{impact}}\n"
            "Operations contact: {{contact}}\n"
            "Reference: {{reference}}\n\n"
            "Please contact the Network Operations Center with questions or concerns."
        ),
        new_body=(
            "PLANNED MAINTENANCE NOTIFICATION\n\n"
            "Site / service: {{site}}\n"
            "Planned work: {{work_scope}}\n"
            "Maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Expected impact: {{impact}}\n"
            "Departmental impact: {{departmental_impact}}\n"
            "Operations contact: {{contact}}\n"
            "Reference: {{reference}}\n\n"
            "Please contact the Network Operations Center with questions or concerns."
        ),
    )
    _refresh_unedited_default(
        "outage_dispatch",
        old_body=(
            "TECHNICIAN DISPATCH REQUEST\n\n"
            "Priority: {{priority}}\n"
            "Site: {{site}}\n"
            "System / circuit: {{system}}\n"
            "Outage start: {{outage_start}}\n"
            "Service impact: {{impact}}\n"
            "Requested action: {{dispatch_action}}\n"
            "On-site contact: {{contact}}\n"
            "Ticket / incident reference: {{reference}}\n\n"
            "Please confirm dispatch and provide an estimated arrival time."
        ),
        new_body=(
            "TECHNICIAN DISPATCH REQUEST\n\n"
            "Priority: {{priority}}\n"
            "Site: {{site}}\n"
            "System / circuit: {{system}}\n"
            "Outage start: {{outage_start}} {{timezone}}\n"
            "Service impact: {{impact}}\n"
            "Requested action: {{dispatch_action}}\n"
            "On-site contact: {{contact}}\n"
            "Ticket / incident reference: {{reference}}\n\n"
            "Please confirm dispatch and provide an estimated arrival time."
        ),
    )
    _refresh_unedited_default(
        "fiber_outage",
        old_body=(
            "FIBER OUTAGE NOTIFICATION\n\n"
            "Site / route: {{site}}\n"
            "Fiber circuit / segment: {{circuit}}\n"
            "Provider: {{provider}}\n"
            "Outage start: {{outage_start}}\n"
            "Service impact: {{impact}}\n"
            "Estimated restoration: {{restoration_estimate}}\n"
            "Requested action: {{requested_action}}\n"
            "Ticket / carrier reference: {{reference}}"
        ),
        new_body=(
            "FIBER OUTAGE NOTIFICATION\n\n"
            "Site / route: {{site}}\n"
            "Fiber circuit / segment: {{circuit}}\n"
            "Provider: {{provider}}\n"
            "Outage start: {{outage_start}} {{timezone}}\n"
            "Service impact: {{impact}}\n"
            "Estimated restoration: {{restoration_estimate}}\n"
            "Requested action: {{requested_action}}\n"
            "Ticket / carrier reference: {{reference}}"
        ),
    )
    _refresh_unedited_default(
        "after_hours_onpage",
        old_body=(
            "URGENT AFTER-HOURS ONPAGE — ACKNOWLEDGEMENT REQUIRED\n\n"
            "Severity / priority: {{severity}}\n"
            "Site: {{site}}\n"
            "Node / system: {{system}}\n"
            "Incident / alert: {{incident}}\n"
            "Observed at: {{observed_at}}\n"
            "Operational impact: {{impact}}\n"
            "Required response: {{requested_response}}\n"
            "Callback / NOC contact: {{callback}}\n\n"
            "Please acknowledge this page and contact the NOC immediately."
        ),
        new_body=(
            "URGENT AFTER-HOURS ONPAGE — ACKNOWLEDGEMENT REQUIRED\n\n"
            "Severity / priority: {{severity}}\n"
            "Site: {{site}}\n"
            "Node / system: {{system}}\n"
            "Incident / alert: {{incident}}\n"
            "Observed at: {{observed_at}} {{timezone}}\n"
            "Operational impact: {{impact}}\n"
            "Required response: {{requested_response}}\n"
            "Callback / NOC contact: {{callback}}\n\n"
            "Please acknowledge this page and contact the NOC immediately."
        ),
    )
    _refresh_unedited_default(
        "maintenance_complete",
        old_body=(
            "MAINTENANCE COMPLETE\n\n"
            "Site / service: {{site}}\n"
            "Work performed: {{work_performed}}\n"
            "Original maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Actual completion: {{completion_time}}\n"
            "Service status: {{service_status}}\n"
            "Follow-up notes: {{follow_up}}\n"
            "Ticket / change reference: {{reference}}\n\n"
            "This message closes the previously issued maintenance notification."
        ),
        new_body=(
            "MAINTENANCE COMPLETE\n\n"
            "Site / service: {{site}}\n"
            "Work performed: {{work_performed}}\n"
            "Original maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Expected impact: {{impact}}\n"
            "Departmental impact: {{departmental_impact}}\n"
            "Actual completion: {{completion_time}}\n"
            "Service status: {{service_status}}\n"
            "Follow-up notes: {{follow_up}}\n"
            "Ticket / change reference: {{reference}}\n\n"
            "This message closes the previously issued maintenance notification."
        ),
    )
    _refresh_unedited_default(
        "morning_report",
        old_subject="Morning Operations Report — {{report_date}} — {{title}}",
        new_subject="Morning Operations Report",
        old_body=(
            "MORNING OPERATIONS REPORT\n\n"
            "Report date: {{report_date}}\n"
            "Reporting window: {{reporting_window}}\n"
            "Title: {{title}}\n\n"
            "EXECUTIVE SUMMARY\n{{summary}}\n\n"
            "Supporting files are attached."
        ),
        new_body="{{shift_analysis}}",
    )


def downgrade():
    """Reject downgrade because signatures and updated message defaults are operational records."""
    raise RuntimeError(
        "This Operational Email enhancement migration is forward-only; restore a verified backup instead."
    )
