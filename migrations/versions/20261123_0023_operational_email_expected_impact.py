"""Combine maintenance impact defaults into one Expected impact field.

Revision ID: 20261123_0023
Revises: 20261120_0022
Create Date: 2026-11-23
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261123_0023"
down_revision = "20261120_0022"
branch_labels = None
depends_on = None


BODY_UPDATES = {
    "maintenance_notice": (
        (
            "PLANNED MAINTENANCE NOTIFICATION\n\n"
            "Ticket title: {{ticket_title}}\n"
            "Site / service: {{site}}\n"
            "Planned work: {{work_scope}}\n"
            "Maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Risk: {{impact}}\n"
            "Disruption: {{disruption}}\n"
            "Operational impact: {{operational_impact}}\n"
            "Department performing the change: {{change_department}}\n"
            "Departmental impact: {{departmental_impact}}\n"
            "Operations contact: {{contact}}\n"
            "Reference: {{reference}}\n\n"
            "Please contact the Network Operations Center with questions or concerns."
        ),
        (
            "PLANNED MAINTENANCE NOTIFICATION\n\n"
            "Ticket title: {{ticket_title}}\n"
            "Site / service: {{site}}\n"
            "Planned work: {{work_scope}}\n"
            "Maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Risk: {{impact}}\n"
            "Disruption: {{disruption}}\n"
            "Department performing the change: {{change_department}}\n"
            "Expected impact: {{expected_impact}}\n"
            "Operations contact: {{contact}}\n"
            "Reference: {{reference}}\n\n"
            "Please contact the Network Operations Center with questions or concerns."
        ),
    ),
    "maintenance_start": (
        (
            "MAINTENANCE START NOTIFICATION\n\n"
            "Ticket title: {{ticket_title}}\n"
            "Site / service: {{site}}\n"
            "Planned work: {{work_scope}}\n"
            "Scheduled maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Network Orders/Circuit IDs and A/Z locations:\n"
            "{{network_orders}}\n"
            "Risk: {{impact}}\n"
            "Disruption: {{disruption}}\n"
            "Department performing the change: {{change_department}}\n"
            "Operational impact: {{operational_impact}}\n"
            "Departmental impact: {{departmental_impact}}\n"
            "MOP Type: {{mop_type}}\n"
            "Expected impact: {{expected_impact}}\n"
            "Contact: {{contact}}\n"
            "Ticket / change reference: {{reference}}\n\n"
            "This notification confirms the scheduled maintenance has started."
        ),
        (
            "MAINTENANCE START NOTIFICATION\n\n"
            "Ticket title: {{ticket_title}}\n"
            "Site / service: {{site}}\n"
            "Planned work: {{work_scope}}\n"
            "Scheduled maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Network Orders/Circuit IDs and A/Z locations:\n"
            "{{network_orders}}\n"
            "Risk: {{impact}}\n"
            "Disruption: {{disruption}}\n"
            "Department performing the change: {{change_department}}\n"
            "MOP Type: {{mop_type}}\n"
            "Expected impact: {{expected_impact}}\n"
            "Contact: {{contact}}\n"
            "Ticket / change reference: {{reference}}\n\n"
            "This notification confirms the scheduled maintenance has started."
        ),
    ),
    "maintenance_complete": (
        (
            "MAINTENANCE COMPLETE\n\n"
            "Ticket title: {{ticket_title}}\n"
            "Site / service: {{site}}\n"
            "Work performed: {{work_performed}}\n"
            "Original maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Risk: {{impact}}\n"
            "Disruption: {{disruption}}\n"
            "Departmental impact: {{departmental_impact}}\n"
            "Actual completion: {{completion_time}}\n"
            "Service status: {{service_status}}\n"
            "Follow-up notes: {{follow_up}}\n"
            "Ticket / change reference: {{reference}}\n"
            "{{fiber_details}}\n"
            "This message closes the previously issued maintenance notification."
        ),
        (
            "MAINTENANCE COMPLETE\n\n"
            "Ticket title: {{ticket_title}}\n"
            "Site / service: {{site}}\n"
            "Work performed: {{work_performed}}\n"
            "Original maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Risk: {{impact}}\n"
            "Disruption: {{disruption}}\n"
            "Expected impact: {{expected_impact}}\n"
            "Actual completion: {{completion_time}}\n"
            "Service status: {{service_status}}\n"
            "Follow-up notes: {{follow_up}}\n"
            "Ticket / change reference: {{reference}}\n"
            "{{fiber_details}}\n"
            "This message closes the previously issued maintenance notification."
        ),
    ),
}


def upgrade():
    """Refresh exact shipped maintenance bodies without replacing custom wording."""
    bind = op.get_bind()
    if not inspect(bind).has_table("operational_email_templates"):
        return
    for template_key, (old_body, new_body) in BODY_UPDATES.items():
        bind.execute(
            sa.text(
                "UPDATE operational_email_templates "
                "SET default_body = :new_body, updated_at = CURRENT_TIMESTAMP "
                "WHERE template_key = :template_key AND default_body = :old_body"
            ),
            {"template_key": template_key, "old_body": old_body, "new_body": new_body},
        )


def downgrade():
    """Reject downgrade because saved template wording is operator configuration."""
    raise RuntimeError(
        "This Operational Email migration is forward-only; restore a verified backup instead."
    )
