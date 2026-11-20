"""Group Fiber Maintenance circuit IDs with their A/Z locations.

Revision ID: 20261120_0021
Revises: 20261118_0020
Create Date: 2026-11-20
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261120_0021"
down_revision = "20261118_0020"
branch_labels = None
depends_on = None


BODY_UPDATES = {
    "fiber_maintenance_notice": (
        (
            "FIBER MAINTENANCE NOTIFICATION\n\n"
            "Ticket title: {{ticket_title}}\n"
            "A location: {{a_location}}\n"
            "Z location: {{z_location}}\n"
            "Network Orders/Circuit IDs: {{network_orders}}\n"
            "Planned work: {{work_scope}}\n"
            "Maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Risk: {{impact}}\n"
            "Disruption: {{disruption}}\n"
            "MOP Type: {{mop_type}}\n"
            "Expected impact: {{expected_impact}}\n"
            "Fiber contact information: {{contact}}\n"
            "Ticket / change reference: {{reference}}"
        ),
        (
            "FIBER MAINTENANCE NOTIFICATION\n\n"
            "Ticket title: {{ticket_title}}\n"
            "Network Orders/Circuit IDs and A/Z locations:\n"
            "{{network_orders}}\n"
            "Planned work: {{work_scope}}\n"
            "Maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Risk: {{impact}}\n"
            "Disruption: {{disruption}}\n"
            "MOP Type: {{mop_type}}\n"
            "Expected impact: {{expected_impact}}\n"
            "Fiber contact information: {{contact}}\n"
            "Ticket / change reference: {{reference}}"
        ),
    ),
    "maintenance_start": (
        (
            "MAINTENANCE START NOTIFICATION\n\n"
            "Ticket title: {{ticket_title}}\n"
            "Site / service: {{site}}\n"
            "Planned work: {{work_scope}}\n"
            "Scheduled maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Network Orders/Circuit IDs: {{network_orders}}\n"
            "A location: {{a_location}}\n"
            "Z location: {{z_location}}\n"
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
            "Operational impact: {{operational_impact}}\n"
            "Departmental impact: {{departmental_impact}}\n"
            "MOP Type: {{mop_type}}\n"
            "Expected impact: {{expected_impact}}\n"
            "Contact: {{contact}}\n"
            "Ticket / change reference: {{reference}}\n\n"
            "This notification confirms the scheduled maintenance has started."
        ),
    ),
}


def upgrade():
    """Refresh exact shipped bodies without overwriting administrator wording."""
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
