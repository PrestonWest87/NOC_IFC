"""Refresh untouched Fiber Operational Email defaults for the new routing rules.

Revision ID: 20261116_0015
Revises: 20261112_0014
Create Date: 2026-11-16
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261116_0015"
down_revision = "20261112_0014"
branch_labels = None
depends_on = None


def _refresh_body(template_key, old_body, new_body):
    """Refresh exact shipped copy while preserving administrator-customized text."""
    bind = op.get_bind()
    if not inspect(bind).has_table("operational_email_templates"):
        return
    bind.execute(
        sa.text(
            "UPDATE operational_email_templates "
            "SET default_body = :new_body, updated_at = CURRENT_TIMESTAMP "
            "WHERE template_key = :template_key AND default_body = :old_body"
        ),
        {"template_key": template_key, "old_body": old_body, "new_body": new_body},
    )


def upgrade():
    """Refresh Fiber defaults only when they still match the previous shipped copy."""
    _refresh_body(
        "fiber_maintenance_notice",
        (
            "FIBER MAINTENANCE NOTIFICATION\n\n"
            "Ticket title: {{ticket_title}}\n"
            "A location: {{a_location}}\n"
            "Z location: {{z_location}}\n"
            "Network Orders: {{network_orders}}\n"
            "Company: {{company}}\n"
            "Planned work: {{work_scope}}\n"
            "Maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Risk: {{impact}}\n"
            "Disruption: {{disruption}}\n"
            "MOP Type: {{mop_type}}\n"
            "Departmental impact: {{departmental_impact}}\n"
            "Fiber contact information: {{contact}}\n"
            "Ticket / change reference: {{reference}}"
        ),
        (
            "FIBER MAINTENANCE NOTIFICATION\n\n"
            "Ticket title: {{ticket_title}}\n"
            "A location: {{a_location}}\n"
            "Z location: {{z_location}}\n"
            "Network Orders/Circuit IDs: {{network_orders}}\n"
            "Company: {{company}}\n"
            "Planned work: {{work_scope}}\n"
            "Maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Risk: {{impact}}\n"
            "Disruption: {{disruption}}\n"
            "MOP Type: {{mop_type}}\n"
            "Expected impact: {{expected_impact}}\n"
            "Department performing the change: {{change_department}}\n"
            "Fiber contact information: {{contact}}\n"
            "Ticket / change reference: {{reference}}"
        ),
    )
    _refresh_body(
        "fiber_outage",
        (
            "FIBER OUTAGE NOTIFICATION\n\n"
            "Location: {{site}}\n"
            "A location: {{a_location}}\n"
            "Z location: {{z_location}}\n"
            "Network Orders: {{network_orders}}\n"
            "Company: {{company}}\n"
            "Fiber contact information: {{contact}}\n"
            "Outage start: {{outage_start}} {{timezone}}\n"
            "Service impact: {{impact}}\n"
            "Estimated restoration: {{restoration_estimate}}\n"
            "Requested action: {{requested_action}}\n"
            "Ticket / carrier reference: {{reference}}"
        ),
        (
            "FIBER OUTAGE NOTIFICATION\n\n"
            "Location: {{site}}\n"
            "A location: {{a_location}}\n"
            "Z location: {{z_location}}\n"
            "Network Orders/Circuit IDs: {{network_orders}}\n"
            "Company: {{company}}\n"
            "Fiber contact information: {{contact}}\n"
            "Outage start: {{outage_start}} {{timezone}}\n"
            "Service impact: {{impact}}\n"
            "Ticket / carrier reference: {{reference}}"
        ),
    )
    _refresh_body(
        "fiber_outage_update",
        (
            "FIBER OUTAGE PROGRESS UPDATE\n\n"
            "Location: {{site}}\n"
            "A location: {{a_location}}\n"
            "Z location: {{z_location}}\n"
            "Network Orders: {{network_orders}}\n"
            "Company: {{company}}\n"
            "Fiber contact information: {{contact}}\n"
            "Original outage start: {{outage_start}} {{timezone}}\n"
            "Update time: {{update_time}} {{timezone}}\n"
            "Current status: {{current_status}}\n"
            "Progress update: {{update_details}}\n"
            "Updated restoration estimate: {{restoration_estimate}}\n"
            "Next update: {{next_update}}\n"
            "Ticket / carrier reference: {{reference}}"
        ),
        (
            "FIBER OUTAGE PROGRESS UPDATE\n\n"
            "Location: {{site}}\n"
            "A location: {{a_location}}\n"
            "Z location: {{z_location}}\n"
            "Network Orders/Circuit IDs: {{network_orders}}\n"
            "Company: {{company}}\n"
            "Fiber contact information: {{contact}}\n"
            "Original outage start: {{outage_start}} {{timezone}}\n"
            "Update time: {{update_time}} {{timezone}}\n"
            "Current status: {{current_status}}\n"
            "Progress update: {{update_details}}\n"
            "Updated restoration estimate: {{restoration_estimate}}\n"
            "Next update: {{next_update}}\n"
            "Ticket / carrier reference: {{reference}}"
        ),
    )
    _refresh_body(
        "fiber_outage_resolution",
        (
            "FIBER SERVICE RESTORED\n\n"
            "Location: {{site}}\n"
            "A location: {{a_location}}\n"
            "Z location: {{z_location}}\n"
            "Network Orders: {{network_orders}}\n"
            "Company: {{company}}\n"
            "Fiber contact information: {{contact}}\n"
            "Original outage start: {{outage_start}} {{timezone}}\n"
            "Service restored at: {{resolution_time}} {{timezone}}\n"
            "Resolution details: {{resolution_details}}\n"
            "Current service status: {{service_status}}\n"
            "Follow-up / monitoring plan: {{follow_up}}\n"
            "Ticket / carrier reference: {{reference}}"
        ),
        (
            "FIBER SERVICE RESTORED\n\n"
            "Location: {{site}}\n"
            "A location: {{a_location}}\n"
            "Z location: {{z_location}}\n"
            "Network Orders/Circuit IDs: {{network_orders}}\n"
            "Company: {{company}}\n"
            "Fiber contact information: {{contact}}\n"
            "Original outage start: {{outage_start}} {{timezone}}\n"
            "Service restored at: {{resolution_time}} {{timezone}}\n"
            "Resolution details: {{resolution_details}}\n"
            "Current service status: {{service_status}}\n"
            "Follow-up / monitoring plan: {{follow_up}}\n"
            "Ticket / carrier reference: {{reference}}"
        ),
    )


def downgrade():
    """Reject downgrade because these message defaults are operator configuration."""
    raise RuntimeError(
        "This Operational Email migration is forward-only; restore a verified backup instead."
    )
