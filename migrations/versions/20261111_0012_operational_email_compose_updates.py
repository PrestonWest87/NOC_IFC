"""Refresh untouched Operational Email defaults for new compose fields.

Revision ID: 20261111_0012
Revises: 20261111_0011
Create Date: 2026-11-11
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261111_0012"
down_revision = "20261111_0011"
branch_labels = None
depends_on = None


def _refresh_default(template_key, *, old_subject=None, new_subject=None, old_body=None, new_body=None):
    """Refresh exact shipped text only; preserve administrator-customized defaults."""
    bind = op.get_bind()
    if not inspect(bind).has_table("operational_email_templates"):
        return
    if old_subject is not None:
        bind.execute(
            sa.text(
                "UPDATE operational_email_templates "
                "SET default_subject = :new_value, updated_at = CURRENT_TIMESTAMP "
                "WHERE template_key = :template_key AND default_subject = :old_value"
            ),
            {"template_key": template_key, "old_value": old_subject, "new_value": new_subject},
        )
    if old_body is not None:
        bind.execute(
            sa.text(
                "UPDATE operational_email_templates "
                "SET default_body = :new_value, updated_at = CURRENT_TIMESTAMP "
                "WHERE template_key = :template_key AND default_body = :old_value"
            ),
            {"template_key": template_key, "old_value": old_body, "new_value": new_body},
        )


def upgrade():
    """Update shipped subjects/bodies only when they still equal the previous defaults."""
    _refresh_default(
        "maintenance_notice",
        old_subject="Planned Maintenance — {{site}} — {{start_time}}",
        new_subject="PLANNED MAINTENANCE — {{ticket_title}}",
        old_body=(
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
        new_body=(
            "PLANNED MAINTENANCE NOTIFICATION\n\n"
            "Ticket title: {{ticket_title}}\n"
            "Site / service: {{site}}\n"
            "Planned work: {{work_scope}}\n"
            "Maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Risk: {{impact}}\n"
            "Disruption: {{disruption}}\n"
            "Departmental impact: {{departmental_impact}}\n"
            "Operations contact: {{contact}}\n"
            "Reference: {{reference}}\n\n"
            "Please contact the Network Operations Center with questions or concerns."
        ),
    )
    _refresh_default(
        "fiber_maintenance_notice",
        old_subject="FIBER MAINTENANCE — {{a_location}} to {{z_location}} — {{start_time}}",
        new_subject="FIBER MAINTENANCE — {{ticket_title}}",
        old_body=(
            "FIBER MAINTENANCE NOTIFICATION\n\n"
            "A location: {{a_location}}\n"
            "Z location: {{z_location}}\n"
            "Circuit IDs: {{circuit_ids}}\n"
            "Planned work: {{work_scope}}\n"
            "Maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Expected impact: {{impact}}\n"
            "Departmental impact: {{departmental_impact}}\n"
            "Operations / field contact: {{contact}}\n"
            "Ticket / change reference: {{reference}}"
        ),
        new_body=(
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
    )
    _refresh_default(
        "fiber_outage",
        old_subject="FIBER OUTAGE — {{site}} — {{circuit}}",
        new_subject="FIBER OUTAGE — {{site}} — {{network_orders}}",
        old_body=(
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
        new_body=(
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
    )
    _refresh_default(
        "fiber_outage_update",
        old_subject="FIBER OUTAGE UPDATE — {{site}} — {{circuit}}",
        new_subject="FIBER OUTAGE UPDATE — {{site}} — {{network_orders}}",
        old_body=(
            "FIBER OUTAGE PROGRESS UPDATE\n\n"
            "Site / route: {{site}}\n"
            "Circuit: {{circuit}}\n"
            "Original outage start: {{outage_start}} {{timezone}}\n"
            "Update time: {{update_time}} {{timezone}}\n"
            "Current status: {{current_status}}\n"
            "Progress update: {{update_details}}\n"
            "Updated restoration estimate: {{restoration_estimate}}\n"
            "Next update: {{next_update}}\n"
            "Ticket / carrier reference: {{reference}}"
        ),
        new_body=(
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
    )
    _refresh_default(
        "fiber_outage_resolution",
        old_subject="FIBER OUTAGE RESOLVED — {{site}} — {{circuit}}",
        new_subject="FIBER OUTAGE RESOLVED — {{site}} — {{network_orders}}",
        old_body=(
            "FIBER SERVICE RESTORED\n\n"
            "Site / route: {{site}}\n"
            "Circuit: {{circuit}}\n"
            "Original outage start: {{outage_start}} {{timezone}}\n"
            "Service restored at: {{resolution_time}} {{timezone}}\n"
            "Resolution details: {{resolution_details}}\n"
            "Current service status: {{service_status}}\n"
            "Follow-up / monitoring plan: {{follow_up}}\n"
            "Ticket / carrier reference: {{reference}}"
        ),
        new_body=(
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
    )
    _refresh_default(
        "maintenance_complete",
        old_body=(
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
        new_body=(
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
            "Ticket / change reference: {{reference}}\n\n"
            "This message closes the previously issued maintenance notification."
        ),
    )


def downgrade():
    """Reject downgrade because these message defaults are operational configuration."""
    raise RuntimeError(
        "This Operational Email migration is forward-only; restore a verified backup instead."
    )
