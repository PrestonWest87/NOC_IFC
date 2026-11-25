"""Update unused Fiber outage status and ONPAGE reference fields.

Revision ID: 20261125_0025
Revises: 20261125_0024
Create Date: 2026-11-25
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261125_0025"
down_revision = "20261125_0024"
branch_labels = None
depends_on = None


BODY_UPDATES = {
    "fiber_outage_update": (
        (
            "FIBER OUTAGE PROGRESS UPDATE\n\n"
            "Location: {{site}}\n"
            "Network Orders/Circuit IDs: {{network_orders}}\n"
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
            "Network Orders/Circuit IDs: {{network_orders}}\n"
            "Fiber contact information: {{contact}}\n"
            "Original outage start: {{outage_start}} {{timezone}}\n"
            "Update time: {{update_time}} {{timezone}}\n"
            "Progress update: {{update_details}}\n"
            "Updated restoration estimate: {{restoration_estimate}}\n"
            "Next update: {{next_update}}\n"
            "Ticket / carrier reference: {{reference}}"
        ),
    ),
    "fiber_outage_resolution": (
        (
            "FIBER SERVICE RESTORED\n\n"
            "Location: {{site}}\n"
            "Network Orders/Circuit IDs: {{network_orders}}\n"
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
            "Network Orders/Circuit IDs: {{network_orders}}\n"
            "Fiber contact information: {{contact}}\n"
            "Original outage start: {{outage_start}} {{timezone}}\n"
            "Service restored at: {{resolution_time}} {{timezone}}\n"
            "Resolution details: {{resolution_details}}\n"
            "Follow-up / monitoring plan: {{follow_up}}\n"
            "Ticket / carrier reference: {{reference}}"
        ),
    ),
    "fiber_outage_onpage": (
        (
            "FIBER OUTAGE ONPAGE NOTIFICATION\n\n"
            "Location: {{site}}\n"
            "Network Orders/Circuit IDs: {{network_orders}}\n"
            "Fiber contact information: {{contact}}\n"
            "Outage start: {{outage_start}} {{timezone}}\n"
            "Service impact: {{impact}}\n"
            "Ticket / carrier reference: {{reference}}"
        ),
        (
            "FIBER OUTAGE ONPAGE NOTIFICATION\n\n"
            "Location: {{site}}\n"
            "Network Orders/Circuit IDs: {{network_orders}}\n"
            "Rcount: {{rcount}}\n"
            "Maps URL: {{maps_url}}\n"
            "Closest Hand Hole: {{closest_hand_hole}}\n"
            "Fiber contact information: {{contact}}\n"
            "Outage start: {{outage_start}} {{timezone}}\n"
            "Service impact: {{impact}}\n"
            "Ticket / carrier reference: {{reference}}"
        ),
    ),
}


def upgrade():
    """Refresh exact shipped bodies without replacing administrator-customized wording."""
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
