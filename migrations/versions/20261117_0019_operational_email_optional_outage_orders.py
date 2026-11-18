"""Remove Network Orders placeholders from shipped Fiber Outage subjects.

Revision ID: 20261117_0019
Revises: 20261117_0018
Create Date: 2026-11-17
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261117_0019"
down_revision = "20261117_0018"
branch_labels = None
depends_on = None


SHIPPED_SUBJECTS = {
    "fiber_outage": (
        "FIBER OUTAGE — {{site}} — {{network_orders}}",
        "FIBER OUTAGE — {{site}}",
    ),
    "fiber_outage_onpage": (
        "FIBER OUTAGE ONPAGE — {{site}} — {{network_orders}}",
        "FIBER OUTAGE ONPAGE — {{site}}",
    ),
    "fiber_outage_update": (
        "FIBER OUTAGE UPDATE — {{site}} — {{network_orders}}",
        "FIBER OUTAGE UPDATE — {{site}}",
    ),
    "fiber_outage_resolution": (
        "FIBER OUTAGE RESOLVED — {{site}} — {{network_orders}}",
        "FIBER OUTAGE RESOLVED — {{site}}",
    ),
}


def upgrade():
    """Update exact shipped subjects so Network Orders remain optional."""
    bind = op.get_bind()
    if not inspect(bind).has_table("operational_email_templates"):
        return
    for template_key, (old_subject, new_subject) in SHIPPED_SUBJECTS.items():
        bind.execute(
            sa.text(
                "UPDATE operational_email_templates "
                "SET default_subject = :new_subject, updated_at = CURRENT_TIMESTAMP "
                "WHERE template_key = :template_key AND default_subject = :old_subject"
            ),
            {
                "template_key": template_key,
                "old_subject": old_subject,
                "new_subject": new_subject,
            },
        )


def downgrade():
    """Reject downgrade because template subjects are operator configuration."""
    raise RuntimeError(
        "This Operational Email migration is forward-only; restore a verified backup instead."
    )
