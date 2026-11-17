"""Add Operational impact to the saved Maintenance Notification default.

Revision ID: 20261117_0018
Revises: 20261117_0017
Create Date: 2026-11-17
"""
import re

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261117_0018"
down_revision = "20261117_0017"
branch_labels = None
depends_on = None


OPERATIONAL_IMPACT = re.compile(r"\{\{\s*operational_impact\s*\}\}")


def _add_operational_impact(body):
    """Insert the new field after disruption without replacing custom wording."""
    body = (body or "").replace("\r\n", "\n").replace("\r", "\n")
    if OPERATIONAL_IMPACT.search(body):
        return body
    line = "Operational impact: {{operational_impact}}"
    marker = "Disruption: {{disruption}}"
    if marker in body:
        return body.replace(marker, f"{marker}\n{line}", 1)
    marker = "Department performing the change:"
    if marker in body:
        return body.replace(marker, f"{line}\n{marker}", 1)
    separator = "" if not body or body.endswith("\n") else "\n"
    return body + separator + line


def upgrade():
    """Add Operational impact to an existing Maintenance Notification default."""
    bind = op.get_bind()
    if not inspect(bind).has_table("operational_email_templates"):
        return
    row = bind.execute(sa.text(
        "SELECT default_body FROM operational_email_templates "
        "WHERE template_key = 'maintenance_notice'"
    )).first()
    if not row:
        return
    body = _add_operational_impact(row.default_body)
    if body == row.default_body:
        return
    bind.execute(
        sa.text(
            "UPDATE operational_email_templates "
            "SET default_body = :body, updated_at = CURRENT_TIMESTAMP "
            "WHERE template_key = 'maintenance_notice'"
        ),
        {"body": body},
    )


def downgrade():
    """Reject downgrade because saved template wording may be administrator-owned."""
    raise RuntimeError(
        "This Operational Email migration is forward-only; restore a verified backup instead."
    )
