"""Remove A/Z location placeholders from saved Fiber Outage templates.

Revision ID: 20261117_0017
Revises: 20261117_0016
Create Date: 2026-11-17
"""
import re

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261117_0017"
down_revision = "20261117_0016"
branch_labels = None
depends_on = None


FIBER_OUTAGE_TEMPLATE_KEYS = {
    "fiber_outage",
    "fiber_outage_onpage",
    "fiber_outage_update",
    "fiber_outage_resolution",
}
ENDPOINT_PLACEHOLDER_LINE = re.compile(
    r"(?im)^.*\{\{\s*(?:a_location|z_location)\s*\}\}.*(?:\r?\n|$)"
)
ENDPOINT_PLACEHOLDER = re.compile(r"\{\{\s*(?:a_location|z_location)\s*\}\}", re.IGNORECASE)


def upgrade():
    """Remove endpoint placeholders from outage defaults while retaining other text."""
    bind = op.get_bind()
    if not inspect(bind).has_table("operational_email_templates"):
        return

    rows = bind.execute(sa.text(
        "SELECT template_key, default_subject, default_body "
        "FROM operational_email_templates"
    )).mappings().all()
    for row in rows:
        if row["template_key"] not in FIBER_OUTAGE_TEMPLATE_KEYS:
            continue
        subject = ENDPOINT_PLACEHOLDER.sub("", row["default_subject"] or "").strip()
        body = ENDPOINT_PLACEHOLDER_LINE.sub("", row["default_body"] or "")
        if not subject:
            subject = row["template_key"].replace("_", " ").title()
        if subject == row["default_subject"] and body == row["default_body"]:
            continue
        bind.execute(
            sa.text(
                "UPDATE operational_email_templates "
                "SET default_subject = :subject, default_body = :body, updated_at = CURRENT_TIMESTAMP "
                "WHERE template_key = :template_key"
            ),
            {"template_key": row["template_key"], "subject": subject, "body": body},
        )


def downgrade():
    """Reject downgrade because removed template text may have been administrator-owned."""
    raise RuntimeError(
        "This Operational Email migration is forward-only; restore a verified backup instead."
    )
