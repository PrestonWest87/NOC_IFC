"""Update saved Operational Email defaults for the revised Fiber fields.

Revision ID: 20261117_0016
Revises: 20261116_0015
Create Date: 2026-11-17
"""
import re

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "20261117_0016"
down_revision = "20261116_0015"
branch_labels = None
depends_on = None


FIBER_TEMPLATE_KEYS = {
    "fiber_maintenance_notice",
    "fiber_outage",
    "fiber_outage_onpage",
    "fiber_outage_update",
    "fiber_outage_resolution",
}
COMPANY_PLACEHOLDER_LINE = re.compile(r"(?im)^.*\{\{\s*company\s*\}\}.*(?:\r?\n|$)")
COMPANY_PLACEHOLDER = re.compile(r"\{\{\s*company\s*\}\}")
CHANGE_DEPARTMENT_PLACEHOLDER = re.compile(r"\{\{\s*change_department\s*\}\}")
CHANGE_DEPARTMENT_PLACEHOLDER_LINE = re.compile(
    r"(?im)^.*\{\{\s*change_department\s*\}\}.*(?:\r?\n|$)"
)


def _add_change_department_line(body):
    """Add the new Maintenance Notification field to saved defaults if missing."""
    if "{{change_department}}" in body:
        return body
    line = "Department performing the change: {{change_department}}\n"
    if "Departmental impact:" in body:
        return body.replace("Departmental impact:", f"{line}Departmental impact:", 1)
    separator = "" if not body or body.endswith(("\n", "\r")) else "\n"
    return body + separator + line.rstrip()


def upgrade():
    """Move the department placeholder and remove company fields, preserving other text."""
    bind = op.get_bind()
    if not inspect(bind).has_table("operational_email_templates"):
        return

    rows = bind.execute(sa.text(
        "SELECT template_key, default_subject, default_body "
        "FROM operational_email_templates"
    )).mappings().all()
    for row in rows:
        template_key = row["template_key"]
        if template_key not in FIBER_TEMPLATE_KEYS and template_key != "maintenance_notice":
            continue
        subject = COMPANY_PLACEHOLDER.sub("", row["default_subject"] or "").strip()
        body = COMPANY_PLACEHOLDER_LINE.sub("", row["default_body"] or "")
        if template_key in FIBER_TEMPLATE_KEYS:
            subject = CHANGE_DEPARTMENT_PLACEHOLDER.sub("", subject).strip()
            body = CHANGE_DEPARTMENT_PLACEHOLDER_LINE.sub("", body)
        if template_key == "maintenance_notice":
            body = _add_change_department_line(body)
        if not subject:
            subject = template_key.replace("_", " ").title()
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
