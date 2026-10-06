"""Backfill site scope for legacy webhook alert timeline events.

Revision ID: 20261005_0004
Revises: 20261005_0003
Create Date: 2026-10-05
"""
import sqlalchemy as sa
from alembic import op


revision = "20261005_0004"
down_revision = "20261005_0003"
branch_labels = None
depends_on = None


def infer_legacy_webhook_alert_site_name(message, monitored_site_names):
    """Return the known site suffix from the exact webhook alert format only."""
    prefix = "[CRITICAL] Alert: "
    if not isinstance(message, str) or not message.startswith(prefix):
        return None

    alert_details, separator, site_name = message.rpartition(") at ")
    if not separator or not site_name or site_name not in monitored_site_names:
        return None

    node_name, separator, device_type = alert_details[len(prefix):].rpartition(" (")
    if not separator or not node_name.strip() or not device_type.strip():
        return None
    return site_name


def upgrade():
    bind = op.get_bind()
    timeline_events = sa.table(
        "timeline_events",
        sa.column("id", sa.Integer),
        sa.column("source", sa.String),
        sa.column("event_type", sa.String),
        sa.column("message", sa.String),
        sa.column("site_name", sa.String(255)),
    )
    monitored_locations = sa.table(
        "monitored_locations",
        sa.column("name", sa.String),
    )
    known_site_names = {
        str(name)
        for name in bind.execute(sa.select(monitored_locations.c.name)).scalars()
        if name
    }
    if not known_site_names:
        return

    legacy_events = bind.execute(
        sa.select(timeline_events.c.id, timeline_events.c.message).where(
            timeline_events.c.source == "Webhook",
            timeline_events.c.event_type == "Alert",
            timeline_events.c.site_name.is_(None),
        )
    ).all()
    updates = []
    for event_id, message in legacy_events:
        site_name = infer_legacy_webhook_alert_site_name(message, known_site_names)
        if site_name:
            updates.append({"_event_id": event_id, "_site_name": site_name})

    if updates:
        bind.execute(
            timeline_events.update()
            .where(timeline_events.c.id == sa.bindparam("_event_id"))
            .where(timeline_events.c.site_name.is_(None))
            .values(site_name=sa.bindparam("_site_name")),
            updates,
        )


def downgrade():
    raise RuntimeError(
        "This timeline site-scope backfill is forward-only; restore a verified backup instead."
    )
