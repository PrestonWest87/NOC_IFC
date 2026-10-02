"""Adopt the legacy SQLite schema into Alembic revision tracking.

Revision ID: 20261002_0001
Revises:
Create Date: 2026-10-02
"""
from alembic import op
from sqlalchemy import inspect, text

from migrations.schema_v1 import Base as BaselineBase

revision = "20261002_0001"
down_revision = None
branch_labels = None
depends_on = None


# Historical SQLite column additions that were previously attempted on every
# startup. Definitions stay explicit here so future model changes require a new
# revision instead of being silently picked up by startup metadata.
LEGACY_COLUMNS = {
    "users": [
        ("account_type", "VARCHAR(20) NOT NULL DEFAULT 'individual'"),
        ("email", "VARCHAR(254)"),
        ("email_normalized", "VARCHAR(254)"),
        ("email_verified_at", "TIMESTAMP"),
        ("is_active", "BOOLEAN NOT NULL DEFAULT TRUE"),
        ("created_at", "TIMESTAMP"),
        ("last_login_at", "TIMESTAMP"),
        ("last_activity_at", "TIMESTAMP"),
        ("theme", "VARCHAR DEFAULT 'standard'"),
        ("default_shift", "VARCHAR DEFAULT 'No Shift'"),
    ],
    "registration_invites": [
        ("email", "VARCHAR(254) NOT NULL DEFAULT ''"),
        ("email_normalized", "VARCHAR(254) NOT NULL DEFAULT ''"),
        ("account_type", "VARCHAR(20) NOT NULL DEFAULT 'individual'"),
    ],
    "roles": [("allowed_site_types", "JSON")],
    "timeline_events": [("site_name", "VARCHAR(255)")],
    "articles": [
        ("ingested_at", "TIMESTAMP"),
        ("enrichment_status", "VARCHAR DEFAULT 'enriched'"),
        ("enrichment_attempts", "INTEGER DEFAULT 0"),
        ("last_enrichment_error", "TEXT"),
        ("last_enriched_at", "TIMESTAMP"),
        ("full_content", "TEXT"),
    ],
    "system_config": [
        ("permission_catalog_version", "INTEGER NOT NULL DEFAULT 0"),
        ("scheduler_revision", "INTEGER NOT NULL DEFAULT 0"),
        ("scheduler_applied_revision", "INTEGER NOT NULL DEFAULT 0"),
        ("alerted_eq_ids", "TEXT DEFAULT '[]'"),
        ("alerted_wildfire_ids", "TEXT DEFAULT '[]'"),
        ("wildfire_proximity_state", "TEXT DEFAULT '{}'"),
        ("baseline_override_cyber", "FLOAT DEFAULT 0.0"),
        ("baseline_override_phys", "FLOAT DEFAULT 0.0"),
        ("unified_brief", "TEXT"),
        ("unified_brief_time", "TIMESTAMP"),
        ("global_brief", "TEXT"),
        ("global_brief_time", "TIMESTAMP"),
        ("internal_brief", "TEXT"),
        ("internal_brief_time", "TIMESTAMP"),
        ("public_app_url", "VARCHAR DEFAULT 'http://localhost:8501'"),
        ("failed_login_alert_enabled", "BOOLEAN NOT NULL DEFAULT FALSE"),
        ("failed_login_alert_recipients", "TEXT NOT NULL DEFAULT ''"),
        ("failed_login_alert_threshold", "INTEGER NOT NULL DEFAULT 5"),
        ("failed_login_alert_window_minutes", "INTEGER NOT NULL DEFAULT 5"),
        ("failed_login_alert_last_sent", "TIMESTAMP"),
        ("last_global_risk", "VARCHAR"),
        ("last_internal_risk", "VARCHAR"),
        ("last_risk_alert_time", "TIMESTAMP"),
        ("sys_countermeasures", "INTEGER DEFAULT 3"),
        ("net_countermeasures", "INTEGER DEFAULT 3"),
        ("scoring_mode", "VARCHAR DEFAULT 'auto'"),
        ("cyber_criticality_override", "INTEGER DEFAULT 0"),
        ("cyber_lethality_override", "INTEGER DEFAULT 0"),
        ("physical_criticality_override", "INTEGER DEFAULT 0"),
        ("physical_lethality_override", "INTEGER DEFAULT 0"),
        ("internal_criticality_override", "INTEGER DEFAULT 0"),
        ("internal_lethality_override", "INTEGER DEFAULT 0"),
        ("global_risk_offset", "INTEGER DEFAULT 0"),
        ("internal_risk_offset", "INTEGER DEFAULT 0"),
        ("llm_context_window", "INTEGER DEFAULT 128000"),
    ],
    "solarwinds_alerts": [
        ("is_dispatched", "BOOLEAN DEFAULT FALSE"),
        ("is_ticketed", "BOOLEAN DEFAULT FALSE"),
        ("acknowledged_by", "VARCHAR"),
        ("acknowledged_at", "TIMESTAMP"),
        ("dispatched_by", "VARCHAR"),
        ("dispatched_at", "TIMESTAMP"),
    ],
    "monitored_locations": [
        ("district", "VARCHAR DEFAULT 'Central'"),
        ("status_modified_by", "VARCHAR"),
        ("status_modified_at", "TIMESTAMP"),
        ("last_auto_ticket", "TIMESTAMP"),
        ("last_escalation_ticket", "TIMESTAMP"),
        ("last_auto_dispatch", "TIMESTAMP"),
        ("last_escalation_dispatch", "TIMESTAMP"),
    ],
    "shift_logs": [
        ("author_role", "VARCHAR DEFAULT 'analyst'"),
        ("is_deleted", "BOOLEAN DEFAULT FALSE"),
    ],
    "crime_incidents": [("is_alert_dispatched", "BOOLEAN DEFAULT FALSE")],
}

CUSTOM_INDEXES = (
    ("ix_articles_published_score_pinned", "articles", "published_date, score, is_pinned"),
    ("ix_internal_risk_snapshots_timestamp", "internal_risk_snapshots", "timestamp"),
    ("ix_solarwinds_status_received", "solarwinds_alerts", "status, received_at"),
    ("ix_solarwinds_node_ticketed_received", "solarwinds_alerts", "node_name, is_ticketed, received_at"),
    ("ix_cloud_outages_resolved_updated", "cloud_outages", "is_resolved, updated_at"),
    ("ix_crime_timestamp_category_distance", "crime_incidents", "timestamp, category, distance_miles"),
    ("ix_shift_logs_deleted_created", "shift_logs", "is_deleted, created_at"),
    ("ix_email_change_requests_user_status", "email_change_requests", "user_id, status"),
    ("ix_password_reset_requests_ip_time", "password_reset_requests", "requester_ip, requested_at"),
)


def _table_columns(bind, table_name):
    return {column["name"] for column in inspect(bind).get_columns(table_name)}


def upgrade():
    bind = op.get_bind()

    # This is the one-time bridge for both new installations and databases that
    # predate Alembic. Existing tables are left intact by create_all(checkfirst).
    BaselineBase.metadata.create_all(bind=bind, checkfirst=True)

    for table_name, columns in LEGACY_COLUMNS.items():
        present = _table_columns(bind, table_name)
        for column_name, definition in columns:
            if column_name not in present:
                bind.execute(text(
                    f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"
                ))
                present.add(column_name)

    inspector = inspect(bind)
    missing_columns = {}
    for table in BaselineBase.metadata.sorted_tables:
        present = {column["name"] for column in inspector.get_columns(table.name)}
        missing = sorted(column.name for column in table.columns if column.name not in present)
        if missing:
            missing_columns[table.name] = missing
    if missing_columns:
        details = "; ".join(
            f"{table}: {', '.join(columns)}" for table, columns in sorted(missing_columns.items())
        )
        raise RuntimeError(
            "Legacy schema adoption is missing explicit column definitions for: " + details
        )

    duplicate_email_groups = bind.execute(text(
        "SELECT COUNT(*) FROM (SELECT email_normalized FROM users "
        "WHERE email_normalized IS NOT NULL GROUP BY email_normalized HAVING COUNT(*) > 1)"
    )).scalar_one()
    if duplicate_email_groups:
        raise RuntimeError(
            "Cannot install the unique normalized-email index: "
            f"{duplicate_email_groups} duplicate email groups must be resolved before startup."
        )

    # create_all skips indexes when a table already exists, so add any missing
    # model indexes here. Unique-index conflicts fail the migration explicitly.
    for table in BaselineBase.metadata.sorted_tables:
        for index in sorted(table.indexes, key=lambda item: item.name or ""):
            index.create(bind=bind, checkfirst=True)

    for name, table, columns in CUSTOM_INDEXES:
        op.create_index(name, table, columns.split(", "), if_not_exists=True)

    bind.execute(text("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL"))
    bind.execute(text(
        "UPDATE users SET last_login_at = (SELECT MAX(created_at) FROM user_sessions "
        "WHERE user_sessions.user_id = users.id) WHERE last_login_at IS NULL "
        "AND EXISTS (SELECT 1 FROM user_sessions WHERE user_sessions.user_id = users.id)"
    ))
    bind.execute(text(
        "UPDATE users SET last_activity_at = last_login_at "
        "WHERE last_activity_at IS NULL AND last_login_at IS NOT NULL"
    ))
    bind.execute(text(
        "UPDATE registration_invites SET used_at = CURRENT_TIMESTAMP "
        "WHERE email = '' AND used_at IS NULL"
    ))
    bind.execute(text(
        "UPDATE monitored_locations SET priority = CASE "
        "WHEN priority = '1' OR priority = 1 THEN 'P1-Critical' "
        "WHEN priority = '2' OR priority = 2 THEN 'P2-High' "
        "WHEN priority = '3' OR priority = 3 THEN 'P3-Moderate' "
        "WHEN priority = '4' OR priority = 4 THEN 'P4-Low' "
        "WHEN priority = '5' OR priority = 5 THEN 'P5-Planning' "
        "ELSE 'P3-Moderate' END "
        "WHERE priority IS NOT NULL AND CAST(priority AS INTEGER) = priority"
    ))


def downgrade():
    raise RuntimeError("The legacy adoption revision is intentionally non-reversible; restore a database backup instead.")
