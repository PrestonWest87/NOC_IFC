"""Supported background-job schedules and validation bounds."""

from __future__ import annotations

from datetime import datetime


JOB_REGISTRY = {
    "tiered_alert_escalation": {
        "label": "Tiered alert escalation",
        "description": "P1-P5 SLA escalation, dispatch, and on-call paging.",
        "function": "job_tiered_alert_escalation",
        "schedule_type": "interval", "every_value": 1, "unit": "minutes",
        "min_value": 1, "max_value": 5, "enabled": True, "can_disable": False,
        "startup_run": True,
    },
    "rss_fetch": {
        "label": "RSS feed fetch", "description": "Fetch, score, and classify RSS articles.",
        "function": "fetch_feeds", "schedule_type": "interval", "every_value": 5, "unit": "minutes",
        "min_value": 3, "max_value": 30, "enabled": True, "can_disable": True, "startup_run": True,
    },
    "article_enrichment": {
        "label": "Article enrichment", "description": "Retrieve article full text for high-scoring items.",
        "function": "enrich_pending_articles", "schedule_type": "interval", "every_value": 3, "unit": "minutes",
        "min_value": 1, "max_value": 30, "enabled": True, "can_disable": True, "startup_run": False,
    },
    "maintenance_expiry": {
        "label": "Maintenance expiry", "description": "Clear site maintenance after its ETR.",
        "function": "job_clear_expired_maintenance", "schedule_type": "interval", "every_value": 5, "unit": "minutes",
        "min_value": 1, "max_value": 30, "enabled": True, "can_disable": True, "startup_run": True,
    },
    "telemetry_sync": {
        "label": "Telemetry sync", "description": "Synchronize telemetry and BGP data.",
        "function": "run_telemetry_sync", "schedule_type": "interval", "every_value": 6, "unit": "minutes",
        "min_value": 3, "max_value": 60, "enabled": True, "can_disable": True, "startup_run": True,
    },
    "elastic_sync": {
        "label": "Elastic cache sync", "description": "Refresh high-severity Elastic events.",
        "function": "job_sync_elastic", "schedule_type": "interval", "every_value": 6, "unit": "minutes",
        "min_value": 5, "max_value": 120, "enabled": True, "can_disable": True, "startup_run": True,
    },
    "regional_hazards": {
        "label": "Regional hazards", "description": "Refresh NWS, SPC, USGS, and wildfire hazards.",
        "function": "fetch_regional_hazards", "schedule_type": "interval", "every_value": 7, "unit": "minutes",
        "min_value": 5, "max_value": 60, "enabled": True, "can_disable": True, "startup_run": True,
    },
    "cloud_outages": {
        "label": "Cloud status", "description": "Refresh cloud provider outage status.",
        "function": "fetch_cloud_outages", "schedule_type": "interval", "every_value": 8, "unit": "minutes",
        "min_value": 5, "max_value": 60, "enabled": True, "can_disable": True, "startup_run": True,
    },
    "crime_fetch": {
        "label": "Crime fetch", "description": "Refresh nearby crime incidents and alerts.",
        "function": "fetch_live_crimes", "schedule_type": "interval", "every_value": 10, "unit": "minutes",
        "min_value": 5, "max_value": 60, "enabled": True, "can_disable": True, "startup_run": True,
    },
    "database_maintenance": {
        "label": "Database maintenance", "description": "Run retention cleanup and SQLite maintenance.",
        "function": "run_database_maintenance", "schedule_type": "interval", "every_value": 60, "unit": "minutes",
        "min_value": 15, "max_value": 240, "enabled": True, "can_disable": True, "startup_run": False,
    },
    "internal_risk": {
        "label": "Internal risk calculation", "description": "Calculate and save internal asset risk.",
        "function": "job_internal_risk", "schedule_type": "interval", "every_value": 2, "unit": "hours",
        "min_value": 1, "max_value": 24, "enabled": True, "can_disable": True, "startup_run": True,
    },
    "rolling_summary": {
        "label": "Rolling shift summary", "description": "Generate the shift handoff summary.",
        "function": "job_rolling_summary", "schedule_type": "interval", "every_value": 30, "unit": "minutes",
        "min_value": 15, "max_value": 360, "enabled": True, "can_disable": True, "startup_run": False,
    },
    "internal_brief": {
        "label": "Internal asset brief", "description": "Generate the internal asset risk brief.",
        "function": "job_internal_brief", "schedule_type": "interval", "every_value": 3, "unit": "hours",
        "min_value": 1, "max_value": 12, "enabled": True, "can_disable": True, "startup_run": True,
    },
    "unified_brief": {
        "label": "Unified brief", "description": "Generate the unified cyber/physical risk brief.",
        "function": "job_unified_brief", "schedule_type": "interval", "every_value": 6, "unit": "hours",
        "min_value": 2, "max_value": 24, "enabled": True, "can_disable": True, "startup_run": True,
    },
    "cisa_kev": {
        "label": "CISA KEV sync", "description": "Refresh the Known Exploited Vulnerabilities catalog.",
        "function": "fetch_cisa_kev", "schedule_type": "interval", "every_value": 7, "unit": "hours",
        "min_value": 4, "max_value": 24, "enabled": True, "can_disable": True, "startup_run": True,
    },
    "global_brief": {
        "label": "Global threat brief", "description": "Generate the US critical-infrastructure threat brief.",
        "function": "job_global_brief", "schedule_type": "daily", "run_at": "02:00",
        "timezone": "America/Chicago", "enabled": True, "can_disable": True, "startup_run": True,
    },
    "ml_retrain": {
        "label": "ML retraining", "description": "Retrain and hot-reload the scoring model.",
        "function": "job_retrain_ml", "schedule_type": "weekly", "weekday": "sunday", "run_at": "02:00",
        "timezone": "America/Chicago", "enabled": True, "can_disable": True, "startup_run": False,
    },
    "daily_email_brief": {
        "label": "Daily email brief", "description": "Email the latest unified brief to configured recipients.",
        "function": "job_daily_email_unified_brief", "schedule_type": "daily", "run_at": "07:00",
        "timezone": "America/Chicago", "enabled": True, "can_disable": True, "startup_run": False,
    },
    "daily_fusion_report": {
        "label": "Daily fusion report", "description": "Generate the previous day's fusion report.",
        "function": "run_daily_report", "schedule_type": "daily", "run_at": "06:00",
        "timezone": "America/Chicago", "enabled": True, "can_disable": True, "startup_run": False,
    },
    "database_backup": {
        "label": "Encrypted database backup",
        "description": "Create a full encrypted SQLite backup and retain the latest three scheduled copies.",
        "function": "job_database_backup", "schedule_type": "weekly", "weekday": "sunday", "run_at": "00:00",
        "timezone": "America/Chicago", "enabled": True, "can_disable": False, "startup_run": False,
    },
}

SCHEDULER_POLL_SECONDS = 30


def default_schedule(job_key: str) -> dict:
    job = JOB_REGISTRY[job_key]
    fields = ("schedule_type", "every_value", "unit", "run_at", "weekday", "timezone", "enabled")
    return {key: job[key] for key in fields if key in job}


def validate_schedule(job_key: str, value: dict) -> dict:
    if job_key not in JOB_REGISTRY:
        raise ValueError("Unknown scheduler job.")
    job = JOB_REGISTRY[job_key]
    expected_type = job["schedule_type"]
    if value.get("schedule_type", expected_type) != expected_type:
        raise ValueError("Schedule type cannot be changed for this job.")
    enabled = value.get("enabled", job.get("enabled", True))
    if not isinstance(enabled, bool):
        raise ValueError("enabled must be a boolean.")
    if not job.get("can_disable", True) and not enabled:
        raise ValueError("This safety-critical scheduler job cannot be disabled.")

    result = {"schedule_type": expected_type, "enabled": enabled}
    if expected_type == "interval":
        every_value = value.get("every_value", job["every_value"])
        unit = value.get("unit", job["unit"])
        if isinstance(every_value, bool) or not isinstance(every_value, int):
            raise ValueError("Interval must be a whole number.")
        if not job["min_value"] <= every_value <= job["max_value"]:
            raise ValueError(
                f"Interval must be between {job['min_value']} and {job['max_value']} {job['unit']}."
            )
        if unit != job["unit"]:
            raise ValueError(f"This job must use {job['unit']}.")
        result.update({"every_value": every_value, "unit": unit})
    else:
        run_at = str(value.get("run_at", job["run_at"]))
        try:
            datetime.strptime(run_at, "%H:%M")
        except ValueError as exc:
            raise ValueError("Run time must use 24-hour HH:MM format.") from exc
        timezone = str(value.get("timezone", job.get("timezone", "America/Chicago")))
        if timezone != "America/Chicago":
            raise ValueError("Scheduler times must use America/Chicago.")
        result.update({"run_at": run_at, "timezone": timezone})
        if expected_type == "weekly":
            weekday = str(value.get("weekday", job["weekday"])).lower()
            if weekday not in {"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"}:
                raise ValueError("Select a valid day of the week.")
            result["weekday"] = weekday
    return result
