"""Canonical permission keys and descriptions shared by API policy and role UI."""

from __future__ import annotations


PAGE_CATALOG = [
    {"key": "Global Dashboards", "route": "/", "description": "Operational and risk dashboards."},
    {"key": "Threat Telemetry", "route": "/threat-telemetry", "description": "RSS, vulnerabilities, cloud outages, and crime."},
    {"key": "Regional Grid", "route": "/regional-grid", "description": "Geospatial site and hazard information."},
    {"key": "Threat Hunting & IOCs", "route": "/threat-hunting", "description": "IOC search, pivots, and Elastic events."},
    {"key": "AIOps RCA", "route": "/aiops-rca", "description": "Operational alerts, correlation, and RCA."},
    {"key": "Shift Logbook", "route": "/shift-logbook", "description": "Shift notes and handoff history."},
    {"key": "Reporting & Briefings", "route": "/reporting", "description": "Reports, briefings, and shared reports."},
    {"key": "Settings & Admin", "route": "/settings", "description": "Profile, application settings, and user administration."},
    {"key": "Keyword Analysis", "route": "/keyword-analysis", "description": "Scoring and keyword analytics."},
]

ACTION_CATALOG = [
    {"key": "Action: Pin Articles", "group": "Threat Telemetry", "description": "Pin and unpin articles."},
    {"key": "Action: Boost Threat Score", "group": "Threat Telemetry", "description": "Manually change an article score."},
    {"key": "Action: Manually Sync Data", "group": "Data Operations", "description": "Manually trigger external data synchronization."},
    {"key": "Action: Generate Reports", "group": "Reports and AI", "description": "Generate or regenerate operational reports and briefs."},
    {"key": "Action: Generate Risk Snapshot", "group": "Risk Operations", "description": "Run the internal asset-risk calculation."},
    {"key": "Action: Run RCA Analysis", "group": "AIOps RCA", "description": "Run root-cause analysis and correlation."},
    {"key": "Action: Clear AIOps Data", "group": "AIOps RCA", "description": "Delete timeline events or active alert data."},
    {"key": "Action: Dispatch Exec Report", "group": "Reports and Email", "description": "Send or broadcast executive and generated reports."},
    {"key": "Action: Send Email", "group": "Reports and Email", "description": "Send an arbitrary operational email."},
    {"key": "Action: Submit Shift Log", "group": "Shift Logbook", "description": "Create, edit, or delete shift-log entries."},
    {"key": "Action: Manage Shift Logs", "group": "Shift Logbook", "description": "Edit or delete entries created by other users."},
    {"key": "Action: Dispatch RCA Tickets", "group": "AIOps RCA", "description": "Investigate, dispatch, and send RCA tickets."},
    {"key": "Action: Acknowledge RCA Alerts", "group": "AIOps RCA", "description": "Acknowledge RCA alerts."},
    {"key": "Action: Manage Site Maintenance", "group": "AIOps RCA", "description": "Change site maintenance status and ETR."},
    {"key": "Action: Train ML Model", "group": "Model Operations", "description": "Run manual model retraining."},
    {"key": "Action: Adjust Risk Scoring Overrides", "group": "Application Settings", "description": "Change scoring modes, baselines, overrides, and risk offsets."},
    {"key": "Action: Manage Scheduler Settings", "group": "Application Settings", "description": "Change validated scheduler timing settings."},
    {"key": "Action: Manage Application Settings", "group": "Application Settings", "description": "Change non-scheduler global application settings."},
    {"key": "Action: Manage Users", "group": "Users and Recovery", "description": "Create and manage individual and display accounts."},
    {"key": "Action: Manage Roles", "group": "Users and Recovery", "description": "Create roles and edit permission grants."},
    {"key": "Action: Review Account Recovery Requests", "group": "Users and Recovery", "description": "Approve or deny password-reset requests."},
    {"key": "Action: Approve Recovery Email Changes", "group": "Users and Recovery", "description": "Approve or deny recovery-email changes."},
    # Kept as a recognized legacy grant during migration. New API routes use
    # narrower grants so this umbrella cannot authorize mail or settings writes.
    {"key": "Action: Trigger AI Functions", "group": "Legacy", "description": "Legacy grant; migrate to narrower report-generation permissions.", "legacy": True},
]

TAB_CATALOG = {
    "dashboard": [
        {"key": "Tab: Dashboards -> Operational", "tab": "0", "label": "Operational"},
        {"key": "Tab: Dashboards -> Global Risk", "tab": "1", "label": "Global Risk"},
        {"key": "Tab: Dashboards -> Internal Risk", "tab": "2", "label": "Internal Risk"},
        {"key": "Tab: Dashboards -> Unified Brief", "tab": "3", "label": "Unified Brief"},
    ],
    "threatTelemetry": [
        {"key": "Tab: Threat Telemetry -> RSS Triage", "tab": "0", "label": "RSS Triage"},
        {"key": "Tab: Threat Telemetry -> CISA KEV", "tab": "1", "label": "CISA KEV"},
        {"key": "Tab: Threat Telemetry -> Cloud Services", "tab": "2", "label": "Cloud Services"},
        {"key": "Tab: Threat Telemetry -> Perimeter Crime", "tab": "3", "label": "Perimeter Crime"},
    ],
    "regionalGrid": [
        {"key": "Tab: Regional Grid -> Geospatial Map", "tab": "geospatial", "label": "Geospatial Map"},
        {"key": "Tab: Regional Grid -> Executive Dash", "tab": "executive", "label": "Executive Dash"},
        {"key": "Tab: Regional Grid -> Hazard Analytics", "tab": "hazard", "label": "Hazard Analytics"},
        {"key": "Tab: Regional Grid -> Location Matrix", "tab": "matrix", "label": "Location Matrix"},
        {"key": "Tab: Regional Grid -> Weather Alerts Log", "tab": "alerts", "label": "Weather Alerts Log"},
        {"key": "Tab: Regional Grid -> Atmos Weather", "tab": "atmos", "label": "Atmos Weather"},
    ],
    "threatHunting": [
        {"key": "Tab: Threat Hunting -> Global IOC Matrix", "tab": "ioc", "label": "Global IOC Matrix"},
        {"key": "Tab: Threat Hunting -> Deep Hunt Builder", "tab": "hunt", "label": "Deep Hunt Builder"},
        {"key": "Tab: Reporting -> Elastic SIEM Report", "tab": "siem", "label": "Elastic SIEM Report"},
    ],
    "aiopsRca": [
        {"key": "Tab: AIOps RCA -> Active Board", "tab": "0", "label": "Active Board"},
        {"key": "Tab: AIOps RCA -> Predictive Analytics", "tab": "1", "label": "Predictive Analytics"},
        {"key": "Tab: AIOps RCA -> Global Correlation", "tab": "2", "label": "Global Correlation"},
    ],
    "shiftLogbook": [
        {"key": "Tab: Shift Log -> Active Shift", "tab": "active", "label": "Active Shift"},
        {"key": "Tab: Shift Log -> History", "tab": "history", "label": "History"},
    ],
    "reporting": [
        {"key": "Tab: Reporting -> Daily Fusion", "tab": "0", "label": "Daily Fusion"},
        {"key": "Tab: Reporting -> Report Builder", "tab": "1", "label": "Report Builder"},
        {"key": "Tab: Reporting -> Shared Library", "tab": "2", "label": "Shared Library"},
    ],
    "settings": [
        {"key": "Tab: Settings -> Facility Locations", "tab": "facilities", "label": "Facility Locations"},
        {"key": "Tab: Settings -> Internal Assets", "tab": "assets", "label": "Internal Assets"},
        {"key": "Tab: Settings -> RSS Sources", "tab": "rss", "label": "RSS Sources"},
        {"key": "Tab: Settings -> ML Training", "tab": "ml", "label": "ML Training"},
        {"key": "Tab: Settings -> AI & SMTP", "tab": "ai-smtp", "label": "AI & SMTP"},
        {"key": "Tab: Settings -> Application Settings", "tab": "application", "label": "Application Settings"},
        {"key": "Tab: Settings -> Users & Roles", "tab": "users", "label": "Users & Roles"},
        {"key": "Tab: Settings -> Backup & Restore", "tab": "backup", "label": "Backup & Restore"},
        {"key": "Tab: Settings -> Danger Zone", "tab": "danger", "label": "Danger Zone"},
    ],
}

PAGE_KEYS = [item["key"] for item in PAGE_CATALOG]
ACTION_KEYS = [item["key"] for item in ACTION_CATALOG]
TAB_KEYS = [item["key"] for tabs in TAB_CATALOG.values() for item in tabs]
ADMIN_ACTIONS = [*ACTION_KEYS, *TAB_KEYS]


def public_permission_catalog() -> dict:
    """Return the permission schema consumed by the role-management UI."""
    return {
        "pages": PAGE_CATALOG,
        "actions": ACTION_CATALOG,
        "tabs": TAB_CATALOG,
    }
