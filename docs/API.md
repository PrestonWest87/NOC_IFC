# NOC Intelligence Fusion Center — API Reference

Base URL: `http://localhost:8101/api/v1`
WebSocket: `ws://localhost:8101/ws`

## Authentication

Most endpoints accept a `token` query parameter for user authentication. Some RCA endpoints use FastAPI `Depends(require_action(...))` middleware which reads the token from query params and checks `allowed_actions`.

### POST /auth/login

Request body:
```json
{"username": "admin", "password": "admin123"}
```
Response (200):
```json
{"user": {"id": 1, "username": "admin", ...}, "token": "uuid-string"}
```

### GET /auth/me?token=

Returns the authenticated user object with permissions attached.

### POST /auth/logout?username=

Clears the user's session token.

### POST /auth/update-profile?username=

Body: `{full_name, job_title, contact_info, default_shift, old_password, new_password}`

Returns `{"status": "ok", "message": "..."}`

## Dashboard Endpoints (/dashboard)

### GET /dashboard/metrics
Returns counts: high-score articles, recent CVEs, active hazards, unresolved cloud outages.

### GET /dashboard/pinned-articles
All pinned articles, newest first.

### GET /dashboard/live-articles?limit=15
Articles with score >= 50 from last 24h, ordered by score desc.

### GET /dashboard/hazards?limit=15

### GET /dashboard/threat-trends?days=14
Historical DailyThreatScore records.

### GET /dashboard/internal-risk
Latest InternalRiskSnapshot with deserialized JSON data.

### GET /dashboard/internal-risk/history?days=28

### GET /dashboard/executive-intel
Runs the full CIS scoring algorithm and returns the executive grid intel.

### POST /dashboard/generate-internal-risk
Generates and saves a new InternalRiskSnapshot.

### POST /dashboard/generate-unified-brief
Spawns background thread to generate Unified Risk Brief. Returns `{"status": "started", "generation_id": "uuid"}`.

### GET /dashboard/brief-generation-status?generation_id=
Returns progress: `{stage, message, total_items, processed_items, percent}` or `{"status": "unknown"}`.
Stage values: starting, gathering, cyber_map, phys_map, synthesizing, complete, error.

### POST /dashboard/generate-rolling-summary

### POST /dashboard/generate-scoring-rationale
Body: `{intel_data...}`

### POST /dashboard/articles/toggle-pin?article_id=

### POST /dashboard/articles/boost-score?article_id=&amount=15

### POST /dashboard/articles/feedback?article_id=&feedback=
Feedback: 0=neutral, 1=dismiss (negative), 2=keep (positive). Triggers keyword weight adjustment.

### POST /dashboard/articles/generate-bluf?article_id=
Generates an AI BLUF summary for an article.

## Threat Endpoints (/threat)

### GET /threat/cves?limit=50&days_back=30

### GET /threat/cloud-outages?active_only=true&days_back=7

### GET /threat/crime-incidents?hours_back=24&max_distance=1.0

### GET /threat/articles?category=live&cat_filter=All&page=1&page_size=20&search_term=&min_score=0
Returns `{items, total, total_pages, page}`.
Category enum: live, pinned, low, search.

### POST /threat/fetch-feeds
Manually triggers RSS feed fetch cycle.

### POST /threat/sync-cisa-kev

### POST /threat/sync-cloud-status

### POST /threat/fetch-crime-data

### POST /threat/sync-elastic-cache?hours_back=24

### POST /threat/generate-siem-triage
Body expects `.events` key. Returns AI-generated SIEM triage summary.

## Regional Endpoints (/regional)

### GET /regional/locations
Cached list of all MonitoredLocation records.

### GET /regional/geojson
Returns all cached GeoJSON layers: spc_day1-3, nws_ar, nws_oos, usgs_ar, usgs_oos.

### POST /regional/compile-map
The heavy computation endpoint. Body keys: `toggles`, `spc_data`, `ar_data`, `oos_data`, `usgs_ar_data`, `usgs_oos_data`, `selected_events`, `map_df`.
Returns 6-element array: `[layers, viewState, diagnostics, toggled_affected_sites, master_affected_sites, analytics]`.

### GET /regional/weather-prefs?username=

### POST /regional/weather-prefs?username=
Body: `{alerts: ["Tornado Warning", "Severe Thunderstorm Warning", ...]}`

### GET /regional/forecast?lat=34.8&lon=-92.2

### GET /regional/weather-alerts-log

### GET /regional/site-types
Merges default site types with DB `loc_type` values.

### POST /regional/sync-hazards
Manually triggers regional hazard fetch.

## Hunting Endpoints (/hunting)

### GET /hunting/iocs?days_back=3
Returns list of extracted IOCs with source article links.

### GET /hunting/osint-pivot?ioc_type=&ioc_value=
Returns external pivot URL (VirusTotal, Shodan, NVD, MITRE).

### GET /hunting/search-articles?target=&days_back=3
Full-text search of articles by target string.

## RCA Endpoints (/rca)

All RCA endpoints that require auth use `require_action()` dependency.

### GET /rca/dashboard
Returns alerts, events, grid, locations, investigating_sites.

### POST /rca/investigate
Requires: "Action: Dispatch RCA Tickets"
Body: `{site, is_investigating}`

### POST /rca/analyze
Runs full EnterpriseAIOpsEngine analysis. Returns clustered alerts, fleet outages, root cause, chronic insights.

### POST /rca/acknowledge
Body: `{alert_ids: [...]}`, Query: `token`. Updates alerts and tracking info.

### POST /rca/dispatch
Requires: "Action: Dispatch RCA Tickets"
Body: `{alert_ids, is_dispatched}`

### POST /rca/site-maintenance
Requires: "Action: Manage Site Maintenance"
Body: `{site_name, is_maint, etr, reason}`

### POST /rca/generate-ticket
Body: `{site, priority, patient_zero, root_cause, cluster}`. Returns generated ticket text.

### POST /rca/send-ticket
Requires: "Action: Dispatch RCA Tickets"
Body: `{site, ticket_text, recipient, alert_ids, priority, district, sla}`

### GET /rca/sitrep
Returns current sitrep report.

### POST /rca/sitrep
Body: `{action: "refresh_briefing" | "scoring_rationale" | "security_audit"}`

### POST /rca/clear-events
Deletes all timeline events.

### POST /rca/nuke-alerts
Deletes all SolarWinds alerts.

### POST /rca/resolve-alert?alert_id=&node_name=

## AIOps Endpoints (/aiops)

### GET /aiops/dashboard
Returns alerts, events, grid.

### GET /aiops/sitrep

### GET /aiops/sites
Returns all monitored locations with maintenance status.

### PATCH /aiops/sites/{site_id}/acknowledge?token=
Acknowledges site alerts.

## Logbook Endpoints (/logbook)

### GET /logbook/entries?role_filter=All&start_date=&end_date=&session_token=

### POST /logbook/entries?analyst=&role=&shift_period=&content=&custom_date=&session_token=

### PATCH /logbook/entries/{entry_id}
Body: `{is_deleted: true, reason: "..."}`. Soft delete.

### POST /logbook/generate-summary
Body: `{role_filter, shift_period, timeframe_label, auto_append, timeframe}`

## Reporting Endpoints (/reporting)

### GET /reporting/executive-intel

### GET /reporting/saved-reports

### GET /reporting/daily-briefings

### POST /reporting/generate-daily
Generates daily fusion report via LLM.

### POST /reporting/broadcast
Body: `{report_date, content, recipients}`

### POST /reporting/save-report
Body: `{title, author, content}`

### DELETE /reporting/saved-reports/{report_id}

### POST /reporting/generate-custom
Body: `{target, days_back, objective, analyst}`

## Settings Endpoints (/settings)

### GET /settings/config
Returns all SystemConfig rows.

### GET /settings/users
Returns all users.

## Admin Endpoints (/admin)

### GET /admin/lists
Returns keywords, feeds, users.

### POST /admin/keywords/bulk?raw_text=
Bulk add keywords (one per line: "word, weight").

### POST /admin/feeds/bulk?raw_text=
Bulk add feeds (one per line: "url, name").

### PATCH /admin/keywords/{keyword_id}
Body: `{weight: N}`. Validates 1-100, force-reloads scorer.

### DELETE /admin/keywords/{keyword_id}

### DELETE /admin/feeds/{feed_id}

### GET /admin/ml-counts

### POST /admin/config
Body: arbitrary key-value pairs to upsert on SystemConfig.

### POST /admin/assets/software
Body: `{csv_body: "..."}`. Replaces all software assets.

### POST /admin/assets/hardware
Body: `{csv_body: "..."}`. Replaces all hardware assets.

### GET /admin/roles

### POST /admin/roles
Body: `{name, allowed_pages, allowed_actions, allowed_site_types}`

### PUT /admin/roles/{name}
Body: `{allowed_pages, allowed_actions, allowed_site_types}`

### POST /admin/users
Body: `{username, password, role, full_name}`

### PUT /admin/users/{username}/role
Body: `{role}`

### POST /admin/users/{username}/reset-password
Body: `{new_password}`

### GET /admin/location

### POST /admin/location/import?mode=add|upsert|replace
Body: array of location dicts.

### PUT /admin/location
Body: array of edited location dicts from DataFrame.

### GET /admin/backup
Returns full backup: keywords, feeds, locations, aliases.

### POST /admin/restore
Body: backup data dict.

### GET /admin/export-all
Exports all 22+ tables.

### POST /admin/import-all?merge=false
Body: full export data. Truncate+insert or merge.

### POST /admin/upload-db
File upload (.db). Restores from uploaded SQLite database.

### DELETE /admin/record?model_name=&record_id=
Generic record deletion.

### POST /admin/nuke
Body: `{tables: ["Keyword", "Article", ...]}`

### POST /admin/nuke/crime
Deletes all crime data.

### POST /admin/nuke/weather
Wipes all weather/hazard/GeoJSON data.

### POST /admin/maintenance
Runs database maintenance (dedup, purge old data).

### POST /admin/ml-retrain
Runs ML training pipeline and force-reloads scorer.

## LLM Endpoints (/llm)

### POST /llm/test-connection
Body: `{llm_endpoint, llm_api_key, llm_model_name}`. Tests LLM connectivity.

### POST /llm/executive-weather-brief
Body: `{analytics, p1_at_risk}`. Generates weather brief.

## Email Endpoints (/email)

### POST /email/send
Body: `{to, subject, html_body}`. Sends email via SMTP.

### POST /email/broadcast-brief
Body: `{email}`. Sends the current unified brief via email.

### POST /email/broadcast-global-brief
Body: `{email}`. Sends the current global threat brief via email (red header, US CI focus).

### POST /email/broadcast-internal-brief
Body: `{email}`. Sends the current internal asset risk brief via email (purple header, asset risk focus).

## WebSocket

Connect to `ws://localhost:8101/ws`.

Receives JSON messages with type `dashboard_update` every 5 seconds containing metrics data.

Send JSON commands for bidirectional control. Broadcasts `RCA_UPDATE` events when RCA actions (investigate, dispatch, acknowledge, site-maintenance, send-ticket) occur.
