# NOC Intelligence Fusion Center — API Reference

Base URL: `http://localhost:8101/api/v1`
WebSocket: `ws://localhost:8101/ws`

## Authentication

The API installs `authentication_middleware` for `/api/v1/*`. Login, invitation validation/registration, password-reset request/completion, and recovery-email verification are public. Protected routes accept `Authorization: Bearer <session-token>` and retain `token`/`session_token` query parameters for compatibility. Route dependencies enforce page, tab, action, role, and site-type permissions.

401 responses mean the session is missing, invalid, revoked, or belongs to an inactive account; 403 responses preserve the session and return a structured permission error, for example `detail.code = "permission_denied"` with the missing `permission`. Site-scope denials use `detail.code = "site_scope_denied"`.

The API mounts the REST, account-administration, application-settings, and permission-catalog routers. See `docs/CODE_REFERENCE.md` for module-level function documentation and verify endpoint details against the route source before integrating.

### POST /auth/login

Request body:
```json
{"username": "admin", "password": "<value configured in DEFAULT_ADMIN_PASSWORD>"}
```
Response (200):
```json
{"user": {"id": 1, "username": "admin", ...}, "token": "uuid-string"}
```

When failed-login alerts are enabled in Settings > Application Settings, failed credentials are counted across users. Reaching the configured threshold queues a background email to the configured alert recipient list. Login failures return generic `401` responses.

### GET /auth/me

Returns the authenticated user object with permissions attached. Send `Authorization: Bearer <session-token>`; the legacy `token` or `session_token` query parameter remains accepted for compatibility.

### POST /auth/logout

Revokes the authenticated session used for the request.

### POST /auth/update-profile

Body: `{full_name, job_title, contact_info, default_shift, old_password, new_password}`. The user identity comes from the authenticated session.

Returns `{"status": "ok", "message": "..."}`

### POST /auth/request-recovery-email

Authenticated users submit `{ "email": "person@example.com" }`. The address remains pending until a user administrator approves the request and the user verifies mailbox ownership.

### POST /auth/request-password-reset

Public body: `{ "identifier": "username-or-approved-email" }`. Always returns a generic accepted response. Matching requests are placed in the user-administrator review queue; an approved request sends a one-hour, single-use reset link to the verified recovery email.

### POST /auth/reset-password

Public body: `{ "token": "...", "new_password": "..." }`. Requires at least 12 characters. Successful reset revokes all existing sessions; reset tokens are hashed, expiring, and single-use.

### GET /auth/verify-recovery-email?token=

Verifies an administrator-approved pending recovery-email change.

## Permission Catalog (`/permissions`)

### GET /permissions/catalog

Returns the canonical page, tab, action, and description catalog to an authenticated role editor.

## User Administration (`/user-admin`)

User-management routes require the Settings page, Users & Roles tab, and `Action: Manage Users`; role editing requires `Action: Manage Roles`; reset review and recovery-email approval have separate permissions. Built-in administrators retain the full-access override.

- `GET /user-admin/users` — directory data including account type, email/recovery status, active state, last sign-in, and last activity.
- `GET /user-admin/roles` — roles assignable to accounts.
- `POST /user-admin/display-accounts` — email-optional display account with administrator-selected password and role.
- `POST /user-admin/invitations` — email-required individual invitation delivered to that address.
- `GET /user-admin/invitations`, `POST /user-admin/invitations/{id}/resend`, and `DELETE /user-admin/invitations/{id}` — manage pending invitations.
- `PUT /user-admin/users/{username}/profile`
- `PUT /user-admin/users/{username}/role`
- `PATCH /user-admin/users/{username}/status`
- `PATCH /user-admin/users/{username}/account-type`
- `POST /user-admin/users/{username}/administrator-reset` — display/email-less accounts only for delegated user managers; root administrators may perform assisted resets.
- `POST /user-admin/users/{username}/revoke-sessions`
- `GET /user-admin/recovery-requests` and `POST /user-admin/recovery-requests/{id}/decision`
- `GET /user-admin/email-change-requests` and `POST /user-admin/email-change-requests/{id}/decision`
- `GET /user-admin/role-definitions`, `POST /user-admin/roles`, and `PUT /user-admin/roles/{name}` — require role-management permission.

Non-administrator role editors cannot grant pages, actions, or site types that their own role does not have and cannot assign the built-in administrator role.

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

### GET /dashboard/briefs
Returns only saved dashboard briefs whose tabs the caller is allowed to view.

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

Returns a success result with the number of imported events, or HTTP 502 when the Elastic sync fails. The preferred Threat Hunting UI endpoint is `/hunting/sync-elastic-cache`.

### POST /threat/generate-siem-triage
Body expects `.events` key. Returns AI-generated SIEM triage summary.

## Keyword Analysis Endpoints (`/keyword-analysis`)

All keyword-analysis endpoints require the exact page permission `Keyword Analysis`. `POST /keyword-analysis/recategorize` also requires `Action: Trigger AI Functions`.

### GET /keyword-analysis/overview

Returns total keyword and article counts, average/minimum/maximum weights, used/unused keyword counts, and article match counts.

### GET /keyword-analysis/keyword-stats?sort_by=trigger_count&order=desc&search=&limit=100

Returns each matching keyword with configured weight, trigger count, and calculated score contribution. `sort_by` accepts `weight`, `trigger_count`, or `avg_score_contribution`.

### GET /keyword-analysis/category-distribution?days=0

Returns article counts, percentages, and average scores by category. `days=0` includes all stored articles.

### GET /keyword-analysis/timeline?keyword=&days=30&interval=day

Returns total articles, matched articles, match rate, and average score grouped by day or week.

### GET /keyword-analysis/keyword-articles?keyword=<word>&limit=50

Returns recent articles whose persisted `keywords_found` list contains the requested keyword.

### GET /keyword-analysis/score-distribution?days=0&bucket_size=10

Returns score buckets and the most common category in each bucket.

### GET /keyword-analysis/category-keyword-matrix?top_n=20

Returns category names, the most frequently occurring keywords, and their occurrence matrix.

### GET /keyword-analysis/category-details?category=<name>&days=0

Returns category totals, average score, top keywords, top sources, and recent matching articles.

### POST /keyword-analysis/recategorize

Re-runs the article categorizer against every stored article and returns `{status, total, changed}`. Requires `Action: Trigger AI Functions`.

## Regional Endpoints (/regional)

### GET /regional/locations
Cached list of all MonitoredLocation records.

### GET /regional/geojson
Returns all cached GeoJSON layers: spc_day1-3, nws_ar, nws_oos, usgs_ar, usgs_oos, plus per-feed freshness metadata.

### POST /regional/compile-map
The heavy computation endpoint. Body keys: `toggles`, `selected_events`, and `map_df`. The server uses its coherent cached hazard snapshot; legacy raw feed keys remain accepted for compatibility.
Returns 6-element array: `[layers, viewState, diagnostics, toggled_affected_sites, master_affected_sites, analytics]`.

### GET /regional/weather-prefs?username=

### POST /regional/weather-prefs?username=
Body: `{alerts: ["Tornado Warning", "Severe Thunderstorm Warning", ...]}`

### GET /regional/forecast?lat=34.8&lon=-92.2

### GET /regional/weather-alerts-log

### GET /regional/site-types
Merges default site types with DB `loc_type` values.

### POST /regional/sync-hazards
Manually triggers regional hazard fetch and cache invalidation. Returns HTTP 502 when synchronization fails.

## Hunting Endpoints (/hunting)

### GET /hunting/iocs?days_back=3
Returns list of extracted IOCs with source article links.

### GET /hunting/osint-pivot?ioc_type=&ioc_value=
Returns external pivot URL (VirusTotal, Shodan, NVD, MITRE).

### GET /hunting/search-articles?target=&days_back=3
Searches article title, summary, and full content by target string. Results are deterministically ordered and capped at 30 articles.

### GET /hunting/elastic-events?hours_back=24&page=1&page_size=100
Returns a paginated view of locally cached high-severity Elastic events. Requires the Threat Hunting page and Elastic SIEM tab permission.

### POST /hunting/sync-elastic-cache?hours_back=24
Synchronizes high-severity Elastic events into the local cache. Requires the Threat Hunting page and manual sync action permission.

### POST /hunting/generate-siem-triage
Generates an AI triage summary from up to 50 bounded, flat SIEM events. Requires the Threat Hunting page and AI action permission.

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
Returns LLM/SMTP configuration fields. Requires the Settings page and AI & SMTP tab; secret values are not returned.

### GET /settings/users
Compatibility endpoint for the user directory; requires `Action: Manage Users`.

## Application Settings (`/application-settings`)

- `GET /application-settings` and `PUT /application-settings` — global application defaults and failed-login alert settings.
- `GET /application-settings/risk-scoring` and `PUT /application-settings/risk-scoring` — writes require `Action: Adjust Risk Scoring Overrides`.
- `GET /application-settings/scheduler` — registered jobs, defaults, bounds, and current schedules.
- `PATCH /application-settings/scheduler/jobs/{job_key}` — writes require `Action: Manage Scheduler Settings`; settings are bounded and reloaded by the worker without restart.
- `GET /application-settings/ml-counts` and `POST /application-settings/ml-retrain` — training requires the ML Training tab and `Action: Train ML Model`.

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
Administrator-only compatibility endpoint for global configuration. Risk scoring, application defaults, and scheduler edits use the category-specific `/application-settings/*` routes and action permissions.

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
Administrator-only compatibility path for creating a display account without email. New UI uses `/user-admin/display-accounts`.

### POST /admin/registration-invites
Body: `{username, email, role, ttl_hours}`. Email is required; the invitation is delivered to that address.

### PUT /admin/users/{username}/role
Body: `{role}`

### POST /admin/users/{username}/reset-password
Body: `{new_password}`

### GET /admin/location

### POST /admin/location/import?mode=add|upsert|replace
Body: array of location dicts.

### PUT /admin/location
Body: array of edited location records (`list[dict]`).

### GET /admin/backup
Returns the legacy configuration backup containing keywords, feeds, monitored locations, and node aliases. This is a four-collection logical backup, not a full database snapshot.

### POST /admin/restore
Body: legacy backup data dict. Adds records that are not already present for those four collections.

### GET /admin/export-all
Exports the 27 application models listed in `src/services.py` `ALL_MODELS`. It excludes session, failed-login, invitation, recovery-request/token, account-audit, and scheduler-job configuration tables, so it is not a complete database backup. The export is administrator-only and may contain password hashes and stored integration credentials; protect it as sensitive data.

### POST /admin/import-all
Body: JSON export data for supported models; set `"_merge": true` in the body to skip duplicate IDs. With the default `"_merge": false`, non-empty supported tables are cleared before inserting their supplied rows.

### POST /admin/upload-db
Accepts a `.db` upload and imports table rows into the current database. It does not replace the SQLite database file; make a file-level backup and stop other writers before using this administrative import.

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
Administrator-only compatibility endpoint for ML training. Delegated retraining uses `POST /application-settings/ml-retrain` with `Action: Train ML Model`.

## LLM Endpoints (/llm)

### POST /llm/test-connection
Body: `{llm_endpoint, llm_api_key, llm_model_name}`. Tests LLM connectivity.

### POST /llm/executive-weather-brief
Body: `{analytics, p1_at_risk}`. Generates weather brief.

## Email Endpoints (/email)

### POST /email/send
Body: `{to, subject, html_body}`. Sends email via SMTP; requires `Action: Send Email`.

### POST /email/broadcast-brief
Body: `{email}`. Sends the current unified brief via email; requires the Global Dashboards or Reporting page and `Action: Dispatch Exec Report`.

### POST /email/broadcast-global-brief
Body: `{email}`. Sends the current global threat brief via email (red header, US CI focus); requires `Action: Dispatch Exec Report`.

### POST /email/broadcast-internal-brief
Body: `{email}`. Sends the current internal asset risk brief via email (purple header, asset risk focus); requires `Action: Dispatch Exec Report`.

## WebSocket

Connect to `ws://localhost:8101/ws?token=<session-token>`. The user must have AIOps RCA page permission. Dashboard pushes are filtered by allowed site types, and the connection is periodically revalidated so revoked sessions or grants are closed.

Receives JSON messages with type `dashboard_update` every 10 seconds containing metrics data.

Send only authorized JSON commands. `INVESTIGATING_UPDATE` and `RCA_UPDATE` require the relevant RCA action; investigating-site commands are filtered by site-type access. The server broadcasts `RCA_UPDATE` after permitted RCA actions.
