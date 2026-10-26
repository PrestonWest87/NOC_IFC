# Route module: `src.api.routes.threat`

Prefix: `/api/v1/threat`. Every route requires page permission `Threat Telemetry`; data-view and manual-sync endpoints also require the tab/action grants below.

## Read endpoints

| Method/path | Additional grant | Parameters/behavior |
|---|---|---|
| `GET /cves` | `Tab: Threat Telemetry -> CISA KEV` | `limit` 1–200 (default 50), `days_back` 1–365 (default 30); returns CISA KEV rows. |
| `GET /cloud-outages` | `Tab: Threat Telemetry -> Cloud Services` | `active_only` default true; `days_back` 1–90 (default 7); there is no `limit` query parameter on this route. |
| `GET /crime-incidents` | `Tab: Threat Telemetry -> Perimeter Crime` | `hours_back` 1–168 (default 24), `max_distance` at least 0.1 miles (default 1.0). Stored distance is measured from the Little Rock headquarters point by the current crime worker. |
| `GET /articles` | `Tab: Threat Telemetry -> RSS Triage` | `category` is `live|pinned|low|search`; page starts at 1; `page_size` 5–100; optional `cat_filter`, `search_term`, and `min_score>=0`. Returns `{items,total,total_pages,page}`. |
| `GET /articles/{article_id}` | RSS Triage tab | Returns article detail, matched keyword weights, summed keyword contribution, and extracted IOCs; missing article currently returns `{error:"Article not found"}` in a normal response. |

Article category filter options are rendered by `ThreatTelemetryPage.tsx`. Their exact strings currently lag some category labels emitted by the backend categorizer; see [`DOCUMENTATION_AUDIT.md`](../../../DOCUMENTATION_AUDIT.md#source-level-mismatches-surfaced-during-the-audit).

## Manual synchronization

Each manual sync requires the relevant tab plus `Action: Manually Sync Data`.

| Method/path | Tab | Behavior |
|---|---|---|
| `POST /fetch-feeds` | RSS Triage | Runs the scheduler's RSS fetch cycle synchronously; returns a status/message object. |
| `POST /sync-cisa-kev` | CISA KEV | Calls `fetch_cisa_kev()` synchronously. |
| `POST /sync-cloud-status` | Cloud Services | Calls `fetch_cloud_outages()` synchronously. |
| `POST /fetch-crime-data` | Perimeter Crime | Calls `force_fetch_crime_data()` and returns status from its boolean result. |

## Elastic compatibility endpoints

These routes are mounted under Threat Telemetry for compatibility, but additionally require the `Threat Hunting & IOCs` page and `Tab: Reporting -> Elastic SIEM Report`.

| Method/path | Additional grant | Behavior |
|---|---|---|
| `POST /sync-elastic-cache?hours_back=24` | `Action: Manually Sync Data` | `hours_back` 1–168; calls the Elastic worker. Returns imported count; HTTP 502 on sync error and HTTP 503 when sync is skipped because `ELASTIC_URL` is blank. |
| `POST /generate-siem-triage` | Legacy `Action: Trigger AI Functions` | JSON `{events:[...]}` with 1–50 bounded event records. Each optional field has a maximum length; serialized payload over 100 KB returns HTTP 413. |

The Threat Hunting UI calls the corresponding `/hunting/*` endpoints to keep its page/tab authorization aligned. See [`API.md`](../../../API.md#threat-endpoints-threat).
