# Route module: `src.api.routes.dashboard`

Prefix: `/api/v1/dashboard`. Every route requires the `Global Dashboards` page. Each endpoint below also lists its tab/action dependency; administrators receive the backend override.

## Read endpoints

| Method/path | Additional grant | Behavior |
|---|---|---|
| `GET /metrics` | `Tab: Dashboards -> Operational` | Counts last-24-hour score-50+ articles, recent KEVs, recent hazards, and unresolved cloud outages updated in the last day. The service result is cached for 60 seconds. |
| `GET /pinned-articles` | Operational tab | Returns all pinned articles newest first. |
| `GET /live-articles?limit=15` | Operational tab | Returns last-day, score-50+, unpinned articles; `limit` is 1–100. |
| `GET /hazards?limit=15` | Operational tab | Returns recent hazards newest first; `limit` is 1–100. |
| `GET /threat-trends?days=14` | `Tab: Dashboards -> Global Risk` | Returns daily threat-score rows; `days` is 1–90. |
| `GET /executive-intel` | Global Risk tab | Calls `get_executive_grid_intel()` with recent grid-relevant crimes and a count of persisted hazard rows. It records the resulting daily score. |
| `GET /internal-risk` | `Tab: Dashboards -> Internal Risk` | Returns latest snapshot with deserialized hardware/software data, or `{status:"empty", ...}`. |
| `GET /internal-risk/history?days=28` | Internal Risk tab | Returns snapshot time/score/tier history; `days` is 1–365. |
| `GET /briefs` | Router page only | Returns saved rolling, global, internal, and unified brief fields only when the caller has the corresponding dashboard tab grant. |

## Risk and brief generation

| Method/path | Additional grants | Behavior |
|---|---|---|
| `POST /generate-internal-risk` | Internal Risk tab + `Action: Generate Risk Snapshot` | Synchronously calculates and stores a new internal-risk snapshot. |
| `POST /generate-rolling-summary` | Operational tab + `Action: Generate Reports` | Synchronously generates/saves the rolling handoff summary. |
| `POST /generate-unified-brief` | Unified Brief tab + `Action: Generate Reports` | Starts a tracked daemon thread and returns `{status:"started",generation_id}`. |
| `GET /brief-generation-status?generation_id=...` | Unified Brief tab | Returns progress or `{status:"unknown"}` from the process-local progress store. |
| `POST /generate-global-brief` | Global Risk tab + `Action: Generate Reports` | Starts global threat-brief generation asynchronously and returns a generation ID. |
| `GET /global-brief-generation-status?generation_id=...` | Global Risk tab | Returns process-local progress or unknown. |
| `POST /generate-internal-brief` | Internal Risk tab + `Action: Generate Reports` | Starts internal asset-risk brief generation asynchronously and returns a generation ID. |
| `GET /internal-brief-generation-status?generation_id=...` | Internal Risk tab | Returns process-local progress or unknown. |
| `POST /generate-scoring-rationale` | Global Risk tab + legacy `Action: Trigger AI Functions` | Accepts optional JSON `{intel:{...}}`, runs the LLM scoring rationale synchronously, and returns its status/report. |

The background brief threads register with the restore coordinator so a UI restore waits for active database-writing work. Progress is stored in API-process memory and is lost if that process restarts.

## Article actions

All article mutation parameters are query parameters, not JSON bodies.

| Method/path | Additional grants | Behavior |
|---|---|---|
| `POST /articles/toggle-pin?article_id=...` | Operational tab + `Action: Pin Articles` | Toggles the article's shared pin state. |
| `POST /articles/boost-score?article_id=...&amount=15` | Operational tab + `Action: Boost Threat Score` | Adds a 1–100 amount; score is capped at 100. |
| `POST /articles/feedback?article_id=...&feedback=...` | Operational tab + legacy `Action: Trigger AI Functions` | Accepts 0 (neutral), 1 (dismiss), or 2 (keep). A first transition from neutral to 1/2 adjusts matched keyword weights by one; repeat feedback does not reapply the adjustment. |
| `POST /articles/generate-bluf?article_id=...` | Operational tab + legacy `Action: Trigger AI Functions` | Generates and stores an article BLUF. Missing ID returns a controlled error result. |

Detailed endpoint inventory and response notes are in [`API.md`](../../../API.md#dashboard-endpoints-dashboard).
