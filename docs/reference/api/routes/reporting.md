# Route module: `src.api.routes.reporting`

Prefix: `/api/v1/reporting`. Every route requires `Reporting & Briefings`; the tab/action requirements are listed below.

## Request model bounds

- `BroadcastRequest`: `report_date` ≤50 chars, `content` ≤200,000, `recipients` ≤2,000.
- `BroadcastCustomRequest`: `title` ≤200 chars, `content` ≤200,000, `recipients` ≤2,000.
- Both broadcast recipient fields reject newlines, accept comma/semicolon-separated addresses, validate a simple email shape, and allow at most 20 recipients.
- `SaveReportRequest`: title ≤200, author ≤120, content ≤200,000.
- `GenerateCustomRequest`: target ≤500, `days_back` 1–30 (default 7), at most 100 positive unique `article_ids`, objective ≤4,000, analyst ≤120.
- `SearchArticlesRequest`: target ≤500 and `days_back` 1–30 (default 7).

## Routes

| Method/path | Additional grant | Behavior |
|---|---|---|
| `GET /executive-intel` | `Tab: Reporting -> Daily Fusion` | Calls executive scoring with zero weather count and no crime rows. |
| `GET /saved-reports` | `Tab: Reporting -> Shared Library` | Returns all saved report rows, newest first. |
| `GET /daily-briefings` | `Tab: Reporting -> Daily Fusion` | Returns archived Daily Fusion reports newest first. |
| `POST /generate-daily` | Daily Fusion tab + `Action: Generate Reports` | Synchronously generates and saves the previous local-day Daily Fusion report; returns status, date, and content or a controlled generation error. |
| `POST /broadcast` | Daily Fusion tab + `Action: Dispatch Exec Report` | Sends the supplied report date/content to validated recipients as HTML. Empty recipients return a status/message error. |
| `POST /broadcast-custom` | Report Builder tab + `Action: Dispatch Exec Report` | Sends non-empty custom content to validated recipients. |
| `POST /save-report` | Report Builder tab + `Action: Dispatch Exec Report` | Saves `{title,author,content}` to the shared report library. |
| `DELETE /saved-reports/{report_id}` | Shared Library tab + `Action: Dispatch Exec Report` | Deletes the selected saved report. |
| `POST /search-articles` | Report Builder tab | Accepts `{target,days_back}`; parses comma/semicolon/space-separated terms and quoted phrases, searches title/summary/full content using OR across terms, and returns up to 30 article summaries. |
| `POST /generate-custom` | Report Builder tab + `Action: Generate Reports` | Requires a non-empty target or article ID list; starts a tracked background thread and returns `{status:"started",generation_id}`. |
| `GET /generate-custom-status?generation_id=...` | Report Builder tab | Returns progress while running. When complete/error, returns the result and removes the stored progress/result; invalid IDs return a controlled error. |

## Custom generation lifecycle

The in-memory progress/result dictionaries are protected by a thread lock and are process-local. The generation thread registers as an API background writer so a coordinated restore waits for it. It loads selected IDs or searches the target, calls `build_custom_intel_report()`, adds target/date/analyst metadata, and stores either the completed report or an error. A restart loses the in-memory polling record; the generated output is not automatically saved to `SavedReport` until the user invokes `POST /save-report`.
