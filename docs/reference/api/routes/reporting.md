# Module: `src.api.routes.reporting`

Reporting and daily briefing routes for executive intel, saved reports, daily fusion reports, custom intel reports, and email broadcast. Prefix: `/api/v1/reporting`.

---

## Pydantic Models

### `BroadcastRequest`
| Field         | Type     | Default | Description                         |
|---------------|----------|---------|-------------------------------------|
| `report_date` | `str`    | `""`    | Date of the report being broadcast. |
| `content`     | `str`    | `""`    | Report body content.                |
| `recipients`  | `str`    | `""`    | Comma-separated email recipients.   |

### `SaveReportRequest`
| Field    | Type     | Default             | Description                |
|----------|----------|---------------------|----------------------------|
| `title`  | `str`    | `"Untitled Report"` | Report title.              |
| `author` | `str`    | `"Unknown"`         | Report author name.        |
| `content`| `str`    | `""`                | Report body content.       |

### `GenerateCustomRequest`
| Field       | Type     | Default      | Description                          |
|-------------|----------|--------------|--------------------------------------|
| `target` | `str` | `""` | Search target/keyword for the report. |
| `days_back` | `int` | `7` | Lookback window, constrained to 1–30 days. |
| `article_ids` | `list[int] \| None` | `None` | Optional selection of up to 100 positive article IDs. |
| `objective` | `str` | `""` | Report objective/context. |
| `analyst` | `str` | `"Unknown"` | Analyst attribution shown in the report. |

`BroadcastCustomRequest` contains `title`, `content`, and `recipients`. `SearchArticlesRequest` contains `target` and `days_back` (1–30); both reporting recipient request models reject newlines, validate addresses, and limit recipient lists to 20.

---

## Endpoint: `GET /executive-intel`

### Purpose
Returns executive-level intelligence grid data.

### Parameters
None.

### Returns
Executive intel grid object from `svc.get_executive_grid_intel()`.

### Raises
None.

### Flow
Calls `svc.get_executive_grid_intel()` with zero values (no hazard or crime context), returns the default intel structure.

### Dependencies
- `src.services.get_executive_grid_intel()`

---

## Endpoint: `GET /saved-reports`

### Purpose
Lists all previously saved custom reports.

### Parameters
None.

### Returns
List of saved report objects.

### Raises
None.

### Flow
Direct delegation to `svc.get_saved_reports()`.

### Dependencies
- `src.services.get_saved_reports()`

---

## Endpoint: `GET /daily-briefings`

### Purpose
Lists all generated daily briefing records.

### Parameters
None.

### Returns
List of daily briefing objects.

### Raises
None.

### Flow
Direct delegation to `svc.get_all_daily_briefings()`.

### Dependencies
- `src.services.get_all_daily_briefings()`

---

## Endpoint: `POST /generate-daily`

### Purpose
Generates a new daily fusion report using the AI/LLM, saves it as a daily briefing, and returns the content.

### Parameters
None.

### Returns
```json
{
  "status": "ok" | "error",
  "date": "<YYYY-MM-DD>",
  "content": "<report markdown>" | null,
  "message": "<error description>"
}
```

### Raises
None.

### Flow
1. Opens a database session.
2. Calls `generate_daily_fusion_report(session)` from `src.utils.llm`.
3. If a report was generated successfully:
   - Saves it via `svc.save_daily_briefing()`.
   - Formats the date string.
   - Returns success with date and content.
4. If generation failed, returns error status.

### Dependencies
- `src.utils.llm.generate_daily_fusion_report()`
- `src.services.save_daily_briefing()`
- `src.core.db.SessionLocal`

---

## Endpoint: `POST /broadcast`

### Purpose
Broadcasts a daily fusion report to specified email recipients as an HTML email.

### Parameters
| Parameter | Type               | Description                 |
|-----------|--------------------|-----------------------------|
| `data`    | `BroadcastRequest` | Report date, content, and recipients.|

### Returns
```json
{
  "status": "ok" | "error",
  "message": "<description>"
}
```

### Raises
None.

### Flow
1. Validates that recipients are specified; returns error if empty.
2. Calls `svc.generate_daily_report_email_html()` to format the report as HTML.
3. Sends the email via `send_alert_email()` with HTML content type.
4. Returns success or error based on the send result.

### Dependencies
- `src.services.generate_daily_report_email_html()`
- `src.utils.mailer.send_alert_email()`

---

## Endpoint: `POST /save-report`

### Purpose
Saves a custom intelligence report to the database.

### Parameters
| Parameter | Type               | Description              |
|-----------|--------------------|--------------------------|
| `data`    | `SaveReportRequest`| Report title, author, content.|

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Direct delegation to `svc.save_custom_report()`.

### Dependencies
- `src.services.save_custom_report()`

---

## Endpoint: `DELETE /saved-reports/{report_id}`

### Purpose
Deletes a saved custom report by its ID.

### Parameters
| Parameter   | Type  | Description                    |
|-------------|-------|--------------------------------|
| `report_id` | `int` | ID of the report to delete.    |

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Calls `svc.delete_record("SavedReport", report_id)`.

### Dependencies
- `src.services.delete_record()`

---

## Endpoint: `POST /generate-custom`

### Purpose
Starts asynchronous custom intelligence report generation from either a search target/lookback window or selected article IDs.

### Parameters
| Parameter | Type                   | Description                      |
|-----------|------------------------|----------------------------------|
| `data`    | `GenerateCustomRequest`| Target, days_back, objective, analyst.|

### Returns
```json
{"status":"started","generation_id":"<uuid>"}
```
The endpoint returns this immediately; poll the custom-report status route for progress/result.

### Raises
None.

### Flow
1. Requires either a non-empty target or a non-empty `article_ids` list and validates search terms.
2. Creates a generation ID and starts a tracked daemon thread.
3. Loads the selected articles or searches by target, then calls `build_custom_intel_report()` with the objective and database session.
4. Stores progress/results in process memory; poll `GET /generate-custom-status?generation_id=...` for progress or the completed report.

### Dependencies
- `src.services.search_articles_for_hunting()`
- `src.utils.llm.build_custom_intel_report()`
- `src.core.db.SessionLocal`
## Current Source Corrections

Router prefix: `/api/v1/reporting`. The router requires page permission `Reporting & Briefings`.

### Request Models

- `BroadcastRequest`: `report_date` max 50 characters, `content` max 200,000, `recipients` max 2,000; recipient validation accepts commas/semicolons, rejects newlines, limits to 20 addresses, and validates email format.
- `BroadcastCustomRequest`: custom report content and recipient validation using the same recipient rules.
- `GenerateCustomRequest`: supports `target`, `days_back` constrained to 1–30, `objective`, and optional `article_ids`.
- `SearchArticlesRequest`: request model for targeted article searches.

### Current Endpoints

| Endpoint | Permission | Behavior |
|---|---|---|
| `POST /broadcast-custom` | `Action: Dispatch Exec Report` | Sends a custom report to validated recipients. |
| `POST /search-articles` | Router page permission | Searches source articles for custom report building. |
| `POST /generate-custom` | `Action: Generate Reports` | Starts daemon/background custom report generation and returns a generation ID. |
| `GET /generate-custom-status` | Router page permission | Reads progress/result from the in-memory report stores. |
| `DELETE /saved-reports/{report_id}` | `Action: Dispatch Exec Report` | Deletes a saved report. |
| `POST /generate-daily` | `Action: Generate Reports` | Generates the daily report. |

Custom generation uses `_report_progress_store`, `_report_result_store`, and `_report_lock` to coordinate progress and result retrieval. Generation can use either a search `target` or explicit `article_ids`.
