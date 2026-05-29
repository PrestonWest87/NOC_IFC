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
| `target`    | `str`    | `""`         | Search target/keyword for the report.|
| `days_back` | `int`    | `7`          | Days of article history to include.  |
| `objective` | `str`    | `""`         | Report objective/context.            |
| `analyst`   | `str`    | `"Unknown"`  | Analyst name for attribution.        |

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
Generates a custom intelligence report using AI/LLM based on a search target, lookback window, and objective.

### Parameters
| Parameter | Type                   | Description                      |
|-----------|------------------------|----------------------------------|
| `data`    | `GenerateCustomRequest`| Target, days_back, objective, analyst.|

### Returns
```json
{
  "status": "ok" | "error",
  "content": "<full report markdown>" | null,
  "message": "<error description>"
}
```

### Raises
None.

### Flow
1. Searches for articles matching the target via `svc.search_articles_for_hunting()`.
2. If no articles found, returns an error status.
3. Opens a database session.
4. Calls `build_custom_intel_report()` from `src.utils.llm` with articles, objective, and session.
5. If report generation failed, returns an error.
6. Prepends a report header with the target, current datetime (America/Chicago), and analyst name.
7. Returns the full report markdown.

### Dependencies
- `src.services.search_articles_for_hunting()`
- `src.utils.llm.build_custom_intel_report()`
- `src.core.db.SessionLocal`
