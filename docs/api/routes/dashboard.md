# Module: `src.api.routes.dashboard`

Dashboard data, article management, and manual generation trigger routes. Prefix: `/api/v1/dashboard`.

---

## Endpoint: `GET /metrics`

### Purpose
Returns aggregated dashboard metrics (alert counts, risk levels, etc.).

### Parameters
None.

### Returns
The dashboard metrics object from `svc.get_dashboard_metrics()`.

### Raises
None.

### Flow
Direct delegation to service layer.

### Dependencies
- `src.services.get_dashboard_metrics()`

---

## Endpoint: `GET /pinned-articles`

### Purpose
Returns all articles that have been pinned by users.

### Parameters
None.

### Returns
List of pinned article objects.

### Raises
None.

### Flow
Direct delegation to service layer.

### Dependencies
- `src.services.get_pinned_articles()`

---

## Endpoint: `GET /live-articles`

### Purpose
Returns the most recent live (unpinned, scored) articles.

### Parameters
| Parameter | Type  | Default | Constraints | Description                   |
|-----------|-------|---------|-------------|-------------------------------|
| `limit`   | `int` | `15`    | 1-100       | Maximum number of articles.   |

### Returns
List of live article objects.

### Raises
None.

### Flow
Direct delegation to service layer with limit parameter.

### Dependencies
- `src.services.get_live_articles()`

---

## Endpoint: `GET /hazards`

### Purpose
Returns recent regional hazard entries.

### Parameters
| Parameter | Type  | Default | Constraints | Description                   |
|-----------|-------|---------|-------------|-------------------------------|
| `limit`   | `int` | `15`    | 1-100       | Maximum number of hazards.    |

### Returns
List of hazard objects.

### Raises
None.

### Flow
Direct delegation to service layer.

### Dependencies
- `src.services.get_hazards()`

---

## Endpoint: `GET /threat-trends`

### Purpose
Returns historical threat score data for trend visualization.

### Parameters
| Parameter | Type  | Default | Constraints | Description                         |
|-----------|-------|---------|-------------|-------------------------------------|
| `days`    | `int` | `14`    | 1-90        | Number of days of history to return.|

### Returns
Historical threat score series data.

### Raises
None.

### Flow
Direct delegation to service layer.

### Dependencies
- `src.services.get_historical_threat_scores()`

---

## Endpoint: `GET /internal-risk`

### Purpose
Returns the latest internal risk snapshot.

### Parameters
None.

### Returns
Risk snapshot object, or `{"status": "empty", "message": "..."}` if no snapshot exists.

### Raises
None.

### Flow
1. Calls `svc.get_latest_internal_risk()`.
2. If falsy, returns an empty status response.
3. Otherwise returns the data directly.

### Dependencies
- `src.services.get_latest_internal_risk()`

---

## Endpoint: `GET /internal-risk/history`

### Purpose
Returns the historical internal risk data for charting.

### Parameters
| Parameter | Type  | Default | Constraints | Description                       |
|-----------|-------|---------|-------------|-----------------------------------|
| `days`    | `int` | `28`    | 1-365       | Number of days of history.        |

### Returns
List of historical risk snapshot objects.

### Raises
None.

### Flow
Direct delegation to service layer.

### Dependencies
- `src.services.get_internal_risk_history()`

---

## Endpoint: `GET /executive-intel`

### Purpose
Returns executive-level intelligence combining recent crime data and active hazard counts.

### Parameters
None.

### Returns
Executive intel grid object.

### Raises
None.

### Flow
1. Fetches recent crimes within 1.0 max distance, grid-only, last 24 hours.
2. Counts active `RegionalHazard` rows from the database.
3. Delegates to `svc.get_executive_grid_intel()`.

### Dependencies
- `src.services.get_recent_crimes()`
- `src.services.get_executive_grid_intel()`
- `src.models.schema.RegionalHazard`
- `src.core.db.SessionLocal`

---

## Endpoint: `POST /generate-internal-risk`

### Purpose
Manually triggers generation of a new internal risk snapshot.

### Parameters
None.

### Returns
Result of `svc.generate_and_save_internal_risk_snapshot()`.

### Raises
None.

### Flow
Direct delegation to service layer.

### Dependencies
- `src.services.generate_and_save_internal_risk_snapshot()`

---

## Endpoint: `POST /generate-unified-brief`

### Purpose
Manually triggers generation of a unified intelligence briefing.

### Parameters
None.

### Returns
Result of `svc.trigger_unified_brief()`.

### Raises
None.

### Flow
Logs the trigger, then delegates to service layer.

### Dependencies
- `src.services.trigger_unified_brief()`

---

## Endpoint: `POST /generate-rolling-summary`

### Purpose
Manually triggers generation of a rolling situational summary.

### Parameters
None.

### Returns
Result of `svc.trigger_rolling_summary()`.

### Raises
None.

### Flow
Logs the trigger, then delegates to service layer.

### Dependencies
- `src.services.trigger_rolling_summary()`

---

## Endpoint: `POST /generate-scoring-rationale`

### Purpose
Manually triggers generation of an AI-driven rationale explaining current article scores, based on optional intel context.

### Parameters
| Parameter | Type               | Default | Description                       |
|-----------|--------------------|---------|-----------------------------------|
| `data`    | `dict[str, Any]`   | `{}`    | JSON body with optional `intel` key.|

### Returns
Result of `svc.trigger_scoring_rationale()`.

### Raises
None.

### Flow
1. Logs the trigger.
2. Extracts `intel` from request body (defaults to `{}`).
3. Delegates to service layer.

### Dependencies
- `src.services.trigger_scoring_rationale()`

---

## Endpoint: `POST /articles/toggle-pin`

### Purpose
Toggles the pin status of a specific article.

### Parameters
| Parameter   | Type  | Description                     |
|-------------|-------|---------------------------------|
| `article_id`| `int` | Article ID (body/query).        |

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Direct delegation to service layer.

### Dependencies
- `src.services.toggle_pin()`

---

## Endpoint: `POST /articles/boost-score`

### Purpose
Manually boosts the relevance score of an article.

### Parameters
| Parameter   | Type  | Default | Constraints | Description               |
|-------------|-------|---------|-------------|---------------------------|
| `article_id`| `int` | —       | —           | Article ID (body/query).  |
| `amount`    | `int` | `15`    | 1-100       | Score boost amount.       |

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Direct delegation to service layer.

### Dependencies
- `src.services.boost_score()`

---

## Endpoint: `POST /articles/feedback`

### Purpose
Submits user feedback on an article (e.g., mark as helpful/not helpful) by changing its status.

### Parameters
| Parameter   | Type  | Default | Constraints | Description                      |
|-------------|-------|---------|-------------|----------------------------------|
| `article_id`| `int` | —       | —           | Article ID (body/query).         |
| `feedback`  | `int` | `0`     | 0-2         | Feedback value (0/1/2).          |

### Returns
```json
{ "status": "ok" }
```

### Raises
None.

### Flow
Direct delegation to service layer.

### Dependencies
- `src.services.change_status()`

---

## Endpoint: `POST /articles/generate-bluf`

### Purpose
Generates an AI-powered BLUF (Bottom Line Up Front) summary for a specific article.

### Parameters
| Parameter   | Type  | Default | Constraints | Description             |
|-------------|-------|---------|-------------|-------------------------|
| `article_id`| `int` | `0`     | >=0         | Article ID (query).     |

### Returns
```json
{
  "status": "ok" | "error",
  "bluf": "<generated summary>" | null,
  "message": "<error description>" | null
}
```

### Raises
None.

### Flow
1. Opens a database session and queries for the `Article` by ID.
2. If not found, returns error status.
3. Calls `generate_bluf(art, session)` from `src.utils.llm`.
4. If successful, saves the BLUF via `svc.save_ai_bluf()` and returns it.
5. If AI generation fails, returns error status.

### Dependencies
- `src.utils.llm.generate_bluf()`
- `src.models.schema.Article`
- `src.core.db.SessionLocal`
- `src.services.save_ai_bluf()`
