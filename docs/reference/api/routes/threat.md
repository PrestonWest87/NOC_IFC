# Module: `src.api.routes.threat`

Threat intelligence routes for CVEs, cloud outages, crime incidents, article management, feed fetching, CISA KEV sync, cloud status sync, elastic cache sync, and SIEM triage generation. Prefix: `/api/v1/threat`.

---

## Endpoint: `GET /cves`

### Purpose
Returns CVE (Common Vulnerabilities and Exposures) entries with configurable lookback and limit.

### Parameters
| Parameter    | Type  | Default | Constraints  | Description                           |
|--------------|-------|---------|--------------|---------------------------------------|
| `limit`      | `int` | `50`    | 1-200        | Maximum number of CVEs to return.     |
| `days_back`  | `int` | `30`    | 1-365        | Days of CVE history to include.       |

### Returns
List of CVE objects.

### Raises
None.

### Flow
Direct delegation to `svc.get_cves()`.

### Dependencies
- `src.services.get_cves()`

---

## Endpoint: `GET /cloud-outages`

### Purpose
Returns cloud service provider outage records, optionally filtering to only active outages.

### Parameters
| Parameter      | Type    | Default | Constraints | Description                             |
|----------------|---------|---------|-------------|-----------------------------------------|
| `active_only`  | `bool`  | `True`  | —           | If true, returns only unresolved outages.|
| `days_back`    | `int`   | `7`     | 1-90        | Days of outage history to include.      |

### Returns
List of cloud outage objects.

### Raises
None.

### Flow
Direct delegation to `svc.get_cloud_outages()`.

### Dependencies
- `src.services.get_cloud_outages()`

---

## Endpoint: `GET /crime-incidents`

### Purpose
Returns recent crime incidents within a configurable time window and distance radius.

### Parameters
| Parameter      | Type    | Default | Constraints | Description                             |
|----------------|---------|---------|-------------|-----------------------------------------|
| `hours_back`   | `int`   | `24`    | 1-168       | Hours of crime history to include.      |
| `max_distance` | `float` | `1.0`   | >=0.1       | Maximum distance in miles from sites.   |

### Returns
List of crime incident objects.

### Raises
None.

### Flow
Direct delegation to `svc.get_recent_crimes()`.

### Dependencies
- `src.services.get_recent_crimes()`

---

## Endpoint: `GET /articles`

### Purpose
Returns paginated articles with filtering by category type, sub-category, search term, and minimum score.

### Parameters
| Parameter     | Type   | Default   | Constraints                     | Description                                    |
|---------------|--------|-----------|---------------------------------|------------------------------------------------|
| `category`    | `str`  | `"live"`  | `^(live\|pinned\|low\|search)$` | Top-level article category.                    |
| `cat_filter`  | `str`  | `"All"`   | —                               | Sub-category filter (e.g., threat type).       |
| `page`        | `int`  | `1`       | >=1                             | Page number.                                   |
| `page_size`   | `int`  | `20`      | 5-100                           | Articles per page.                             |
| `search_term` | `str`  | `None`    | —                               | Optional search query string.                  |
| `min_score`   | `int`  | `0`       | >=0                             | Minimum relevance score filter.                |

### Returns
```json
{
  "items": [...],
  "total": <int>,
  "total_pages": <int>,
  "page": <int>
}
```

### Raises
None.

### Flow
Calls `svc.get_paginated_articles()` with all filter parameters and returns the paginated result.

### Dependencies
- `src.services.get_paginated_articles()`

---

## Endpoint: `POST /fetch-feeds`

### Purpose
Manually triggers an RSS feed fetch operation.

### Parameters
None.

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
1. Imports `fetch_feeds` from `src.scheduler`.
2. Calls it with `source="API Trigger"`.
3. Returns success, or catches any exception and returns error message.

### Dependencies
- `src.scheduler.fetch_feeds()`

---

## Endpoint: `POST /sync-cisa-kev`

### Purpose
Manually syncs the CISA Known Exploited Vulnerabilities (KEV) catalog.

### Parameters
None.

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
1. Imports `fetch_cisa_kev` from `src.workers.cve_worker`.
2. Calls the fetch function.
3. Returns success, or catches any exception and returns error message.

### Dependencies
- `src.workers.cve_worker.fetch_cisa_kev()`

---

## Endpoint: `POST /sync-cloud-status`

### Purpose
Manually triggers a sync of cloud provider status/outage data.

### Parameters
None.

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
1. Imports `fetch_cloud_outages` from `src.workers.cloud_worker`.
2. Calls the fetch function.
3. Returns success, or catches any exception and returns error message.

### Dependencies
- `src.workers.cloud_worker.fetch_cloud_outages()`

---

## Endpoint: `POST /fetch-crime-data`

### Purpose
Manually triggers a fetch of crime incident data.

### Parameters
None.

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
Calls `svc.force_fetch_crime_data()` and returns success or error based on the boolean result.

### Dependencies
- `src.services.force_fetch_crime_data()`

---

## Endpoint: `POST /sync-elastic-cache`

### Purpose
Manually triggers synchronization of the Elasticsearch cache for recent data.

### Parameters
| Parameter    | Type  | Default | Constraints | Description                           |
|--------------|-------|---------|-------------|---------------------------------------|
| `hours_back` | `int` | `24`    | >=1         | Hours of data to include in the sync. |

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
1. Imports `run_elastic_sync` from `src.workers.elastic_worker`.
2. Calls the sync function with the hours_back parameter.
3. Returns success, or catches any exception and returns error message.

### Dependencies
- `src.workers.elastic_worker.run_elastic_sync()`

---

## Endpoint: `POST /generate-siem-triage`

### Purpose
Generates an AI-powered SIEM triage summary for a given set of security events.

### Parameters
| Parameter | Type               | Description                                   |
|-----------|--------------------|-----------------------------------------------|
| `data`    | `dict`             | JSON body with optional `events` list.        |

### Returns
```json
{
  "summary": "<generated triage summary or fallback message>"
}
```

### Raises
None.

### Flow
1. Imports `generate_siem_triage_summary` from `src.utils.llm`.
2. Opens a database session.
3. Calls the triage generator with the session and events list.
4. Returns the summary or a fallback message if generation failed.

### Dependencies
- `src.utils.llm.generate_siem_triage_summary()`
- `src.core.db.SessionLocal`
