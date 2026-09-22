# Module: `src.api.routes.hunting`

Threat hunting routes for IOC retrieval, OSINT pivoting, and article searching. Prefix: `/api/v1/hunting`.

---

## Endpoint: `GET /iocs`

### Purpose
Returns Indicators of Compromise (IOCs) observed within a configurable lookback window.

### Parameters
| Parameter   | Type  | Default | Constraints | Description                              |
|-------------|-------|---------|-------------|------------------------------------------|
| `days_back` | `int` | `3`     | 1-30        | Number of days of IOC history to return. |
| `limit`     | `int` | `1000`  | 1-1000      | Maximum IOC rows to inspect.             |

### Returns
Bounded list of IOC objects.

### Raises
None.

### Flow
Direct delegation to `svc.get_iocs()`.

### Dependencies
- `src.services.get_iocs()`

---

## Endpoint: `GET /osint-pivot`

### Purpose
Generates an OSINT pivot search link for a given IOC type and value (e.g., IP address, hash, domain).

### Parameters
| Parameter  | Type   | Default | Description                    |
|------------|--------|---------|--------------------------------|
| `ioc_type` | `str`  | `""`    | IOC type (e.g., "ip", "hash"). |
| `ioc_value`| `str`  | `""`    | IOC value to pivot on.         |

### Returns
```json
{
  "link": "<generated OSINT search URL>"
}
```

### Raises
None.

### Flow
Calls `svc.get_osint_pivot_link()` and returns the URL wrapped in an object.

### Dependencies
- `src.services.get_osint_pivot_link()`

---

## Endpoint: `GET /search-articles`

### Purpose
Searches articles for a given target string within a configurable lookback window, for hunting purposes.

### Parameters
| Parameter   | Type   | Default | Constraints | Description                              |
|-------------|--------|---------|-------------|------------------------------------------|
| `target`    | `str`  | `""`    | —           | Search query string.                     |
| `days_back` | `int`  | `3`     | 1-30        | Number of days to search back.           |

### Returns
List of article objects matching the search criteria.

### Raises
None.

### Flow
Direct delegation to `svc.search_articles_for_hunting()`.

### Dependencies
- `src.services.search_articles_for_hunting()`
## Current Source Surface

Router prefix: `/api/v1/hunting` with `Threat Hunting & IOCs` page permission.

- `GET /iocs` returns extracted indicators for a bounded `days_back` range of 1–30.
- `GET /osint-pivot` maps an IOC type/value to external investigation URLs.
- `GET /search-articles` searches articles for a target with a bounded 1–30 day range.
- `GET /elastic-events` returns paginated cached SIEM events and requires the Elastic SIEM tab permission.
- `POST /sync-elastic-cache` synchronizes high-severity Elastic events and requires manual sync permission.
- `POST /generate-siem-triage` accepts up to 50 bounded events and requires the AI action permission.
