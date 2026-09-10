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

### Returns
List of IOC objects.

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
