# Enterprise Architecture & Functional Specification: `src/elastic_worker.py`

## 1. Executive Overview

The `src/elastic_worker.py` module is the **SIEM Telemetry Synchronization Engine** for the NOC Intelligence Fusion Center. It provides a bidirectional bridge between the organization's Elastic SIEM (Security Information and Event Management) instance and the local SQLite database.

This module serves two critical functions:
1. **Ingestion:** Pulls high-severity SIEM alerts to enrich OSINT correlation and AIOps root cause analysis
2. **Querying:** Provides a live query interface for ad-hoc Elastic searches without hitting the database

---

## 2. External API Integration

### Elasticsearch Connection

| Parameter | Source | Default |
|----------|--------|---------|
| `ELASTIC_URL` | Environment Variable | `https://localhost:9200` |
| `ELASTIC_API_KEY` | Environment Variable | `your_read_only_api_key` |

**Connection Details:**
- Uses `Elasticsearch` Python client
- SSL certificate verification disabled (`verify_certs=False`) for legacy compatibility
- Falls back gracefully if connection fails (sets `es = None`)

---

## 3. Core Functions

### `sync_elastic_telemetry(hours_back=24)`

**Purpose:** Pulls high-severity SIEM alerts to enrich OSINT and AIOps correlation.

**Parameters:**
- `hours_back` (int, default=24): Lookback window in hours

**Query Logic:**
1. Filters by `@timestamp` >= cutoff time
2. Matches severity via two parallel conditions:
   - `log.level` in: emergency, alert, critical, error, severe (ECS standard)
   - `event.severity` <= 3 (Cisco syslog numeric: 0-3 are Crit/Error)
3. Excludes system indices via `index="*,-.*"`

**Field Extraction:**
- **Severity Mapping:** Converts numeric Cisco severity to string (0-2=CRITICAL, 3=HIGH, else=WARNING)
- **Message:** Falls back to `event.original` if `message` missing
- **Source IP:** Extracts from `source.ip`, then `log.source.address`
- **Category:** Handles list/tuple extraction from `event.category`

**Storage:** Creates `ElasticEvent` records in SQLite

---

### `execute_live_query(index_pattern="*", query_body=None, size=100)`

**Purpose:** Executes direct live queries against Elastic without touching SQLite.

**Parameters:**
- `index_pattern` (str, default="*"): Index glob pattern
- `query_body` (dict, optional): Custom Elasticsearch query DSL
- `size` (int, default=100): Result limit (hard-capped at 500)

**Returns:**
- List of hit documents or `{"error": "message"}`

**Usage Example:**
```python
from src.elastic_worker import execute_live_query
results = execute_live_query(
    index_pattern="firewalls-*",
    query_body={"query": {"match": {"event.category": "intrusion_detection"}}},
    size=50
)
```

---

### `purge_stale_elastic_data(hours_to_keep=72)`

**Purpose:** Ensures local SQLite cache remains small by dropping old SIEM records.

**Parameters:**
- `hours_to_keep` (int, default=72): Retention window

**Behavior:**
- Deletes all `ElasticEvent` records older than cutoff
- Called by scheduler job every 60 minutes

---

## 4. Database Model Reference

### `ElasticEvent`

| Field | Type | Description |
|-------|------|-------------|
| `id` | String (PK) | Elastic document `_id` |
| `index_name` | String | Source index |
| `timestamp` | DateTime | Event timestamp |
| `severity` | String | CRITICAL/HIGH/WARNING/UNKNOWN |
| `message` | String (250) | Truncated message |
| `source_ip` | String | Source IP address |
| `event_category` | String | Event category |

---

## 5. System Integration Context

| Integration Point | Module | Purpose |
|-----------------|--------|---------|
| Scheduler Job | `scheduler.py` | Runs `sync_elastic_telemetry()` every 15 min |
| Scheduler Job | `scheduler.py` | Runs `purge_stale_elastic_data()` every 60 min |
| AIOps Engine | `aiops_engine.py` | Correlates SIEM events with network topology |

---

## 6. API Citations

- **Elasticsearch Python Client:** https://elasticsearch-py.readthedocs.io/
- **ECS (Elastic Common Schema):** https://www.elastic.co/guide/en/ecs/current/
- **Cisco FTD Syslog:** https://www.cisco.com/c/en/us/td/docs/security/firepower/ftdx-command-reference/c console/日志.html