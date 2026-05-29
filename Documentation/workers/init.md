# Workers Package

**File:** `src/workers/__init__.py`

## Overview

Package initialiser for the `workers` module. Re-exports all top-level worker entry-point functions for convenient access and provides placeholder lifecycle management functions.

---

## Re-exports

| Symbol | Source Module |
|---|---|
| `fetch_cloud_outages` | `workers.cloud_worker` |
| `fetch_live_crimes` | `workers.crime_worker` |
| `fetch_cisa_kev` | `workers.cve_worker` |
| `sync_elastic_telemetry` | `workers.elastic_worker` |
| `execute_live_query` | `workers.elastic_worker` |
| `purge_stale_elastic_data` | `workers.elastic_worker` |
| `fetch_regional_hazards` | `workers.infra_worker` |
| `start_report_scheduler` | `workers.report_worker` |
| `run_daily_report` | `workers.report_worker` |
| `run_telemetry_sync` | `workers.telemetry_worker` |

---

## Functions

### `start_all_workers() -> None`

- **Purpose:** Placeholder for future centralised worker lifecycle management. Intended to start all registered background workers.
- **Parameters:** None
- **Returns:** `None`
- **Raises:** None.
- **Flow:** No-op currently.
- **Dependencies:** None.

### `stop_all_workers() -> None`

- **Purpose:** Placeholder for future centralised worker lifecycle management. Intended to gracefully stop all running workers.
- **Parameters:** None
- **Returns:** `None`
- **Raises:** None.
- **Flow:** No-op currently.
- **Dependencies:** None.
