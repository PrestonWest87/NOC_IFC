# CVE Worker Module

**File:** `src/workers/cve_worker.py`

## Overview

Fetches the CISA Known Exploited Vulnerabilities (KEV) catalog from the official CISA JSON feed and ingests new entries into the `CveItem` table. Designed to run on a scheduled interval to keep the vulnerability database synchronised with CISA's authoritative list.

---

## Constants

### `CISA_KEV_URL` (`str`)

The URL of the CISA Known Exploited Vulnerabilities catalog:
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

---

## Functions

### `fetch_cisa_kev() -> None`

- **Purpose:** Main entry point. Downloads the CISA KEV JSON catalog, compares each vulnerability against the database by `cve_id`, and inserts any new records.
- **Parameters:** None
- **Returns:** `None`
- **Raises:** None (top-level exceptions are caught and logged).
- **Flow:**
  1. Log `"Fetching latest CISA KEV catalog..."`.
  2. HTTP GET `CISA_KEV_URL` (30 s timeout).
  3. Raise for non-200 status.
  4. Parse JSON response, extract `vulnerabilities` list.
  5. For each vulnerability:
     a. Extract `cveID`.
     b. Query `CveItem` by `cve_id`; skip if already present.
     c. Parse `dateAdded` from `YYYY-MM-DD` string, or default to `UTC now`.
     d. Build `CveItem` with `cve_id`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`.
     e. Add to session; increment counter.
  6. Commit session.
  7. Log success with count of newly added vulnerabilities.
  8. On failure, log error with exception details.
- **Dependencies:**
  - `requests` - HTTP client
  - `src.core.db.SessionLocal` - SQLAlchemy session factory
  - `src.models.schema.CveItem` - ORM model
  - `datetime`
