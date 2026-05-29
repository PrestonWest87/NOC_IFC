# Cloud Worker Module

**File:** `src/workers/cloud_worker.py`

## Overview

Fetches and ingests cloud provider status feed data from 18 major providers (AWS, Google Cloud, Azure, Cisco Umbrella, Cisco Webex, Cisco Meraki, Cloudflare, GitHub, Slack, Zoom, Atlassian, Datadog, PagerDuty, Twilio, Okta, Zscaler, CrowdStrike, Mimecast). Filters maintenance windows and non-US regions, extracts US-region impact, and persists new or resolved outages to the `CloudOutage` table.

---

## Constants

### `CLOUD_FEEDS` (`dict[str, str]`)

Maps 18 cloud provider names to their RSS/Atom status feed URLs.

### `US_REGIONS` (`dict[str, str]`)

Maps 16 canonical region keys (e.g. `"us-east-1"`, `"eastus"`) to human-readable display names.

### `FOREIGN_IDENTIFIERS` (`list[str]`)

List of substrings (e.g. `"eu-"`, `"asia"`, `"london"`) used to identify non-US region mentions.

---

## Functions

### `is_foreign_region(text: str) -> bool`

- **Purpose:** Determine whether the given text references a non-US region, excluding global or US-ambiguous phrases.
- **Parameters:**
  - `text` (`str`): Combined title and description text to check.
- **Returns:** `True` if a foreign identifier is found and no US-qualifying term (`"us-"`, `"united states"`, etc.) is present, otherwise `False`.
- **Raises:** None (uses safe `re.search`).
- **Flow:**
  1. Lowercase the input text.
  2. For each foreign identifier:
     a. Use regex word-boundary matching.
     b. If matched and no US-qualifying term exists, return `True`.
  3. Return `False`.
- **Dependencies:** `re`

### `extract_us_regions(text: str) -> list[str]`

- **Purpose:** Extract a list of US-region display names referenced in the given text.
- **Parameters:**
  - `text` (`str`): Combined title and description text to scan.
- **Returns:** `list[str]` of matching US region display names, or `["US-General / Multi-Region"]` if a US qualifier is found without a specific match.
- **Raises:** None.
- **Flow:**
  1. Lowercase input.
  2. Iterate `US_REGIONS`; collect display names for any key found.
  3. If none matched but a US qualifier is present, return `["US-General / Multi-Region"]`.
- **Dependencies:** None (module constant `US_REGIONS`).

### `is_future_maintenance(title: str, description: str) -> bool`

- **Purpose:** Detect whether a status entry describes a future scheduled maintenance event that should be excluded from the alert feed.
- **Parameters:**
  - `title` (`str`): Entry title.
  - `description` (`str`): Entry description body.
- **Returns:** `True` if the entry is a future maintenance notice, `False` if it is current or already in progress.
- **Raises:** None.
- **Flow:**
  1. Combine and lowercase title + description.
  2. If no maintenance keywords found, return `False`.
  3. If explicit in-progress keywords found, return `False`.
  4. If today's date appears, return `False` (already relevant).
  5. Otherwise return `True` (future event).
- **Dependencies:** `datetime`

### `extract_service_name(provider: str, title: str) -> str`

- **Purpose:** Extract a clean service name from an alert title by stripping status brackets and splitting on common delimiters.
- **Parameters:**
  - `provider` (`str`): The cloud provider name.
  - `title` (`str`): Raw feed entry title.
- **Returns:** `str` - Cleaned service name, or a provider-level fallback such as `"AWS Infrastructure"` or `"General/Multiple Services"`.
- **Raises:** None.
- **Flow:**
  1. Strip `[Investigating]`, `[Resolved]`, `[Update]` prefixes.
  2. Try splitting on ` - `, `: `, or ` | `; return the first segment.
  3. If no delimiter found, return a provider-specific fallback.
- **Dependencies:** None.

### `fetch_cloud_outages() -> None`

- **Purpose:** Main entry point. Fetches all 18 cloud provider RSS feeds, parses entries from the last 7 days, filters future maintenance and foreign-region events, extracts US-region impact, and upserts `CloudOutage` records. Also marks previously unresolved alerts as resolved when the feed indicates resolution.
- **Parameters:** None
- **Returns:** `None`
- **Raises:** None (top-level exceptions are caught and logged as critical failures).
- **Flow:**
  1. Compute cutoff window: `UTC now - 7 days`.
  2. For each provider in `CLOUD_FEEDS`:
     a. HTTP GET the feed URL (10 s timeout).
     b. Parse with `feedparser`.
     c. For each of the first 15 entries:
        i.   Parse `published_parsed` or fall back to `UTC now`.
        ii.  Skip if older than cutoff.
        iii. Skip if `is_future_maintenance()` returns `True`.
        iv.  Skip if `is_foreign_region()` returns `True`.
        v.   Detect resolved status via keywords (`[RESOLVED]`, `OPERATIONAL`, etc.).
        vi.  Extract service name via `extract_service_name()`.
        vii. Extract US region via `extract_us_regions()`.
        viii. Check for existing record by (provider, title, updated_at).
        ix.  If new: insert `CloudOutage`.
        x.   If existing and newly resolved: update `is_resolved`.
     d. On failure: log warning, append to `failed_providers`, continue.
  3. Purge resolved alerts older than 3 days.
  4. Commit session.
  5. Log summary with counts for added, resolved, filtered, and failed providers.
- **Dependencies:**
  - `feedparser` - RSS/Atom feed parsing
  - `requests` - HTTP client
  - `src.core.db.SessionLocal` - SQLAlchemy session factory
  - `src.models.schema.CloudOutage` - ORM model
  - `datetime`, `re`
