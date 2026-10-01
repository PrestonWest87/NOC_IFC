# Report Worker Module

**File:** `src/workers/report_worker.py`

## Overview

Generates and persists the Daily Fusion Report for the NOC. The main scheduler invokes `run_daily_report()` at the registry-configured time (default 06:00 America/Chicago), calls the LLM-based report generator, and saves the resulting markdown report to the `DailyBriefing` table.

---

## Constants

### `LOCAL_TZ` (`ZoneInfo`)

`America/Chicago` timezone used to compute the prior local calendar day.

---

## Functions

### `run_daily_report() -> None`

- **Purpose:** Generate and persist a Daily Fusion Report for the previous calendar day. Guards against duplicate generation.
- **Parameters:** None
- **Returns:** `None`
- **Raises:** None (exceptions are caught, logged, and the session is rolled back).
- **Flow:**
  1. Log that the scheduled report job started.
  2. Open a database session.
  3. Compute `yesterday_local` as midnight-to-midnight in `LOCAL_TZ` on the previous day.
  4. Query `DailyBriefing` for the target date; if a report already exists, log and return.
  5. Call `generate_daily_fusion_report(session)`:
     - Returns `(date_obj, report_markdown)`.
  6. If `report_markdown` is non-empty:
     a. Create and add `DailyBriefing(report_date=date_obj, content=report_markdown)`.
     b. Commit.
     c. Log success.
  7. If `report_markdown` is empty: log warning about AI API connection.
  8. On exception: rollback and log error.
  9. `finally`: close the session.
- **Dependencies:**
  - `src.core.db.SessionLocal` - SQLAlchemy session factory
  - `src.models.schema.DailyBriefing` - ORM model
  - `src.utils.llm.generate_daily_fusion_report` - LLM-based report generation
  - `datetime`, `zoneinfo`

## Current Runtime Boundary

The report-generation schedule is stored in `SchedulerJobConfig` and reloaded by `src/scheduler.py`. Daily email dispatch is a separate registered job at its own configured time.
