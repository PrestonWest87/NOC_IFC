# Report Worker Module

**File:** `src/workers/report_worker.py`

## Overview

Generates and persists the Daily Fusion Report for the NOC. Listens for the 06:00 AM CST trigger window, calls the LLM-based report generator, and saves the resulting markdown report to the `DailyBriefing` table. Designed to run as a long-lived scheduler service.

---

## Constants

### `LOCAL_TZ` (`ZoneInfo`)

`America/Chicago` timezone used for the 06:00 AM trigger detection.

---

## Functions

### `run_daily_report() -> None`

- **Purpose:** Generate and persist a Daily Fusion Report for the previous calendar day. Guards against duplicate generation.
- **Parameters:** None
- **Returns:** `None`
- **Raises:** None (exceptions are caught, logged, and the session is rolled back).
- **Flow:**
  1. Log `"06:00 AM trigger hit! Initiating Daily Fusion Report synthesis..."`.
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

### `start_report_scheduler() -> None`

- **Purpose:** Blocking scheduler loop that checks the current local time every 60 seconds and triggers `run_daily_report()` when the clock is at 06:00-06:09 AM CST.
- **Parameters:** None
- **Returns:** `None` (blocks indefinitely).
- **Raises:** None.
- **Flow:**
  1. Log `"Online. Standing by for 06:00 AM CST..."`.
  2. Infinite loop:
     a. Get current time in `LOCAL_TZ`.
     b. If hour == `6` and minute < `10`:
        i.  Call `run_daily_report()`.
        ii. Sleep for 3600 s (1 hour) to avoid re-triggering within the window.
     c. Else: sleep for 60 s.
- **Dependencies:**
  - `time.sleep` - loop pacing
  - `run_daily_report()` - actual report generation
  - `datetime`, `zoneinfo`
