# Enterprise Architecture & Functional Specification: `src/report_worker.py`

## 1. Executive Overview

The `src/report_worker.py` module serves as the **Autonomous Reporting Cron-Engine** for the Intelligence Fusion Center (IFC). It is a persistent, long-running background daemon responsible for orchestrating the generation of the "Daily Master Fusion Report" at 06:00 AM CST.

By abstracting this heavy, time-consuming LLM Map-Reduce workload into a dedicated background worker, the system ensures the comprehensive daily situational briefing is fully generated, formatted, and cached in the database *before* NOC operators arrive for their morning shift.

---

## 2. Core Execution Logic: `run_daily_report()`

### Timezone & Temporal Scoping
- **Strict Localization:** Enforces `ZoneInfo("America/Chicago")` (CST/CDT)
- **Date Normalization:** Subtracts 1 day from current local time, strips time components

### Idempotency
Queries `DailyBriefing` for a record matching `yesterday_local`. If a record exists, the function aborts (`return`) to prevent duplicate generation.

### LLM Handoff & Persistence
1. Calls `generate_daily_fusion_report(session)` from `src.llm`
2. Receives a tuple `(date_obj, report_markdown)`
3. Validates `report_markdown` is non-empty
4. Creates and commits `DailyBriefing` ORM object

---

## 3. The Scheduling Mechanism: `start_report_scheduler()`

- **Infinite Polling:** Operates on `while True:` loop
- **Target Trigger:** Checks if `now_cst.hour == 6 and now_cst.minute < 10` (10-minute window)
- **Debounce:** Once triggered, sleeps for 1 hour to clear the window
- **Idle Polling:** Sleeps 60 seconds between checks

---

## 4. Complete Function Reference

| Function | Signature | Purpose |
|----------|-----------|---------|
| `run_daily_report` | `() -> None` | Generate and save daily report |
| `start_report_scheduler` | `() -> None` | Report scheduler event loop |

---

## 5. API Citations

| API / Service | Purpose | Documentation |
|---------------|---------|---------------|
| datetime | Time handling | https://docs.python.org/3/library/datetime.html |
| time | Sleep | https://docs.python.org/3/library/time.html |
