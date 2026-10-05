# Module: `src.core.scheduler_registry`

`JOB_REGISTRY` is the source of truth for the 20 supported background jobs, their defaults, validation bounds, startup-run policy, and whether an operator can disable them.

Each registry entry identifies a job key/function and uses one of three schedule shapes:

- `interval`: integer `every_value` and the fixed unit declared for that job, within `min_value`/`max_value`.
- `daily`: `run_at` in 24-hour `HH:MM` form.
- `weekly`: `weekday` and `run_at`.

Daily and weekly jobs use `America/Chicago`. `tiered_alert_escalation` is required, cannot be disabled, and is bounded to one through five minutes. `database_backup` also cannot be disabled. `startup_run` controls which jobs are submitted on worker boot; it is separate from the persisted recurring schedule. The complete current schedule and startup policy are maintained in [`docs/SCHEDULER.md`](../../SCHEDULER.md).

`default_schedule(job_key)` returns the registry fields persisted for a job. `validate_schedule(job_key, value)` rejects unknown jobs, schedule-type changes, out-of-range intervals, invalid times/days, non-Central time zones, and attempts to disable a required job. The worker polls `SCHEDULER_POLL_SECONDS` (30 seconds) for persisted revisions and reloads schedules without interrupting in-flight work.
