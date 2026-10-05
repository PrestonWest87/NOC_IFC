# Component: `ApplicationSettingsTab`

**Source:** `web/src/components/ApplicationSettingsTab.tsx`

Renders the Settings > Application Settings sections for global defaults/sign-in alerts, risk scoring, and persisted scheduler jobs. It receives the current user and checks a separate action grant for each editable section:

- `Action: Manage Application Settings`
- `Action: Adjust Risk Scoring Overrides`
- `Action: Manage Scheduler Settings`

The component queries `/application-settings`, `/application-settings/risk-scoring`, and `/application-settings/scheduler`. It saves global/risk fields through `PUT` and per-job schedules through `PATCH /application-settings/scheduler/jobs/{job_key}`. Schedule data refreshes every 30 seconds; successful saves invalidate the relevant React Query caches and report an accessible status message. Backend validation remains authoritative for bounds and required jobs.
