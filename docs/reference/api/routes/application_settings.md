# Route module: `src.api.routes.application_settings`

Routes are under `/api/v1/application-settings` and require the Settings page. Global, risk-scoring, and scheduler routes require `Tab: Settings -> Application Settings`; ML counts and manual retraining require `Tab: Settings -> ML Training`. Writes also require the section-specific action listed below.

| Method/path | Behavior and authorization |
|---|---|
| `GET /application-settings` | Returns global defaults and failed-login alert settings. Alert recipients are shown only to administrators or users with `Action: Manage Application Settings`. |
| `PUT /application-settings` | Updates public URL, technology stack, monitored ASNs, and failed-login alert fields. Requires `Action: Manage Application Settings`; unknown body fields are rejected. |
| `GET /application-settings/integrations` | Requires `Action: Manage Application Settings`; returns effective alert destinations and Elastic settings, identifying whether each value comes from the environment or database. It returns only an `elastic_api_key_configured` flag, never the key. |
| `PUT /application-settings/integrations` | Saves validated alert/Elastic overrides; requires `Action: Manage Application Settings`. Addresses accept comma/semicolon-separated email destinations, Elastic timeout is greater than 0 and at most 120 seconds, and maximum results is 1–5000. Explicit `null` resets a field to the environment; a blank optional string disables it. |
| `GET /application-settings/risk-scoring` | Returns the current scoring mode, baselines, overrides, offsets, and countermeasure settings. |
| `PUT /application-settings/risk-scoring` | Updates only declared risk fields; requires `Action: Adjust Risk Scoring Overrides`. Baselines/overrides are bounded 0–5, offsets −3–3, and countermeasures 1–5. |
| `GET /application-settings/scheduler` | Returns registry defaults, bounds, saved schedules, and worker-applied revision. |
| `PATCH /application-settings/scheduler/jobs/{job_key}` | Body is `{"schedule": {...}}`; requires `Action: Manage Scheduler Settings`. `src.core.scheduler_registry.validate_schedule()` enforces supported schedule type, range, timezone, and non-disableable jobs. |
| `GET /application-settings/ml-counts` | Returns positive, negative, and total training-label counts; requires the ML Training tab. |
| `POST /application-settings/ml-retrain` | Trains and reloads the scorer; requires the ML Training tab and `Action: Train ML Model`. Exceptions return a generic `500`. |

These category-specific endpoints replace broad delegated configuration writes. Integration writes are audited by changed field name, not by value. The administrator-only legacy `/admin/config` endpoint remains for compatibility.
