# Route module: `src.api.routes.aiops`

Prefix: `/api/v1/aiops`. All routes require page permission `AIOps RCA` and a valid session. Site data is filtered by the caller's allowed site types; administrators receive the full set.

| Method/path | Additional grants | Behavior |
|---|---|---|
| `GET /dashboard` | `Tab: AIOps RCA -> Active Board` | Returns filtered active, uncorrelated alerts, scoped timeline events, and active regional outage grid data. This compatibility response does not include the richer `locations` and `active_issue_counts` fields returned by `/rca/dashboard`. |
| `GET /sites` | Active Board tab | Returns site ID/name/coordinates/type/district/priority/maintenance, filtered by allowed site types. |
| `GET /sitrep` | `Tab: AIOps RCA -> Global Correlation` + `Action: Generate Reports` + access to all site types | Generates and returns a global situation report from the current configuration and AIOps records. |
| `PATCH /sites/{site_id}/acknowledge` | Active Board tab + `Action: Acknowledge RCA Alerts` + site access | Acknowledges that site's unresolved, not-yet-correlated alerts. It records acknowledgement metadata but does not set `status="Resolved"`; the separate `/rca/resolve-site` action marks operational health Up. |

`PATCH /sites/{site_id}/acknowledge` returns 404 when the site ID is unknown and a structured site-scope 403 when the user cannot access its site type. This older `/aiops` compatibility surface is retained alongside the richer `/rca` routes.
