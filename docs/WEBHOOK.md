# SolarWinds Webhook Gateway

The legacy FastAPI gateway in `src/webhook_listener.py` listens on container port 8100 and is retained in the ignored local `docker-compose.yml` backup. The tracked default `compose.yaml` includes `compose.dev-c.yaml` and selects the C# gateway; the Python listener remains available through the backup Compose file.

## Endpoint and successful response

```text
POST /webhook/solarwinds
Content-Type: application/json
```

The route currently returns HTTP **200** with a JSON body like `{"status":"accepted","message":"Payload queued for AI processing."}` once the payload is queued. The message text is legacy wording: persistence is performed by `process_payload_background`; an accepted response does not guarantee the background database write completed.

## Validation and signing

1. Rejects while a restore maintenance marker is active (503).
2. Enforces `WEBHOOK_MAX_BODY_BYTES` against both `Content-Length` when supplied and the actual body bytes (413 when too large).
3. Parses a non-empty JSON object with no more than 100 top-level fields (400 for invalid JSON, 422 for the wrong object shape/field count).
4. If `WEBHOOK_HMAC_SECRET` is set, requires the configured signature header. With the default positive replay window it also requires a numeric Unix timestamp header within `WEBHOOK_REPLAY_WINDOW_SECONDS`.
5. Compares HMAC-SHA256 in constant time. With a timestamp, it accepts the timestamp-prefixed `timestamp + "." + body` signing form and the legacy body-only form. It rejects a repeated `timestamp:signature` pair from the in-process 10,000-entry replay cache (409).
6. If no HMAC secret is configured, unsigned requests are rejected with 503 unless the explicit migration exception `ALLOW_UNSIGNED_WEBHOOKS=true` is enabled.

`WEBHOOK_SIGNATURE_HEADER`, `WEBHOOK_TIMESTAMP_HEADER`, `WEBHOOK_REPLAY_WINDOW_SECONDS`, `WEBHOOK_MAX_BODY_BYTES`, `WEBHOOK_HMAC_SECRET`, and `ALLOW_UNSIGNED_WEBHOOKS` are documented in [the environment reference](reference/config/env_example.md). The nonce cache is process-local, so request signing and network isolation remain important.

## Payload normalization

`smart_extract(payload)` reads:

| Normalized field | Source fields |
|---|---|
| Node | `Node_Details.NodeName`, `Node_Details.SysName`, `entity_caption` |
| IP | `Node_Details.IP_Address`; if absent, first IPv4-shaped value found in the serialized payload |
| Device hint | `Node_Details.MachineType`, `Custom_Properties_Universal.Node_Type`, `entity_type` |
| Severity/alert level | top-level and universal custom properties |
| Event type | `AlertName`, `check`, `class`, `description` |
| Status | node status description or top-level description |
| Site | `Custom_Properties_Universal.Site`, then `City` |
| Communications metadata | `Primary_Comms` and `Secondary_Comms` |

Resolution detection uses word-boundary matches for `resolved`, `up`, `ok`, `clear`, `operational`, or `recovered` in normalized status/description. The alert level is copied into `raw_payload.Normalized_Alert_Level` for later escalation.

### Device domain keys

The classifier first passes an explicit device hint through `EnterpriseAIOpsEngine.normalize_domain_hint()`. If that produces no canonical key, keyword matching can return `INTERNET`, `COMMS_EQUIPMENT`, `POWER_SUPPLIES`, `COMPUTE`, or `SCADA`; unmatched text falls back to `Network Node`. Hints can also normalize to `RTU` or `FACILITIES`. The engine's canonical internet key is `INTERNET`; `PRIMARY_INTERNET` is a compatibility alias, not the engine's canonical output.

## Persistence and resolution

- For a resolution event, the background task marks every unresolved alert with the same node name `Resolved`, sets `resolved_at`, adds a site-scoped `TimelineEvent`, and commits.
- For a new event, it creates `SolarWindsAlert` with normalized fields and the original JSON in `raw_payload`, then creates a site-scoped alert timeline row and commits.
- Any background exception rolls back and is logged; it cannot change the already-returned HTTP response.

## Response/error summary

| Condition | HTTP response |
|---|---|
| Accepted and queued | 200, `status="accepted"` |
| Invalid JSON | 400 |
| Missing/invalid/expired signature or replayed request | 401 / 409 |
| Body too large | 413 |
| Invalid JSON object shape / more than 100 fields | 422 |
| Signing is not configured and unsigned exception is disabled | 503 |
| Unhandled gateway failure before acceptance | 500 |

`GET /health` is an unauthenticated liveness response. The legacy Python backup publishes host port 8099; default C# dev-c publishes 8100. Restrict the selected host port to approved sender networks and use signed requests in production.

## C# dev-c port

`src/NocIfc.Webhook/` implements the endpoint and signing settings as a separate ASP.NET Core host, built by the `webhook` target in `deploy/Dockerfile.backend`. The default `compose.yaml` publishes it at `http://localhost:8100/webhook/solarwinds` alongside the C# API and Worker on isolated `data-dev-c` storage; the legacy Python Compose file remains available as a local backup.

- `GET /health` reports liveness. The host probes SQLite readiness against Alembic revision `20261125_0025`; POST requests return 503 until the database is ready and while restore maintenance is active.
- Accepted requests use a bounded process-local queue. HTTP 200 means queued, not committed; a process restart can lose queued bodies. The Python background-task path has the same accepted-versus-persisted distinction.
- A resolution with a known `Site`/`City` only resolves same-node alerts at that mapped location. If the resolution site is missing or `Unknown`, it retains the legacy same-node fallback because there is no site to disambiguate.
- The .NET configuration validates `WEBHOOK_MAX_BODY_BYTES` from 1 byte through 16 MiB; the other signing and replay settings use the environment names above.
