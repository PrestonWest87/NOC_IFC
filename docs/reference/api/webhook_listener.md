# Module: `src.webhook_listener`

Standalone SolarWinds gateway on port 8100. Lifespan startup runs `init_db()` before request handling unless a coordinated restore marker is active; a status task publishes worker/webhook drain acknowledgements every 0.5 seconds for UI restore coordination.

## `GET /health`

Unauthenticated liveness endpoint. Returns `{"status":"ok"}` and does not query the database.

## Request validation: `_verify_webhook(request, body)`

- If no HMAC secret is configured, unsigned traffic is accepted only when `ALLOW_UNSIGNED_WEBHOOKS=true`; otherwise the route returns 503.
- With a secret, the configured signature header is mandatory. With the default replay window, the configured numeric timestamp header is also mandatory and must be within the configured window.
- Compares HMAC-SHA256 signatures in constant time; timestamped requests accept a `timestamp + "." + body` signature and the legacy body-only form.
- Tracks timestamp/signature pairs in a process-local ordered cache, removes old entries, and bounds it to 10,000 entries.

Body byte size is enforced in `receive_alert()` before `_verify_webhook()`; invalid JSON, non-object/empty JSON, and more than 100 top-level keys are rejected before queueing.

## `classify_device(text_corpus, node_type_hint=None)`

First normalizes a supplied type hint using `EnterpriseAIOpsEngine.normalize_domain_hint()`. Otherwise scans the combined text for Internet, communications, power, compute, or SCADA fingerprints. The fallback is the string `Network Node`. The engine's canonical Internet key is `INTERNET`; `PRIMARY_INTERNET` is accepted as an input alias.

## `smart_extract(payload)`

Reads `Node_Details`, `Performance_Metrics`, and `Custom_Properties_Universal`; returns a normalized dict containing node/IP, severity, alert level, event type, status, resolution flag, device type, event category, site group, and primary/secondary communications. Missing IPv4 values may be recovered from the serialized payload. Resolution terms are matched on word boundaries. The function does not persist data.

## `process_payload_background(raw_payload)`

Creates its own SQLAlchemy session, normalizes/classifies, adds `Normalized_Alert_Level` to the payload, and:

- Resolves all currently unresolved rows for the same node name and writes a `Webhook`/`Resolution` timeline event; or
- Inserts a new `SolarWindsAlert` with the raw JSON and a `Webhook`/`Alert` timeline event.

The timeline records carry structured `site_name`. Exceptions roll back, log, and are swallowed by the background handler. The function itself does not run AIOps clustering or escalation.

## `receive_alert(request, background_tasks)`

`POST /webhook/solarwinds`. It checks the restore gate and byte limit, verifies signing, parses and validates the JSON object, increments the pending-task count, and queues `_process_payload_with_restore_tracking()`. The current decorator has no `status_code=202`, so success is HTTP 200 with an accepted JSON body. Acceptance means queued, not persisted.

## Relevant settings

`WEBHOOK_HMAC_SECRET`, `WEBHOOK_SIGNATURE_HEADER`, `WEBHOOK_TIMESTAMP_HEADER`, `WEBHOOK_REPLAY_WINDOW_SECONDS`, `WEBHOOK_MAX_BODY_BYTES`, `ALLOW_UNSIGNED_WEBHOOKS`, and the restore coordination paths are described in [`docs/WEBHOOK.md`](../../WEBHOOK.md) and [`docs/reference/config/env_example.md`](../config/env_example.md).
