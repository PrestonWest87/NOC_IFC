# Module: `src.webhook_listener`

FastAPI SolarWinds gateway running on port `8100`. It accepts webhook requests separately from the authenticated API so public monitoring infrastructure does not need access to the main application surface.

## Configuration

| Setting | Behavior |
|---|---|
| `WEBHOOK_HMAC_SECRET` | Enables HMAC validation when set. |
| `WEBHOOK_SIGNATURE_HEADER` | Signature header; default `X-SolarWinds-Signature`. |
| `WEBHOOK_TIMESTAMP_HEADER` | Timestamp header; default `X-SolarWinds-Timestamp`. |
| `WEBHOOK_REPLAY_WINDOW_SECONDS` | Timestamp/replay window; default 300 seconds. |
| `WEBHOOK_MAX_BODY_BYTES` | Maximum request body; default 1 MiB. |
| `ALLOW_UNSIGNED_WEBHOOKS` | Explicit migration exception for unsigned requests. |

## Functions

### `health() -> dict`

`GET /health` returns `{"status": "ok"}` without authentication.

### `_verify_webhook(request, body) -> None`

Validates request size, signature, and timestamp. HMAC is calculated over the request body and timestamp using the configured secret. It rejects missing/invalid signatures, malformed timestamps, timestamps outside the replay window, and repeated signatures tracked in the in-memory replay cache. It raises an HTTP error on failure.

### `classify_device(text_corpus, node_type_hint=None) -> str`

Lowercases the combined node/device text and matches keyword fingerprints against the seven-domain infrastructure ontology. An explicit usable hint is considered with the same normalization rules. It returns the best domain or the fallback classification.

### `smart_extract(payload) -> dict`

Normalizes supported SolarWinds payload shapes into the fields needed by the alert model: node name, IP, status, severity, alert level, event type, custom properties, and raw payload. The alert-level chain includes direct `Alert_Level`, nested universal custom properties, and normalized values.

### `process_payload_background(raw_payload) -> None`

Runs after the HTTP response. It extracts and classifies the alert, adds `Normalized_Alert_Level`, detects resolution terms with word-boundary matching, creates or resolves `SolarWindsAlert`, and writes `TimelineEvent` records. Database sessions are created inside the background operation.

### `receive_alert(request, background_tasks)`

`POST /webhook/solarwinds`. Reads and limits the body, validates the webhook, parses JSON, queues `process_payload_background` with FastAPI `BackgroundTasks`, and returns an acceptance response before correlation completes.

## Operational Expectations

A successful HTTP response confirms request acceptance, not necessarily completed persistence. Check webhook logs and the database-backed AIOps board for processing results. Restrict port `8100` at the firewall and prefer signed requests in production.
