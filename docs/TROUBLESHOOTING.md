# Troubleshooting Runbook

Use the narrowest check first. Capture timestamps, container status, the affected feature, and relevant log lines before restarting services.

## First Response

```bash
docker compose ps
docker compose logs --tail=200 api
docker compose logs --tail=200 worker
docker compose logs --tail=200 webhook
curl -i http://localhost:8102/health
curl -i http://localhost:8102/ready
docker compose stats --no-stream
```

## API or Web UI Is Unavailable

Check `/health` for process liveness and `/ready` for database readiness. If `/ready` returns `503`, inspect API logs for schema, permissions, or database-lock errors. If the API is healthy but the UI is blank, inspect browser developer-console errors and rebuild the production frontend:

```bash
docker compose up --build -d --force-recreate web
```

For a port conflict:

```bash
ss -ltnp | grep -E ':8099|:8102|:8503|:5174'
docker compose down
docker compose up -d
```

## No Articles or Stale Feeds

1. Confirm the worker is running: `docker compose ps`.
2. Read `docker compose logs --tail=300 worker` for DNS, timeout, parser, or database errors.
3. Confirm active `FeedSource` rows in Settings.
4. Check system time and outbound HTTPS access.
5. Confirm the worker can open the database volume and that SQLite is not locked.
6. Check whether the feed is returning valid RSS/Atom rather than an HTML block page.

The RSS path downloads in chunks of five, scores title and summary text, and skips links seen in the last seven days. A feed can be reachable while producing zero new records because all links are duplicates.

## Elastic Sync Endpoint Returns an Error

Use `POST /api/v1/hunting/sync-elastic-cache?hours_back=24` from the Threat Hunting workspace. A blank effective Elastic URL disables scheduled sync; the manual endpoint reports that configuration state. Check Settings > Application Settings > Notification destinations and Elastic integration first, including whether each value comes from the database or environment. The worker runs a sync every six minutes and logs the endpoint host, page counts, and request errors (never the API key). Check `docker compose logs --tail=300 worker` for connection, authentication, mapping, or database details. In Docker, `localhost` points to the API/worker container, so configure an Elastic URL reachable from both containers. Verify the API key, TLS/CA settings, and network reachability. The sync uses scroll pagination and does not sort on `_id`.

## Scores Are Zero or Unexpected

Check keyword rows and weights in Keyword Analysis/Settings. Keyword changes are persisted in `Keyword.weight`; the scorer can be reloaded through the application. To explicitly rescore existing articles, set `RESCORE_ON_STARTUP=true` for a controlled restart or use the administrative rescore operation if available. Do not leave startup rescoring enabled on every restart for a large database.

Inspect scorer and model logs. `HybridScorer` loads the runtime model from `/app/data/models/ml_model.pkl` alongside the shared SQLite volume. The model is created by training and included in encrypted full backups when present; it is not committed source.

## Worker Repeatedly Restarts or Jobs Do Not Run

```bash
docker compose logs --tail=300 worker
```

Look for import errors, database initialization failures, unhandled scheduler startup errors, and memory termination. The worker uses a two-thread executor and skips a job when the same function is already running. A long external request can therefore explain a missing subsequent run without indicating a scheduler failure.

## Database Locked, Missing Columns, or Migration Errors

```bash
docker compose logs --tail=300 api | grep -iE 'database|sqlite|migration|column|locked'
```

Back up first. Confirm the API, worker, and webhook share the intended SQLite file. Startup migrations serialize on a lock file next to the database and apply only revisions absent from `alembic_version`. The pre-Alembic adoption migration adds known legacy columns and preserves existing rows; unknown missing columns or conflicting normalized emails stop startup before revision success. Some additive objects may already exist after a failed attempt; the revision checks before retry. Long-running SQLite writes can still contend. Never manually drop columns, stamp `alembic_version`, or invoke migration code as a repair shortcut. Follow [Migration Compatibility](MIGRATION_COMPATIBILITY.md) and resolve the reported issue before restarting.

## WebSocket Disconnects or No Live Updates

1. Confirm the API is ready.
2. Confirm the browser has a valid session token.
3. Verify the client connects to `/ws?token=<token>` through the correct host/proxy.
4. Check API logs for close code `1008` (authentication) or `1009` (message too large).
5. Confirm the reverse proxy supports HTTP/1.1 upgrade headers.

The server broadcasts every 10 seconds only when clients are connected. Client-to-server RCA messages require `Action: Dispatch RCA Tickets`.

## SolarWinds Webhook Failures

```bash
curl -i http://localhost:8099/health
docker compose logs --tail=300 webhook
```

Check port/firewall routing, JSON content type, body size, HMAC secret/header names, timestamp skew, and whether `ALLOW_UNSIGNED_WEBHOOKS` matches the migration state. The listener accepts the request before background processing completes; a successful HTTP response does not prove that persistence or correlation succeeded. Search subsequent webhook logs for extraction, classification, and database errors.

## No Emails, Tickets, or On-Page Alerts

1. In Settings > AI & SMTP, confirm the active sender selector, that the selected profile is enabled, and use Send Test Email after saving the configuration.
2. For Gmail, confirm the account address, OAuth client ID/secret, and offline refresh token are configured; the OAuth grant must include `https://mail.google.com/` and be allowed by Workspace policy. A `401 invalid_client` means the client ID/secret is wrong or does not match the client used to create the refresh token. A `400 invalid_grant` means reauthorize and replace the refresh token.
3. Confirm the effective recipient destinations in Settings > Application Settings; unset database overrides use `RISK_ALERT_RECIPIENTS`, `REMEDYFORCE_TICKET_EMAIL`, `NOC_NOTIFY_EMAIL`, `NOC_ONPAGE_EMAIL`, and `ITNETWORK_ONPAGE_EMAIL` from the environment.
4. Read worker logs for `SMTP Error`, `missing`, or `Skipping` messages.
5. Confirm the event is in the applicable Central-time day/after-hours window and has passed its tier wait.
6. Check node cooldown, site mute, `is_ticketed`, and resolution status.

The escalation job skips when the effective Remedyforce destination is missing. Daily email skips when no saved unified brief or no effective risk-recipient setting exists.

## LLM Briefs Time Out or Are Empty

Check the selected provider, model, endpoint reachability from the API container, API key, context window, and worker logs. Ollama native requires `/api/chat`; Ollama OpenAI-compatible and vLLM use `/v1/chat/completions`. In Docker, use a reachable service name or host gateway rather than container-local `localhost`. The map/reduce pipeline chunks content and stores generation progress; inspect the corresponding status endpoint and generation ID in browser session storage. Reduce input volume or context size through application settings before increasing job frequency. A fallback response may be generated when the LLM exceeds the request budget.

## Regional Map Has No Hazards or Wrong Affected Sites

Check regional worker logs and cached GeoJSON timestamps. Confirm external NWS/SPC/USGS access and site latitude/longitude. The compile-map response is positional; a frontend/backend mismatch can render valid data incorrectly. Verify the six response positions in `docs/ARCHITECTURE.md` and inspect the browser network response.

## Recovery Escalation

If a restart does not resolve the issue, preserve logs and database backup, identify the first failing timestamp, compare API/worker/webhook versions, and isolate external dependencies with a direct connectivity test. Do not reset the database as a first response.
