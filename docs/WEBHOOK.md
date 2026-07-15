# SolarWinds Webhook Gateway

## Overview

FastAPI gateway on port **8100** (`src/webhook_listener.py`). Receives
SolarWinds Orion webhook POSTs, normalizes payloads, classifies devices against
a 7-domain ontology, and persists alerts to the database. Runs as a standalone
container.

---

## Endpoint

```
POST /webhook/solarwinds
```

Accepts a JSON body from SolarWinds Orion alert actions. Returns `202 Accepted`
immediately while processing continues in the background.

---

## Processing Flow

1. **Receive** — parse JSON body via `request.json()`. Return `400` on failure.
2. **Queue background task** — FastAPI `BackgroundTasks` runs the remaining steps
   asynchronously so the webhook caller gets an immediate `202`.
3. **Normalize** — `smart_extract()` extracts and standardises:
   - **Node details**: `node_name`, `ip_address`, `severity`, `alert_level`,
     `event_type`, `status`.
   - **Device type** from `MachineType` or
     `Custom_Properties_Universal.Node_Type`.
   - **Site group** from `Custom_Properties_Universal.Site` or `City`.
   - **Primary / secondary comms** for fleet correlation.
   - **Resolution detection** via keywords: `resolved`, `up`, `ok`, `clear`,
     `operational`, `recovered`.
   - **IP fallback** — regex extraction from the raw payload when `ip_address`
     is `"Unknown"`.
4. **Classify** — `classify_device()` fingerprints the device against the 7
   ontology domains (see below).

---

## Device Classification Ontology

| Domain | Matching Keywords |
|--------|-------------------|
| `PRIMARY_INTERNET` | vsat, cellular, sd-wan, modem, radio, isp, internet |
| `COMMS_EQUIPMENT` | fw, firewall, asa, palo, fortigate, meraki, rtr, router, gateway, switch, nexus, catalyst, ap, wireless |
| `POWER_SUPPLIES` | ups, pdu, ats, battery, generator, hvac, ac unit, dc power |
| `COMPUTE` | vm, host, server, storage, san, nas, esxi |
| `SCADA` | rtu, plc, meter, substation, plant, relay |
| `FACILITIES` | Match by location type or fallback |
| `Network Node` | Default fallback when no other domain matches |

---

## Alert Resolution Logic

When the incoming status contains a resolution keyword (`resolved`, `up`, `ok`,
`clear`, `operational`, `recovered`), all **active (non-Resolved)** alerts for
the same `node_name` are updated:

- `status` → `"Resolved"`
- `resolved_at` → `datetime.utcnow()`
- A `TimelineEvent(type=Resolution)` is created to record the event.

---

## New Alert Logic

For non-resolution alerts a new `SolarWindsAlert` record is created with:

- All normalised fields from `smart_extract()`.
- Original payload preserved in the `raw_payload` JSON column.
- `mapped_location` set from the extracted site group.
- `is_correlated = False` (correlation runs downstream in the AIOps engine).
- A `TimelineEvent(type=Alert)` is created to record the event.

---

## Error Handling

| Condition | Response |
|-----------|----------|
| Invalid JSON in request body | `400 Bad Request` |
| Unhandled exception during processing | `500 Internal Server Error` |
| Database write failure | Rollback + `500` |

Comprehensive logging is emitted at every processing step for audit and
debugging purposes.
