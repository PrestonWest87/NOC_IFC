# Module: `src.webhook_listener.py`

FastAPI webhook gateway for external ITSM telemetry ingestion. Runs as a standalone service on port 8100. Receives SolarWinds alert payloads, normalizes them, and persists to the database.

---

## Overview

The webhook listener is a separate FastAPI application (not the main API) that:
1. Receives POST requests from SolarWinds (or compatible ITSM tools)
2. Queues background processing via `BackgroundTasks`
3. Extracts, normalizes, and classifies alert data
4. Creates or resolves `SolarWindsAlert` records
5. Creates `TimelineEvent` entries for the RCA activity feed

---

## Endpoint

### `POST /webhook/solarwinds`

**Port**: 8100

**Request**: JSON payload (SolarWinds webhook format)

**Response**: `{"status": "accepted", "message": "Payload queued for AI processing."}`

**Error Responses**:
- `400 Bad Request` — Invalid JSON payload
- `500 Internal Server Error` — Gateway processing failure

---

## Processing Pipeline

```
receive_alert()
  │
  ├── Parse JSON body
  └── background_tasks.add_task(process_payload_background)
        │
        └── process_payload_background(raw_payload)
              │
              ├── smart_extract(payload)
              │     ├── Extract: node_name, ip_address, severity, alert_level,
              │     │             event_type, status, device_type, site_group,
              │     │             primary_comms, secondary_comms
              │     ├── Inject Normalized_Alert_Level into raw_payload
              │     ├── Classify device_type via classify_device()
              │     └── Detect resolution status
              │
              ├── If resolution:
              │     ├── Find active alerts for node_name
              │     ├── Mark all as Resolved
              │     └── Create TimelineEvent (Resolution)
              │
              └── If new alert:
                    ├── Create SolarWindsAlert record
                    └── Create TimelineEvent (Alert)
```

---

## Functions

### `classify_device(text_corpus: str, node_type_hint: str = None) -> str`

Classifies a device into one of 6 ontology domains using keyword fingerprint matching.

| Device Class | Keywords |
|-------------|----------|
| `PRIMARY_INTERNET` | vsat, cellular, sd-wan, modem, radio, isp, internet |
| `COMMS_EQUIPMENT` | fw, firewall, asa, palo, fortigate, meraki, rtr, router, asr, isr, gateway, sw, switch, nexus, catalyst, idf, mdf, ap, wireless, wlc |
| `POWER_SUPPLIES` | ups, pdu, ats, battery, generator, hvac, ac unit, dc power, dc controller |
| `COMPUTE` | vm, host, server, storage, san, nas, esxi |
| `SCADA` | rtu, plc, meter, substation, plant, relay, sel- |
| `Network Node` (fallback) | Any unmatched device |

If `node_type_hint` is provided and not "unknown", it is returned immediately without fingerprint matching. The fingerprint text corpus is constructed from `{node_name} {event_type} {device_type}`.

---

### `smart_extract(payload: dict) -> dict`

Extracts and normalizes fields from a SolarWinds webhook payload.

**Extraction Chain Order** (first non-empty wins):

| Output Field | Extraction Chain |
|-------------|------------------|
| `node_name` | `Node_Details.NodeName` → `Node_Details.SysName` → `entity_caption` → `"Unknown"` |
| `ip_address` | `Node_Details.IP_Address` → regex fallback on full payload → `"Unknown"` |
| `severity` | `severity` → `Custom_Properties_Universal.Severity` → `"Unknown"` |
| `alert_level` | `Alert_Level` → `Custom_Properties_Universal.Alert_Level` → `"Unknown"` |
| `event_type` | `AlertName` → `check` → `class` → `description` → `"Unknown"` |
| `status` | `Node_Details.StatusDescription` → `description` → `"Unknown"` |
| `device_type` | `Node_Details.MachineType` → `Custom_Properties_Universal.Node_Type` → `entity_type` → `"Unknown"` |
| `site_group` | `Custom_Properties_Universal.Site` → `Custom_Properties_Universal.City` → `"Unknown"` |
| `primary_comms` | `Custom_Properties_Universal.Primary_Comms` → `"Unknown"` |
| `secondary_comms` | `Custom_Properties_Universal.Secondary_Comms` → `"Unknown"` |

**Resolution Detection**: Checks if status + description contain any of `resolved`, `up`, `ok`, `clear`, `operational`, `recovered` using word-boundary regex.

---

## Alert Level Normalization

The webhook injects `Normalized_Alert_Level` into the raw payload before DB insertion. This field is critical for the tiered alert escalation engine's `get_tier()` function, which parses values like `p1-high`, `p2-low`, `p3`, `p4`, `p5` to determine SLA targets.

Extraction chain: `Alert_Level` → `Custom_Properties_Universal.Alert_Level` → stored as `Normalized_Alert_Level`.

---

## Resolution Handling

When a resolution alert is received (e.g., a "Node Up" message):
1. All active (non-Resolved) `SolarWindsAlert` records for that `node_name` are marked as `Resolved`
2. A `TimelineEvent` is created with source "Webhook", event_type "Resolution"
3. No new alert record is created

---

## Dependencies

- `src.core.db.SessionLocal`, `init_db()`
- `src.models.schema.SolarWindsAlert`, `TimelineEvent`
- FastAPI `BackgroundTasks` for async processing
- Standard library: `re`, `json`, `datetime`

---

## Configuration

- Runs on port 8100 by default (configured in `__main__` block)
- Requires `init_db()` call at module level for database readiness
- Logging via `src.core.config.setup_logging()`
