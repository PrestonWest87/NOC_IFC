# Module: `src/webhook_listener.py`

## Overview

FastAPI-based enterprise webhook gateway running on port 8100. Receives SolarWinds alert payloads via HTTP POST, performs intelligent field extraction and device classification, and persists normalized alerts to the database for downstream AIOps correlation.

---

## Function: `log(msg)`

**Purpose:** Writes a prefixed log message at INFO level for the webhook module.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `msg` | `str` | The log message content. |

**Returns:** None

**Raises:** None

**Flow:**
1. Calls `logger.info("[WEBHOOK] %s", msg)`.

**Dependencies:** `logging.getLogger(__name__)`

---

## Function: `classify_device(text_corpus, node_type_hint=None)`

**Purpose:** Classifies a network device into a standardized domain category using keyword fingerprint matching on node name, event type, and device type text.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `text_corpus` | `str` | Concatenated text from node name, event type, and device type. |
| `node_type_hint` | `str \| None` | Pre-existing device type classification from the payload. If valid, returned directly. |

**Returns:**
| Type | Description |
|------|-------------|
| `str` | One of: `PRIMARY_INTERNET`, `COMMS_EQUIPMENT`, `POWER_SUPPLIES`, `COMPUTE`, `SCADA`, or `Network Node` (fallback). |

**Raises:** None

**Flow:**
1. If `node_type_hint` is a known non-empty value, returns it immediately.
2. Converts text corpus to lowercase.
3. Checks against ordered fingerprint dictionaries:
   - `PRIMARY_INTERNET`: vsat, cellular, sd-wan, modem, radio, isp, internet
   - `COMMS_EQUIPMENT`: fw, firewall, asa, palo, fortigate, meraki, rtr, router, switch, nexus, catalyst, ap, wireless, wlc, etc.
   - `POWER_SUPPLIES`: ups, pdu, ats, battery, generator, hvac, dc power, etc.
   - `COMPUTE`: vm, host, server, storage, san, nas, esxi
   - `SCADA`: rtu, plc, meter, substation, plant, relay, sel-
4. Returns the first matching class, or `"Network Node"` as fallback.

**Dependencies:** None (pure function)

---

## Function: `smart_extract(payload)`

**Purpose:** Extracts and normalizes structured fields from a raw SolarWinds webhook payload using intelligent field mapping with fallbacks.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `payload` | `dict` | Raw JSON payload from the SolarWinds webhook. |

**Returns:**
| Type | Description |
|------|-------------|
| `dict` | Normalized extraction dict with keys: `node_name`, `ip_address`, `severity`, `alert_level`, `event_type`, `status`, `is_resolution`, `device_type`, `event_category`, `site_group`, `primary_comms`, `secondary_comms`. |

**Raises:** None

**Flow:**
1. Extracts `Node_Details`, `Performance_Metrics`, and `Custom_Properties_Universal` from payload.
2. Maps fields with multi-level fallbacks (e.g., `node_name` from `Node_Details.NodeName` -> `Node_Details.SysName` -> `payload.entity_caption` -> `"Unknown"`).
3. Extracts `primary_comms` and `secondary_comms` from `Custom_Properties_Universal` for fleet correlation.
4. Checks if status text contains resolution indicators (resolved, up, ok, clear, operational, recovered) using regex word boundary matching; if so, sets `is_resolution = True` and `status = "Resolved"`.
5. If `ip_address` is "Unknown", performs a regex fallback scan of the entire JSON payload for IPv4 patterns.
6. Runs `classify_device()` on the concatenated node name, event type, and device type text.
7. Returns the structured extraction dict.

**Dependencies:** `re`, `json`, `classify_device`

---

## Function: `process_payload_background(raw_payload)`

**Purpose:** Background task that processes a normalized webhook payload by persisting it to the database as either a resolution or a new alert.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `raw_payload` | `dict` | The original raw JSON payload as received from the webhook. |

**Returns:** None

**Raises:** None (exceptions caught, rollback, and logged)

**Flow:**
1. Opens a new database session.
2. Calls `smart_extract(raw_payload)` to get normalized fields.
3. Injects `Normalized_Alert_Level` into `raw_payload`.
4. If `is_resolution` is True:
   - Queries all active (non-Resolved) alerts matching the node name.
   - Sets each to `status = 'Resolved'` with `resolved_at = datetime.utcnow()`.
   - Adds a `TimelineEvent` for the resolution.
   - Commits and returns.
5. If not a resolution:
   - Creates a new `SolarWindsAlert` record with all extracted fields and the raw payload.
   - Adds a `TimelineEvent` for the critical alert.
   - Commits.

**Dependencies:** `smart_extract`, `SolarWindsAlert`, `TimelineEvent`, `SessionLocal`

---

## Endpoint: `POST /webhook/solarwinds`

**Purpose:** FastAPI route that receives SolarWinds webhook payloads, validates JSON, and queues processing as a background task.

**Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `request` | `Request` | FastAPI request object. |
| `background_tasks` | `BackgroundTasks` | FastAPI background task manager. |

**Returns:**
| Type | Description |
|------|-------------|
| `dict` | `{"status": "accepted", "message": "Payload queued for AI processing."}` on success. |

**Raises:**
| Exception | Condition |
|-----------|-----------|
| `HTTPException(status_code=400)` | Invalid JSON payload (JSONDecodeError). |
| `HTTPException(status_code=500)` | Internal gateway error. |

**Flow:**
1. Reads JSON body via `await request.json()`.
2. Adds `process_payload_background` as a FastAPI background task with the raw payload.
3. Returns acceptance response.
4. On `JSONDecodeError`, returns 400.
5. On other exceptions, logs and returns 500.

**Dependencies:** `fastapi.Request`, `fastapi.BackgroundTasks`, `fastapi.HTTPException`, `process_payload_background`

---

## Module-Level Execution (if `__name__ == "__main__"`)

**Purpose:** Starts the Uvicorn server when the module is run directly.

**Flow:**
1. Calls `setup_logging()` from `src.core.config`.
2. Starts `uvicorn.run(app, host="0.0.0.0", port=8100)`.

**Dependencies:** `src.core.config.setup_logging`, `uvicorn`
