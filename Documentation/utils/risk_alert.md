# Module: `src/utils/risk_alert.py`

Risk alert engine for the NOC Intelligence Fusion Center. Monitors global and internal risk levels, detects escalations, and sends email alerts to configured recipients when risk levels increase. Also includes earthquake proximity alert building.

---

## Module-level Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `CENTRAL_TZ` | `ZoneInfo("America/Chicago")` | Central Time timezone for all timestamps |
| `RISK_TIER_ORDER` | `["GREEN", "BLUE", "YELLOW", "ORANGE", "RED"]` | Ordered list of risk levels from lowest to highest |

---

## Functions

---

### `get_tier_level`

**Purpose:** Convert a risk level string to its numeric tier index for comparison.

**Signature:**
```python
def get_tier_level(risk: str) -> int
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `risk` | `str` | Risk level string (case-insensitive, e.g., `"GREEN"`, `"red"`) |

**Returns:**

| Type | Description |
|------|-------------|
| `int` | 0-based index into `RISK_TIER_ORDER`; returns `-1` if the risk string is not a valid tier |

**Raises:** None (`ValueError` from `.index()` is caught)

**Flow:**
1. Uppercases the input string
2. Attempts `RISK_TIER_ORDER.index(risk.upper())`
3. Returns the index on success, `-1` on `ValueError`

**Dependencies:** None

---

### `is_increase`

**Purpose:** Determine whether a risk level transition represents an escalation (moving to a higher tier).

**Signature:**
```python
def is_increase(from_level: str, to_level: str) -> bool
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `from_level` | `str` | Previous risk level string |
| `to_level` | `str` | Current/New risk level string |

**Returns:**

| Type | Description |
|------|-------------|
| `bool` | `True` if `to_level` is at a strictly higher tier than `from_level` |

**Raises:** None

**Flow:**
1. Compares tier indices via `get_tier_level(to_level) > get_tier_level(from_level)`
2. Returns the boolean result

**Dependencies:** `get_tier_level`

---

### `get_alert_recipients`

**Purpose:** Parse the `RISK_ALERT_RECIPIENTS` environment variable into a list of email addresses.

**Signature:**
```python
def get_alert_recipients() -> list[str]
```

**Parameters:** None

**Returns:**

| Type | Description |
|------|-------------|
| `list[str]` | List of trimmed email addresses; empty list if the env var is unset or empty |

**Raises:** None

**Flow:**
1. Checks if `RISK_ALERT_RECIPIENTS` (from `src.core.config`) is truthy
2. If not, returns `[]`
3. Splits the comma-separated string, strips whitespace, filters empty strings
4. Returns the resulting list

**Dependencies:** `src.core.config.RISK_ALERT_RECIPIENTS`

---

### `get_smtp_config`

**Purpose:** Retrieve the first `SystemConfig` row for SMTP configuration.

**Signature:**
```python
def get_smtp_config() -> SystemConfig | None
```

**Parameters:** None

**Returns:**

| Type | Description |
|------|-------------|
| `SystemConfig \| None` | The first `SystemConfig` row, or `None` if none exists |

**Raises:** None

**Flow:**
1. Opens a database session via `SessionLocal()` context manager
2. Queries `session.query(SystemConfig).first()`
3. Returns the config object

**Dependencies:** `src.core.db.SessionLocal`, `src.models.schema.SystemConfig`

---

### `should_send_alert`

**Purpose:** Enforce a minimum cooldown period (4 hours) between risk alert emails.

**Signature:**
```python
def should_send_alert() -> bool
```

**Parameters:** None

**Returns:**

| Type | Description |
|------|-------------|
| `bool` | `True` if no alert has been sent before, or if 4+ hours have elapsed since the last alert |

**Raises:** None

**Flow:**
1. Opens a database session
2. Queries `SystemConfig`
3. Returns `True` if config is `None` or `last_risk_alert_time` is `None` (no previous alert)
4. Computes elapsed time: `datetime.now(CENTRAL_TZ) - config.last_risk_alert_time`
5. Returns `True` if `elapsed >= timedelta(hours=4)`, `False` otherwise

**Dependencies:** `get_smtp_config` (implicitly via direct DB query), `datetime`, `timedelta`, `zoneinfo.ZoneInfo`

---

### `update_last_alert_time`

**Purpose:** Persist the current timestamp as the last risk alert time in the database.

**Signature:**
```python
def update_last_alert_time()
```

**Parameters:** None

**Returns:** None

**Raises:** None

**Flow:**
1. Opens a database session
2. Queries the first `SystemConfig` row
3. If config exists, sets `config.last_risk_alert_time = datetime.now(CENTRAL_TZ)`
4. Commits the transaction

**Dependencies:** `src.core.db.SessionLocal`, `src.models.schema.SystemConfig`, `datetime`

---

### `update_tracked_risks`

**Purpose:** Persist the current global and/or internal risk levels into the database for comparison on the next cycle.

**Signature:**
```python
def update_tracked_risks(global_risk: str = None, internal_risk: str = None)
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `global_risk` | `str \| None` | Current global risk level; if provided, updates `last_global_risk` |
| `internal_risk` | `str \| None` | Current internal risk level; if provided, updates `last_internal_risk` |

**Returns:** None

**Raises:** None

**Flow:**
1. Opens a database session
2. Queries the first `SystemConfig` row
3. If config exists:
   - Sets `config.last_global_risk` if `global_risk` is provided
   - Sets `config.last_internal_risk` if `internal_risk` is provided
4. Commits the transaction

**Dependencies:** `src.core.db.SessionLocal`, `src.models.schema.SystemConfig`

---

### `build_alert_email_body`

**Purpose:** Construct a plain-text email body for a risk level change alert.

**Signature:**
```python
def build_alert_email_body(
    global_change: tuple = None,
    internal_change: tuple = None,
    current_global: str = None,
    current_internal: str = None
) -> str
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `global_change` | `tuple \| None` | `(previous_level, new_level)` tuple for global risk increase |
| `internal_change` | `tuple \| None` | `(previous_level, new_level)` tuple for internal risk increase |
| `current_global` | `str \| None` | Current global risk level string |
| `current_internal` | `str \| None` | Current internal risk level string |

**Returns:**

| Type | Description |
|------|-------------|
| `str` | Formatted plain-text email body |

**Raises:** None

**Flow:**
1. Initializes a list of lines with a header banner
2. If `global_change` is provided, appends "GLOBAL RISK INCREASED:" section with previous/current values
3. If `internal_change` is provided, appends "INTERNAL RISK INCREASED:" section with previous/current values
4. Appends current state section with both risk levels
5. Appends timestamp formatted in Central Time
6. Appends automated alert footer
7. Joins all lines with newlines and returns

**Dependencies:** `datetime`, `zoneinfo.ZoneInfo`

---

### `send_alert`

**Purpose:** Send a plain-text email alert to a list of recipients via SMTP.

**Signature:**
```python
def send_alert(recipients: list[str], subject: str, body: str) -> tuple[bool, str]
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `recipients` | `list[str]` | List of recipient email addresses |
| `subject` | `str` | Email subject line |
| `body` | `str` | Plain-text email body |

**Returns:**

| Type | Description |
|------|-------------|
| `tuple[bool, str]` | `(True, "Alert sent successfully")` on success; `(False, error_message)` on failure |

**Raises:** None (all exceptions are caught and returned)

**Flow:**
1. Retrieves SMTP config via `get_smtp_config()`
2. Returns `(False, "SMTP not enabled")` if config is `None` or `smtp_enabled` is falsy
3. Constructs a `MIMEMultipart` email with sender, comma-joined recipients, and subject
4. Attaches body as `MIMEText` with `'plain'` subtype
5. Connects to SMTP server at `config.smtp_server:config.smtp_port`
6. If credentials are configured: starts TLS, logs in
7. Sends email via `server.sendmail()`
8. Quits the server
9. Returns success tuple
10. On any `Exception`, returns `(False, str(e))`

**Dependencies:** `smtplib`, `email.mime.text.MIMEText`, `email.mime.multipart.MIMEMultipart`, `get_smtp_config`

---

### `check_and_alert`

**Purpose:** Main orchestration function. Compares previous and current risk levels, and sends an email alert if risk has increased and cooldown has expired.

**Signature:**
```python
def check_and_alert(global_risk: str = None, internal_risk: str = None)
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `global_risk` | `str \| None` | Current global risk level |
| `internal_risk` | `str \| None` | Current internal risk level |

**Returns:** None

**Raises:** None

**Flow:**
1. Initializes `global_change` and `internal_change` as `None`
2. Opens a database session and retrieves `last_global_risk` and `last_internal_risk` from `SystemConfig`
3. Checks for increase:
   - If `global_risk` and `previous_global` both exist and `is_increase()` returns `True`, sets `global_change = (previous, current)`
   - Same logic for `internal_risk`
4. **No increase detected:** calls `update_tracked_risks()` to persist current levels and returns
5. **Increase detected but cooldown active (`should_send_alert()` is `False`):** calls `update_tracked_risks()` and returns
6. **No recipients configured:** calls `update_tracked_risks()` and returns
7. **Alert required:**
   a. Builds email body via `build_alert_email_body()` with change tuples and current levels
   b. Constructs subject line dynamically based on which risks increased
   c. Sends via `send_alert(recipients, subject, body)`
   d. Calls `update_tracked_risks()` to persist current levels
   e. If send was successful, calls `update_last_alert_time()` to reset cooldown timer
   f. Calls `update_tracked_risks()` a second time (duplicate, likely intentional to ensure persistence)

**Dependencies:** `get_tier_level`, `is_increase`, `should_send_alert`, `get_alert_recipients`, `build_alert_email_body`, `send_alert`, `update_tracked_risks`, `update_last_alert_time`, `src.core.db.SessionLocal`, `src.models.schema.SystemConfig`

**Note:** There is a redundant second call to `update_tracked_risks()` at the end of the success path (lines 168 and 173). Both calls write the same values.

---

### `build_eq_alert_email_body`

**Purpose:** Construct a plain-text email body for earthquake proximity alerts when earthquakes are detected within 50 miles of monitored sites.

**Signature:**
```python
def build_eq_alert_email_body(alerts: list[dict]) -> str
```

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `alerts` | `list[dict]` | List of earthquake alert dicts, each containing keys: `site`, `site_type`, `distance`, `mag`, `place`, `depth`, `time` |

**Returns:**

| Type | Description |
|------|-------------|
| `str` | Formatted plain-text email body detailing each proximate earthquake |

**Raises:** None

**Flow:**
1. Initializes lines list with header banner
2. For each alert dict in the list:
   - Appends site name and type
   - Appends distance in miles, magnitude, location description, depth in km, and time
   - Appends a blank line separator
3. Appends current timestamp in Central Time
4. Appends automated alert footer
5. Joins all lines with newlines and returns

**Dependencies:** `datetime`, `zoneinfo.ZoneInfo`
