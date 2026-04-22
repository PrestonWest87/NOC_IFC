# Enterprise Architecture & Functional Specification: `src/risk_alert.py`

## 1. Executive Overview

The `src/risk_alert.py` module is the **Risk Level Change Alert Engine** for the NOC Intelligence Fusion Center. It monitors risk tier transitions (GREEN→BLUE→YELLOW→ORANGE→RED) and sends automated email notifications to configured recipients when levels increase.

Key features:
- **Tier-based detection:** Compares current risk against stored previous levels
- **Cooldown logic:** Prevents alert storms with 4-hour minimum interval
- **SMTP integration:** Configurable email relay via database settings
- **Dual tracking:** Monitors both Global (OSINT) and Internal (Asset) risk independently

---

## 2. Risk Tier Hierarchy

```python
RISK_TIER_ORDER = ["GREEN", "BLUE", "YELLOW", "ORANGE", "RED"]
```

| Tier | Numeric | Description |
|------|---------|-------------|
| GREEN | 0 | Minimal threat |
| BLUE | 1 | Elevated (advisory) |
| YELLOW | 2 | Elevated (watch) |
| ORANGE | 3 | High threat |
| RED | 4 | Critical threat |

---

## 3. Core Functions

### `get_tier_level(risk: str) -> int`

**Purpose:** Converts risk tier name to numeric level.

**Parameters:**
- `risk` (str): Tier name (e.g., "GREEN", "YELLOW")

**Returns:**
- Integer 0-4, or -1 if invalid

---

### `is_increase(from_level: str, to_level: str) -> bool`

**Purpose:** Checks if `to_level` represents an increase over `from_level`.

**Parameters:**
- `from_level` (str): Previous tier
- `to_level` (str): Current tier

**Returns:** `True` if numeric level increased, `False` otherwise

---

### `get_alert_recipients() -> list`

**Purpose:** Loads alert recipients from environment variable.

**Returns:** List of email addresses from `RISK_ALERT_RECIPIENTS` (comma-separated)

---

### `get_smtp_config()`

**Purpose:** Fetches SMTP configuration from `SystemConfig` database record.

**Returns:** `SystemConfig` object or `None`

---

### `should_send_alert() -> bool`

**Purpose:** Checks if 4-hour cooldown period has elapsed since last alert.

**Returns:** `True` if eligible to send, `False` if in cooldown

---

### `update_last_alert_time()`

**Purpose:** Records current UTC time as last alert timestamp in database.

---

### `update_tracked_risks(global_risk: str = None, internal_risk: str = None)`

**Purpose:** Persists current risk levels to database for future comparison.

**Parameters:**
- `global_risk` (str, optional): New global risk tier
- `internal_risk` (str, optional): New internal risk tier

---

### `build_alert_email_body(...) -> str`

**Purpose:** Constructs plain-text email body with change details.

**Parameters:**
- `global_change` (tuple, optional): (previous, current) tuple
- `internal_change` (tuple, optional): (previous, current) tuple
- `current_global` (str, optional): Current global tier
- `current_internal` (str, optional): Current internal tier

**Returns:** Formatted plain-text email body

---

### `send_alert(recipients: list, subject: str, body: str)`

**Purpose:** Sends email via configured SMTP server.

**Parameters:**
- `recipients` (list): Email addresses
- `subject` (str): Email subject line
- `body` (str): Email body

**Returns:** (success: bool, message: str)

**SMTP Flow:**
1. Connects to `smtp_server:smtp_port`
2. Starts TLS if credentials provided
3. Authenticates and sends
4. Logs out and closes

---

### `check_and_alert(global_risk: str = None, internal_risk: str = None)`

**Purpose:** Main entry point for risk alerting.

**Parameters:**
- `global_risk` (str, optional): New global risk tier
- `internal_risk` (str, optional): New internal risk tier

**Logic Flow:**
1. Load previous risk levels from database
2. Detect increases (GLOBAL, INTERNAL, or BOTH)
3. Check cooldown eligibility
4. Load recipients from environment
5. Build and send email
6. Update last alert timestamp
7. Persist new risk levels

---

## 4. Configuration

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `RISK_ALERT_RECIPIENTS` | Comma-separated email list |
| `DATABASE_URL` | Database connection |

### Database Configuration (SystemConfig)

| Field | Source |
|-------|--------|
| `smtp_enabled` | Boolean enable flag |
| `smtp_server` | SMTP hostname |
| `smtp_port` | SMTP port |
| `smtp_username` | Auth username |
| `smtp_password` | Auth password |
| `smtp_sender` | From address |
| `last_risk_alert_time` | Last send timestamp |
| `last_global_risk` | Previous global tier |
| `last_internal_risk` | Previous internal tier |

---

## 5. Scheduler Integration

| Job | Interval | Function |
|-----|----------|----------|
| Risk Alert Check | After unified brief | `check_and_alert()` |

---

## 6. Usage Examples

### Basic Alert Check

```python
from src.risk_alert import check_and_alert

# After risk calculation completes
check_and_alert(global_risk="YELLOW", internal_risk="GREEN")
```

### Manual Email Send

```python
from src.risk_alert import send_alert, get_alert_recipients

recipients = get_alert_recipients()
success, msg = send_alert(
    recipients,
    "Test Alert",
    "This is a test from NOC IFC"
)
```

---

## 7. API Citations

- **Python smtplib:** https://docs.python.org/3/library/smtplib.html
- **email.mime:** https://docs.python.org/3/library/email.mime.html
- **Python dotenv:** https://pypi.org/project/python-dotenv/