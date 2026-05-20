# Enterprise Architecture & Functional Specification: `src/risk_alert.py`

## 1. Executive Overview

The `src/risk_alert.py` module is the **Risk Level Change Alert Engine** for the NOC Intelligence Fusion Center. It monitors risk tier transitions (GREEN→BLUE→YELLOW→ORANGE→RED) and sends automated email notifications to configured recipients when levels increase.

It also handles **Earthquake Proximity Alerts**, triggered by seismic events within 50 miles of monitored facilities.

---

## 2. Risk Tier Hierarchy

```
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
Converts risk tier name to numeric level (0-4), returns -1 for invalid input.

### `is_increase(from_level: str, to_level: str) -> bool`
Returns `True` if `to_level` represents a tier increase over `from_level`.

### `get_alert_recipients() -> list`
Loads comma-separated email addresses from `RISK_ALERT_RECIPIENTS` environment variable.

### `get_smtp_config() -> SystemConfig`
Fetches SMTP configuration from `SystemConfig` database record.

### `should_send_alert() -> bool`
Checks if 4-hour cooldown period has elapsed since last alert.

### `update_last_alert_time() -> None`
Records current Central time as last alert timestamp in database.

### `update_tracked_risks(global_risk, internal_risk) -> None`
Persists current risk levels to database for future comparison.

### `build_alert_email_body(global_change, internal_change, current_global, current_internal) -> str`
Constructs plain-text email body with change details for risk level transitions.

### `send_alert(recipients, subject, body) -> tuple`
Sends email via configured SMTP server with TLS support. Returns `(success: bool, message: str)`.

### `check_and_alert(global_risk, internal_risk) -> None`
Main entry point. Compares current risk levels against stored previous levels and sends alert if any increased. Checks cooldown eligibility before sending.

### `build_eq_alert_email_body(alerts) -> str`
Constructs plain-text email body for earthquake proximity alerts. Lists each affected site with distance, magnitude, location, depth, and time.

---

## 4. Configuration

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `RISK_ALERT_RECIPIENTS` | Comma-separated email list |
| `DATABASE_URL` | Database connection |

### Database Configuration (SystemConfig)

| Field | Purpose |
|-------|---------|
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
| Risk Alert Check | After unified brief | `check_and_alert(global_risk=...)` |
| Risk Alert Check | After internal risk | `check_and_alert(internal_risk=...)` |
| Earthquake Alert | Every 2 min | `check_earthquake_proximity()` via infra_worker |

---

## 6. API Citations

- **Python smtplib:** https://docs.python.org/3/library/smtplib.html
- **email.mime:** https://docs.python.org/3/library/email.mime.html
- **Python dotenv:** https://pypi.org/project/python-dotenv/
