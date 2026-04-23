"""
Risk Alert Module - Sends automated emails when global or internal risk levels increase.

This module monitors risk level changes and triggers email notifications to configured
recipients when increases are detected. Includes cooldown logic to prevent alert storms.
"""

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

load_dotenv()


RISK_TIER_ORDER = ["GREEN", "BLUE", "YELLOW", "ORANGE", "RED"]


def get_tier_level(risk: str) -> int:
    """Convert risk tier name to numeric level for comparison."""
    try:
        return RISK_TIER_ORDER.index(risk.upper())
    except ValueError:
        return -1


def is_increase(from_level: str, to_level: str) -> bool:
    """Check if to_level represents an increase over from_level."""
    return get_tier_level(to_level) > get_tier_level(from_level)


def get_alert_recipients() -> list:
    """Load alert recipients from environment variable."""
    recipients = os.getenv("RISK_ALERT_RECIPIENTS", "")
    if not recipients:
        return []
    return [r.strip() for r in recipients.split(",") if r.strip()]


def get_smtp_config():
    """Fetch SMTP configuration from database."""
    from src.database import SessionLocal, SystemConfig

    with SessionLocal() as session:
        config = session.query(SystemConfig).first()
        return config


def should_send_alert() -> bool:
    """Check if cooldown period has elapsed since last alert."""
    from src.database import SessionLocal, SystemConfig

    with SessionLocal() as session:
        config = session.query(SystemConfig).first()
        if not config or not config.last_risk_alert_time:
            return True

        elapsed = datetime.now(timezone.utc) - config.last_risk_alert_time
        return elapsed >= timedelta(hours=4)


def update_last_alert_time():
    """Record the current time as the last alert sent."""
    from src.database import SessionLocal, SystemConfig

    with SessionLocal() as session:
        config = session.query(SystemConfig).first()
        if config:
            config.last_risk_alert_time = datetime.now(timezone.utc)
            session.commit()


def update_tracked_risks(global_risk: str = None, internal_risk: str = None):
    """Update the tracked risk values in the database."""
    from src.database import SessionLocal, SystemConfig

    with SessionLocal() as session:
        config = session.query(SystemConfig).first()
        if config:
            if global_risk:
                config.last_global_risk = global_risk
            if internal_risk:
                config.last_internal_risk = internal_risk
            session.commit()


def build_alert_email_body(
    global_change: tuple = None,
    internal_change: tuple = None,
    current_global: str = None,
    current_internal: str = None
) -> str:
    """Build plain text email body for risk alert."""
    lines = [
        "NOC Intelligence Fusion Center - Risk Level Change Alert",
        "=" * 50,
        "",
    ]

    if global_change:
        prev, new = global_change
        lines.append(f"GLOBAL RISK INCREASED:")
        lines.append(f"  Previous: {prev}")
        lines.append(f"  Current:  {new}")
        lines.append("")

    if internal_change:
        prev, new = internal_change
        lines.append(f"INTERNAL RISK INCREASED:")
        lines.append(f"  Previous: {prev}")
        lines.append(f"  Current:  {new}")
        lines.append("")

    lines.append("-" * 50)
    lines.append("CURRENT STATE:")
    lines.append(f"  Global Risk:   {current_global or 'UNKNOWN'}")
    lines.append(f"  Internal Risk: {current_internal or 'UNKNOWN'}")
    lines.append("")
    lines.append(f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')}")
    lines.append("")
    lines.append("-" * 50)
    lines.append("This is an automated alert from the NOC Intelligence Fusion Center.")

    return "\n".join(lines)


def send_alert(recipients: list, subject: str, body: str):
    """Send email via configured SMTP server."""
    config = get_smtp_config()
    if not config or not config.smtp_enabled:
        return False, "SMTP not enabled"

    try:
        msg = MIMEMultipart()
        msg['From'] = config.smtp_sender
        msg['To'] = ", ".join(recipients)
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(config.smtp_server, config.smtp_port)
        if config.smtp_username and config.smtp_password:
            server.starttls()
            server.login(config.smtp_username, config.smtp_password)

        server.sendmail(config.smtp_sender, recipients, msg.as_string())
        server.quit()

        return True, "Alert sent successfully"

    except Exception as e:
        return False, str(e)


def check_and_alert(global_risk: str = None, internal_risk: str = None):
    """
    Main entry point for risk alerting.

    Call this after risk calculations complete. Compares current levels against
    stored previous levels and sends email if any increased.
    """
    from src.database import SessionLocal, SystemConfig

    global_change = None
    internal_change = None

    with SessionLocal() as session:
        config = session.query(SystemConfig).first()
        previous_global = config.last_global_risk if config else None
        previous_internal = config.last_internal_risk if config else None

    if global_risk and previous_global and is_increase(previous_global, global_risk):
        global_change = (previous_global, global_risk)

    if internal_risk and previous_internal and is_increase(previous_internal, internal_risk):
        internal_change = (previous_internal, internal_risk)

    if not global_change and not internal_change:
        update_tracked_risks(global_risk, internal_risk)
        return

    if not should_send_alert():
        return

    recipients = get_alert_recipients()
    if not recipients:
        return

    body = build_alert_email_body(
        global_change=global_change,
        internal_change=internal_change,
        current_global=global_risk,
        current_internal=internal_risk
    )

    subject = "NOC Risk Alert"
    if global_change and internal_change:
        subject += ": GLOBAL and INTERNAL Risk Increased"
    elif global_change:
        subject += f": Global Risk {global_change[1]}"
    elif internal_change:
        subject += f": Internal Risk {internal_change[1]}"

    success, msg = send_alert(recipients, subject, body)

    if success:
        update_last_alert_time()

    update_tracked_risks(global_risk, internal_risk)


def build_eq_alert_email_body(alerts: list) -> str:
    """Build plain text email body for earthquake proximity alerts."""
    lines = [
        "NOC Intelligence Fusion Center - Earthquake Proximity Alert",
        "=" * 50,
        "",
        f"Earthquake(s) detected within 50 miles of monitored sites:",
        ""
    ]
    
    for a in alerts:
        lines.append(f"Site: {a['site']} ({a['site_type']})")
        lines.append(f"  Distance: {a['distance']} miles")
        lines.append(f"  Magnitude: M{a['mag']}")
        lines.append(f"  Location: {a['place']}")
        lines.append(f"  Depth: {a['depth']:.1f} km")
        lines.append(f"  Time: {a['time']}")
        lines.append("")
    
    lines.append("-" * 50)
    lines.append(f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S %Z')}")
    lines.append("")
    lines.append("This is an automated alert from the NOC Intelligence Fusion Center.")
    
    return "\n".join(lines)