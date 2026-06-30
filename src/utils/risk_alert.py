import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from src.core.db import SessionLocal
from src.core.config import RISK_ALERT_RECIPIENTS
from src.models.schema import SystemConfig

logger = logging.getLogger(__name__)

CENTRAL_TZ = ZoneInfo("America/Chicago")

RISK_TIER_ORDER = ["GREEN", "BLUE", "YELLOW", "ORANGE", "RED"]

def get_tier_level(risk: str) -> int:
    try:
        return RISK_TIER_ORDER.index(risk.upper())
    except ValueError:
        logger.warning("get_tier_level: unknown risk level %s", risk)
        return -1

def is_increase(from_level: str, to_level: str) -> bool:
    result = get_tier_level(to_level) > get_tier_level(from_level)
    logger.debug("is_increase: from=%s to=%s result=%s", from_level, to_level, result)
    return result

def get_alert_recipients() -> list:
    if not RISK_ALERT_RECIPIENTS:
        logger.warning("get_alert_recipients: RISK_ALERT_RECIPIENTS not set")
        return []
    recipients = [r.strip() for r in RISK_ALERT_RECIPIENTS.split(",") if r.strip()]
    logger.debug("get_alert_recipients: %s", recipients)
    return recipients

def get_smtp_config():
    logger.debug("get_smtp_config: fetching SMTP config from DB")
    with SessionLocal() as session:
        config = session.query(SystemConfig).first()
        return config

def should_send_alert() -> bool:
    with SessionLocal() as session:
        config = session.query(SystemConfig).first()
        if not config or not config.last_risk_alert_time:
            logger.debug("should_send_alert: no prior alert time, sending")
            return True
        elapsed = datetime.now(CENTRAL_TZ) - config.last_risk_alert_time
        can_send = elapsed >= timedelta(hours=4)
        logger.debug("should_send_alert: elapsed=%.1f hours can_send=%s", elapsed.total_seconds() / 3600, can_send)
        return can_send

def update_last_alert_time():
    with SessionLocal() as session:
        config = session.query(SystemConfig).first()
        if config:
            config.last_risk_alert_time = datetime.now(CENTRAL_TZ)
            session.commit()
            logger.info("update_last_alert_time: updated to %s", config.last_risk_alert_time)

def update_tracked_risks(global_risk: str = None, internal_risk: str = None):
    with SessionLocal() as session:
        config = session.query(SystemConfig).first()
        if config:
            if global_risk:
                config.last_global_risk = global_risk
            if internal_risk:
                config.last_internal_risk = internal_risk
            session.commit()
            logger.debug("update_tracked_risks: global=%s internal=%s", global_risk, internal_risk)

def build_alert_email_body(
    global_change: tuple = None,
    internal_change: tuple = None,
    current_global: str = None,
    current_internal: str = None
) -> str:
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
    lines.append(f"Time: {datetime.now(CENTRAL_TZ).strftime('%Y-%m-%d %H:%M:%S %Z')}")
    lines.append("")
    lines.append("-" * 50)
    lines.append("This is an automated alert from the NOC Intelligence Fusion Center.")

    return "\n".join(lines)

def send_alert(recipients: list, subject: str, body: str):
    logger.info("send_alert: subject=%s recipients=%s body_length=%d", subject, recipients, len(body) if body else 0)
    config = get_smtp_config()
    if not config or not config.smtp_enabled:
        logger.warning("send_alert: SMTP not enabled")
        return False, "SMTP not enabled"

    try:
        msg = MIMEMultipart()
        msg['From'] = config.smtp_sender
        msg['To'] = ", ".join(recipients)
        msg['Subject'] = subject

        msg.attach(MIMEText(body, 'plain'))

        logger.debug("send_alert: connecting to SMTP server=%s port=%s", config.smtp_server, config.smtp_port)
        server = smtplib.SMTP(config.smtp_server, config.smtp_port, timeout=10)
        if config.smtp_username and config.smtp_password:
            logger.debug("send_alert: starting TLS")
            server.starttls()
            logger.debug("send_alert: logging in as %s", config.smtp_username)
            server.login(config.smtp_username, config.smtp_password)
            logger.debug("send_alert: login successful")

        logger.debug("send_alert: sending mail to %s", recipients)
        server.sendmail(config.smtp_sender, recipients, msg.as_string())
        server.quit()
        logger.info("send_alert: alert sent successfully")

        return True, "Alert sent successfully"

    except smtplib.SMTPAuthenticationError as auth_err:
        logger.error("send_alert: SMTP authentication failed: %s", auth_err)
        return False, f"SMTP authentication failed: {auth_err}"
    except smtplib.SMTPConnectError as conn_err:
        logger.error("send_alert: SMTP connection failed: %s", conn_err)
        return False, f"SMTP connection failed: {conn_err}"
    except smtplib.SMTPException as smtp_err:
        logger.error("send_alert: SMTP error: %s", smtp_err)
        return False, f"SMTP error: {smtp_err}"
    except Exception as e:
        logger.error("send_alert: unexpected exception: %s", str(e), exc_info=True)
        return False, str(e)

def check_and_alert(global_risk: str = None, internal_risk: str = None):
    logger.info("check_and_alert: global=%s internal=%s", global_risk, internal_risk)
    global_change = None
    internal_change = None

    with SessionLocal() as session:
        config = session.query(SystemConfig).first()
        previous_global = config.last_global_risk if config else None
        previous_internal = config.last_internal_risk if config else None
    logger.debug("check_and_alert: previous_global=%s previous_internal=%s", previous_global, previous_internal)

    if global_risk and previous_global and is_increase(previous_global, global_risk):
        global_change = (previous_global, global_risk)
        logger.info("check_and_alert: GLOBAL risk increased from %s to %s", previous_global, global_risk)

    if internal_risk and previous_internal and is_increase(previous_internal, internal_risk):
        internal_change = (previous_internal, internal_risk)
        logger.info("check_and_alert: INTERNAL risk increased from %s to %s", previous_internal, internal_risk)

    if not global_change and not internal_change:
        logger.debug("check_and_alert: no risk increase detected")
        update_tracked_risks(global_risk, internal_risk)
        return

    if not should_send_alert():
        logger.debug("check_and_alert: within cooldown, updating risks only")
        update_tracked_risks(global_risk, internal_risk)
        return

    recipients = get_alert_recipients()
    if not recipients:
        logger.warning("check_and_alert: no recipients configured, skipping alert")
        update_tracked_risks(global_risk, internal_risk)
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

    logger.info("check_and_alert: sending alert subject=%s", subject)
    success, msg = send_alert(recipients, subject, body)

    update_tracked_risks(global_risk, internal_risk)

    if success:
        update_last_alert_time()
        logger.info("check_and_alert: alert sent successfully")
    else:
        logger.error("check_and_alert: alert failed: %s", msg)

    update_tracked_risks(global_risk, internal_risk)

def build_eq_alert_email_body(alerts: list) -> str:
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
    lines.append(f"Time: {datetime.now(CENTRAL_TZ).strftime('%Y-%m-%d %H:%M:%S %Z')}")
    lines.append("")
    lines.append("This is an automated alert from the NOC Intelligence Fusion Center.")

    return "\n".join(lines)
