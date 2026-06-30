import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from src.core.db import SessionLocal
from src.models.schema import SystemConfig

logger = logging.getLogger(__name__)

def send_alert_email(subject: str, body: str, recipient_override: str = None, is_html: bool = True):
    logger.info("send_alert_email: subject=%s recipient_override=%s is_html=%s body_length=%d",
                 subject, recipient_override, is_html, len(body) if body else 0)
    session = SessionLocal()
    try:
        config = session.query(SystemConfig).first()
        if not config or not config.smtp_enabled:
            logger.warning("send_alert_email: SMTP is disabled in Settings")
            return False, "SMTP is disabled in Settings."

        target_recipient = recipient_override if recipient_override else config.smtp_recipient
        logger.debug("send_alert_email: target_recipient=%s", target_recipient)

        if not config.smtp_server or not config.smtp_sender or not target_recipient:
            logger.warning("send_alert_email: incomplete SMTP config server=%s sender=%s recipient=%s",
                            config.smtp_server, config.smtp_sender, target_recipient)
            return False, "SMTP configuration is incomplete (Missing Server, Sender, or Recipient)."

        msg = MIMEMultipart()
        msg['From'] = config.smtp_sender
        msg['To'] = target_recipient
        msg['Subject'] = f"[NOC FUSION] {subject}"

        if is_html:
            html_body = body.replace("\n", "<br>").replace("**", "<b>").replace("##", "<h2>").replace("###", "<h3>")
            msg.attach(MIMEText(html_body, 'html', 'utf-8'))
        else:
            msg.attach(MIMEText(body, 'plain', 'utf-8'))

        logger.debug("send_alert_email: connecting to SMTP server=%s port=%s timeout=10",
                      config.smtp_server, config.smtp_port)
        server = smtplib.SMTP(config.smtp_server, config.smtp_port, timeout=10)
        logger.debug("send_alert_email: SMTP connection established")

        try:
            logger.debug("send_alert_email: starting TLS")
            server.starttls()
            logger.debug("send_alert_email: TLS established")
        except Exception as tls_err:
            logger.warning("send_alert_email: StartTLS skipped or unsupported: %s", tls_err)

        if config.smtp_username and config.smtp_password:
            logger.debug("send_alert_email: logging in as %s", config.smtp_username)
            server.login(config.smtp_username, config.smtp_password)
            logger.debug("send_alert_email: login successful")

        logger.debug("send_alert_email: sending message to %s", target_recipient)
        server.send_message(msg)
        server.quit()
        logger.info("send_alert_email: email sent successfully to %s", target_recipient)

        return True, "Email sent successfully."

    except smtplib.SMTPAuthenticationError as auth_err:
        logger.error("send_alert_email: SMTP authentication failed: %s", auth_err)
        return False, f"SMTP authentication failed: {auth_err}"
    except smtplib.SMTPConnectError as conn_err:
        logger.error("send_alert_email: SMTP connection failed: %s", conn_err)
        return False, f"SMTP connection failed: {conn_err}"
    except smtplib.SMTPException as smtp_err:
        logger.error("send_alert_email: SMTP error: %s", smtp_err)
        return False, f"SMTP error: {smtp_err}"
    except Exception as e:
        logger.error("send_alert_email: critical exception: %s", str(e), exc_info=True)
        return False, str(e)
    finally:
        session.close()
        logger.debug("send_alert_email: session closed")
