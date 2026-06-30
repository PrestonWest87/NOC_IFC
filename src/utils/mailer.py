import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from src.core.db import SessionLocal
from src.models.schema import SystemConfig

logger = logging.getLogger(__name__)

def send_alert_email(subject: str, body: str, recipient_override: str = None, is_html: bool = True):
    session = SessionLocal()
    try:
        config = session.query(SystemConfig).first()
        if not config or not config.smtp_enabled:
            return False, "SMTP is disabled in Settings."

        target_recipient = recipient_override if recipient_override else config.smtp_recipient

        if not config.smtp_server or not config.smtp_sender or not target_recipient:
            return False, "SMTP configuration is incomplete (Missing Server, Sender, or Recipient)."

        msg = MIMEMultipart()
        msg['From'] = config.smtp_sender
        msg['To'] = target_recipient
        msg['Subject'] = f"[NOC FUSION] {subject}"

        if is_html:
            html_body = body.replace("\n", "<br>").replace("**", "<b>").replace("##", "<h2>").replace("###", "<h3>")
            # FIXED: Added 'utf-8' encoding argument to safeguard against rich text unicode characters
            msg.attach(MIMEText(html_body, 'html', 'utf-8'))
        else:
            # FIXED: Added 'utf-8' encoding argument here as well
            msg.attach(MIMEText(body, 'plain', 'utf-8'))

        # FIXED: Added a explicit 10-second timeout to prevent network drop hangs
        server = smtplib.SMTP(config.smtp_server, config.smtp_port, timeout=10)

        try:
            server.starttls()
        except Exception as tls_err:
            logger.warning(f"SMTP StartTLS skipped or unsupported: {tls_err}")

        if config.smtp_username and config.smtp_password:
            server.login(config.smtp_username, config.smtp_password)

        server.send_message(msg)
        server.quit()

        return True, "Email sent successfully."

    except Exception as e:
        logger.error(f"Mailer critical exception: {str(e)}")
        return False, str(e)
    finally:
        session.close()
