import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from src.database import SessionLocal, SystemConfig

def send_alert_email(subject: str, body: str, recipient_override: str = None, is_html: bool = True):
    """Fetches SMTP config from DB and sends an email (supports unauthenticated internal relays)."""
    session = SessionLocal()
    try:
        config = session.query(SystemConfig).first()
        if not config or not config.smtp_enabled:
            return False, "SMTP is disabled in Settings."
            
        # Determine the final recipient (override from the UI, or fallback to default)
        target_recipient = recipient_override if recipient_override else config.smtp_recipient
        
        # We only STRICTLY need the server, sender, and at least one recipient
        if not config.smtp_server or not config.smtp_sender or not target_recipient:
            return False, "SMTP configuration is incomplete (Missing Server, Sender, or Recipient)."

        msg = MIMEMultipart()
        msg['From'] = config.smtp_sender
        msg['To'] = target_recipient
        msg['Subject'] = f"[NOC FUSION] {subject}"
        
        if is_html:
            # Convert simple markdown to basic HTML for the email body
            html_body = body.replace("\n", "<br>").replace("**", "<b>").replace("##", "<h2>").replace("###", "<h3>")
            msg.attach(MIMEText(html_body, 'html'))
        else:
            msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(config.smtp_server, config.smtp_port)
        
        # Attempt TLS encryption, but pass gracefully if the internal relay doesn't support it
        try:
            server.starttls()
        except Exception:
            pass 
            
        # Only attempt to authenticate if a username and password were provided in Settings
        if config.smtp_username and config.smtp_password:
            server.login(config.smtp_username, config.smtp_password)
            
        server.send_message(msg)
        server.quit()
        
        return True, "Email sent successfully."
        
    except Exception as e:
        return False, str(e)
    finally:
        session.close()
