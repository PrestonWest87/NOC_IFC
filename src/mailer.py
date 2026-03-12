import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from src.database import SessionLocal, SystemConfig

def send_alert_email(subject: str, markdown_body: str):
    """Fetches SMTP config from DB and sends an HTML-formatted email."""
    session = SessionLocal()
    try:
        config = session.query(SystemConfig).first()
        if not config or not config.smtp_enabled:
            return False, "SMTP is disabled in Settings."
        if not all([config.smtp_server, config.smtp_username, config.smtp_password, config.smtp_sender, config.smtp_recipient]):
            return False, "SMTP configuration is incomplete."

        # Convert simple markdown to basic HTML for the email body
        html_body = markdown_body.replace("\n", "<br>").replace("**", "<b>").replace("##", "<h2>").replace("###", "<h3>")
        
        msg = MIMEMultipart()
        msg['From'] = config.smtp_sender
        msg['To'] = config.smtp_recipient
        msg['Subject'] = f"[NOC FUSION] {subject}"
        msg.attach(MIMEText(html_body, 'html'))

        server = smtplib.SMTP(config.smtp_server, config.smtp_port)
        server.starttls()
        server.login(config.smtp_username, config.smtp_password)
        server.send_message(msg)
        server.quit()
        
        return True, "Email sent successfully."
    except Exception as e:
        return False, str(e)
    finally:
        session.close()