"""Send SMTP alerts using database configuration, with bounded optional attachments."""

import smtplib
import logging
import base64
import os
from email.utils import getaddresses, parseaddr
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from src.core.db import SessionLocal
from src.core.email_settings import get_active_smtp_profile
from src.core.gmail_oauth import GmailOAuthError, refresh_gmail_access_token
from src.models.schema import SystemConfig

logger = logging.getLogger(__name__)


def _recipient_addresses(*values):
    """Return envelope recipients from visible and hidden recipient fields."""
    normalized = [str(value).replace(";", ",") for value in values if value]
    return [address for _name, address in getaddresses(normalized) if address]


def _recipient_count(value):
    """Count non-empty comma/semicolon-separated recipient entries for safe logging."""
    if not value:
        return 0
    return len([recipient for recipient in value.replace(";", ",").split(",") if recipient.strip()])


def send_alert_email(
    subject: str,
    body: str,
    recipient_override: str = None,
    is_html: bool = True,
    attachments=None,
    cc_override: str = None,
    bcc_override: str = None,
    subject_prefix: str = "[NOC FUSION]",
):
    """Send configured SMTP mail and return `(success, message)` instead of raising.

    Existing callers retain their original From/To headers and default SMTP
    envelope behavior. The optional Cc/Bcc arguments are used by Operational
    Email; Bcc recipients are envelope-only and never appear as a message header.
    Attachments are basename-sanitized, strict-base64 decoded, and limited to
    5 MiB each.
    """
    logger.info(
        "send_alert_email: subject=%s recipient_override_set=%s is_html=%s body_length=%d",
        subject, bool(recipient_override), is_html, len(body) if body else 0,
    )
    session = SessionLocal()
    server = None
    try:
        config = session.query(SystemConfig).first()
        profile = get_active_smtp_profile(config)
        provider_label = "Gmail SMTP" if profile["provider"] == "gmail" else "SMTP"
        if not profile["enabled"]:
            if profile["provider"] == "gmail":
                logger.warning("send_alert_email: Gmail SMTP is disabled in Settings")
            else:
                logger.warning("send_alert_email: SMTP is disabled in Settings")
            return False, f"{provider_label} is disabled in Settings."

        target_recipient = recipient_override if recipient_override else profile["recipient"]
        target_count = _recipient_count(target_recipient)
        if cc_override or bcc_override:
            target_count = len(_recipient_addresses(target_recipient, cc_override, bcc_override))
        logger.debug("send_alert_email: target_recipient_count=%d", target_count)

        if not profile["server"] or not profile["sender"] or not target_recipient:
            logger.warning(
                "send_alert_email: incomplete provider=%s server_set=%s sender_set=%s recipient_count=%d",
                profile["provider"], bool(profile["server"]), bool(profile["sender"]), target_count,
            )
            return False, f"{provider_label} configuration is incomplete (missing server, sender, or recipient)."
        if profile["provider"] == "gmail" and not all(
            profile.get(key) for key in ("username", "client_id", "client_secret", "refresh_token")
        ):
            return False, "Gmail SMTP requires the account address and complete OAuth 2.0 credentials."

        msg = MIMEMultipart()
        msg['From'] = profile["sender"]
        msg['To'] = target_recipient
        if cc_override:
            msg['Cc'] = cc_override
        msg['Subject'] = f"{subject_prefix} {subject}".strip() if subject_prefix else subject

        if is_html:
            html_body = body.replace("\n", "<br>").replace("**", "<b>").replace("##", "<h2>").replace("###", "<h3>")
            msg.attach(MIMEText(html_body, 'html', 'utf-8'))
        else:
            msg.attach(MIMEText(body, 'plain', 'utf-8'))

        for attachment in attachments or []:
            filename = os.path.basename(str(attachment.get("filename", "attachment")))[:120]
            content_type = str(attachment.get("content_type", "application/octet-stream"))
            try:
                raw_content = base64.b64decode(attachment.get("content_base64", ""), validate=True)
            except Exception as exc:
                return False, f"Invalid email attachment: {filename}"
            if len(raw_content) > 5 * 1024 * 1024:
                return False, f"Email attachment too large: {filename}"
            maintype, subtype = (content_type.split("/", 1) + ["octet-stream"])[:2]
            part = MIMEBase(maintype, subtype)
            part.set_payload(raw_content)
            from email import encoders
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", "attachment", filename=filename)
            msg.attach(part)

        logger.debug("send_alert_email: connecting provider=%s server=%s port=%s timeout=10",
                      profile["provider"], profile["server"], profile["port"])
        server = smtplib.SMTP(profile["server"], profile["port"], timeout=10)
        logger.debug("send_alert_email: SMTP connection established")

        try:
            logger.debug("send_alert_email: starting TLS")
            server.starttls()
            logger.debug("send_alert_email: TLS established")
        except Exception as tls_err:
            logger.error("send_alert_email: StartTLS failed: %s", tls_err)
            return False, "SMTP TLS negotiation failed."

        if profile["provider"] == "gmail":
            access_token = refresh_gmail_access_token(profile)
            xoauth2 = f"user={profile['username']}\x01auth=Bearer {access_token}\x01\x01"

            def xoauth2_response(challenge=None):
                """Send the initial SASL token, then acknowledge OAuth error challenges."""
                return xoauth2 if challenge is None else ""

            server.auth("XOAUTH2", xoauth2_response)
        elif profile["username"] and profile["password"]:
            logger.debug("send_alert_email: authenticating with configured SMTP credentials")
            server.login(profile["username"], profile["password"])
            logger.debug("send_alert_email: login successful")

        logger.debug("send_alert_email: sending message to recipient_count=%d", target_count)
        if cc_override or bcc_override:
            envelope_recipients = _recipient_addresses(target_recipient, cc_override, bcc_override)
            if not envelope_recipients:
                return False, "Email recipients are invalid or empty."
            sender_address = parseaddr(profile["sender"])[1] or profile["sender"]
            # BCC addresses are envelope recipients only; never add a Bcc header.
            server.send_message(msg, from_addr=sender_address, to_addrs=envelope_recipients)
        else:
            server.send_message(msg)
        logger.info("send_alert_email: email sent successfully recipient_count=%d", target_count)

        return True, "Email sent successfully."

    except GmailOAuthError as oauth_err:
        logger.warning("send_alert_email: Gmail OAuth token refresh failed")
        return False, str(oauth_err)
    except smtplib.SMTPAuthenticationError as auth_err:
        config_provider = profile.get("provider") if "profile" in locals() else "smtp"
        logger.error("send_alert_email: SMTP authentication failed provider=%s", config_provider)
        if config_provider == "gmail":
            return False, "Gmail OAuth2 SMTP authentication failed. Check the account, refresh token, and granted Gmail scope."
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
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass
        session.close()
        logger.debug("send_alert_email: session closed")
