import logging
from fastapi import APIRouter, Body
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/email", tags=["email"])


class SendEmailRequest(BaseModel):
    to: str = ""
    subject: str = ""
    html_body: str = ""


class BroadcastBriefRequest(BaseModel):
    email: str = ""


@router.post("/send")
def send_email(req: SendEmailRequest):
    logger.info("POST /email/send subject=%s to=%s body_length=%d",
                 req.subject, req.to, len(req.html_body) if req.html_body else 0)
    from src.utils.mailer import send_alert_email

    success, msg = send_alert_email(
        req.subject, req.html_body,
        recipient_override=req.to,
        is_html=True,
    )
    logger.info("POST /email/send result: success=%s msg=%s", success, msg)
    return {"status": "ok" if success else "error", "message": msg}


@router.post("/broadcast-brief")
def broadcast_brief(req: BroadcastBriefRequest):
    logger.info("POST /email/broadcast-brief email=%s", req.email)
    if not req.email:
        return {"status": "error", "message": "No recipient email specified."}

    from src.services import get_cached_config, generate_unified_brief_email_html
    from src.utils.mailer import send_alert_email
    from datetime import datetime
    from zoneinfo import ZoneInfo

    config = get_cached_config()
    brief = config.get("unified_brief")
    if not brief:
        logger.warning("POST /email/broadcast-brief: no unified brief available")
        return {"status": "error", "message": "No unified brief available. Generate one first."}

    brief_time = datetime.now(ZoneInfo("America/Chicago")).strftime("%A, %B %d, %Y at %I:%M %p %Z")
    global_risk = config.get("last_global_risk", "UNKNOWN")
    internal_risk = config.get("last_internal_risk", "UNKNOWN")

    formatted_html = generate_unified_brief_email_html(
        brief_time, brief,
        global_risk=global_risk,
        internal_risk=internal_risk,
    )

    success, msg = send_alert_email(
        "Executive Unified Risk Brief", formatted_html,
        recipient_override=req.email, is_html=True,
    )
    logger.info("POST /email/broadcast-brief result: success=%s msg=%s", success, msg)
    return {"status": "ok" if success else "error", "message": msg}
