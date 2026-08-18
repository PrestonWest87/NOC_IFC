import logging
from fastapi import APIRouter, Body, Depends
from pydantic import BaseModel, Field
from src.api.auth_guard import require_page

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/email", tags=["email"], dependencies=[Depends(require_page("Reporting & Briefings"))])


class EmailAttachment(BaseModel):
    filename: str = Field("attachment", max_length=120)
    content_type: str = Field("application/octet-stream", max_length=100)
    content_base64: str = Field("", max_length=7_000_000)


class SendEmailRequest(BaseModel):
    to: str = Field("", max_length=2000)
    subject: str = Field("", max_length=200)
    html_body: str = Field("", max_length=200000)
    attachments: list[EmailAttachment] = Field(default_factory=list, max_length=5)


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
        attachments=[attachment.model_dump() for attachment in req.attachments],
    )
    logger.info("POST /email/send result: success=%s msg=%s", success, msg)
    return {"status": "ok" if success else "error", "message": msg}


@router.post("/broadcast-brief")
def broadcast_brief(req: BroadcastBriefRequest):
    logger.info("POST /email/broadcast-brief email=%s", req.email)
    if not req.email:
        return {"status": "error", "message": "No recipient email specified."}

    from src.services import get_cached_config, generate_unified_brief_email_html
    from src.database import SessionLocal, InternalRiskSnapshot
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
    with SessionLocal() as db:
        latest_internal = db.query(InternalRiskSnapshot).order_by(InternalRiskSnapshot.timestamp.desc()).first()
    internal_risk = latest_internal.risk_level if latest_internal else config.get("last_internal_risk", "UNKNOWN")

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


@router.post("/broadcast-global-brief")
def broadcast_global_brief(req: BroadcastBriefRequest):
    logger.info("POST /email/broadcast-global-brief email=%s", req.email)
    if not req.email:
        return {"status": "error", "message": "No recipient email specified."}

    from src.services import get_cached_config, generate_global_brief_email_html
    from src.database import SessionLocal, InternalRiskSnapshot
    from src.utils.mailer import send_alert_email
    from datetime import datetime
    from zoneinfo import ZoneInfo

    config = get_cached_config()
    brief = config.get("global_brief")
    if not brief:
        logger.warning("POST /email/broadcast-global-brief: no global brief available")
        return {"status": "error", "message": "No global brief available. Generate one first."}

    brief_time = datetime.now(ZoneInfo("America/Chicago")).strftime("%A, %B %d, %Y at %I:%M %p %Z")
    global_risk = config.get("last_global_risk", "UNKNOWN")
    with SessionLocal() as db:
        latest_internal = db.query(InternalRiskSnapshot).order_by(InternalRiskSnapshot.timestamp.desc()).first()
    internal_risk = latest_internal.risk_level if latest_internal else config.get("last_internal_risk", "UNKNOWN")

    formatted_html = generate_global_brief_email_html(
        brief_time, brief,
        global_risk=global_risk,
        internal_risk=internal_risk,
    )

    success, msg = send_alert_email(
        "Global Threat Brief - US Critical Infrastructure", formatted_html,
        recipient_override=req.email, is_html=True,
    )
    logger.info("POST /email/broadcast-global-brief result: success=%s msg=%s", success, msg)
    return {"status": "ok" if success else "error", "message": msg}


@router.post("/broadcast-internal-brief")
def broadcast_internal_brief(req: BroadcastBriefRequest):
    logger.info("POST /email/broadcast-internal-brief email=%s", req.email)
    if not req.email:
        return {"status": "error", "message": "No recipient email specified."}

    from src.services import get_cached_config, generate_internal_brief_email_html
    from src.database import SessionLocal, InternalRiskSnapshot
    from src.utils.mailer import send_alert_email
    from datetime import datetime
    from zoneinfo import ZoneInfo

    config = get_cached_config()
    brief = config.get("internal_brief")
    if not brief:
        logger.warning("POST /email/broadcast-internal-brief: no internal brief available")
        return {"status": "error", "message": "No internal brief available. Generate one first."}

    brief_time = datetime.now(ZoneInfo("America/Chicago")).strftime("%A, %B %d, %Y at %I:%M %p %Z")
    global_risk = config.get("last_global_risk", "UNKNOWN")
    with SessionLocal() as db:
        latest_internal = db.query(InternalRiskSnapshot).order_by(InternalRiskSnapshot.timestamp.desc()).first()
    internal_risk = latest_internal.risk_level if latest_internal else config.get("last_internal_risk", "UNKNOWN")

    formatted_html = generate_internal_brief_email_html(
        brief_time, brief,
        global_risk=global_risk,
        internal_risk=internal_risk,
    )

    success, msg = send_alert_email(
        "Internal Asset Risk Brief", formatted_html,
        recipient_override=req.email, is_html=True,
    )
    logger.info("POST /email/broadcast-internal-brief result: success=%s msg=%s", success, msg)
    return {"status": "ok" if success else "error", "message": msg}
