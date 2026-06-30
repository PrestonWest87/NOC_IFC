import logging
from fastapi import APIRouter, Body
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/email", tags=["email"])


class SendEmailRequest(BaseModel):
    subject: str = ""
    body: str = ""
    recipients: str = ""
    is_html: bool = False


@router.post("/send")
def send_email(req: SendEmailRequest):
    logger.info("POST /email/send subject=%s recipients=%s is_html=%s body_length=%d",
                 req.subject, req.recipients, req.is_html, len(req.body) if req.body else 0)
    from src.utils.mailer import send_alert_email
    
    success, msg = send_alert_email(
        req.subject, req.body,
        recipient_override=req.recipients,
        is_html=req.is_html,
    )
    logger.info("POST /email/send result: success=%s msg=%s", success, msg)
    return {"status": "ok" if success else "error", "message": msg}
