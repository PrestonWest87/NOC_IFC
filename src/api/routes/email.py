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
    from src.utils.mailer import send_alert_email
    if not req.recipients:
        return {"status": "error", "message": "No recipients specified."}
    success, msg = send_alert_email(
        req.subject, req.body,
        recipient_override=req.recipients,
        is_html=req.is_html,
    )
    return {"status": "ok" if success else "error", "message": msg}
