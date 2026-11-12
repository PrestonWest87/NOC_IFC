"""Template-driven operational email, scheduling, and delivery-history endpoints."""

import logging
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from src.api.auth_guard import get_current_user, require_admin, require_page
from src.core import operational_email as email_service

logger = logging.getLogger(__name__)
router = APIRouter(
    prefix="/api/v1/operational-email",
    tags=["operational-email"],
    dependencies=[Depends(require_page("Operational Email"))],
)


class EmailAttachmentInput(BaseModel):
    """Base64 attachment with field bounds; decoded size is checked by the service."""
    model_config = ConfigDict(extra="forbid")

    filename: str = Field(min_length=1, max_length=500)
    content_type: str = Field(default="application/octet-stream", max_length=100)
    content_base64: str = Field(min_length=1, max_length=7_000_000)


class ComposeOperationalEmailRequest(BaseModel):
    """One composed message; From is always resolved from global SMTP settings."""
    model_config = ConfigDict(extra="forbid")

    template_key: str = Field(min_length=1, max_length=64)
    to: str = Field(default="", max_length=5000)
    cc: str = Field(default="", max_length=5000)
    bcc: str = Field(default="", max_length=5000)
    subject: str | None = Field(default=None, max_length=500)
    body: str | None = Field(default=None, max_length=200000)
    fields: dict[str, str] = Field(default_factory=dict, max_length=40)
    attachments: list[EmailAttachmentInput] = Field(default_factory=list, max_length=5)
    maintenance_notice_id: int | None = Field(default=None, ge=1)
    source_email_id: int | None = Field(default=None, ge=1)
    signature_id: int | None = Field(default=None, ge=1)
    use_default_signature: bool = True


class OperationalEmailSchedule(BaseModel):
    """One-time future instant or daily/weekly America/Chicago recurrence."""
    model_config = ConfigDict(extra="forbid")

    schedule_type: Literal["once", "daily", "weekly"]
    scheduled_at: datetime | None = None
    recurrence_time: str | None = Field(default=None, max_length=5)
    recurrence_weekday: int | None = Field(default=None, ge=0, le=6)
    timezone: str = Field(default="America/Chicago", max_length=64)


class ScheduleOperationalEmailRequest(ComposeOperationalEmailRequest):
    """A message snapshot plus its persistent schedule definition."""
    schedule: OperationalEmailSchedule


class OperationalEmailTemplateUpdate(BaseModel):
    """Administrator-edited shared defaults; per-message edits remain available to page users."""
    model_config = ConfigDict(extra="forbid")

    default_subject: str | None = Field(default=None, max_length=500)
    default_body: str | None = Field(default=None, max_length=200000)
    default_to: str | None = Field(default=None, max_length=5000)
    default_cc: str | None = Field(default=None, max_length=5000)
    default_bcc: str | None = Field(default=None, max_length=5000)


class OperationalEmailSignatureCreate(BaseModel):
    """Create an administrator-managed reusable plain-text signature."""
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=4000)
    is_active: bool = True
    is_default: bool = False


class OperationalEmailSignatureUpdate(BaseModel):
    """Partially update signature content and availability/default selection."""
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=100)
    content: str | None = Field(default=None, min_length=1, max_length=4000)
    is_active: bool | None = None
    is_default: bool | None = None


@router.get("/templates")
def get_templates():
    """Return built-in templates, administrator defaults, global sender, and bounds."""
    return email_service.get_operational_email_templates()


@router.get("/reference-data")
def get_reference_data():
    """Return contact/network directories for Operational Email recipient selection."""
    return email_service.get_operational_email_reference_data()


@router.put("/templates/{template_key}")
def update_template(
    template_key: str,
    body: OperationalEmailTemplateUpdate,
    user=Depends(require_admin),
):
    """Update shared subject/body/recipient defaults; administrators alone may change these."""
    values = body.model_dump(exclude_unset=True)
    try:
        return email_service.update_operational_email_template(template_key, values, user.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/signatures")
def list_signatures():
    """List active reusable signatures and the current default for senders."""
    return email_service.list_operational_email_signatures()


@router.get("/signatures/manage")
def list_signatures_for_administration(user=Depends(require_admin)):
    """List active and inactive signatures for administrator management."""
    return email_service.list_operational_email_signatures(include_inactive=True)


@router.post("/signatures")
def create_signature(body: OperationalEmailSignatureCreate, user=Depends(require_admin)):
    """Create a signature; only administrators manage shared signature defaults."""
    try:
        return email_service.create_operational_email_signature(body.model_dump(), user.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.put("/signatures/{signature_id}")
def update_signature(
    signature_id: int,
    body: OperationalEmailSignatureUpdate,
    user=Depends(require_admin),
):
    """Update signature text or its active/default state."""
    try:
        return email_service.update_operational_email_signature(
            signature_id,
            body.model_dump(exclude_unset=True),
            user.id,
        )
    except ValueError as exc:
        status_code = 404 if "not found" in str(exc).lower() else 400
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc


@router.delete("/signatures/{signature_id}")
def deactivate_signature(signature_id: int, user=Depends(require_admin)):
    """Soft-disable a signature without deleting historical message references."""
    try:
        return email_service.deactivate_operational_email_signature(signature_id, user.id)
    except ValueError as exc:
        status_code = 404 if "not found" in str(exc).lower() else 400
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc


@router.post("/send")
def send_email(body: ComposeOperationalEmailRequest, user=Depends(get_current_user)):
    """Persist and send one template-based operational email immediately."""
    values = body.model_dump()
    values["attachments"] = [item.model_dump() for item in body.attachments]
    try:
        result = email_service.send_operational_email(values, user.id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    logger.info(
        "Operational email send user_id=%s template=%s email_id=%s status=%s",
        user.id, body.template_key, result.get("email_id"), result.get("status"),
    )
    return result


@router.post("/schedule")
def schedule_email(body: ScheduleOperationalEmailRequest, user=Depends(get_current_user)):
    """Persist a one-time, daily, or weekly email without relying on API process memory."""
    values = body.model_dump(exclude={"schedule"})
    values["attachments"] = [item.model_dump() for item in body.attachments]
    try:
        result = email_service.schedule_operational_email(
            values,
            body.schedule.model_dump(),
            user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    logger.info(
        "Operational email scheduled user_id=%s template=%s email_id=%s type=%s",
        user.id, body.template_key, result.get("id"), body.schedule.schedule_type,
    )
    return result


@router.get("/scheduled")
def list_scheduled_emails(limit: int = Query(100, ge=1, le=250)):
    """List active, pending, and currently processing schedules."""
    return email_service.list_scheduled_operational_emails(limit)


@router.delete("/scheduled/{email_id}")
def cancel_scheduled_email(email_id: int, user=Depends(get_current_user)):
    """Cancel a pending or recurring send; already in-flight SMTP sends are not cancellable."""
    try:
        return email_service.cancel_scheduled_operational_email(email_id, user.id)
    except ValueError as exc:
        message = str(exc)
        status_code = 409 if "being sent" in message else 404 if "not found" in message else 409
        raise HTTPException(status_code=status_code, detail=message) from exc


@router.get("/history")
def list_email_history(limit: int = Query(100, ge=1, le=250)):
    """Return recent SMTP attempt metadata for delivery history."""
    return email_service.list_operational_email_history(limit)


@router.get("/history/{delivery_id}")
def get_email_delivery(delivery_id: int):
    """Read the full immutable body/recipient snapshot for one delivery attempt."""
    delivery = email_service.get_operational_email_delivery(delivery_id)
    if not delivery:
        raise HTTPException(status_code=404, detail="Email delivery was not found.")
    return delivery


@router.get("/maintenance-notices")
def list_maintenance_notices(limit: int = Query(100, ge=1, le=250)):
    """List successfully sent maintenance notifications eligible for a completion email."""
    return email_service.list_sent_maintenance_notifications(limit)


@router.get("/fiber-outages")
def list_fiber_outages(limit: int = Query(100, ge=1, le=250)):
    """List successfully sent fiber outage notices eligible for linked progress/resolution emails."""
    return email_service.list_sent_fiber_outages(limit)
