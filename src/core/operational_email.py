"""Persistent operational email templates, delivery history, and scheduling."""

from __future__ import annotations

import base64
import binascii
import os
import re
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr
from zoneinfo import ZoneInfo

from src.core.db import SessionLocal
from src.models.schema import (
    AccountAuditEvent,
    OperationalEmail,
    OperationalEmailAttachment,
    OperationalEmailDelivery,
    OperationalEmailTemplate,
    SystemConfig,
)


EMAIL_TIMEZONE = "America/Chicago"
MAX_ATTACHMENTS = 5
MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024
MAX_TOTAL_ATTACHMENT_BYTES = 20 * 1024 * 1024
_EMAIL_RE = re.compile(
    r"^[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}$",
    re.IGNORECASE,
)
_TOKEN_RE = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")
_CONTENT_TYPE_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$")


TEMPLATE_DEFINITIONS = {
    "maintenance_notice": {
        "label": "Maintenance Notification",
        "description": "Notify stakeholders of planned work and its expected impact.",
        "allows_bcc": False,
        "allows_attachments": False,
        "fields": [
            {"key": "site", "label": "Site / service", "required": True, "max_length": 200},
            {"key": "work_scope", "label": "Planned work", "required": True, "max_length": 2000},
            {"key": "start_time", "label": "Maintenance start", "required": True, "max_length": 120},
            {"key": "end_time", "label": "Expected completion", "required": True, "max_length": 120},
            {"key": "timezone", "label": "Time zone", "required": False, "max_length": 80},
            {"key": "impact", "label": "Expected impact", "required": False, "max_length": 2000},
            {"key": "contact", "label": "Operations contact", "required": False, "max_length": 500},
            {"key": "reference", "label": "Ticket / change reference", "required": False, "max_length": 200},
        ],
        "default_subject": "Planned Maintenance — {{site}} — {{start_time}}",
        "default_body": (
            "PLANNED MAINTENANCE NOTIFICATION\n\n"
            "Site / service: {{site}}\n"
            "Planned work: {{work_scope}}\n"
            "Maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Expected impact: {{impact}}\n"
            "Operations contact: {{contact}}\n"
            "Reference: {{reference}}\n\n"
            "Please contact the Network Operations Center with questions or concerns."
        ),
    },
    "outage_dispatch": {
        "label": "Outage — Request Technician Dispatch",
        "description": "Request field technician dispatch for an active service outage.",
        "allows_bcc": False,
        "allows_attachments": False,
        "fields": [
            {"key": "site", "label": "Site", "required": True, "max_length": 200},
            {"key": "system", "label": "System / circuit", "required": True, "max_length": 250},
            {"key": "outage_start", "label": "Outage start", "required": True, "max_length": 120},
            {"key": "impact", "label": "Service impact", "required": True, "max_length": 2000},
            {"key": "priority", "label": "Priority", "required": True, "max_length": 40},
            {"key": "dispatch_action", "label": "Requested technician action", "required": True, "max_length": 2000},
            {"key": "contact", "label": "On-site contact", "required": False, "max_length": 500},
            {"key": "reference", "label": "Ticket / incident reference", "required": False, "max_length": 200},
        ],
        "default_subject": "TECH DISPATCH REQUEST — {{priority}} — {{site}} — {{system}}",
        "default_body": (
            "TECHNICIAN DISPATCH REQUEST\n\n"
            "Priority: {{priority}}\n"
            "Site: {{site}}\n"
            "System / circuit: {{system}}\n"
            "Outage start: {{outage_start}}\n"
            "Service impact: {{impact}}\n"
            "Requested action: {{dispatch_action}}\n"
            "On-site contact: {{contact}}\n"
            "Ticket / incident reference: {{reference}}\n\n"
            "Please confirm dispatch and provide an estimated arrival time."
        ),
    },
    "fiber_outage": {
        "label": "Fiber Outage",
        "description": "Notify recipients of a fiber outage; supports hidden BCC recipients.",
        "allows_bcc": True,
        "allows_attachments": False,
        "fields": [
            {"key": "site", "label": "Site / route", "required": True, "max_length": 200},
            {"key": "circuit", "label": "Fiber circuit / segment", "required": True, "max_length": 250},
            {"key": "provider", "label": "Provider", "required": False, "max_length": 200},
            {"key": "outage_start", "label": "Outage start", "required": True, "max_length": 120},
            {"key": "impact", "label": "Service impact", "required": True, "max_length": 2000},
            {"key": "restoration_estimate", "label": "Estimated restoration", "required": False, "max_length": 120},
            {"key": "requested_action", "label": "Requested action", "required": True, "max_length": 2000},
            {"key": "reference", "label": "Ticket / carrier reference", "required": False, "max_length": 200},
        ],
        "default_subject": "FIBER OUTAGE — {{site}} — {{circuit}}",
        "default_body": (
            "FIBER OUTAGE NOTIFICATION\n\n"
            "Site / route: {{site}}\n"
            "Fiber circuit / segment: {{circuit}}\n"
            "Provider: {{provider}}\n"
            "Outage start: {{outage_start}}\n"
            "Service impact: {{impact}}\n"
            "Estimated restoration: {{restoration_estimate}}\n"
            "Requested action: {{requested_action}}\n"
            "Ticket / carrier reference: {{reference}}"
        ),
    },
    "after_hours_onpage": {
        "label": "After-Hours ONPAGE",
        "description": "Urgent after-hours page requiring acknowledgement and response.",
        "allows_bcc": False,
        "allows_attachments": False,
        "fields": [
            {"key": "site", "label": "Site", "required": True, "max_length": 200},
            {"key": "severity", "label": "Severity / priority", "required": True, "max_length": 40},
            {"key": "system", "label": "Node / system", "required": True, "max_length": 250},
            {"key": "incident", "label": "Incident / alert", "required": False, "max_length": 500},
            {"key": "impact", "label": "Operational impact", "required": True, "max_length": 2000},
            {"key": "observed_at", "label": "Observed at", "required": False, "max_length": 120},
            {"key": "requested_response", "label": "Required response", "required": True, "max_length": 2000},
            {"key": "callback", "label": "Callback / NOC contact", "required": False, "max_length": 250},
        ],
        "default_subject": "URGENT AFTER-HOURS ONPAGE — {{severity}} — {{site}} — {{system}}",
        "default_body": (
            "URGENT AFTER-HOURS ONPAGE — ACKNOWLEDGEMENT REQUIRED\n\n"
            "Severity / priority: {{severity}}\n"
            "Site: {{site}}\n"
            "Node / system: {{system}}\n"
            "Incident / alert: {{incident}}\n"
            "Observed at: {{observed_at}}\n"
            "Operational impact: {{impact}}\n"
            "Required response: {{requested_response}}\n"
            "Callback / NOC contact: {{callback}}\n\n"
            "Please acknowledge this page and contact the NOC immediately."
        ),
    },
    "morning_report": {
        "label": "Morning Report",
        "description": "Send a morning operational report with bounded file attachments.",
        "allows_bcc": False,
        "allows_attachments": True,
        "fields": [
            {"key": "report_date", "label": "Report date", "required": True, "max_length": 80},
            {"key": "reporting_window", "label": "Reporting window", "required": False, "max_length": 120},
            {"key": "title", "label": "Report title", "required": True, "max_length": 250},
            {"key": "summary", "label": "Executive summary", "required": True, "max_length": 4000},
        ],
        "default_subject": "Morning Operations Report — {{report_date}} — {{title}}",
        "default_body": (
            "MORNING OPERATIONS REPORT\n\n"
            "Report date: {{report_date}}\n"
            "Reporting window: {{reporting_window}}\n"
            "Title: {{title}}\n\n"
            "EXECUTIVE SUMMARY\n{{summary}}\n\n"
            "Supporting files are attached."
        ),
    },
    "maintenance_complete": {
        "label": "Maintenance Complete",
        "description": "Close out a previously sent maintenance notification.",
        "allows_bcc": False,
        "allows_attachments": False,
        "fields": [
            {"key": "site", "label": "Site / service", "required": False, "max_length": 200},
            {"key": "work_scope", "label": "Planned work", "required": False, "max_length": 2000},
            {"key": "start_time", "label": "Original maintenance start", "required": False, "max_length": 120},
            {"key": "end_time", "label": "Original expected completion", "required": False, "max_length": 120},
            {"key": "timezone", "label": "Time zone", "required": False, "max_length": 80},
            {"key": "impact", "label": "Original expected impact", "required": False, "max_length": 2000},
            {"key": "contact", "label": "Operations contact", "required": False, "max_length": 500},
            {"key": "reference", "label": "Ticket / change reference", "required": False, "max_length": 200},
            {"key": "completion_time", "label": "Actual completion", "required": True, "max_length": 120},
            {"key": "work_performed", "label": "Work performed", "required": True, "max_length": 2000},
            {"key": "service_status", "label": "Service status", "required": True, "max_length": 500},
            {"key": "follow_up", "label": "Follow-up notes", "required": False, "max_length": 2000},
        ],
        "default_subject": "MAINTENANCE COMPLETE — {{site}} — {{completion_time}}",
        "default_body": (
            "MAINTENANCE COMPLETE\n\n"
            "Site / service: {{site}}\n"
            "Work performed: {{work_performed}}\n"
            "Original maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Actual completion: {{completion_time}}\n"
            "Service status: {{service_status}}\n"
            "Follow-up notes: {{follow_up}}\n"
            "Ticket / change reference: {{reference}}\n\n"
            "This message closes the previously issued maintenance notification."
        ),
    },
}


def ensure_operational_email_templates(session_factory=None) -> None:
    """Seed missing template defaults without overwriting administrator edits."""
    session_factory = session_factory or SessionLocal
    with session_factory() as db:
        existing = {
            key for (key,) in db.query(OperationalEmailTemplate.template_key).all()
        }
        for key, definition in TEMPLATE_DEFINITIONS.items():
            if key in existing:
                continue
            db.add(OperationalEmailTemplate(
                template_key=key,
                label=definition["label"],
                description=definition["description"],
                default_subject=definition["default_subject"],
                default_body=definition["default_body"],
                default_to="",
                default_cc="",
                default_bcc="",
            ))
        db.commit()


def normalize_recipient_list(value: str | None) -> list[str]:
    """Normalize and validate a comma/semicolon-separated email recipient list."""
    if value is None or not str(value).strip():
        return []
    if not isinstance(value, str):
        raise ValueError("Email recipients must be a comma-separated text value.")
    recipients = [item.strip() for item in re.split(r"[,;]", value) if item.strip()]
    if len(recipients) > 100:
        raise ValueError("No more than 100 recipients may be used per field.")
    invalid = [item for item in recipients if len(item) > 254 or not _EMAIL_RE.fullmatch(item)]
    if invalid:
        raise ValueError("Recipients must be valid email addresses separated by commas or semicolons.")
    seen = set()
    normalized = []
    for recipient in recipients:
        key = recipient.casefold()
        if key not in seen:
            seen.add(key)
            normalized.append(recipient)
    return normalized


def _normalize_subject(value: str, field_name: str = "Subject") -> str:
    """Reject empty subjects and header newlines before saving or sending."""
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be text.")
    value = value.strip()
    if not value or len(value) > 500 or "\r" in value or "\n" in value:
        raise ValueError(f"{field_name} must be 1–500 characters with no line breaks.")
    return value


def _fields_by_key(template_key: str) -> dict[str, dict]:
    definition = TEMPLATE_DEFINITIONS.get(template_key)
    if not definition:
        raise ValueError("Unknown operational email template.")
    return {field["key"]: field for field in definition["fields"]}


def _validate_template_text(template_key: str, value: str, label: str) -> str:
    """Validate template text length and ensure every placeholder is supported."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is required.")
    if len(value) > (500 if label == "Default subject" else 200000):
        raise ValueError(f"{label} is too long.")
    if label == "Default subject" and ("\r" in value or "\n" in value):
        raise ValueError("Default subject cannot contain line breaks.")
    supported = set(_fields_by_key(template_key))
    tokens = set(_TOKEN_RE.findall(value))
    unknown = tokens - supported
    if unknown:
        raise ValueError(f"Unsupported template placeholder(s): {', '.join(sorted(unknown))}.")
    return value.strip()


def _normalize_fields(template_key: str, fields: dict | None, inherited: dict | None = None) -> dict[str, str]:
    """Validate message-specific form fields against the selected template schema."""
    if fields is None:
        fields = {}
    if not isinstance(fields, dict):
        raise ValueError("Template fields must be an object.")
    field_schema = _fields_by_key(template_key)
    unknown = set(fields) - set(field_schema)
    if unknown:
        raise ValueError(f"Unsupported field(s) for this template: {', '.join(sorted(unknown))}.")
    result = {}
    for key, spec in field_schema.items():
        raw = fields.get(key, (inherited or {}).get(key, ""))
        if raw is None:
            raw = ""
        if not isinstance(raw, str):
            raise ValueError(f"{spec['label']} must be text.")
        value = raw.strip()
        if len(value) > spec["max_length"]:
            raise ValueError(f"{spec['label']} must be no more than {spec['max_length']} characters.")
        if spec["required"] and not value:
            raise ValueError(f"{spec['label']} is required.")
        result[key] = value
    return result


def _render_text(value: str, fields: dict[str, str]) -> str:
    """Replace only the template's simple, named placeholders; no expression evaluation."""
    return _TOKEN_RE.sub(lambda match: fields.get(match.group(1), ""), value)


def _normalize_attachments(template_key: str, attachments: list[dict] | None) -> list[dict]:
    """Decode a bounded attachment list for persistence with the email snapshot."""
    attachments = attachments or []
    if not isinstance(attachments, list) or len(attachments) > MAX_ATTACHMENTS:
        raise ValueError(f"No more than {MAX_ATTACHMENTS} attachments may be included.")
    if attachments and not TEMPLATE_DEFINITIONS[template_key]["allows_attachments"]:
        raise ValueError("Attachments are only supported by the Morning Report template.")
    result = []
    total_size = 0
    for item in attachments:
        if not isinstance(item, dict):
            raise ValueError("Invalid attachment payload.")
        original_name = str(item.get("filename") or "attachment").replace("\\", "/")
        filename = os.path.basename(original_name).strip()
        filename = "".join(char for char in filename if char >= " " and char != "\x7f")[:120]
        if not filename:
            raise ValueError("Attachment filename is required.")
        content_type = str(item.get("content_type") or "application/octet-stream").strip()
        if len(content_type) > 100 or not _CONTENT_TYPE_RE.fullmatch(content_type):
            raise ValueError(f"Attachment content type is invalid: {filename}.")
        encoded = item.get("content_base64")
        if not isinstance(encoded, str) or len(encoded) > 7_000_000:
            raise ValueError(f"Attachment content is invalid or too large: {filename}.")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError(f"Attachment content is invalid: {filename}.") from exc
        if len(content) > MAX_ATTACHMENT_BYTES:
            raise ValueError(f"Attachment exceeds the 5 MiB limit: {filename}.")
        total_size += len(content)
        if total_size > MAX_TOTAL_ATTACHMENT_BYTES:
            raise ValueError("Combined attachments may not exceed 20 MiB.")
        result.append({
            "filename": filename,
            "content_type": content_type,
            "content": content,
            "size_bytes": len(content),
        })
    return result


def _next_recurrence(schedule_type: str, run_at: str, weekday: int | None, after_utc: datetime) -> datetime:
    """Calculate the next Central wall-clock daily or weekly occurrence as naive UTC."""
    local_zone = ZoneInfo(EMAIL_TIMEZONE)
    now_local = after_utc.replace(tzinfo=timezone.utc).astimezone(local_zone)
    try:
        wall_time = datetime.strptime(run_at, "%H:%M").time()
    except (TypeError, ValueError) as exc:
        raise ValueError("Recurring send time must use 24-hour HH:MM format.") from exc
    if schedule_type == "daily":
        candidate = datetime.combine(now_local.date(), wall_time, tzinfo=local_zone)
        if candidate <= now_local:
            candidate = datetime.combine(now_local.date() + timedelta(days=1), wall_time, tzinfo=local_zone)
    elif schedule_type == "weekly":
        if isinstance(weekday, bool) or not isinstance(weekday, int) or not 0 <= weekday <= 6:
            raise ValueError("Choose a weekday from Monday through Sunday.")
        days_until = (weekday - now_local.weekday()) % 7
        candidate = datetime.combine(now_local.date() + timedelta(days=days_until), wall_time, tzinfo=local_zone)
        if candidate <= now_local:
            candidate += timedelta(days=7)
    else:
        raise ValueError("Unsupported email schedule type.")
    return candidate.astimezone(timezone.utc).replace(tzinfo=None)


def _parse_once_schedule(value) -> datetime:
    """Require a future timezone-aware timestamp and normalize it to naive UTC."""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("One-time send must use an ISO 8601 date and time.") from exc
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("One-time send must include a time zone.")
    normalized = value.astimezone(timezone.utc).replace(tzinfo=None)
    if normalized <= datetime.utcnow():
        raise ValueError("One-time send must be scheduled in the future.")
    return normalized


def _account_event(db, event_type: str, actor_user_id: int | None, detail: dict) -> None:
    """Record a low-sensitivity audit event without copying recipient addresses."""
    db.add(AccountAuditEvent(
        actor_user_id=actor_user_id,
        event_type=event_type,
        event_detail=detail,
        created_at=datetime.utcnow(),
    ))


def get_operational_email_templates() -> dict:
    """Return the template catalog, editable defaults, SMTP sender, and capability flags."""
    ensure_operational_email_templates()
    with SessionLocal() as db:
        rows = {
            row.template_key: row
            for row in db.query(OperationalEmailTemplate).all()
        }
        config = db.query(SystemConfig).first()
        templates = []
        for key, definition in TEMPLATE_DEFINITIONS.items():
            row = rows[key]
            templates.append({
                "key": key,
                "label": definition["label"],
                "description": definition["description"],
                "fields": definition["fields"],
                "allows_bcc": definition["allows_bcc"],
                "allows_attachments": definition["allows_attachments"],
                "default_subject": row.default_subject,
                "default_body": row.default_body,
                "default_to": row.default_to or "",
                "default_cc": row.default_cc or "",
                "default_bcc": row.default_bcc or "",
                "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            })
        return {
            "templates": templates,
            "sender_address": config.smtp_sender if config else "",
            "smtp_enabled": bool(config.smtp_enabled) if config else False,
            "timezone": EMAIL_TIMEZONE,
            "attachment_limits": {
                "max_attachments": MAX_ATTACHMENTS,
                "max_bytes_each": MAX_ATTACHMENT_BYTES,
                "max_bytes_total": MAX_TOTAL_ATTACHMENT_BYTES,
            },
        }


def update_operational_email_template(template_key: str, values: dict, actor_user_id: int) -> dict:
    """Update shared template defaults after validating supported placeholders and destinations."""
    if template_key not in TEMPLATE_DEFINITIONS:
        raise ValueError("Unknown operational email template.")
    allowed = {"default_subject", "default_body", "default_to", "default_cc", "default_bcc"}
    unknown = set(values) - allowed
    if unknown:
        raise ValueError(f"Unsupported template field(s): {', '.join(sorted(unknown))}.")
    if not values:
        raise ValueError("Provide at least one template default to update.")
    with SessionLocal() as db:
        row = db.query(OperationalEmailTemplate).filter_by(template_key=template_key).first()
        if not row:
            ensure_operational_email_templates()
            row = db.query(OperationalEmailTemplate).filter_by(template_key=template_key).first()
        if not row:
            raise ValueError("Operational email template is not initialized.")
        for field_name in ("default_subject", "default_body"):
            if field_name in values:
                label = "Default subject" if field_name == "default_subject" else "Default body"
                setattr(row, field_name, _validate_template_text(template_key, values[field_name], label))
        for field_name in ("default_to", "default_cc", "default_bcc"):
            if field_name not in values:
                continue
            if field_name == "default_bcc" and not TEMPLATE_DEFINITIONS[template_key]["allows_bcc"]:
                raise ValueError("BCC defaults are only supported by the Fiber Outage template.")
            normalized = normalize_recipient_list(values[field_name])
            setattr(row, field_name, ", ".join(normalized))
        row.updated_by_user_id = actor_user_id
        row.updated_at = datetime.utcnow()
        _account_event(
            db,
            "operational_email_template_updated",
            actor_user_id,
            {"template_key": template_key, "changed_fields": sorted(values)},
        )
        db.commit()
        return {"status": "updated", "template_key": template_key}


def _prepare_message(db, template_key: str, values: dict) -> dict:
    """Resolve defaults, validate recipients/fields, and create rendered message content."""
    definition = TEMPLATE_DEFINITIONS.get(template_key)
    if not definition:
        raise ValueError("Unknown operational email template.")
    template = db.query(OperationalEmailTemplate).filter_by(template_key=template_key).first()
    if not template:
        raise ValueError("Operational email template is not initialized.")

    parent_id = values.get("maintenance_notice_id")
    parent = None
    parent_fields = {}
    if template_key == "maintenance_complete":
        if isinstance(parent_id, bool) or not isinstance(parent_id, int):
            raise ValueError("Select a previously sent maintenance notification.")
        parent = db.query(OperationalEmail).filter_by(
            id=parent_id,
            template_key="maintenance_notice",
        ).first()
        has_sent_delivery = parent and db.query(OperationalEmailDelivery.id).filter_by(
            operational_email_id=parent.id,
            status="sent",
        ).first()
        if not parent or not has_sent_delivery:
            raise ValueError("The selected maintenance notification has not been sent successfully.")
        parent_fields = parent.fields_json or {}
    elif parent_id is not None:
        raise ValueError("A maintenance notice can only be linked to a Maintenance Complete email.")

    fields = _normalize_fields(template_key, values.get("fields"), parent_fields)
    subject_input = values.get("subject") or template.default_subject
    body_input = values.get("body") or template.default_body
    if not isinstance(subject_input, str) or not isinstance(body_input, str):
        raise ValueError("Email subject and body must be text.")
    fields_allowed = set(_fields_by_key(template_key))
    for text_value, label in ((subject_input, "Subject"), (body_input, "Body")):
        unknown_tokens = set(_TOKEN_RE.findall(text_value)) - fields_allowed
        if unknown_tokens:
            raise ValueError(f"Unsupported {label.lower()} placeholder(s): {', '.join(sorted(unknown_tokens))}.")
    subject = _normalize_subject(_render_text(subject_input, fields))
    body = _render_text(body_input, fields).strip()
    if not body or len(body) > 200000:
        raise ValueError("Email body must contain no more than 200,000 characters and cannot be blank.")

    to_input = values.get("to")
    cc_input = values.get("cc")
    bcc_input = values.get("bcc")
    if parent:
        to_input = to_input or ", ".join(parent.to_recipients or [])
        cc_input = cc_input or ", ".join(parent.cc_recipients or [])
        bcc_input = bcc_input or ", ".join(parent.bcc_recipients or [])
    to_input = to_input or template.default_to
    cc_input = cc_input or template.default_cc
    bcc_input = bcc_input or template.default_bcc

    to_recipients = normalize_recipient_list(to_input)
    cc_recipients = normalize_recipient_list(cc_input)
    bcc_recipients = normalize_recipient_list(bcc_input)
    if not to_recipients:
        raise ValueError("At least one To recipient is required.")
    if bcc_recipients and not definition["allows_bcc"]:
        raise ValueError("BCC recipients are only supported by the Fiber Outage template.")
    if not set(to_recipients + cc_recipients).isdisjoint(set(bcc_recipients)):
        raise ValueError("A recipient cannot appear in both a visible field and BCC.")

    attachments = _normalize_attachments(template_key, values.get("attachments"))
    return {
        "template_key": template_key,
        "parent_email_id": parent.id if parent else None,
        "subject": subject,
        "body": body,
        "fields": fields,
        "to_recipients": to_recipients,
        "cc_recipients": cc_recipients,
        "bcc_recipients": bcc_recipients,
        "attachments": attachments,
    }


def _create_email_record(db, actor_user_id: int, prepared: dict, schedule: dict | None = None) -> OperationalEmail:
    """Persist the message snapshot and any attachment bytes before SMTP delivery."""
    schedule = schedule or {"schedule_type": "immediate"}
    schedule_type = schedule["schedule_type"]
    scheduled_at = schedule.get("scheduled_at")
    next_run_at = scheduled_at
    if schedule_type in {"daily", "weekly"}:
        next_run_at = _next_recurrence(
            schedule_type,
            schedule["recurrence_time"],
            schedule.get("recurrence_weekday"),
            datetime.utcnow(),
        )
    if schedule_type == "immediate":
        status = "processing"
    elif schedule_type == "once":
        status = "scheduled"
    else:
        status = "active"
    now = datetime.utcnow()
    email = OperationalEmail(
        template_key=prepared["template_key"],
        created_by_user_id=actor_user_id,
        parent_email_id=prepared["parent_email_id"],
        subject=prepared["subject"],
        body=prepared["body"],
        fields_json=prepared["fields"],
        to_recipients=prepared["to_recipients"],
        cc_recipients=prepared["cc_recipients"],
        bcc_recipients=prepared["bcc_recipients"],
        schedule_type=schedule_type,
        timezone=EMAIL_TIMEZONE,
        scheduled_at=scheduled_at,
        recurrence_time=schedule.get("recurrence_time"),
        recurrence_weekday=schedule.get("recurrence_weekday"),
        next_run_at=next_run_at,
        processing_started_at=now if schedule_type == "immediate" else None,
        status=status,
        created_at=now,
        updated_at=now,
    )
    db.add(email)
    db.flush()
    for item in prepared["attachments"]:
        db.add(OperationalEmailAttachment(
            operational_email_id=email.id,
            filename=item["filename"],
            content_type=item["content_type"],
            content=item["content"],
            size_bytes=item["size_bytes"],
        ))
    _account_event(
        db,
        "operational_email_scheduled" if schedule_type != "immediate" else "operational_email_created",
        actor_user_id,
        {"email_id": email.id, "template_key": prepared["template_key"], "schedule_type": schedule_type},
    )
    db.commit()
    return email


def _delivery_snapshot(db, email: OperationalEmail, status: str = "sending") -> OperationalEmailDelivery:
    """Create an immutable recipient/body snapshot for one SMTP attempt."""
    config = db.query(SystemConfig).first()
    sender = config.smtp_sender if config else None
    delivery = OperationalEmailDelivery(
        operational_email_id=email.id,
        status=status,
        sender_address=sender,
        to_recipients=list(email.to_recipients or []),
        cc_recipients=list(email.cc_recipients or []),
        bcc_recipients=list(email.bcc_recipients or []),
        subject=email.subject,
        body=email.body,
        fields_json=dict(email.fields_json or {}),
        attachment_names=[attachment.filename for attachment in email.attachments],
        attempted_at=datetime.utcnow(),
    )
    db.add(delivery)
    db.flush()
    return delivery


def _configured_sender_is_valid(sender: str | None) -> bool:
    """Accept a bare or display-name sender only when it resolves to one valid address."""
    if not sender:
        return False
    _display_name, address = parseaddr(sender)
    return bool(address and _EMAIL_RE.fullmatch(address) and len(address) <= 254)


def _attempt_delivery(email_id: int) -> dict:
    """Send one stored message through the shared SMTP mailer and persist its outcome."""
    with SessionLocal() as db:
        email = db.query(OperationalEmail).filter_by(id=email_id).first()
        if not email or email.status != "processing":
            return {"email_id": email_id, "status": "error", "message": "Message is not ready to send."}
        attachments = [
            {
                "filename": item.filename,
                "content_type": item.content_type,
                "content_bytes": bytes(item.content),
            }
            for item in email.attachments
        ]
        delivery = _delivery_snapshot(db, email)
        delivery_id = delivery.id
        sender = delivery.sender_address
        subject = email.subject
        body = email.body
        to_recipients = list(email.to_recipients or [])
        cc_recipients = list(email.cc_recipients or [])
        bcc_recipients = list(email.bcc_recipients or [])
        schedule_type = email.schedule_type
        recurrence_time = email.recurrence_time
        recurrence_weekday = email.recurrence_weekday
        db.commit()

    if not _configured_sender_is_valid(sender):
        success, message = False, "Configure one valid global SMTP sender address in Settings > AI & SMTP."
    else:
        try:
            from src.utils.mailer import send_alert_email

            encoded_attachments = [
                {
                    "filename": item["filename"],
                    "content_type": item["content_type"],
                    "content_base64": base64.b64encode(item["content_bytes"]).decode("ascii"),
                }
                for item in attachments
            ]
            success, message = send_alert_email(
                subject,
                body,
                recipient_override=", ".join(to_recipients),
                cc_override=", ".join(cc_recipients),
                bcc_override=", ".join(bcc_recipients),
                is_html=False,
                attachments=encoded_attachments,
            )
        except Exception:
            success, message = False, "SMTP delivery failed."

    now = datetime.utcnow()
    with SessionLocal() as db:
        email = db.query(OperationalEmail).filter_by(id=email_id).first()
        delivery = db.query(OperationalEmailDelivery).filter_by(id=delivery_id).first()
        if not email or not delivery:
            return {"email_id": email_id, "status": "error", "message": "Delivery record could not be updated."}
        delivery.status = "sent" if success else "failed"
        delivery.sent_at = now if success else None
        delivery.error_message = None if success else str(message)[:2000]
        email.last_sent_at = now if success else email.last_sent_at
        email.last_error = None if success else str(message)[:2000]
        email.processing_started_at = None
        if schedule_type in {"daily", "weekly"}:
            email.status = "active"
            email.next_run_at = _next_recurrence(schedule_type, recurrence_time, recurrence_weekday, now)
        else:
            email.status = "sent" if success else "failed"
            email.next_run_at = None
        email.updated_at = now
        _account_event(
            db,
            "operational_email_sent" if success else "operational_email_failed",
            None,
            {"email_id": email_id, "delivery_id": delivery_id, "template_key": email.template_key},
        )
        db.commit()
        return {
            "email_id": email_id,
            "delivery_id": delivery_id,
            "status": delivery.status,
            "message": message,
            "sent_at": delivery.sent_at.isoformat() if delivery.sent_at else None,
        }


def send_operational_email(values: dict, actor_user_id: int) -> dict:
    """Validate, persist, and immediately deliver one operator-composed message."""
    template_key = values.get("template_key")
    ensure_operational_email_templates()
    with SessionLocal() as db:
        prepared = _prepare_message(db, template_key, values)
        email = _create_email_record(db, actor_user_id, prepared)
        email_id = email.id
    return _attempt_delivery(email_id)


def schedule_operational_email(values: dict, schedule_values: dict, actor_user_id: int) -> dict:
    """Persist one-time or recurring email delivery for the worker queue."""
    schedule_type = schedule_values.get("schedule_type")
    if schedule_type == "once":
        scheduled_at = _parse_once_schedule(schedule_values.get("scheduled_at"))
        schedule = {"schedule_type": "once", "scheduled_at": scheduled_at}
    elif schedule_type in {"daily", "weekly"}:
        timezone_name = schedule_values.get("timezone", EMAIL_TIMEZONE)
        if timezone_name != EMAIL_TIMEZONE:
            raise ValueError("Operational email schedules must use America/Chicago.")
        recurrence_time = str(schedule_values.get("recurrence_time") or "")
        try:
            datetime.strptime(recurrence_time, "%H:%M")
        except ValueError as exc:
            raise ValueError("Recurring send time must use 24-hour HH:MM format.") from exc
        schedule = {
            "schedule_type": schedule_type,
            "recurrence_time": recurrence_time,
            "recurrence_weekday": schedule_values.get("recurrence_weekday") if schedule_type == "weekly" else None,
        }
        if schedule_type == "weekly":
            weekday = schedule["recurrence_weekday"]
            if isinstance(weekday, bool) or not isinstance(weekday, int) or not 0 <= weekday <= 6:
                raise ValueError("Choose a weekday from Monday through Sunday.")
    else:
        raise ValueError("Choose a one-time, daily, or weekly schedule.")

    ensure_operational_email_templates()
    with SessionLocal() as db:
        prepared = _prepare_message(db, values.get("template_key"), values)
        email = _create_email_record(db, actor_user_id, prepared, schedule)
        return _serialize_email(email)


def _serialize_email(email: OperationalEmail, include_body: bool = False) -> dict:
    """Return safe message/schedule metadata for the authorized Operational Email page."""
    result = {
        "id": email.id,
        "template_key": email.template_key,
        "created_by_user_id": email.created_by_user_id,
        "parent_email_id": email.parent_email_id,
        "subject": email.subject,
        "to": list(email.to_recipients or []),
        "cc": list(email.cc_recipients or []),
        "bcc": list(email.bcc_recipients or []),
        "fields": dict(email.fields_json or {}),
        "schedule_type": email.schedule_type,
        "timezone": email.timezone,
        "scheduled_at": email.scheduled_at.isoformat() + "Z" if email.scheduled_at else None,
        "recurrence_time": email.recurrence_time,
        "recurrence_weekday": email.recurrence_weekday,
        "next_run_at": email.next_run_at.isoformat() + "Z" if email.next_run_at else None,
        "status": email.status,
        "last_sent_at": email.last_sent_at.isoformat() + "Z" if email.last_sent_at else None,
        "last_error": email.last_error,
        "created_at": email.created_at.isoformat() + "Z" if email.created_at else None,
        "attachments": [
            {"filename": item.filename, "content_type": item.content_type, "size_bytes": item.size_bytes}
            for item in email.attachments
        ],
    }
    if include_body:
        result["body"] = email.body
    return result


def list_scheduled_operational_emails(limit: int = 100) -> list[dict]:
    """Return active and pending scheduled sends for the page's schedule manager."""
    limit = min(max(int(limit), 1), 250)
    with SessionLocal() as db:
        rows = db.query(OperationalEmail).filter(
            OperationalEmail.status.in_(["scheduled", "active", "processing"]),
            OperationalEmail.schedule_type.in_(["once", "daily", "weekly"]),
        ).order_by(OperationalEmail.next_run_at, OperationalEmail.id).limit(limit).all()
        return [_serialize_email(row) for row in rows]


def cancel_scheduled_operational_email(email_id: int, actor_user_id: int) -> dict:
    """Cancel a pending or recurring schedule; in-flight SMTP attempts cannot be revoked."""
    with SessionLocal() as db:
        email = db.query(OperationalEmail).filter_by(id=email_id).first()
        if not email or email.schedule_type not in {"once", "daily", "weekly"}:
            raise ValueError("Scheduled email was not found.")
        if email.status == "processing":
            raise ValueError("This email is being sent and cannot be cancelled now.")
        if email.status not in {"scheduled", "active"}:
            raise ValueError("This email is no longer scheduled.")
        email.status = "cancelled"
        email.next_run_at = None
        email.updated_at = datetime.utcnow()
        _account_event(db, "operational_email_cancelled", actor_user_id, {"email_id": email_id})
        db.commit()
        return {"status": "cancelled", "email_id": email_id}


def list_operational_email_history(limit: int = 100) -> list[dict]:
    """Return recent delivery attempts without loading full message bodies."""
    limit = min(max(int(limit), 1), 250)
    with SessionLocal() as db:
        rows = db.query(OperationalEmailDelivery).order_by(
            OperationalEmailDelivery.attempted_at.desc(),
            OperationalEmailDelivery.id.desc(),
        ).limit(limit).all()
        result = []
        for row in rows:
            result.append({
                "id": row.id,
                "email_id": row.operational_email_id,
                "template_key": row.email.template_key if row.email else "",
                "status": row.status,
                "sender_address": row.sender_address,
                "to": list(row.to_recipients or []),
                "cc": list(row.cc_recipients or []),
                "bcc": list(row.bcc_recipients or []),
                "subject": row.subject,
                "attachment_names": list(row.attachment_names or []),
                "attempted_at": row.attempted_at.isoformat() + "Z" if row.attempted_at else None,
                "sent_at": row.sent_at.isoformat() + "Z" if row.sent_at else None,
                "error_message": row.error_message,
            })
        return result


def get_operational_email_delivery(delivery_id: int) -> dict | None:
    """Return a full immutable delivery snapshot for a message-history detail view."""
    with SessionLocal() as db:
        row = db.query(OperationalEmailDelivery).filter_by(id=delivery_id).first()
        if not row:
            return None
        return {
            "id": row.id,
            "email_id": row.operational_email_id,
            "template_key": row.email.template_key if row.email else "",
            "status": row.status,
            "sender_address": row.sender_address,
            "to": list(row.to_recipients or []),
            "cc": list(row.cc_recipients or []),
            "bcc": list(row.bcc_recipients or []),
            "subject": row.subject,
            "body": row.body,
            "fields": dict(row.fields_json or {}),
            "attachment_names": list(row.attachment_names or []),
            "attempted_at": row.attempted_at.isoformat() + "Z" if row.attempted_at else None,
            "sent_at": row.sent_at.isoformat() + "Z" if row.sent_at else None,
            "error_message": row.error_message,
        }


def list_sent_maintenance_notifications(limit: int = 100) -> list[dict]:
    """Return maintenance message records with at least one successful delivery."""
    limit = min(max(int(limit), 1), 250)
    with SessionLocal() as db:
        deliveries = db.query(OperationalEmailDelivery).join(
            OperationalEmail,
            OperationalEmail.id == OperationalEmailDelivery.operational_email_id,
        ).filter(
            OperationalEmail.template_key == "maintenance_notice",
            OperationalEmailDelivery.status == "sent",
        ).order_by(OperationalEmailDelivery.sent_at.desc()).limit(limit * 3).all()
        result = []
        seen = set()
        for delivery in deliveries:
            email = delivery.email
            if not email or email.id in seen:
                continue
            seen.add(email.id)
            result.append({
                "id": email.id,
                "subject": delivery.subject,
                "to": list(delivery.to_recipients or []),
                "cc": list(delivery.cc_recipients or []),
                "fields": dict(delivery.fields_json or {}),
                "sent_at": delivery.sent_at.isoformat() + "Z" if delivery.sent_at else None,
            })
            if len(result) >= limit:
                break
        return result


def process_due_operational_emails(limit: int = 25) -> int:
    """Claim and deliver due schedules; persist each outcome and advance recurrence."""
    now = datetime.utcnow()
    with SessionLocal() as db:
        stale_before = now - timedelta(minutes=20)
        stale_rows = db.query(OperationalEmail).filter(
            OperationalEmail.status == "processing",
            OperationalEmail.processing_started_at <= stale_before,
        ).all()
        for email in stale_rows:
            email.processing_started_at = None
            interrupted_message = "A send attempt was interrupted; delivery outcome could not be confirmed."
            email.last_error = interrupted_message
            interrupted_delivery = db.query(OperationalEmailDelivery).filter_by(
                operational_email_id=email.id,
                status="sending",
            ).order_by(OperationalEmailDelivery.attempted_at.desc()).first()
            if interrupted_delivery:
                interrupted_delivery.status = "failed"
                interrupted_delivery.error_message = interrupted_message
            if email.schedule_type in {"daily", "weekly"}:
                email.status = "active"
                email.next_run_at = _next_recurrence(
                    email.schedule_type,
                    email.recurrence_time,
                    email.recurrence_weekday,
                    now,
                )
            else:
                email.status = "failed"
                email.next_run_at = None
        db.commit()

        due_ids = [row.id for row in db.query(OperationalEmail.id).filter(
            OperationalEmail.status.in_(["scheduled", "active"]),
            OperationalEmail.next_run_at <= now,
        ).order_by(OperationalEmail.next_run_at, OperationalEmail.id).limit(limit).all()]

    delivered = 0
    for email_id in due_ids:
        with SessionLocal() as db:
            claimed = db.query(OperationalEmail).filter(
                OperationalEmail.id == email_id,
                OperationalEmail.status.in_(["scheduled", "active"]),
                OperationalEmail.next_run_at <= now,
            ).update({
                OperationalEmail.status: "processing",
                OperationalEmail.processing_started_at: datetime.utcnow(),
                OperationalEmail.updated_at: datetime.utcnow(),
            }, synchronize_session=False)
            db.commit()
        if claimed:
            _attempt_delivery(email_id)
            delivered += 1
    return delivered
