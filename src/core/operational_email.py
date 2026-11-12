"""Persistent operational email templates, delivery history, and scheduling."""

from __future__ import annotations

import base64
import binascii
import os
import re
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr
from sqlalchemy import func
from zoneinfo import ZoneInfo

from src.core.db import SessionLocal
from src.models.schema import (
    AccountAuditEvent,
    FiberEmailContact,
    NetworkOrderCircuit,
    OnpageEmailContact,
    OperationalEmail,
    OperationalEmailAttachment,
    OperationalEmailDelivery,
    OperationalEmailSignature,
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


def application_timezone_abbreviation() -> str:
    """Return the application's current Central abbreviation (`CST` or `CDT`)."""
    abbreviation = datetime.now(ZoneInfo(EMAIL_TIMEZONE)).tzname()
    return abbreviation if abbreviation in {"CST", "CDT"} else "CST"


TEMPLATE_DEFINITIONS = {
    "maintenance_notice": {
        "label": "Maintenance Notification",
        "description": "Notify stakeholders of planned work, risk, and disruption level.",
        "allows_bcc": True,
        "allows_cc": True,
        "allows_attachments": False,
        "fields": [
            {"key": "ticket_title", "label": "Ticket title", "required": True, "max_length": 250},
            {"key": "site", "label": "Site / service", "required": True, "max_length": 200},
            {"key": "work_scope", "label": "Planned work", "required": True, "max_length": 2000},
            {"key": "start_time", "label": "Maintenance start", "required": True, "max_length": 40,
             "input_type": "datetime-local"},
            {"key": "end_time", "label": "Expected completion", "required": True, "max_length": 40,
             "input_type": "datetime-local"},
            {"key": "timezone", "label": "Application time zone", "required": False, "max_length": 80},
            {"key": "impact", "label": "Risk", "required": True, "max_length": 20,
             "options": ["None", "Low", "Medium", "High"]},
            {"key": "disruption", "label": "Disruption", "required": True, "max_length": 40,
             "options": ["Disruptive", "Nondisruptive", "Possibly Disruptive"]},
            {"key": "departmental_impact", "label": "Departmental impact", "required": False, "max_length": 2000,
             "multiline": True},
            {"key": "contact", "label": "Operations contact", "required": False, "max_length": 500},
            {"key": "reference", "label": "Ticket / change reference", "required": False, "max_length": 200},
        ],
        "default_subject": "PLANNED MAINTENANCE — {{ticket_title}}",
        "default_body": (
            "PLANNED MAINTENANCE NOTIFICATION\n\n"
            "Ticket title: {{ticket_title}}\n"
            "Site / service: {{site}}\n"
            "Planned work: {{work_scope}}\n"
            "Maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Risk: {{impact}}\n"
            "Disruption: {{disruption}}\n"
            "Departmental impact: {{departmental_impact}}\n"
            "Operations contact: {{contact}}\n"
            "Reference: {{reference}}\n\n"
            "Please contact the Network Operations Center with questions or concerns."
        ),
    },
    "fiber_maintenance_notice": {
        "label": "Fiber Maintenance Notification",
        "description": "Notify recipients about planned fiber work between A and Z endpoints.",
        "allows_bcc": True,
        "allows_cc": True,
        "network_order_autofill": True,
        "allows_attachments": False,
        "fields": [
            {"key": "ticket_title", "label": "Ticket title", "required": True, "max_length": 250},
            {"key": "network_order_ids", "label": "Selected network-order record IDs", "required": False,
             "max_length": 2000, "visible": False},
            {"key": "circuit_ids", "label": "Legacy circuit IDs", "required": False, "max_length": 1000,
             "visible": False},
            {"key": "network_orders", "label": "Network Orders", "required": False, "max_length": 20000,
             "multiline": True},
            {"key": "a_location", "label": "A location", "required": False, "max_length": 20000,
             "multiline": True},
            {"key": "z_location", "label": "Z location", "required": False, "max_length": 20000,
             "multiline": True},
            {"key": "company", "label": "Company", "required": False, "max_length": 20000,
             "multiline": True},
            {"key": "work_scope", "label": "Planned fiber work", "required": True, "max_length": 2000},
            {"key": "start_time", "label": "Maintenance start", "required": True, "max_length": 40,
             "input_type": "datetime-local"},
            {"key": "end_time", "label": "Expected completion", "required": True, "max_length": 40,
             "input_type": "datetime-local"},
            {"key": "timezone", "label": "Application time zone", "required": False, "max_length": 8},
            {"key": "impact", "label": "Risk", "required": True, "max_length": 20,
             "options": ["None", "Low", "Medium", "High"]},
            {"key": "disruption", "label": "Disruption", "required": True, "max_length": 40,
             "options": ["Disruptive", "Nondisruptive", "Possibly Disruptive"]},
            {"key": "mop_type", "label": "MOP Type", "required": False, "max_length": 80,
             "options": ["MOP Type 1", "MOP Type 2", "MOP Type 3"]},
            {"key": "departmental_impact", "label": "Departmental impact", "required": False,
             "max_length": 2000, "multiline": True},
            {"key": "contact", "label": "Fiber contact information", "required": False,
             "max_length": 2000, "multiline": True},
            {"key": "reference", "label": "Ticket / change reference", "required": False, "max_length": 200},
        ],
        "default_subject": "FIBER MAINTENANCE — {{ticket_title}}",
        "default_body": (
            "FIBER MAINTENANCE NOTIFICATION\n\n"
            "Ticket title: {{ticket_title}}\n"
            "A location: {{a_location}}\n"
            "Z location: {{z_location}}\n"
            "Network Orders: {{network_orders}}\n"
            "Company: {{company}}\n"
            "Planned work: {{work_scope}}\n"
            "Maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Risk: {{impact}}\n"
            "Disruption: {{disruption}}\n"
            "MOP Type: {{mop_type}}\n"
            "Departmental impact: {{departmental_impact}}\n"
            "Fiber contact information: {{contact}}\n"
            "Ticket / change reference: {{reference}}"
        ),
    },
    "outage_dispatch": {
        "label": "Outage — Request Technician Dispatch",
        "description": "Request field technician dispatch for an active service outage.",
        "allows_bcc": True,
        "allows_attachments": False,
        "fields": [
            {"key": "site", "label": "Site", "required": True, "max_length": 200},
            {"key": "system", "label": "System / circuit", "required": True, "max_length": 250},
            {"key": "outage_start", "label": "Outage start", "required": True, "max_length": 120},
            {"key": "timezone", "label": "Application time zone", "required": False, "max_length": 80},
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
            "Outage start: {{outage_start}} {{timezone}}\n"
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
        "allows_cc": True,
        "network_order_autofill": True,
        "allows_attachments": False,
        "fields": [
            {"key": "site", "label": "Location", "required": True, "max_length": 250},
            {"key": "circuit", "label": "Legacy circuit/segment", "required": False, "max_length": 250,
             "visible": False},
            {"key": "provider", "label": "Legacy provider", "required": False, "max_length": 200,
             "visible": False},
            {"key": "network_order_ids", "label": "Selected network-order record IDs", "required": False,
             "max_length": 2000, "visible": False},
            {"key": "network_orders", "label": "Network Orders", "required": False, "max_length": 20000,
             "multiline": True},
            {"key": "a_location", "label": "A location", "required": False, "max_length": 20000,
             "multiline": True},
            {"key": "z_location", "label": "Z location", "required": False, "max_length": 20000,
             "multiline": True},
            {"key": "company", "label": "Company", "required": False, "max_length": 20000,
             "multiline": True},
            {"key": "contact", "label": "Fiber contact information", "required": False,
             "max_length": 2000, "multiline": True},
            {"key": "outage_start", "label": "Outage start", "required": True, "max_length": 120},
            {"key": "timezone", "label": "Application time zone", "required": False, "max_length": 80},
            {"key": "impact", "label": "Service impact", "required": True, "max_length": 2000},
            {"key": "restoration_estimate", "label": "Estimated restoration", "required": False, "max_length": 120},
            {"key": "requested_action", "label": "Requested action", "required": True, "max_length": 2000},
            {"key": "reference", "label": "Ticket / carrier reference", "required": False, "max_length": 200},
        ],
        "default_subject": "FIBER OUTAGE — {{site}} — {{network_orders}}",
        "default_body": (
            "FIBER OUTAGE NOTIFICATION\n\n"
            "Location: {{site}}\n"
            "A location: {{a_location}}\n"
            "Z location: {{z_location}}\n"
            "Network Orders: {{network_orders}}\n"
            "Company: {{company}}\n"
            "Fiber contact information: {{contact}}\n"
            "Outage start: {{outage_start}} {{timezone}}\n"
            "Service impact: {{impact}}\n"
            "Estimated restoration: {{restoration_estimate}}\n"
            "Requested action: {{requested_action}}\n"
            "Ticket / carrier reference: {{reference}}"
        ),
    },
    "fiber_outage_update": {
        "label": "Fiber Outage Follow-up",
        "description": "Send a progress update linked to a successfully sent fiber outage ticket.",
        "source_template_key": "fiber_outage",
        "allows_bcc": True,
        "allows_cc": True,
        "allows_attachments": False,
        "fields": [
            {"key": "site", "label": "Location", "required": False, "max_length": 250},
            {"key": "circuit", "label": "Legacy circuit/segment", "required": False, "max_length": 250,
             "visible": False},
            {"key": "provider", "label": "Legacy provider", "required": False, "max_length": 200,
             "visible": False},
            {"key": "network_orders", "label": "Network Orders", "required": False, "max_length": 2000,
             "multiline": True},
            {"key": "a_location", "label": "A location", "required": False, "max_length": 2000,
             "multiline": True},
            {"key": "z_location", "label": "Z location", "required": False, "max_length": 2000,
             "multiline": True},
            {"key": "company", "label": "Company", "required": False, "max_length": 1000,
             "multiline": True},
            {"key": "contact", "label": "Fiber contact information", "required": False,
             "max_length": 2000, "multiline": True},
            {"key": "outage_start", "label": "Outage start", "required": False, "max_length": 120},
            {"key": "timezone", "label": "Application time zone", "required": False, "max_length": 8},
            {"key": "impact", "label": "Service impact", "required": False, "max_length": 2000},
            {"key": "requested_action", "label": "Requested action", "required": False, "max_length": 2000},
            {"key": "reference", "label": "Ticket / carrier reference", "required": False, "max_length": 200},
            {"key": "update_time", "label": "Update time", "required": True, "max_length": 120},
            {"key": "current_status", "label": "Current status", "required": True, "max_length": 120},
            {"key": "update_details", "label": "Progress update", "required": True, "max_length": 3000,
             "multiline": True},
            {"key": "restoration_estimate", "label": "Updated restoration estimate", "required": False, "max_length": 120},
            {"key": "next_update", "label": "Next update", "required": False, "max_length": 500},
        ],
        "default_subject": "FIBER OUTAGE UPDATE — {{site}} — {{network_orders}}",
        "default_body": (
            "FIBER OUTAGE PROGRESS UPDATE\n\n"
            "Location: {{site}}\n"
            "A location: {{a_location}}\n"
            "Z location: {{z_location}}\n"
            "Network Orders: {{network_orders}}\n"
            "Company: {{company}}\n"
            "Fiber contact information: {{contact}}\n"
            "Original outage start: {{outage_start}} {{timezone}}\n"
            "Update time: {{update_time}} {{timezone}}\n"
            "Current status: {{current_status}}\n"
            "Progress update: {{update_details}}\n"
            "Updated restoration estimate: {{restoration_estimate}}\n"
            "Next update: {{next_update}}\n"
            "Ticket / carrier reference: {{reference}}"
        ),
    },
    "fiber_outage_resolution": {
        "label": "Fiber Outage Resolution",
        "description": "Send a restoration/resolution notice linked to a successfully sent fiber outage ticket.",
        "source_template_key": "fiber_outage",
        "allows_bcc": True,
        "allows_cc": True,
        "allows_attachments": False,
        "fields": [
            {"key": "site", "label": "Location", "required": False, "max_length": 250},
            {"key": "circuit", "label": "Legacy circuit/segment", "required": False, "max_length": 250,
             "visible": False},
            {"key": "provider", "label": "Legacy provider", "required": False, "max_length": 200,
             "visible": False},
            {"key": "network_orders", "label": "Network Orders", "required": False, "max_length": 2000,
             "multiline": True},
            {"key": "a_location", "label": "A location", "required": False, "max_length": 2000,
             "multiline": True},
            {"key": "z_location", "label": "Z location", "required": False, "max_length": 2000,
             "multiline": True},
            {"key": "company", "label": "Company", "required": False, "max_length": 1000,
             "multiline": True},
            {"key": "contact", "label": "Fiber contact information", "required": False,
             "max_length": 2000, "multiline": True},
            {"key": "outage_start", "label": "Outage start", "required": False, "max_length": 120},
            {"key": "timezone", "label": "Application time zone", "required": False, "max_length": 8},
            {"key": "impact", "label": "Original service impact", "required": False, "max_length": 2000},
            {"key": "requested_action", "label": "Requested action", "required": False, "max_length": 2000},
            {"key": "reference", "label": "Ticket / carrier reference", "required": False, "max_length": 200},
            {"key": "resolution_time", "label": "Service restored at", "required": True, "max_length": 120},
            {"key": "resolution_details", "label": "Resolution details", "required": True, "max_length": 3000,
             "multiline": True},
            {"key": "service_status", "label": "Current service status", "required": True, "max_length": 500},
            {"key": "follow_up", "label": "Follow-up / monitoring plan", "required": False, "max_length": 2000,
             "multiline": True},
        ],
        "default_subject": "FIBER OUTAGE RESOLVED — {{site}} — {{network_orders}}",
        "default_body": (
            "FIBER SERVICE RESTORED\n\n"
            "Location: {{site}}\n"
            "A location: {{a_location}}\n"
            "Z location: {{z_location}}\n"
            "Network Orders: {{network_orders}}\n"
            "Company: {{company}}\n"
            "Fiber contact information: {{contact}}\n"
            "Original outage start: {{outage_start}} {{timezone}}\n"
            "Service restored at: {{resolution_time}} {{timezone}}\n"
            "Resolution details: {{resolution_details}}\n"
            "Current service status: {{service_status}}\n"
            "Follow-up / monitoring plan: {{follow_up}}\n"
            "Ticket / carrier reference: {{reference}}"
        ),
    },
    "after_hours_onpage": {
        "label": "After-Hours ONPAGE",
        "description": "Urgent after-hours page requiring acknowledgement and response.",
        "allows_bcc": False,
        "allows_cc": False,
        "recipients_mode": "to_only",
        "allows_attachments": False,
        "fields": [
            {"key": "site", "label": "Site", "required": True, "max_length": 200},
            {"key": "severity", "label": "Severity / priority", "required": True, "max_length": 40},
            {"key": "system", "label": "Node / system", "required": True, "max_length": 250},
            {"key": "incident", "label": "Incident / alert", "required": False, "max_length": 500},
            {"key": "impact", "label": "Operational impact", "required": True, "max_length": 2000},
            {"key": "observed_at", "label": "Observed at", "required": False, "max_length": 120},
            {"key": "timezone", "label": "Application time zone", "required": False, "max_length": 80},
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
            "Observed at: {{observed_at}} {{timezone}}\n"
            "Operational impact: {{impact}}\n"
            "Required response: {{requested_response}}\n"
            "Callback / NOC contact: {{callback}}\n\n"
            "Please acknowledge this page and contact the NOC immediately."
        ),
    },
    "morning_report": {
        "label": "Morning Report",
        "description": "Send the latest Global Dashboard shift analysis with optional attachments.",
        "allows_bcc": True,
        "allows_attachments": True,
        "fields": [
            # Hidden legacy keys allow already-customized defaults to continue
            # rendering without exposing date/title/window/summary fields again.
            {"key": "report_date", "label": "Legacy report date", "required": False, "max_length": 80, "visible": False},
            {"key": "reporting_window", "label": "Legacy reporting window", "required": False, "max_length": 120, "visible": False},
            {"key": "title", "label": "Legacy report title", "required": False, "max_length": 250, "visible": False},
            {"key": "summary", "label": "Legacy summary", "required": False, "max_length": 200000, "visible": False},
            {"key": "shift_analysis", "label": "Latest shift analysis", "required": False,
             "max_length": 200000, "visible": False},
        ],
        "default_subject": "Morning Operations Report",
        "default_body": "{{shift_analysis}}",
        "live_source": "global_shift_analysis",
    },
    "maintenance_complete": {
        "label": "Maintenance Complete",
        "description": "Close out a previously sent maintenance notification.",
        "source_template_key": "maintenance_notice",
        "allows_bcc": True,
        "allows_cc": True,
        "allows_attachments": False,
        "fields": [
            {"key": "ticket_title", "label": "Ticket title", "required": False, "max_length": 250},
            {"key": "site", "label": "Site / service", "required": False, "max_length": 200},
            {"key": "work_scope", "label": "Planned work", "required": False, "max_length": 2000},
            {"key": "start_time", "label": "Original maintenance start", "required": False, "max_length": 120},
            {"key": "end_time", "label": "Original expected completion", "required": False, "max_length": 120},
            {"key": "timezone", "label": "Application time zone", "required": False, "max_length": 80},
            {"key": "impact", "label": "Original risk", "required": False, "max_length": 2000},
            {"key": "disruption", "label": "Disruption", "required": False, "max_length": 40},
            {"key": "departmental_impact", "label": "Departmental impact", "required": False, "max_length": 2000},
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
            "Ticket title: {{ticket_title}}\n"
            "Site / service: {{site}}\n"
            "Work performed: {{work_performed}}\n"
            "Original maintenance window: {{start_time}} to {{end_time}} {{timezone}}\n"
            "Risk: {{impact}}\n"
            "Disruption: {{disruption}}\n"
            "Departmental impact: {{departmental_impact}}\n"
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


def _normalize_fields(
    template_key: str,
    fields: dict | None,
    inherited: dict | None = None,
    *,
    defer_required: bool = False,
) -> dict[str, str]:
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
        if key == "timezone":
            value = application_timezone_abbreviation()
        if len(value) > spec["max_length"]:
            raise ValueError(f"{spec['label']} must be no more than {spec['max_length']} characters.")
        if spec["required"] and not value and not defer_required:
            raise ValueError(f"{spec['label']} is required.")
        if value and spec.get("input_type") == "datetime-local":
            if not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?",
                value,
            ):
                raise ValueError(f"{spec['label']} must include a valid date and time.")
            try:
                parsed_value = datetime.fromisoformat(value)
            except ValueError as exc:
                raise ValueError(f"{spec['label']} must be a valid date and time.") from exc
            if parsed_value.tzinfo is not None:
                raise ValueError(f"{spec['label']} must be entered in the application time zone.")
            value = parsed_value.strftime("%Y-%m-%d %H:%M")
        if spec.get("options") and value not in spec["options"]:
            raise ValueError(f"Select a valid {spec['label'].lower()}.")
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


def _serialize_signature(signature: OperationalEmailSignature) -> dict:
    return {
        "id": signature.id,
        "name": signature.name,
        "content": signature.content,
        "is_active": signature.is_active,
        "is_default": signature.is_default,
        "created_at": signature.created_at.isoformat() + "Z" if signature.created_at else None,
        "updated_at": signature.updated_at.isoformat() + "Z" if signature.updated_at else None,
    }


def list_operational_email_signatures(*, include_inactive: bool = False) -> list[dict]:
    """Return active signatures to senders and optionally include disabled admin records."""
    with SessionLocal() as db:
        query = db.query(OperationalEmailSignature)
        if not include_inactive:
            query = query.filter(OperationalEmailSignature.is_active.is_(True))
        signatures = query.order_by(
            OperationalEmailSignature.name,
            OperationalEmailSignature.id,
        ).all()
        return [_serialize_signature(signature) for signature in signatures]


def _validate_signature_values(name, content) -> tuple[str, str]:
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 100:
        raise ValueError("Signature name must contain 1–100 characters.")
    normalized_name = name.strip()
    if any(ord(character) < 32 and character not in "\t" for character in normalized_name):
        raise ValueError("Signature name contains unsupported control characters.")
    if not isinstance(content, str) or not content.strip() or len(content) > 4000:
        raise ValueError("Signature content must contain 1–4,000 characters.")
    normalized_content = content.strip()
    if "\x00" in normalized_content:
        raise ValueError("Signature content contains an unsupported character.")
    return normalized_name, normalized_content


def create_operational_email_signature(values: dict, actor_user_id: int) -> dict:
    """Create an administrator-managed signature and optionally make it the default."""
    name, content = _validate_signature_values(values.get("name"), values.get("content"))
    is_active = values.get("is_active", True)
    is_default = values.get("is_default", False)
    if not isinstance(is_active, bool) or not isinstance(is_default, bool):
        raise ValueError("Signature active/default settings must be boolean values.")
    if is_default and not is_active:
        raise ValueError("An inactive signature cannot be the default.")
    with SessionLocal() as db:
        duplicate = db.query(OperationalEmailSignature.id).filter(
            func.lower(OperationalEmailSignature.name) == name.casefold(),
        ).first()
        if duplicate:
            raise ValueError("A signature with this name already exists.")
        if is_default:
            db.query(OperationalEmailSignature).update({OperationalEmailSignature.is_default: False})
        signature = OperationalEmailSignature(
            name=name,
            content=content,
            is_active=is_active,
            is_default=is_default,
            created_by_user_id=actor_user_id,
            updated_by_user_id=actor_user_id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.add(signature)
        db.flush()
        _account_event(db, "operational_email_signature_created", actor_user_id, {
            "signature_id": signature.id,
            "is_default": is_default,
        })
        db.commit()
        return _serialize_signature(signature)


def update_operational_email_signature(signature_id: int, values: dict, actor_user_id: int) -> dict:
    """Update one signature; default selection is exclusive and inactive defaults are cleared."""
    allowed = {"name", "content", "is_active", "is_default"}
    unknown = set(values) - allowed
    if unknown:
        raise ValueError(f"Unsupported signature field(s): {', '.join(sorted(unknown))}.")
    if not values:
        raise ValueError("Provide at least one signature field to update.")
    with SessionLocal() as db:
        signature = db.query(OperationalEmailSignature).filter_by(id=signature_id).first()
        if not signature:
            raise ValueError("Operational email signature was not found.")
        name = values.get("name", signature.name)
        content = values.get("content", signature.content)
        name, content = _validate_signature_values(name, content)
        duplicate = db.query(OperationalEmailSignature.id).filter(
            func.lower(OperationalEmailSignature.name) == name.casefold(),
            OperationalEmailSignature.id != signature_id,
        ).first()
        if duplicate:
            raise ValueError("A signature with this name already exists.")
        is_active = values.get("is_active", signature.is_active)
        is_default = values.get("is_default", signature.is_default)
        if not isinstance(is_active, bool) or not isinstance(is_default, bool):
            raise ValueError("Signature active/default settings must be boolean values.")
        if not is_active:
            is_default = False
        if is_default and not is_active:
            raise ValueError("An inactive signature cannot be the default.")
        if is_default:
            db.query(OperationalEmailSignature).filter(
                OperationalEmailSignature.id != signature_id,
            ).update({OperationalEmailSignature.is_default: False}, synchronize_session=False)
        signature.name = name
        signature.content = content
        signature.is_active = is_active
        signature.is_default = is_default
        signature.updated_by_user_id = actor_user_id
        signature.updated_at = datetime.utcnow()
        _account_event(db, "operational_email_signature_updated", actor_user_id, {
            "signature_id": signature.id,
            "is_active": is_active,
            "is_default": is_default,
            "changed_fields": sorted(values),
        })
        db.commit()
        return _serialize_signature(signature)


def deactivate_operational_email_signature(signature_id: int, actor_user_id: int) -> dict:
    """Soft-disable a signature so historical message snapshots retain their reference."""
    return update_operational_email_signature(
        signature_id,
        {"is_active": False, "is_default": False},
        actor_user_id,
    )


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
                "allows_cc": definition.get("allows_cc", True),
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
            "timezone_abbreviation": application_timezone_abbreviation(),
            "latest_shift_analysis": (config.rolling_summary or "") if config else "",
            "latest_shift_analysis_time": (
                config.rolling_summary_time.isoformat() + "Z"
                if config and config.rolling_summary_time else None
            ),
            "attachment_limits": {
                "max_attachments": MAX_ATTACHMENTS,
                "max_bytes_each": MAX_ATTACHMENT_BYTES,
                "max_bytes_total": MAX_TOTAL_ATTACHMENT_BYTES,
            },
        }


def get_operational_email_reference_data() -> dict:
    """Return contact and network-order directories for the authorized email composer."""
    with SessionLocal() as db:
        fiber_contacts = db.query(FiberEmailContact).order_by(
            FiberEmailContact.sort_order, FiberEmailContact.id
        ).all()
        onpage_contacts = db.query(OnpageEmailContact).order_by(
            OnpageEmailContact.sort_order, OnpageEmailContact.id
        ).all()
        network_orders = db.query(NetworkOrderCircuit).order_by(
            NetworkOrderCircuit.sort_order, NetworkOrderCircuit.id
        ).all()
        return {
            "fiber_contacts": [
                {"id": item.id, "name": item.name, "company": item.company,
                 "email": item.email, "phone": item.phone}
                for item in fiber_contacts
            ],
            "onpage_contacts": [
                {"id": item.id, "department": item.department, "email": item.email}
                for item in onpage_contacts
            ],
            "network_orders": [
                {"id": item.id, "a_location": item.a_location, "z_location": item.z_location,
                 "circuit_network_order_id": item.circuit_network_order_id, "company": item.company}
                for item in network_orders
            ],
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
                if template_key == "morning_report" and field_name == "default_body":
                    if values[field_name].strip() != "{{shift_analysis}}":
                        raise ValueError("Morning Report body is sourced directly from the latest Global Dashboard shift analysis.")
                if template_key == "morning_report" and field_name == "default_subject":
                    if _TOKEN_RE.search(values[field_name]):
                        raise ValueError("Morning Report subject must be static and cannot contain date/title placeholders.")
        for field_name in ("default_to", "default_cc", "default_bcc"):
            if field_name not in values:
                continue
            if not TEMPLATE_DEFINITIONS[template_key].get("allows_cc", True) and field_name != "default_to":
                normalized = normalize_recipient_list(values[field_name])
                if normalized:
                    raise ValueError("After-Hours ONPAGE supports To recipients only.")
                setattr(row, field_name, "")
                continue
            if field_name == "default_bcc" and not TEMPLATE_DEFINITIONS[template_key]["allows_bcc"]:
                raise ValueError("This email template does not support BCC recipients.")
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


def _append_signature(body: str, signature_content: str | None) -> str:
    """Append signature text without changing the captured body/source content."""
    if not signature_content or not body:
        return body
    separator = "" if body.endswith(("\n", "\r")) else "\n\n"
    return f"{body}{separator}--\n{signature_content}"


def _get_selected_signature(db, values: dict) -> OperationalEmailSignature | None:
    signature_id = values.get("signature_id")
    use_default = values.get("use_default_signature", True)
    if not isinstance(use_default, bool):
        raise ValueError("Use-default-signature must be a boolean value.")
    if signature_id is not None:
        if isinstance(signature_id, bool) or not isinstance(signature_id, int):
            raise ValueError("Select a valid email signature.")
        signature = db.query(OperationalEmailSignature).filter_by(
            id=signature_id,
            is_active=True,
        ).first()
        if not signature:
            raise ValueError("The selected email signature is unavailable.")
        return signature
    if not use_default:
        return None
    return db.query(OperationalEmailSignature).filter_by(
        is_active=True,
        is_default=True,
    ).order_by(OperationalEmailSignature.id).first()


def _resolve_network_order_contacts(db, template_key: str, fields: dict[str, str]) -> list[str]:
    """Validate selected network records, prefill empty details, and return Fiber BCCs."""
    definition = TEMPLATE_DEFINITIONS[template_key]
    if not definition.get("network_order_autofill"):
        return []

    raw_ids = fields.get("network_order_ids", "")
    selected_ids = []
    for value in re.split(r"[,;]", raw_ids):
        value = value.strip()
        if not value:
            continue
        if not value.isdigit() or int(value) <= 0:
            raise ValueError("Selected Network Orders contain an invalid reference ID.")
        reference_id = int(value)
        if reference_id not in selected_ids:
            selected_ids.append(reference_id)
    if len(selected_ids) > 50:
        raise ValueError("No more than 50 network-order records can be selected at once.")

    records_by_id = {}
    if selected_ids:
        records_by_id = {
            row.id: row
            for row in db.query(NetworkOrderCircuit).filter(NetworkOrderCircuit.id.in_(selected_ids)).all()
        }
        missing = [reference_id for reference_id in selected_ids if reference_id not in records_by_id]
        if missing:
            raise ValueError("One or more selected Network Order records no longer exist.")
    records = [records_by_id[reference_id] for reference_id in selected_ids]

    def unique_values(values):
        result = []
        seen = set()
        for value in values:
            value = str(value or "").strip()
            key = value.casefold()
            if value and key not in seen:
                seen.add(key)
                result.append(value)
        return result

    automatic_fields = {
        "network_orders": "; ".join(unique_values(row.circuit_network_order_id for row in records)),
        "a_location": "; ".join(unique_values(row.a_location for row in records)),
        "z_location": "; ".join(unique_values(row.z_location for row in records)),
        "company": "; ".join(unique_values(row.company for row in records)),
    }
    if "site" in _fields_by_key(template_key):
        automatic_fields["site"] = "; ".join(
            unique_values(f"{row.a_location} to {row.z_location}" for row in records)
        )
    for key, value in automatic_fields.items():
        if value and not fields.get(key, "").strip():
            fields[key] = value

    manual_company_text = fields.get("company", "")
    selected_companies = {
        value.strip().casefold()
        for value in re.split(r"[;\n]", manual_company_text)
        if value.strip()
    }
    if not fields.get("contact", "").strip():
        contacts = db.query(FiberEmailContact).order_by(
            FiberEmailContact.sort_order, FiberEmailContact.id
        ).all()
        matching_contacts = [
            contact for contact in contacts
            if contact.company and contact.company.strip().casefold() in selected_companies
        ]
        fields["contact"] = "; ".join(
            f"{contact.name} ({contact.phone})" if contact.phone else contact.name
            for contact in matching_contacts
        )[:2000]
    for key, label in (
        ("network_orders", "Network Orders"),
        ("a_location", "A location"),
        ("z_location", "Z location"),
        ("company", "Company"),
    ):
        if not fields.get(key, "").strip():
            raise ValueError(f"{label} is required.")
    if template_key == "fiber_outage" and not fields.get("site", "").strip():
        raise ValueError("Location is required.")
    return unique_values(
        contact.email
        for contact in db.query(FiberEmailContact).order_by(
            FiberEmailContact.sort_order, FiberEmailContact.id
        ).all()
        if contact.company and contact.company.strip().casefold() in selected_companies
    )


def _prepare_message(db, template_key: str, values: dict, *, for_schedule: bool = False) -> dict:
    """Resolve defaults, source links/signatures, and validate rendered message content."""
    definition = TEMPLATE_DEFINITIONS.get(template_key)
    if not definition:
        raise ValueError("Unknown operational email template.")
    template = db.query(OperationalEmailTemplate).filter_by(template_key=template_key).first()
    if not template:
        raise ValueError("Operational email template is not initialized.")

    legacy_parent_id = values.get("maintenance_notice_id")
    source_email_id = values.get("source_email_id")
    if template_key == "maintenance_complete":
        if source_email_id is not None and legacy_parent_id is not None and source_email_id != legacy_parent_id:
            raise ValueError("Choose one source maintenance notification.")
        parent_id = source_email_id if source_email_id is not None else legacy_parent_id
        source_template_key = "maintenance_notice"
    else:
        if legacy_parent_id is not None:
            raise ValueError("A maintenance notice can only be linked to a Maintenance Complete email.")
        parent_id = source_email_id
        source_template_key = definition.get("source_template_key")
    parent = None
    parent_fields = {}
    if source_template_key:
        if isinstance(parent_id, bool) or not isinstance(parent_id, int):
            raise ValueError("Select a previously sent source email.")
        parent = db.query(OperationalEmail).filter_by(
            id=parent_id,
            template_key=source_template_key,
        ).first()
        has_sent_delivery = parent and db.query(OperationalEmailDelivery.id).filter_by(
            operational_email_id=parent.id,
            status="sent",
        ).first()
        if not parent or not has_sent_delivery:
            raise ValueError("The selected source email has not been sent successfully.")
        parent_fields = parent.fields_json or {}
        if source_template_key == "fiber_outage":
            parent_fields = dict(parent_fields)
            parent_fields.setdefault("network_orders", parent_fields.get("circuit", ""))
            parent_fields.setdefault("company", parent_fields.get("provider", ""))
    elif parent_id is not None:
        raise ValueError("This email template does not support a linked source email.")

    fields = _normalize_fields(
        template_key,
        values.get("fields"),
        parent_fields,
        defer_required=bool(definition.get("network_order_autofill")),
    )
    automatic_bcc_recipients = _resolve_network_order_contacts(db, template_key, fields)
    # Autofilled reference values need the same bounds and choice validation as
    # values supplied directly by the client.
    fields = _normalize_fields(template_key, fields, parent_fields)
    subject_input = values.get("subject") or template.default_subject
    body_input = values.get("body") or template.default_body
    if not isinstance(subject_input, str) or not isinstance(body_input, str):
        raise ValueError("Email subject and body must be text.")
    fields_allowed = set(_fields_by_key(template_key))
    unknown_subject_tokens = set(_TOKEN_RE.findall(subject_input)) - fields_allowed
    if unknown_subject_tokens:
        raise ValueError(f"Unsupported subject placeholder(s): {', '.join(sorted(unknown_subject_tokens))}.")
    if definition.get("live_source") == "global_shift_analysis" and _TOKEN_RE.search(subject_input):
        subject_input = "Morning Operations Report"
    subject = _normalize_subject(_render_text(subject_input, fields))

    live_source = definition.get("live_source")
    if live_source == "global_shift_analysis":
        config = db.query(SystemConfig).first()
        source_text = (config.rolling_summary or "") if config else ""
        fields["shift_analysis"] = source_text
        if not source_text.strip() and not for_schedule:
            raise ValueError("No shift analysis is available in Global Dashboards yet.")
        body = source_text
    else:
        unknown_body_tokens = set(_TOKEN_RE.findall(body_input)) - fields_allowed
        if unknown_body_tokens:
            raise ValueError(f"Unsupported body placeholder(s): {', '.join(sorted(unknown_body_tokens))}.")
        body = _render_text(body_input, fields).strip()

    signature = _get_selected_signature(db, values)
    signature_id = signature.id if signature else None
    signature_name = signature.name if signature else None
    signature_content = signature.content if signature else None
    if live_source != "global_shift_analysis" or body:
        body = _append_signature(body, signature_content)
    if (not body and not for_schedule) or len(body) > 200000:
        raise ValueError("Email body must contain no more than 200,000 characters and cannot be blank.")

    to_input = values.get("to")
    cc_input = values.get("cc")
    bcc_input = values.get("bcc")
    to_only = definition.get("recipients_mode") == "to_only"
    if to_only:
        if normalize_recipient_list(cc_input) or normalize_recipient_list(bcc_input):
            raise ValueError("After-Hours ONPAGE supports To recipients only.")
        cc_input = ""
        bcc_input = ""
    elif parent:
        to_input = to_input or ", ".join(parent.to_recipients or [])
        cc_input = cc_input or ", ".join(parent.cc_recipients or [])
        bcc_input = bcc_input or ", ".join(parent.bcc_recipients or [])
    to_input = to_input or template.default_to
    if not to_only:
        cc_input = cc_input or template.default_cc
        bcc_input = bcc_input or template.default_bcc

    to_recipients = normalize_recipient_list(to_input)
    cc_recipients = normalize_recipient_list(cc_input)
    bcc_recipients = normalize_recipient_list(bcc_input)
    bcc_seen = {recipient.casefold() for recipient in bcc_recipients}
    for recipient in automatic_bcc_recipients:
        if recipient.casefold() not in bcc_seen:
            bcc_seen.add(recipient.casefold())
            bcc_recipients.append(recipient)
    if not to_recipients:
        raise ValueError("At least one To recipient is required.")
    if bcc_recipients and not definition["allows_bcc"]:
        raise ValueError("BCC recipients are not supported by this email template.")
    if not set(to_recipients + cc_recipients).isdisjoint(set(bcc_recipients)):
        raise ValueError("A recipient cannot appear in both a visible field and BCC.")

    attachments = _normalize_attachments(template_key, values.get("attachments"))
    return {
        "template_key": template_key,
        "parent_email_id": parent.id if parent else None,
        "signature_id": signature_id,
        "signature_name": signature_name,
        "signature_content": signature_content,
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
        signature_id=prepared["signature_id"],
        signature_name=prepared["signature_name"],
        signature_content=prepared["signature_content"],
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
        signature_id=email.signature_id,
        signature_name=email.signature_name,
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
        source_error = None
        if TEMPLATE_DEFINITIONS.get(email.template_key, {}).get("live_source") == "global_shift_analysis":
            config = db.query(SystemConfig).first()
            source_text = (config.rolling_summary or "") if config else ""
            fields = dict(email.fields_json or {})
            fields["shift_analysis"] = source_text
            email.fields_json = fields
            if not source_text.strip():
                email.body = ""
                source_error = "No shift analysis is available in Global Dashboards yet."
            else:
                email.body = _append_signature(source_text, email.signature_content)
                if len(email.body) > 200000:
                    source_error = "The latest shift analysis and signature exceed the 200,000-character email limit."
            email.updated_at = datetime.utcnow()
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

    if source_error:
        success, message = False, source_error
    elif not _configured_sender_is_valid(sender):
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
        prepared = _prepare_message(db, values.get("template_key"), values, for_schedule=True)
        email = _create_email_record(db, actor_user_id, prepared, schedule)
        return _serialize_email(email)


def _serialize_email(email: OperationalEmail, include_body: bool = False) -> dict:
    """Return safe message/schedule metadata for the authorized Operational Email page."""
    result = {
        "id": email.id,
        "template_key": email.template_key,
        "created_by_user_id": email.created_by_user_id,
        "signature_id": email.signature_id,
        "signature_name": email.signature_name,
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
                "signature_name": row.signature_name,
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
            "signature_name": row.signature_name,
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
                "bcc": list(delivery.bcc_recipients or []),
                "sent_at": delivery.sent_at.isoformat() + "Z" if delivery.sent_at else None,
            })
            if len(result) >= limit:
                break
        return result


def list_sent_fiber_outages(limit: int = 100) -> list[dict]:
    """Return fiber outage notices with a successful delivery for follow-up linking."""
    limit = min(max(int(limit), 1), 250)
    with SessionLocal() as db:
        deliveries = db.query(OperationalEmailDelivery).join(
            OperationalEmail,
            OperationalEmail.id == OperationalEmailDelivery.operational_email_id,
        ).filter(
            OperationalEmail.template_key == "fiber_outage",
            OperationalEmailDelivery.status == "sent",
        ).order_by(
            OperationalEmailDelivery.sent_at.desc(),
            OperationalEmailDelivery.id.desc(),
        ).limit(limit * 3).all()
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
                "bcc": list(delivery.bcc_recipients or []),
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
