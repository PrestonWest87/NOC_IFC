"""Resolve database-overridable operational integrations across API and worker processes."""

from __future__ import annotations

from src.core.config import settings as environment_settings
from src.models.schema import SystemConfig


ENVIRONMENT_FIELDS = {
    "risk_alert_recipients": "risk_alert_recipients",
    "remedyforce_ticket_email": "remedyforce_ticket_email",
    "noc_notify_email": "noc_notify_email",
    "noc_onpage_email": "noc_onpage_email",
    "itnetwork_onpage_email": "itnetwork_onpage_email",
    "elastic_url": "elastic_url",
    "elastic_api_key": "elastic_api_key",
    "elastic_verify_certs": "elastic_verify_certs",
    "elastic_ca_certs": "elastic_ca_certs",
    "elastic_request_timeout": "elastic_request_timeout",
    "elastic_max_results": "elastic_max_results",
    "crime_alert_sms": "crime_alert_sms",
    "crime_alert_email": "crime_alert_email",
}


def resolve_operational_settings(db=None) -> tuple[dict, dict]:
    """Return effective values and per-field sources, with explicit DB values over environment.

    A nullable `SystemConfig` override means “use the process environment”. An
    explicitly stored empty string remains an override, allowing optional
    integrations to be disabled without editing the container environment.
    """
    if db is None:
        from src.core.db import SessionLocal
        with SessionLocal() as session:
            config = session.query(SystemConfig).first()
            return _resolve_from_config(config)

    return _resolve_from_config(db.query(SystemConfig).first())


def _resolve_from_config(config) -> tuple[dict, dict]:
    """Resolve one database snapshot without leaking environment access to callers."""
    values = {}
    sources = {}
    for field, environment_field in ENVIRONMENT_FIELDS.items():
        override = getattr(config, field, None) if config is not None else None
        if override is None:
            values[field] = getattr(environment_settings, environment_field)
            sources[field] = "environment"
        else:
            values[field] = override
            sources[field] = "database"
    return values, sources
