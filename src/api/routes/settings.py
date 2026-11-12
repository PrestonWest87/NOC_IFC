"""Read-only and compatibility settings endpoints with per-route authorization."""

import logging
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.core.db import get_db
from src.api.auth_guard import get_current_user, is_admin, require_action, require_page
from src import services as svc

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/settings", tags=["settings"])


@router.get("/config", dependencies=[
    Depends(require_page("Settings & Admin")),
    Depends(require_action("Tab: Settings -> AI & SMTP")),
])
def get_config(db: Session = Depends(get_db), user=Depends(get_current_user)):
    """Return AI/SMTP settings without returning stored credentials."""
    logger.debug("GET /settings/config")
    from src.models.schema import SystemConfig
    config = db.query(SystemConfig).first()
    if not config:
        logger.warning("GET /settings/config: no config found")
        return {}
    return {
        "llm_endpoint": config.llm_endpoint,
        "llm_provider": config.llm_provider or "openai_compatible",
        "llm_api_key_configured": bool(config.llm_api_key),
        "llm_model_name": config.llm_model_name,
        "is_active": config.is_active,
        "active_smtp_provider": config.active_smtp_provider or "smtp",
        "smtp_enabled": config.smtp_enabled,
        "smtp_server": config.smtp_server,
        "smtp_port": config.smtp_port,
        "smtp_username": config.smtp_username,
        "smtp_sender": config.smtp_sender,
        "smtp_recipient": config.smtp_recipient,
        "smtp_password_configured": bool(config.smtp_password),
        "gmail_smtp_enabled": bool(config.gmail_smtp_enabled),
        "gmail_smtp_username": config.gmail_smtp_username or "",
        "gmail_smtp_sender": config.gmail_smtp_sender or "",
        "gmail_smtp_client_id_configured": bool(config.gmail_smtp_client_id),
        "gmail_smtp_client_secret_configured": bool(config.gmail_smtp_client_secret),
        "gmail_smtp_refresh_token_configured": bool(config.gmail_smtp_refresh_token),
        "llm_context_window": config.llm_context_window,
    }


@router.get("/users", dependencies=[
    Depends(require_action("Tab: Settings -> Users & Roles")),
    Depends(require_action("Action: Manage Users")),
])
def get_users(user=Depends(get_current_user)):
    """Return the compatibility user-directory view for authorized user managers."""
    logger.debug("GET /settings/users")
    users = svc.get_user_directory()
    logger.debug("GET /settings/users: found %d users", len(users))
    return users


@router.get("/facilities", dependencies=[
    Depends(require_page("Settings & Admin")),
    Depends(require_action("Tab: Settings -> Facility Locations")),
])
def get_facility_locations(user=Depends(get_current_user)):
    """Read-only facility directory scoped by the user's site-type grants."""
    locations = svc.get_cached_locations()
    if is_admin(user):
        return locations
    allowed_types = set(user.allowed_site_types or [])
    return [location for location in locations if location.get("loc_type") in allowed_types]


@router.get("/email-contacts", dependencies=[
    Depends(require_page("Settings & Admin")),
    Depends(require_action("Tab: Settings -> Email Contacts")),
])
def get_email_contacts():
    """Return Fiber and ONPAGE contact directories to users granted this Settings tab."""
    return {
        "fiber": svc.get_fiber_email_contacts(),
        "onpage": svc.get_onpage_email_contacts(),
    }


@router.get("/network-orders", dependencies=[
    Depends(require_page("Settings & Admin")),
    Depends(require_action("Tab: Settings -> Network Orders & Circuits")),
])
def get_network_orders():
    """Return the circuit/network-order directory to users granted its Settings tab."""
    return {"records": svc.get_network_order_circuits()}


@router.get("/rss", dependencies=[
    Depends(require_page("Settings & Admin")),
    Depends(require_action("Tab: Settings -> RSS Sources")),
])
def get_rss_settings():
    """Return RSS/keyword directory data without exposing the legacy user list."""
    keywords, feeds, _users = svc.get_admin_lists()
    return {"keywords": keywords, "feeds": feeds}
