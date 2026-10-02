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
    logger.debug("GET /settings/config")
    from src.models.schema import SystemConfig
    config = db.query(SystemConfig).first()
    if not config:
        logger.warning("GET /settings/config: no config found")
        return {}
    return {
        "llm_endpoint": config.llm_endpoint,
        "llm_model_name": config.llm_model_name,
        "is_active": config.is_active,
        "smtp_enabled": config.smtp_enabled,
        "smtp_server": config.smtp_server,
        "smtp_port": config.smtp_port,
        "smtp_username": config.smtp_username,
        "smtp_sender": config.smtp_sender,
        "smtp_recipient": config.smtp_recipient,
        "llm_context_window": config.llm_context_window,
    }


@router.get("/users", dependencies=[
    Depends(require_action("Tab: Settings -> Users & Roles")),
    Depends(require_action("Action: Manage Users")),
])
def get_users(user=Depends(get_current_user)):
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


@router.get("/rss", dependencies=[
    Depends(require_page("Settings & Admin")),
    Depends(require_action("Tab: Settings -> RSS Sources")),
])
def get_rss_settings():
    """Return RSS/keyword directory data without exposing the legacy user list."""
    keywords, feeds, _users = svc.get_admin_lists()
    return {"keywords": keywords, "feeds": feeds}
