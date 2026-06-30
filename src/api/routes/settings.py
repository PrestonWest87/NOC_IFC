import logging
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.core.db import get_db

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/settings", tags=["settings"])


@router.get("/config")
def get_config(db: Session = Depends(get_db)):
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
        "smtp_sender": config.smtp_sender,
        "smtp_recipient": config.smtp_recipient,
        "tech_stack": config.tech_stack,
        "monitored_asns": config.monitored_asns,
        "scoring_mode": config.scoring_mode,
        "cyber_criticality_override": config.cyber_criticality_override,
        "cyber_lethality_override": config.cyber_lethality_override,
        "physical_criticality_override": config.physical_criticality_override,
        "physical_lethality_override": config.physical_lethality_override,
        "internal_criticality_override": config.internal_criticality_override,
        "internal_lethality_override": config.internal_lethality_override,
        "global_risk_offset": config.global_risk_offset,
        "internal_risk_offset": config.internal_risk_offset,
        "sys_countermeasures": config.sys_countermeasures,
        "net_countermeasures": config.net_countermeasures,
        "unified_brief": config.unified_brief,
        "unified_brief_time": config.unified_brief_time.isoformat() if config.unified_brief_time else None,
        "rolling_summary": config.rolling_summary,
        "rolling_summary_time": config.rolling_summary_time.isoformat() if config.rolling_summary_time else None,
    }


@router.get("/users")
def get_users(db: Session = Depends(get_db)):
    logger.debug("GET /settings/users")
    from src.models.schema import User
    users = db.query(User).all()
    logger.debug("GET /settings/users: found %d users", len(users))
    return [
        {
            "id": u.id, "username": u.username, "role": u.role,
            "full_name": u.full_name, "job_title": u.job_title,
            "contact_info": u.contact_info,
        }
        for u in users
    ]
