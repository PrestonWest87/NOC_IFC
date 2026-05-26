from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.core.db import get_db

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])


@router.get("/config")
def get_config(db: Session = Depends(get_db)):
    from src.models.schema import SystemConfig
    config = db.query(SystemConfig).first()
    if not config:
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
        "sys_countermeasures": config.sys_countermeasures,
        "net_countermeasures": config.net_countermeasures,
    }


@router.get("/users")
def get_users(db: Session = Depends(get_db)):
    from src.models.schema import User
    users = db.query(User).all()
    return [
        {
            "id": u.id, "username": u.username, "role": u.role,
            "full_name": u.full_name, "job_title": u.job_title,
            "contact_info": u.contact_info,
        }
        for u in users
    ]
