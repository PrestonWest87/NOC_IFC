import logging
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session

from src.core.db import get_db
from src.services.aiops_engine import EnterpriseAIOpsEngine
from src import services as svc

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/aiops", tags=["aiops"])


@router.get("/dashboard")
def get_dashboard():
    logger.debug("GET /aiops/dashboard")
    alerts, events, grid = svc.get_aiops_dashboard_data()
    logger.debug("GET /aiops/dashboard: alerts=%d events=%d", len(alerts), len(events))
    return {"alerts": alerts, "events": events, "grid": grid}


@router.get("/sitrep")
def get_sitrep(db: Session = Depends(get_db)):
    logger.debug("GET /aiops/sitrep")
    config = db.query(svc.SystemConfig).first()
    config_dict = {
        "is_active": config.is_active if config else False,
        "llm_endpoint": config.llm_endpoint if config else "",
        "llm_api_key": config.llm_api_key if config else "",
        "llm_model_name": config.llm_model_name if config else "",
    }
    report = svc.generate_global_sitrep(config_dict)
    return {"report": report}


@router.get("/sites")
def get_sites(db: Session = Depends(get_db)):
    logger.debug("GET /aiops/sites")
    from src.models.schema import MonitoredLocation
    sites = db.query(MonitoredLocation).all()
    logger.debug("GET /aiops/sites: found %d sites", len(sites))
    return [
        {
            "id": s.id, "name": s.name, "lat": s.lat, "lon": s.lon,
            "type": s.loc_type, "district": s.district, "priority": s.priority,
            "under_maintenance": s.under_maintenance,
        }
        for s in sites
    ]


def _require_acknowledge(token: str = Query("")):
    user = svc.get_user_by_token(token)
    if not user:
        raise HTTPException(401, "Not authenticated")
    if "Action: Acknowledge RCA Alerts" not in (user.allowed_actions or []):
        raise HTTPException(403, "Missing permission: Action: Acknowledge RCA Alerts")
    return user

@router.patch("/sites/{site_id}/acknowledge")
def acknowledge_site(site_id: int, user=Depends(_require_acknowledge), db: Session = Depends(get_db)):
    logger.info("PATCH /aiops/sites/%d/acknowledge by %s", site_id, user.username)
    from src.models.schema import SolarWindsAlert
    alerts = db.query(SolarWindsAlert).filter(
        SolarWindsAlert.is_correlated == False,
        SolarWindsAlert.status != "Resolved",
    ).all()
    svc.acknowledge_cluster([a.id for a in alerts], username=user.username)
    logger.info("PATCH /aiops/sites/%d/acknowledge: acknowledged %d alerts by %s", site_id, len(alerts), user.username)
    return {"status": "acknowledged"}
